"""Actual BFF/provider transport and JWT code flow with explicitly synthetic IdP.

StateModel is a scheduling model; the same cases also run on isolated native
Valkey through the local acceptance runner. Neither creates a genuine User.
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from urllib.parse import urlencode

import uvicorn
from control_panel_api._native_state_scripts import COMPLETE_LOGIN
from control_panel_api._oidc import RauthyOidcAdapter
from control_panel_api._oidc_browser import (
    _NATIVE_TX_COOKIE,
    _SID_COOKIE,
    OidcBrowserSessionStore,
    oidc_browser_router,
)
from control_panel_api._oidc_native_login import native_login_router
from control_panel_api._oidc_native_start import native_login_start_router
from control_panel_api._rauthy_native_init import PinnedNativeRauthyInit
from control_panel_api.main import create_control_panel_api
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient, MockTransport, Request, Response
from pydantic import SecretStr
from test_native_pow import AsyncValkeyStub
from test_oidc_resource_binding import ProviderFixture
from valkey.exceptions import ConnectionError as ValkeyConnectionError

_ORIGIN = "https://127.0.0.1:18446"
_ISSUER = "https://localhost:18444/auth/v1/"
_CLIENT = "briareus-local-panel"
_RESOURCE = _ORIGIN + "/hands/files/mcp"
_CREDENTIALS = {
    "email": "native-fixture@example.invalid",
    "password": "not-a-provider-password",
    "pow": "fixture.solved.pow",
}
_NEW_CLIENT = AsyncClient


def make_state() -> AsyncValkeyStub:
    return AsyncValkeyStub()


class NativeProviderFixture(ProviderFixture):
    def __init__(self) -> None:
        super().__init__()
        self.mode = "success"
        self.otp_starts = 0
        self.otp_finishes = 0
        self.authorizations = 0
        self.block_path: str | None = None
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    def certificate(self) -> str:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(self.key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )

    async def __call__(self, request: Request) -> Response:
        path = request.url.path
        if self.block_path and path.endswith(self.block_path):
            self.started.set()
            await self.release.wait()
        if path.endswith("/oidc/session") and self.mode == "oversized_init":
            return Response(
                201, content=b"{" + b"I" * 12_000, headers={"Content-Type": "application/json"}
            )
        if path.endswith("/oidc/session"):
            return Response(
                201,
                json={
                    "id": "fixture-init",
                    "state": "Init",
                    "csrf_token": "C" * 32,
                    "exp": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                },
                headers={
                    "Set-Cookie": "__Host-RauthySession="
                    + "X" * 90
                    + "; Path=/; Secure; HttpOnly; SameSite=Lax"
                },
            )
        if path.endswith("/pow") and self.mode == "oversized_pow":
            return Response(200, content=b"P" * 1000, headers={"Content-Type": "text/plain"})
        if path.endswith("/pow"):
            return Response(200, text="fixture.challenge")
        if path.endswith("/users/otp_start"):
            self.otp_starts += 1
            assert request.headers["x-csrf-token"] == "Z" * 32
            assert "__Host-RauthyMfa=" + "M" * 88 in request.headers["cookie"]
            assert request.headers["cookie"].startswith("__Host-RauthySession=" + "X" * 90)
            body = json.loads(request.content)
            assert body == {"otp_id": "otp1", "purpose": {"Login": "O" * 48}}
            assert "authorization" not in request.headers
            return Response(
                200,
                json={
                    "code": "P" * 48,
                    "exp": int((datetime.now(UTC) + timedelta(seconds=120)).timestamp()),
                },
                headers={"x-csrf-token": "Y" * 32},
            )
        if path.endswith("/users/otp_finish"):
            self.otp_finishes += 1
            assert request.headers["x-csrf-token"] == "Y" * 32
            assert "__Host-RauthyMfa=" + "M" * 88 in request.headers["cookie"]
            assert json.loads(request.content) == {"code": "P" * 48, "otp_code": "123456"}
            location = (
                _ORIGIN
                + "/api/auth/oidc/callback?"
                + urlencode({"code": "K" * 64, "state": self.state_for_otp, "iss": _ISSUER})
            )
            return Response(202, json={"loc": location}, headers={"location": location})
        if path.endswith("/oidc/authorize"):
            self.authorizations += 1
            body = json.loads(request.content)
            assert set(body) == {
                "email",
                "password",
                "pow",
                "client_id",
                "redirect_uri",
                "scopes",
                "state",
                "nonce",
                "code_challenge",
                "code_challenge_method",
                "resource",
            }
            assert request.headers["cookie"] == "__Host-RauthySession=" + "X" * 90
            assert request.headers["x-csrf-token"] == "C" * 32
            assert "authorization" not in request.headers and "origin" not in request.headers
            assert body["client_id"] == _CLIENT and body["resource"] == _RESOURCE
            assert body["redirect_uri"] == _ORIGIN + "/api/auth/oidc/callback"
            assert body["code_challenge_method"] == "S256"
            assert body["pow"] == _CREDENTIALS["pow"]
            self.nonce, self.challenge = body["nonce"], body["code_challenge"]
            self.state_for_otp = body["state"]
            if self.mode == "credentials_rejected":
                return Response(401, json={"message": "upstream private detail"})
            if self.mode in {"csrf_rejected", "session_expired", "ambiguous_unauthorized"}:
                category = {
                    "csrf_rejected": "CSRFTokenError",
                    "session_expired": "SessionExpired",
                    "ambiguous_unauthorized": "Unauthorized",
                }[self.mode]
                return Response(
                    401,
                    json={
                        "error": category,
                        "timestamp": 1790000000,
                        "message": "sensitive upstream detail must never leak",
                    },
                )
            if self.mode == "request_rejected":
                return Response(400, json={"message": "upstream private detail"})
            if self.mode == "provider_access_denied":
                return Response(403, json={"message": "upstream private detail"})
            if self.mode == "outage":
                return Response(503, text="upstream private detail")
            if self.mode == "otp_pending":
                return Response(
                    200,
                    json={
                        "code": "O" * 48,
                        "active_otps": [{"otp_id": "otp1", "otp_kind": "email"}],
                    },
                    headers={
                        "Set-Cookie": "__Host-RauthyMfa="
                        + "M" * 88
                        + "; Path=/; Secure; HttpOnly; SameSite=Lax",
                        "X-CSRF-Token": "Z" * 32,
                    },
                )
            if self.mode == "otp_time_only":
                return Response(
                    200,
                    json={
                        "code": "O" * 48,
                        "active_otps": [{"otp_id": "unsupported-time", "otp_kind": "time"}],
                    },
                    headers={
                        "Set-Cookie": "__Host-RauthyMfa="
                        + "M" * 88
                        + "; Path=/; Secure; HttpOnly; SameSite=Lax",
                        "X-CSRF-Token": "Z" * 32,
                    },
                )
            if self.mode == "webauthn_pending":
                return Response(200, json={"code": "W" * 48, "exp": 120})
            if self.mode == "tos_pending":
                return Response(206, json={"tos_await_code": "T" * 48})
            if self.mode in {"account_update_required", "client_mfa_required"}:
                return Response(205 if self.mode == "account_update_required" else 406)
            if self.mode == "rate_limited":
                return Response(
                    429,
                    headers={"x-retry-not-before": str(int(datetime.now(UTC).timestamp()) + 60)},
                )
            location = (
                body["redirect_uri"]
                + "?"
                + urlencode({"code": "K" * 64, "state": body["state"], "iss": _ISSUER})
            )
            headers = [("location", location)]
            if self.mode == "duplicate_location":
                headers.append(("location", location))
            if self.mode == "foreign_callback":
                headers = [("location", "https://foreign.invalid/callback")]
            return Response(202, headers=headers)
        return await super().__call__(request)


class DelayedCompleteStore(OidcBrowserSessionStore):
    def __init__(self, client: object) -> None:
        super().__init__(password=SecretStr("f" * 64), client=client)
        self.pause_complete = False
        self.committed = asyncio.Event()
        self.release = asyncio.Event()
        self.last_ticket: str | None = None

    async def complete_native_login(self, **values: object) -> tuple[str, int] | None:
        result = await super().complete_native_login(**values)
        if result and self.pause_complete:
            self.last_ticket = result[0]
            self.committed.set()
            await self.release.wait()
        return result


class LostCommitReply:
    def __init__(self, delegate: object) -> None:
        self.delegate = delegate
        self.drop_once = True

    def __getattr__(self, name: str) -> object:
        return getattr(self.delegate, name)

    async def eval(self, script: str, *args: object) -> object:
        result = await self.delegate.eval(script, *args)
        if script == COMPLETE_LOGIN and result == 1 and self.drop_once:
            self.drop_once = False
            raise ValkeyConnectionError("controlled lost completion reply")
        return result


class NativeLoginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.fixture = NativeProviderFixture()
        self.state = make_state()
        self.store = DelayedCompleteStore(self.state)
        self.http = _NEW_CLIENT(transport=MockTransport(self.fixture), follow_redirects=False)
        self.provider = RauthyOidcAdapter(
            issuer=_ISSUER, client_id=_CLIENT, http_client=self.http, resource_audience=_RESOURCE
        )
        self.native = PinnedNativeRauthyInit(local_rauthy_cert_pem=self.fixture.certificate())
        self.public = _NEW_CLIENT(
            transport=ASGITransport(app=self.app()), base_url=_ORIGIN, follow_redirects=False
        )

        def native_http(**options: object) -> AsyncClient:
            assert isinstance(options["verify"], ssl.SSLContext)
            assert (
                options["verify"].verify_mode == ssl.CERT_REQUIRED
                and options["verify"].check_hostname
            )
            assert options["trust_env"] is False and options["follow_redirects"] is False
            return _NEW_CLIENT(transport=MockTransport(self.fixture), **options)

        self.patcher = patch(
            "control_panel_api._rauthy_native_init.httpx.AsyncClient", side_effect=native_http
        )
        self.patcher.start()
        self.states: list[str] = []

    def app(self) -> FastAPI:
        app = FastAPI()
        app.include_router(
            native_login_start_router(
                provider=self.provider,
                transactions=self.store,
                native_init=self.native,
                test_only_local_origin=_ORIGIN,
            )
        )
        app.include_router(
            native_login_router(
                provider=self.provider,
                transactions=self.store,
                native_provider=self.native,
                test_only_local_origin=_ORIGIN,
            )
        )
        app.include_router(
            oidc_browser_router(self.provider, self.store, test_only_local_origin=_ORIGIN)
        )
        return app

    async def asyncTearDown(self) -> None:
        self.fixture.release.set()
        self.store.release.set()
        for state in self.states:
            await self.store.delete_native_init(state=state)
        await self.http.aclose()
        await self.public.aclose()
        self.patcher.stop()
        if hasattr(self.state, "aclose"):
            await self.state.aclose()

    async def prepare(self, *, pow_ready: bool = True) -> str:
        started = await self.public.post("/api/v1/auth/start", json={}, headers={"Origin": _ORIGIN})
        self.assertEqual(started.status_code, 201, started.text)
        state = self.public.cookies.get(_NATIVE_TX_COOKIE)
        self.states.append(state)
        if pow_ready:
            issued = await self.public.post(
                "/api/v1/auth/pow", json={}, headers={"Origin": _ORIGIN}
            )
            self.assertEqual(issued.status_code, 200, issued.text)
        return state

    async def submit(self) -> Response:
        return await self.public.post(
            "/api/v1/auth/first-factor", json=_CREDENTIALS, headers={"Origin": _ORIGIN}
        )

    async def test_success_uses_actual_native_transport_and_signed_pkce_once(self) -> None:
        await self.prepare()
        response = await self.submit()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["permissions"], [])
        self.assertFalse(response.json()["platform_membership_verified"])
        sid = self.public.cookies.get(_SID_COOKIE)
        self.assertIsNotNone(
            await self.store.get_resource_credential(
                sid, issuer=_ISSUER, client_id=_CLIENT, audience=_RESOURCE
            )
        )
        self.assertEqual((await self.public.get("/api/v1/auth/session")).status_code, 200)
        for secret in (
            *_CREDENTIALS.values(),
            "X" * 90,
            self.fixture.access_bearer,
            self.fixture.id_bearer,
        ):
            self.assertNotIn(secret, response.text + str(response.headers))
        self.assertEqual((await self.submit()).status_code, 401)
        self.assertEqual(self.fixture.authorizations, 1)
        logout = await self.public.post("/api/v1/auth/logout", headers={"Origin": _ORIGIN})
        self.assertEqual(logout.status_code, 204)
        self.assertIsNone(await self.store.get_session(sid))

    async def test_concurrent_submissions_have_one_winner(self) -> None:
        await self.prepare()
        results = await asyncio.gather(*(self.submit() for _ in range(8)))
        self.assertEqual(sorted(result.status_code for result in results), [200] + [401] * 7)
        self.assertEqual(self.fixture.authorizations, 1)
        self.assertEqual(self.fixture.exchanges, 1)

    async def test_pow_reservation_alone_is_not_successful_issuance(self) -> None:
        state = await self.prepare(pow_ready=False)
        await self.store.reserve_native_pow(
            state=state, issuer=self.provider.issuer, client_id=_CLIENT
        )
        self.assertEqual((await self.submit()).status_code, 401)
        self.assertEqual(self.fixture.authorizations, 0)
        self.assertFalse(
            await self.store.native_init_is_current(
                state=state, issuer=self.provider.issuer, client_id=_CLIENT
            )
        )

    async def test_unimplemented_mfa_tos_and_account_updates_do_not_issue_identity(self) -> None:
        for mode in (
            "webauthn_pending",
            "tos_pending",
            "account_update_required",
            "client_mfa_required",
        ):
            self.fixture.mode = mode
            await self.prepare()
            response = await self.submit()
            self.assertEqual(response.status_code, 409, mode)
            self.assertEqual(response.json()["stage"], mode)
            self.assertIs(response.json()["authenticated"], False)
            self.assertIs(response.json()["continuation_available"], False)
            self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.fixture.exchanges, 0)

    async def test_otp_mfa_uses_private_rotated_provider_session_and_signed_pkce_once(self) -> None:
        self.fixture.mode = "otp_pending"
        await self.prepare()
        first = await self.submit()
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(
            first.json(),
            {
                "stage": "otp_pending",
                "authenticated": False,
                "continuation_available": True,
                "methods": [{"index": 0, "kind": "email"}],
            },
        )
        self.assertEqual(self.fixture.authorizations, 1)
        self.assertEqual(self.fixture.exchanges, 0)
        self.assertNotIn("set-cookie", first.headers)
        self.assertNotIn("otp1", first.text)
        self.assertNotIn("O" * 48, first.text)
        self.assertNotIn("M" * 88, first.text)
        started = await self.public.post(
            "/api/v1/auth/otp/start", json={"method_index": 0}, headers={"Origin": _ORIGIN}
        )
        self.assertEqual(started.status_code, 202, started.text)
        self.assertEqual(started.json()["stage"], "otp_code_pending")
        self.assertNotIn("P" * 48, started.text)
        self.assertEqual(self.fixture.otp_starts, 1)
        self.assertEqual(
            (
                await self.public.post(
                    "/api/v1/auth/otp/start", json={"method_index": 0}, headers={"Origin": _ORIGIN}
                )
            ).status_code,
            409,
        )
        finished = await self.public.post(
            "/api/v1/auth/otp/finish", json={"otp_code": "123456"}, headers={"Origin": _ORIGIN}
        )
        self.assertEqual(finished.status_code, 200, finished.text)
        self.assertTrue(finished.json()["authenticated"])
        self.assertFalse(finished.json()["platform_membership_verified"])
        self.assertEqual(self.fixture.otp_finishes, 1)
        self.assertEqual(self.fixture.exchanges, 1)
        sid = self.public.cookies.get(_SID_COOKIE)
        self.assertIsNotNone(sid)
        self.assertEqual((await self.public.get("/api/v1/auth/session")).status_code, 200)
        self.assertEqual(
            (
                await self.public.post(
                    "/api/v1/auth/otp/finish",
                    json={"otp_code": "123456"},
                    headers={"Origin": _ORIGIN},
                )
            ).status_code,
            409,
        )
        cancel = await self.public.post("/api/v1/auth/cancel", json={}, headers={"Origin": _ORIGIN})
        self.assertEqual(cancel.status_code, 204)
        self.assertIsNone(await self.store.get_session(sid))

    async def test_otp_start_and_finish_cancel_wins_against_in_flight_provider(self) -> None:
        self.fixture.mode = "otp_pending"
        for blocked_path in ("/users/otp_start", "/users/otp_finish"):
            self.fixture.block_path = None
            self.fixture.started.clear()
            self.fixture.release.clear()
            await self.prepare()
            self.assertEqual((await self.submit()).status_code, 202)
            if blocked_path.endswith("otp_finish"):
                started = await self.public.post(
                    "/api/v1/auth/otp/start", json={"method_index": 0}, headers={"Origin": _ORIGIN}
                )
                self.assertEqual(started.status_code, 202)
            self.fixture.block_path = blocked_path
            path = "/api/v1/auth/otp/" + (
                "start" if blocked_path.endswith("otp_start") else "finish"
            )
            body = (
                {"method_index": 0}
                if blocked_path.endswith("otp_start")
                else {"otp_code": "123456"}
            )
            working = asyncio.create_task(
                self.public.post(path, json=body, headers={"Origin": _ORIGIN})
            )
            try:
                await asyncio.wait_for(self.fixture.started.wait(), 3)
                cancelled = await self.public.post(
                    "/api/v1/auth/cancel", json={}, headers={"Origin": _ORIGIN}
                )
                self.assertEqual(cancelled.status_code, 204)
            finally:
                self.fixture.release.set()
            late = await asyncio.wait_for(working, 3)
            self.assertEqual(late.status_code, 401)
            self.assertNotIn("set-cookie", late.headers)
            self.assertIsNone(self.public.cookies.get(_SID_COOKIE))
        self.assertEqual(self.fixture.exchanges, 0)

    async def test_email_otp_accepts_only_pinned_single_space_grouping(self) -> None:
        self.fixture.mode = "otp_pending"
        await self.prepare()
        self.assertEqual((await self.submit()).status_code, 202)
        self.assertEqual(
            (
                await self.public.post(
                    "/api/v1/auth/otp/start",
                    json={"method_index": 0},
                    headers={"Origin": _ORIGIN},
                )
            ).status_code,
            202,
        )
        for malformed in ("12 34 56", "123  456", " 123456", "123456 ", "123\t456"):
            response = await self.public.post(
                "/api/v1/auth/otp/finish",
                json={"otp_code": malformed},
                headers={"Origin": _ORIGIN},
            )
            self.assertEqual(response.status_code, 422, malformed)
        good = await self.public.post(
            "/api/v1/auth/otp/finish",
            json={"otp_code": "123 456"},
            headers={"Origin": _ORIGIN},
        )
        self.assertEqual(good.status_code, 200, good.text)
        self.assertEqual(self.fixture.otp_finishes, 1)
        self.assertEqual(self.fixture.exchanges, 1)

    async def test_time_only_otp_source_is_not_a_fake_available_totp_login(self) -> None:
        self.fixture.mode = "otp_time_only"
        await self.prepare()
        response = await self.submit()
        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(
            response.json(),
            {
                "stage": "otp_pending",
                "authenticated": False,
                "continuation_available": False,
                "restart_required": True,
            },
        )
        self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.fixture.otp_starts, 0)
        self.assertEqual(self.fixture.otp_finishes, 0)
        self.assertEqual(self.fixture.exchanges, 0)
        self.assertIsNone(self.public.cookies.get(_SID_COOKIE))
        denied = await self.public.post(
            "/api/v1/auth/otp/start",
            json={"method_index": 0},
            headers={"Origin": _ORIGIN},
        )
        self.assertEqual(denied.status_code, 409)

    async def test_otp_invalid_method_code_and_duplicate_inputs_deny_before_provider(self) -> None:
        self.fixture.mode = "otp_pending"
        await self.prepare()
        self.assertEqual((await self.submit()).status_code, 202)
        for endpoint, body in (
            ("otp/start", {"method_index": True}),
            ("otp/start", {"method_index": 10}),
            ("otp/finish", {"otp_code": "abc"}),
            ("otp/finish", {"otp_code": "1" * 200}),
        ):
            denied = await self.public.post(
                "/api/v1/auth/" + endpoint, json=body, headers={"Origin": _ORIGIN}
            )
            self.assertEqual(denied.status_code, 422, denied.text)
        self.assertEqual(self.fixture.otp_starts, 0)
        self.assertEqual(self.fixture.otp_finishes, 0)
        self.assertEqual(self.fixture.exchanges, 0)
        cancel = await self.public.post("/api/v1/auth/cancel", json={}, headers={"Origin": _ORIGIN})
        self.assertEqual(cancel.status_code, 204)

    async def test_cancel_during_provider_and_userinfo_wait(self) -> None:
        for path in ("/oidc/authorize", "/oidc/userinfo"):
            self.fixture.block_path = path
            self.fixture.started.clear()
            self.fixture.release.clear()
            await self.prepare()
            task = asyncio.create_task(self.submit())
            try:
                await asyncio.wait_for(self.fixture.started.wait(), 3)
                cancelled = await self.public.post(
                    "/api/v1/auth/cancel", json={}, headers={"Origin": _ORIGIN}
                )
                self.assertEqual(cancelled.status_code, 204)
            finally:
                self.fixture.release.set()
            result = await asyncio.wait_for(task, 3)
            self.assertEqual(result.status_code, 401)
            self.assertNotIn("set-cookie", result.headers)
        self.assertIsNone(self.public.cookies.get(_SID_COOKIE))

    async def test_cancel_after_commit_before_cookie_delivery_revokes_both(self) -> None:
        await self.prepare()
        self.store.pause_complete = True
        task = asyncio.create_task(self.submit())
        try:
            await asyncio.wait_for(self.store.committed.wait(), 3)
            cancelled = await self.public.post(
                "/api/v1/auth/cancel", json={}, headers={"Origin": _ORIGIN}
            )
            self.assertEqual(cancelled.status_code, 204)
        finally:
            self.store.release.set()
        self.assertEqual((await asyncio.wait_for(task, 3)).status_code, 401)
        self.assertIsNone(await self.store.get_session(self.store.last_ticket))
        self.assertIsNone(
            await self.store.get_resource_credential(
                self.store.last_ticket, issuer=_ISSUER, client_id=_CLIENT, audience=_RESOURCE
            )
        )

    async def test_lost_commit_reply_is_retired_and_never_sets_cookie(self) -> None:
        self.store._client = LostCommitReply(self.state)
        state = await self.prepare()
        result = await self.submit()
        self.assertEqual(result.status_code, 503)
        self.assertNotIn("set-cookie", result.headers)
        self.assertIsNone(await self.state.get(self.store._key("native-init", state)))

    async def test_downstream_cancellation_waits_for_state_cleanup(self) -> None:
        self.fixture.block_path = "/oidc/authorize"
        state = await self.prepare()
        task = asyncio.create_task(self.submit())
        await asyncio.wait_for(self.fixture.started.wait(), 3)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIsNone(await self.state.get(self.store._key("native-init", state)))
        self.assertEqual(self.fixture.exchanges, 0)

    async def test_upstream_initialization_and_pow_responses_are_stream_bounded(self) -> None:
        self.fixture.mode = "oversized_init"
        denied = await self.public.post("/api/v1/auth/start", json={}, headers={"Origin": _ORIGIN})
        self.assertEqual(denied.status_code, 503)
        self.assertNotIn("set-cookie", denied.headers)
        self.assertIsNone(self.public.cookies.get(_NATIVE_TX_COOKIE))
        self.assertEqual(self.fixture.authorizations, 0)
        self.fixture.mode = "success"
        await self.prepare(pow_ready=False)
        self.fixture.mode = "oversized_pow"
        challenge = await self.public.post("/api/v1/auth/pow", json={}, headers={"Origin": _ORIGIN})
        self.assertEqual(challenge.status_code, 503)
        self.assertNotIn("challenge", challenge.json())
        self.assertEqual(self.fixture.authorizations, 0)
        burned = await self.public.post("/api/v1/auth/pow", json={}, headers={"Origin": _ORIGIN})
        self.assertEqual(burned.status_code, 409)

    async def test_native_provider_response_classification_never_mislabels_protocol_as_password(
        self,
    ) -> None:
        # Rauthy v0.37.1 POST /oidc/authorize: 400 validation, 401
        # password OR session/CSRF, 403 forbidden client/group; the provider
        # returns error text but Backend must never echo/log it or credentials.
        for mode, status, code, outcome in (
            ("credentials_rejected", 401, "NATIVE_PROVIDER_AUTH_REJECTED", "credentials_rejected"),
            ("csrf_rejected", 401, "NATIVE_PROVIDER_AUTH_REJECTED", "credentials_rejected"),
            ("session_expired", 401, "NATIVE_PROVIDER_AUTH_REJECTED", "credentials_rejected"),
            (
                "ambiguous_unauthorized",
                401,
                "NATIVE_PROVIDER_AUTH_REJECTED",
                "credentials_rejected",
            ),
            ("request_rejected", 400, "NATIVE_PROVIDER_REQUEST_REJECTED", "request_rejected"),
            (
                "provider_access_denied",
                403,
                "NATIVE_PROVIDER_ACCESS_DENIED",
                "provider_access_denied",
            ),
        ):
            with self.subTest(mode=mode):
                self.fixture.mode = mode
                await self.prepare()
                with self.assertLogs("briareus.backend.rauthy_native", level="INFO") as entries:
                    response = await self.submit()
                self.assertEqual(response.status_code, status, response.text)
                self.assertEqual(response.json(), {"error": {"code": code}})
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertNotIn("set-cookie", response.headers)
                self.assertNotIn("upstream private detail", response.text)
                self.assertNotIn("sensitive upstream detail", response.text)
                self.assertEqual(len(entries.output), 1)
                self.assertEqual(
                    entries.output[0],
                    "INFO:briareus.backend.rauthy_native:"
                    f"native_rauthy_first_factor http_status={status} result={outcome}"
                    " denial="
                    + {
                        "csrf_rejected": "csrf",
                        "session_expired": "session_expired",
                        "ambiguous_unauthorized": "ambiguous_unauthorized",
                    }.get(mode, "unclassified" if status == 401 else "none"),
                )
                for private in (
                    *_CREDENTIALS.values(),
                    "C" * 32,
                    "X" * 90,
                    "sensitive upstream detail",
                    "upstream private detail",
                ):
                    self.assertNotIn(private, entries.output[0] + response.text)
        self.assertEqual(self.fixture.exchanges, 0)

    async def test_provider_denials_rate_limits_and_ambiguous_replies_fail_closed(self) -> None:
        for mode, code in (
            ("credentials_rejected", 401),
            ("rate_limited", 429),
            ("outage", 503),
            ("duplicate_location", 503),
            ("foreign_callback", 503),
        ):
            self.fixture.mode = mode
            await self.prepare()
            response = await self.submit()
            self.assertEqual(response.status_code, code, mode)
            self.assertNotIn("upstream private detail", response.text)
            self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.fixture.exchanges, 0)

    async def test_typed_input_and_origin_cannot_override_private_transaction(self) -> None:
        await self.prepare()
        for content, origin, code in (
            (json.dumps({**_CREDENTIALS, "client_id": "foreign"}), _ORIGIN, 422),
            (json.dumps({**_CREDENTIALS, "password": True}), _ORIGIN, 422),
            (json.dumps({**_CREDENTIALS, "pow": "bad\r\nheader"}), _ORIGIN, 422),
            ('{"email":"private-first","email":"private-second"}', _ORIGIN, 422),
            (json.dumps(_CREDENTIALS), "https://foreign.invalid", 403),
        ):
            response = await self.public.post(
                "/api/v1/auth/first-factor",
                content=content,
                headers={"Origin": origin, "Content-Type": "application/json"},
            )
            self.assertEqual(response.status_code, code)
            self.assertNotIn("private-first", response.text)
        self.assertEqual(self.fixture.authorizations, 0)

    async def test_actual_tcp_disconnect_retires_claim_without_delivering_cookie(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                self.app(), log_level="error", access_log=False, lifespan="off", loop="asyncio"
            )
        )
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            for _ in range(100):
                if server.started:
                    break
                if serving.done():
                    await serving
                await asyncio.sleep(0.01)
            self.assertTrue(server.started)
            for path in ("/oidc/authorize", "/oidc/userinfo"):
                self.fixture.block_path = path
                self.fixture.started.clear()
                self.fixture.release.clear()
                state = await self.prepare()
                _reader, writer = await asyncio.open_connection("127.0.0.1", port)
                content = json.dumps(_CREDENTIALS).encode()
                headers = (
                    "POST /api/v1/auth/first-factor HTTP/1.1\r\n"
                    "Host: 127.0.0.1:18446\r\n"
                    f"Origin: {_ORIGIN}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Cookie: {_NATIVE_TX_COOKIE}={state}\r\n"
                    f"Content-Length: {len(content)}\r\n\r\n"
                ).encode()
                writer.write(headers + content)
                await writer.drain()
                await asyncio.wait_for(self.fixture.started.wait(), 3)
                writer.close()
                await writer.wait_closed()
                await asyncio.sleep(0.03)
                self.fixture.release.set()
                for _ in range(100):
                    if await self.state.get(self.store._key("native-init", state)) is None:
                        break
                    await asyncio.sleep(0.01)
                self.assertIsNone(await self.state.get(self.store._key("native-init", state)))
                self.assertIsNone(self.public.cookies.get(_SID_COOKIE))
        finally:
            self.fixture.release.set()
            server.should_exit = True
            await asyncio.wait_for(serving, 5)
            listener.close()

    async def test_capability_is_configuration_not_a_claimed_identity(self) -> None:
        response = await self.public.get("/api/v1/auth/capabilities")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "protocol": "rauthy-native-v1",
                "first_factor": "password",
                "pow": "client-solved",
                "cancel": True,
                "continuations": [],
            },
        )
        self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.fixture.authorizations, 0)

    async def test_unconfigured_factory_has_both_closed_routes(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            app = create_control_panel_api()
        async with _NEW_CLIENT(transport=ASGITransport(app=app), base_url=_ORIGIN) as client:
            self.assertEqual((await client.get("/api/v1/auth/capabilities")).status_code, 503)
            for path in ("first-factor", "cancel"):
                response = await client.post("/api/v1/auth/" + path, json={})
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertEqual(response.json()["error"]["code"], "NATIVE_OWNER_UNAVAILABLE")
