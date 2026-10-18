"""Fixed public first-factor transport with signed but synthetic Rauthy identity.

No real Rauthy account, private key, user password, client registration, or
physical Valkey is touched. The native transport still uses a CA-verifying
HTTPS context; the test client is swapped for an explicitly local mock.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ssl
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from control_panel_api._oidc import RauthyOidcAdapter
from control_panel_api._oidc_browser import (
    _NATIVE_TX_COOKIE,
    _SID_COOKIE,
    _TX_COOKIE,
    OidcBrowserSessionStore,
)
from control_panel_api._oidc_id_token import VerifiedOidcIdentity
from control_panel_api._rauthy_native_init import PinnedNativeRauthyInit
from control_panel_api.main import create_control_panel_api
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient, MockTransport, Request, Response
from pydantic import SecretStr
from test_native_pow import AsyncValkeyStub

_ORIGIN = "https://briareus.koba-nexus.ru"
_ISSUER = _ORIGIN + "/auth/v1/"
_CLIENT = "briareus-control-panel"
_RESOURCE = _ORIGIN + "/hands/files/mcp"
_SUBJECT = "P" * 24


class PublicProviderFixture:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        self.jwk.update(kid="synthetic-public-signer", alg="RS256", use="sig")
        self.nonce: str | None = None
        self.challenge: str | None = None
        self.access: str | None = None
        self.authorizations = 0
        self.mode = "success"

    def sign(self, claims: dict[str, object]) -> str:
        return jwt.encode(
            claims, self.key, headers={"kid": "synthetic-public-signer"}, algorithm="RS256"
        )

    async def __call__(self, request: Request) -> Response:
        if not str(request.url).startswith(_ISSUER):
            raise AssertionError("native request attempted a foreign authority")
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return Response(
                200,
                json={
                    "issuer": _ISSUER,
                    "authorization_endpoint": _ISSUER + "oidc/authorize",
                    "token_endpoint": _ISSUER + "oidc/token",
                    "jwks_uri": _ISSUER + "oidc/certs",
                    "userinfo_endpoint": _ISSUER + "oidc/userinfo",
                    "code_challenge_methods_supported": ["S256"],
                    "response_types_supported": ["code"],
                },
            )
        if path.endswith("/oidc/session"):
            return Response(
                201,
                json={
                    "id": "public-mock-init",
                    "state": "Init",
                    "csrf_token": "C" * 32,
                    "exp": (datetime.now(UTC) + timedelta(minutes=2)).isoformat(),
                },
                headers={
                    "Set-Cookie": "__Host-RauthySession="
                    + "X" * 90
                    + "; Path=/; Secure; HttpOnly; SameSite=Lax"
                },
            )
        if path.endswith("/pow"):
            return Response(200, text="synthetic.challenge")
        if path.endswith("/oidc/authorize"):
            self.authorizations += 1
            assert request.headers.get("cookie") == "__Host-RauthySession=" + "X" * 90
            assert request.headers.get("x-csrf-token") == "C" * 32
            assert not request.headers.get("authorization")
            incoming = json.loads(request.content)
            assert incoming["client_id"] == _CLIENT
            assert incoming["redirect_uri"] == _ORIGIN + "/api/auth/oidc/callback"
            assert incoming["resource"] == _RESOURCE
            assert incoming["pow"] == "synthetic.solution"
            assert incoming["password"] == "a-local-test-value-not-a-user-password"
            assert incoming["scopes"] == ["openid", "profile", "email"]
            self.nonce = incoming["nonce"]
            self.challenge = incoming["code_challenge"]
            if self.mode == "invalid_target":
                return Response(400, json={"error": "invalid_target"})
            callback = (
                _ORIGIN
                + "/api/auth/oidc/callback?"
                + urlencode(
                    {
                        "code": "C" * 64,
                        "state": incoming["state"],
                        "iss": _ISSUER,
                    }
                )
            )
            return Response(202, headers={"Location": callback})
        if path.endswith("/oidc/token"):
            form = parse_qs(request.content.decode())
            assert form["resource"] == [_RESOURCE]
            assert form["client_id"] == [_CLIENT]
            assert form["redirect_uri"] == [_ORIGIN + "/api/auth/oidc/callback"]
            verifier = form["code_verifier"][0]
            expected = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            assert expected == self.challenge
            now = int(datetime.now(UTC).timestamp())
            base = {"iss": _ISSUER, "sub": _SUBJECT, "iat": now, "nbf": now, "exp": now + 90}
            identity = self.sign(
                {**base, "aud": _CLIENT, "azp": _CLIENT, "nonce": self.nonce, "typ": "Id"}
            )
            self.access = self.sign(
                {
                    **base,
                    "aud": [_CLIENT, _RESOURCE],
                    "azp": _CLIENT,
                    "typ": "Bearer",
                    "jti": "public-fixture-token",
                }
            )
            return Response(
                200,
                json={
                    "id_token": identity,
                    "access_token": self.access,
                    "token_type": "Bearer",
                    "expires_in": 80,
                },
            )
        if path.endswith("/oidc/certs"):
            return Response(200, json={"keys": [self.jwk]})
        if path.endswith("/oidc/userinfo"):
            assert request.headers.get("authorization") == "Bearer " + self.access
            return Response(200, json={"id": _SUBJECT, "sub": _SUBJECT})
        raise AssertionError("unsupported fixed public mock route")


class PublicNativeModeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.fixture = PublicProviderFixture()
        self.http = AsyncClient(transport=MockTransport(self.fixture), follow_redirects=False)
        self.provider = RauthyOidcAdapter(
            issuer=_ISSUER, client_id=_CLIENT, http_client=self.http, resource_audience=_RESOURCE
        )
        self.store = OidcBrowserSessionStore(password=SecretStr("f" * 64), client=AsyncValkeyStub())
        self.native = PinnedNativeRauthyInit.for_public_dev()
        self.assertEqual(self.native.issuer + "/", _ISSUER)
        self.assertEqual(self.native.callback, _ORIGIN + "/api/auth/oidc/callback")
        self.assertEqual(self.native.client_id, _CLIENT)
        self.assertTrue(self.native._tls.check_hostname)
        self.assertEqual(self.native._tls.verify_mode, ssl.CERT_REQUIRED)

        def create_public_client(**options: object) -> AsyncClient:
            tls = options.get("verify")
            if tls is not None:
                assert isinstance(tls, ssl.SSLContext)
                assert tls.check_hostname and tls.verify_mode == ssl.CERT_REQUIRED
            assert options.get("trust_env") is False
            assert options.get("follow_redirects") is False
            return AsyncClient(transport=MockTransport(self.fixture), **options)

        self.patch_client = patch(
            "control_panel_api._rauthy_native_init.httpx.AsyncClient",
            side_effect=create_public_client,
        )
        self.patch_client.start()
        self.patch_store = patch(
            "control_panel_api.main.OidcBrowserSessionStore", return_value=self.store
        )
        self.patch_store.start()
        self.env = patch.dict("os.environ", {"OIDC_SESSION_VALKEY_PASSWORD": "f" * 64}, clear=True)
        self.env.start()
        self.app = create_control_panel_api(provider=self.provider, native_init=self.native)
        self.public = AsyncClient(
            transport=ASGITransport(app=self.app), base_url=_ORIGIN, follow_redirects=False
        )

    async def asyncTearDown(self) -> None:
        await self.public.aclose()
        await self.http.aclose()
        self.env.stop()
        self.patch_store.stop()
        self.patch_client.stop()

    async def test_public_factory_protects_full_signed_first_factor(self) -> None:
        app = self.app
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url=_ORIGIN, follow_redirects=False
        ) as client:
            capabilities = await client.get("/api/v1/auth/capabilities")
            self.assertEqual(capabilities.status_code, 200)
            start = await client.post("/api/v1/auth/start", json={}, headers={"Origin": _ORIGIN})
            self.assertEqual(start.status_code, 201, start.text)
            challenge = await client.post("/api/v1/auth/pow", json={}, headers={"Origin": _ORIGIN})
            self.assertEqual(challenge.status_code, 200, challenge.text)
            login = await client.post(
                "/api/v1/auth/first-factor",
                json={
                    "email": "synthetic@example.invalid",
                    "password": "a-local-test-value-not-a-user-password",
                    "pow": "synthetic.solution",
                },
                headers={"Origin": _ORIGIN},
            )
            self.assertEqual(login.status_code, 200, login.text)
            self.assertEqual(login.json()["permissions"], [])
            sid = client.cookies.get(_SID_COOKIE)
            credential = await self.store.get_resource_credential(
                sid, issuer=_ISSUER, client_id=_CLIENT, audience=_RESOURCE
            )
            self.assertEqual(credential.bearer.get_secret_value(), self.fixture.access)
            self.assertEqual((await client.get("/api/v1/auth/session")).status_code, 200)
            self.assertNotIn(self.fixture.access, str(login.headers) + login.text)
            self.assertEqual(self.fixture.authorizations, 1)
            canceled = await client.post(
                "/api/v1/auth/cancel", json={}, headers={"Origin": _ORIGIN}
            )
            self.assertEqual(canceled.status_code, 204)
            self.assertIsNone(await self.store.get_session(sid))

    async def test_existing_oidc_env_derives_native_and_exact_files_resource(self) -> None:
        self.env.stop()
        try:
            with patch.dict(
                "os.environ",
                {
                    "OIDC_ISSUER": _ISSUER,
                    "OIDC_CLIENT_ID": _CLIENT,
                    "OIDC_SESSION_VALKEY_PASSWORD": "f" * 64,
                },
                clear=True,
            ):
                app = create_control_panel_api()
            async with (
                app.router.lifespan_context(app),
                AsyncClient(transport=ASGITransport(app=app), base_url=_ORIGIN) as client,
            ):
                capabilities = await client.get("/api/v1/auth/capabilities")
                self.assertEqual(capabilities.status_code, 200)
                started = await client.post(
                    "/api/v1/auth/start", json={}, headers={"Origin": _ORIGIN}
                )
                self.assertEqual(started.status_code, 201, started.text)
                issued = await client.post("/api/v1/auth/pow", json={}, headers={"Origin": _ORIGIN})
                self.assertEqual(issued.status_code, 200, issued.text)
                confirmed = await client.post(
                    "/api/v1/auth/first-factor",
                    json={
                        "email": "synthetic@example.invalid",
                        "password": "a-local-test-value-not-a-user-password",
                        "pow": "synthetic.solution",
                    },
                    headers={"Origin": _ORIGIN},
                )
                self.assertEqual(confirmed.status_code, 200, confirmed.text)
                self.assertEqual(self.fixture.authorizations, 1)
                self.assertFalse(confirmed.json()["platform_membership_verified"])
                self.assertNotIn(self.fixture.access, confirmed.text)
                ticket = client.cookies.get(_SID_COOKIE)
                private = await self.store.get_resource_credential(
                    ticket, issuer=_ISSUER, client_id=_CLIENT, audience=_RESOURCE
                )
                self.assertEqual(private.bearer.get_secret_value(), self.fixture.access)
                canceled = await client.post(
                    "/api/v1/auth/cancel", json={}, headers={"Origin": _ORIGIN}
                )
                self.assertEqual(canceled.status_code, 204)
                self.assertIsNone(await self.store.get_session(ticket))
        finally:
            self.env.start()

    async def test_versioned_public_auth_has_no_native_or_unversioned_alias(self) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url=_ORIGIN, follow_redirects=False
        ) as client:
            ready = await client.get("/api/v1/auth/capabilities")
            self.assertEqual(ready.status_code, 200)
            self.assertEqual(ready.json()["first_factor"], "password")
            old_routes = (
                ("POST", "/api/auth/native/start"),
                ("POST", "/api/auth/native/pow"),
                ("POST", "/api/auth/native/first-factor"),
                ("POST", "/api/auth/native/cancel"),
                ("GET", "/api/auth/native/capabilities"),
                ("GET", "/api/auth/oidc/session"),
                ("GET", "/api/auth/oidc/me"),
                ("GET", "/api/auth/oidc/catalog"),
                ("GET", "/api/auth/oidc/agent-sessions"),
                ("POST", "/api/auth/oidc/approvals"),
                ("POST", "/api/auth/oidc/files/read"),
                ("POST", "/api/auth/oidc/logout"),
                ("GET", "/api/v1/auth/agent-sessions"),
                ("GET", "/api/v1/auth/catalog"),
                ("GET", "/api/v1/auth/approvals"),
                ("POST", "/api/v1/auth/files/read"),
            )
            for method, path in old_routes:
                with self.subTest(method=method, path=path):
                    response = await client.request(method, path)
                    self.assertEqual(response.status_code, 404)
                    self.assertNotIn("set-cookie", response.headers)
            self.assertEqual((await client.get("/api/v1/auth/start")).status_code, 405)
            self.assertEqual((await client.get("/api/v1/auth/session")).status_code, 401)
            self.assertEqual((await client.get("/api/v1/auth/me")).status_code, 401)
            self.assertEqual((await client.get("/api/v1/auth/callback")).status_code, 404)
            # The registered Rauthy redirect is intentionally immutable until
            # the existing OAuth client actually permits a new redirect URL.
            self.assertEqual((await client.get("/api/auth/oidc/callback")).status_code, 400)
            diagnostic = await client.get("/api/v1/auth/authorize")
            self.assertEqual(diagnostic.status_code, 302, diagnostic.text)
            args = parse_qs(urlsplit(diagnostic.headers["location"]).query)
            self.assertEqual(args["redirect_uri"], [_ORIGIN + "/api/auth/oidc/callback"])
            started = await client.post("/api/v1/auth/start", json={}, headers={"Origin": _ORIGIN})
            self.assertEqual(started.status_code, 201, started.text)
            self.assertIs(started.json()["authenticated"], False)

    async def test_ambiguous_panel_cookies_cannot_authorize_or_mutate_sessions(self) -> None:
        # A legitimate browser ticket is fixture-owned, not a real Rauthy
        # login. Duplicate/malformed Cookie ambiguity must never select it.
        session, _ = await self.store.create_session(
            VerifiedOidcIdentity(
                _ISSUER, _SUBJECT, _CLIENT, datetime.now(UTC) + timedelta(seconds=80)
            )
        )
        pending = "N" * 64
        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url=_ORIGIN, follow_redirects=False
        ) as client:
            cookie_variants = (
                f"{_SID_COOKIE}={session}; {_SID_COOKIE}={session}",
                f"{_SID_COOKIE}={session}; {_NATIVE_TX_COOKIE}=invalid+cookie",
                f"{_SID_COOKIE}={session}; {_TX_COOKIE}=not-a-real-ticket",
                f"{_SID_COOKIE}={session}; {_NATIVE_TX_COOKIE}={pending}; "
                f"{_NATIVE_TX_COOKIE}={pending}",
            )
            endpoints = (
                ("GET", "/api/v1/auth/session", None),
                ("GET", "/api/v1/auth/me", None),
                ("POST", "/api/v1/auth/logout", {}),
                ("POST", "/api/v1/auth/start", {}),
                ("POST", "/api/v1/auth/pow", {}),
                ("POST", "/api/v1/auth/cancel", {}),
                (
                    "POST",
                    "/api/v1/auth/first-factor",
                    {
                        "email": "synthetic@example.invalid",
                        "password": "a-local-test-value-not-a-user-password",
                        "pow": "synthetic.solution",
                    },
                ),
            )
            for index, raw in enumerate(cookie_variants):
                for method, url, body in endpoints:
                    with self.subTest(cookie_kind=index, route=url):
                        headers = {"Cookie": raw, "Origin": _ORIGIN}
                        reply = await client.request(method, url, json=body, headers=headers)
                        self.assertEqual(reply.status_code, 401, (url, reply.text))
                        self.assertNotIn("set-cookie", reply.headers)
            duplicate_headers = await client.get(
                "/api/v1/auth/session",
                headers=[("Cookie", f"{_SID_COOKIE}={session}")] * 2,
            )
            self.assertEqual(duplicate_headers.status_code, 401)
            callback = await client.get(
                "/api/auth/oidc/callback",
                params={"code": "K" * 64, "state": "S" * 48, "iss": _ISSUER},
                headers={"Cookie": f"{_TX_COOKIE}={'S' * 48}; {_TX_COOKIE}={'S' * 48}"},
            )
            self.assertEqual(callback.status_code, 401)
            self.assertIsNotNone(await self.store.get_session(session))
            self.assertEqual(self.fixture.authorizations, 0)

    async def test_public_gates_reject_cross_origin_and_provider_target(self) -> None:
        app = self.app
        async with AsyncClient(transport=ASGITransport(app=app), base_url=_ORIGIN) as client:
            blocked = await client.post(
                "/api/v1/auth/start",
                json={},
                headers={
                    "Origin": "https://foreign.invalid",
                },
            )
            self.assertEqual(blocked.status_code, 403)
            blocked = await client.post(
                "/api/v1/auth/start",
                json={},
                headers={
                    "Origin": _ORIGIN,
                    "Host": "wrong.invalid",
                },
            )
            self.assertEqual(blocked.status_code, 403)
            self.assertEqual(self.fixture.authorizations, 0)
            self.fixture.mode = "invalid_target"
            self.assertEqual(
                (
                    await client.post("/api/v1/auth/start", json={}, headers={"Origin": _ORIGIN})
                ).status_code,
                201,
            )
            self.assertEqual(
                (
                    await client.post("/api/v1/auth/pow", json={}, headers={"Origin": _ORIGIN})
                ).status_code,
                200,
            )
            bad = await client.post(
                "/api/v1/auth/first-factor",
                json={
                    "email": "synthetic@example.invalid",
                    "password": "a-local-test-value-not-a-user-password",
                    "pow": "synthetic.solution",
                },
                headers={"Origin": _ORIGIN},
            )
            # An upstream Rauthy HTTP400 invalid client/redirect/target is
            # a protocol rejection, never evidence of a wrong password.
            self.assertEqual(bad.status_code, 400)
            self.assertEqual(bad.json(), {"error": {"code": "NATIVE_PROVIDER_REQUEST_REJECTED"}})
            self.assertEqual(bad.headers["cache-control"], "no-store")
            self.assertNotIn("set-cookie", bad.headers)

    async def test_unconfigured_and_noncanonical_realms_fail_closed_without_extra_env(self) -> None:
        self.env.stop()
        try:
            with patch.dict("os.environ", {}, clear=True):
                empty = create_control_panel_api()
            self.assertTrue(
                any(route.path == "/api/v1/auth/first-factor" for route in empty.routes)
            )
            for env in (
                {},
                {"OIDC_ISSUER": _ISSUER},
                {"OIDC_CLIENT_ID": _CLIENT},
                {"OIDC_ISSUER": "https://foreign.invalid/auth/v1/", "OIDC_CLIENT_ID": _CLIENT},
                {"OIDC_ISSUER": _ISSUER, "OIDC_CLIENT_ID": "wrong-client"},
            ):
                with patch.dict("os.environ", env, clear=True):
                    if bool(env.get("OIDC_ISSUER")) != bool(env.get("OIDC_CLIENT_ID")):
                        with self.assertRaises(RuntimeError):
                            create_control_panel_api()
                        continue
                    app = create_control_panel_api()
                    native = {
                        route.path for route in app.routes if route.path.startswith("/api/v1/auth/")
                    }
                    self.assertTrue(
                        {
                            "/api/v1/auth/start",
                            "/api/v1/auth/pow",
                            "/api/v1/auth/first-factor",
                            "/api/v1/auth/cancel",
                            "/api/v1/auth/capabilities",
                        }.issubset(native)
                    )
                    self.assertNotIn(
                        "/hands/files/mcp",
                        str(app),
                    )
            # No new operator names are necessary to select either product
            # capability. Existing proper issuer/client plus Valkey suffices.
            with patch.dict(
                "os.environ",
                {
                    "OIDC_ISSUER": _ISSUER,
                    "OIDC_CLIENT_ID": _CLIENT,
                    "OIDC_SESSION_VALKEY_PASSWORD": "f" * 64,
                },
                clear=True,
            ):
                app = create_control_panel_api()
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url=_ORIGIN
                ) as client:
                    result = await client.get("/api/v1/auth/capabilities")
                    self.assertEqual(result.status_code, 200, result.text)
        finally:
            self.env.start()
