"""No-credential native PoW concurrency regressions (stdlib unittest)."""

from __future__ import annotations

import asyncio
import json
import time
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from control_panel_api._native_state_scripts import (
    CANCEL_LOGIN,
    CLAIM_INIT,
    CLAIM_OTP_FINISH,
    CLAIM_OTP_START,
    COMPLETE_LOGIN,
    CONFIRM_OTP_START,
    CONFIRM_POW,
    STAGE_OTP,
)
from control_panel_api._oidc import OidcAuthorizationAttempt, RauthyOidcAdapter
from control_panel_api._oidc_browser import OidcBrowserSessionStore
from control_panel_api._oidc_native_start import native_login_start_router
from control_panel_api._rauthy_native_protocol import (
    NativeProviderProtocolUnavailable,
    PrivateNativeInitSession,
)
from control_panel_api.main import create_control_panel_api
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from valkey.exceptions import OutOfMemoryError

_ORIGIN = "https://127.0.0.1:18446"
_ISSUER = "https://localhost:18444/auth/v1"
_CLIENT = "briareus-local-panel"


class AsyncValkeyStub:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    async def set(self, key: str, value: str, *, nx: bool, ex: int) -> bool:
        assert ex > 0
        await asyncio.sleep(0)
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def get(self, key: str) -> str | None:
        await asyncio.sleep(0)
        return self.values.get(key)

    async def getdel(self, key: str) -> str | None:
        await asyncio.sleep(0)
        return self.values.pop(key, None)

    async def delete(self, *keys: str) -> int:
        await asyncio.sleep(0)
        removed = sum(int(key in self.values) for key in keys)
        for key in keys:
            self.values.pop(key, None)
        return removed

    async def eval(self, script: str, numkeys: int, *args: object) -> object:
        """Deterministic scheduling model ONLY; real Lua is tested separately."""
        assert numkeys in {1, 2}
        await asyncio.sleep(0)
        if numkeys == 2:
            first, second, *values = args
        else:
            first, *values = args
            second = None
        raw = self.values.get(first)
        item = json.loads(raw) if raw else None
        now = time.time() * 1000
        if script == CONFIRM_POW:
            if (
                not item
                or item.get("stage") != "init"
                or item["issuer"] != values[0]
                or item["client_id"] != values[1]
                or item["deadline_ms"] <= now
                or self.values.get(second) != "reserved"
            ):
                return 0
            self.values[second] = "issued"
            return 1
        if script == CLAIM_INIT:
            if not item or item.get("stage") != "init":
                return None
            if (
                item["issuer"] != values[0]
                or item["client_id"] != values[1]
                or item["deadline_ms"] <= now
                or self.values.get(second) != "issued"
            ):
                self.values.pop(first, None)
                self.values.pop(second, None)
                return None
            self.values[first] = json.dumps(
                {
                    "stage": "claimed",
                    "claim": values[2],
                    "issuer": item["issuer"],
                    "client_id": item["client_id"],
                    "deadline_ms": item["deadline_ms"],
                }
            )
            self.values.pop(second, None)
            return raw
        if script == STAGE_OTP:
            if (
                not item
                or item.get("stage") != "claimed"
                or item.get("claim") != values[0]
                or item["deadline_ms"] <= now
            ):
                return 0
            update = json.loads(values[1])
            if (
                update.get("stage") != "otp_ready"
                or update.get("claim") != item.get("claim")
                or update["deadline_ms"] != item["deadline_ms"]
            ):
                return 0
            self.values[first] = values[1]
            return 1
        if script == CLAIM_OTP_START:
            if (
                not item
                or item.get("stage") != "otp_ready"
                or item.get("issuer") != values[0]
                or item.get("client_id") != values[1]
                or item["deadline_ms"] <= now
                or values[2] >= len(item.get("methods", []))
            ):
                return None
            item["selected_otp_id"] = item["methods"][values[2]]["id"]
            item["otp_claim"] = values[3]
            item["stage"] = "otp_starting"
            self.values[first] = json.dumps(item)
            return raw
        if script == CONFIRM_OTP_START:
            if (
                not item
                or item.get("stage") != "otp_starting"
                or item.get("otp_claim") != values[0]
                or item["deadline_ms"] <= now
                or values[2] <= now
            ):
                return 0
            item.update(
                stage="otp_started",
                otp_code=values[1],
                otp_expires_ms=values[2],
                provider_cookie=values[3],
                csrf=values[4],
            )
            for key in ("otp_login_code", "methods", "selected_otp_id"):
                item.pop(key, None)
            self.values[first] = json.dumps(item)
            return 1
        if script == CLAIM_OTP_FINISH:
            if (
                not item
                or item.get("stage") != "otp_started"
                or item.get("issuer") != values[0]
                or item.get("client_id") != values[1]
                or item["deadline_ms"] <= now
                or item["otp_expires_ms"] <= now
            ):
                return None
            self.values[first] = json.dumps(
                {
                    "stage": "claimed",
                    "claim": item["claim"],
                    "deadline_ms": item["deadline_ms"],
                    "issuer": item["issuer"],
                    "client_id": item["client_id"],
                }
            )
            return raw
        if script == COMPLETE_LOGIN:
            if (
                not item
                or item.get("stage") != "claimed"
                or item["claim"] != values[0]
                or item["deadline_ms"] <= now
                or not 1000 <= values[2] - now <= 900000
            ):
                return 0
            if second in self.values:
                return -1
            self.values[first] = json.dumps({"stage": "complete", "session_key": second})
            self.values[second] = values[1]
            return 1
        if script == CANCEL_LOGIN:
            if item and item.get("stage") == "complete":
                target = item["session_key"]
                if not target.startswith(values[0]) or len(target) != len(values[0]) + 64:
                    return -1
                self.values.pop(target, None)
            self.values.pop(first, None)
            self.values.pop(second, None)
            return 1
        raise AssertionError("unknown native lifecycle script")


class WriteExhaustedValkey(AsyncValkeyStub):
    def __init__(self, rejected_key_kind: str) -> None:
        super().__init__()
        self.rejected_key_kind = rejected_key_kind

    async def set(self, key: str, value: str, *, nx: bool, ex: int) -> bool:
        if f":{self.rejected_key_kind}:" in key:
            raise OutOfMemoryError("controlled noeviction allocation failure")
        return await super().set(key, value, nx=nx, ex=ex)


class DelayedInitReply(AsyncValkeyStub):
    """The server claimed Init, but its winning caller has not received it yet."""

    def __init__(self) -> None:
        super().__init__()
        self.claimed = asyncio.Event()
        self.deliver = asyncio.Event()

    async def eval(self, script: str, numkeys: int, *args: object) -> object:
        result = await super().eval(script, numkeys, *args)
        if script == CLAIM_INIT and result is not None:
            self.claimed.set()
            await self.deliver.wait()
        return result


class LocalProvider:
    issuer = _ISSUER
    client_id = _CLIENT

    def __init__(self) -> None:
        self.starts = 0

    async def prepare_authorization_code(self, *, redirect_uri: str) -> OidcAuthorizationAttempt:
        self.starts += 1
        assert redirect_uri == _ORIGIN + "/api/auth/oidc/callback"
        state = "S" * 42 + str(self.starts).zfill(2)
        return OidcAuthorizationAttempt(
            authorization_url=self.issuer + "/oidc/authorize",
            state=state,
            nonce="N" * 48,
            code_verifier=SecretStr("V" * 48),
            redirect_uri=redirect_uri,
            expires_at=datetime.now(UTC) + timedelta(seconds=200),
        )


class LocalRauthyInit:
    issuer = _ISSUER
    client_id = _CLIENT
    callback = _ORIGIN + "/api/auth/oidc/callback"

    def __init__(self) -> None:
        self.pow_calls = 0

    async def initialize(self) -> PrivateNativeInitSession:
        return PrivateNativeInitSession(
            csrf_token=SecretStr("C" * 32),
            provider_cookie_header=SecretStr("__Host-RauthySession=" + "X" * 90),
            expires_at=datetime.now(UTC) + timedelta(seconds=200),
        )

    async def issue_pow(self) -> str:
        self.pow_calls += 1
        await asyncio.sleep(0)
        return "challenge-from-disposable-rauthy"


class FailingRauthyInit(LocalRauthyInit):
    async def issue_pow(self) -> str:
        self.pow_calls += 1
        raise NativeProviderProtocolUnavailable("local upstream challenge unavailable")


class BlockingRauthyInit(LocalRauthyInit):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.proceed = asyncio.Event()

    async def issue_pow(self) -> str:
        self.pow_calls += 1
        self.started.set()
        await self.proceed.wait()
        return "private-upstream-public-challenge"


class NativePoWTests(unittest.IsolatedAsyncioTestCase):
    async def test_spoofed_small_content_length_cannot_buffer_large_body_or_issue_pow(self) -> None:
        provider = LocalProvider()
        native = LocalRauthyInit()
        store = AsyncValkeyStub()
        sessions = OidcBrowserSessionStore(password=SecretStr("f" * 64), client=store)
        app = FastAPI()
        app.include_router(
            native_login_start_router(
                provider=provider,
                transactions=sessions,
                native_init=native,
                test_only_local_origin=_ORIGIN,
            )
        )
        headers = {"Origin": _ORIGIN, "Content-Type": "application/json", "Content-Length": "2"}
        async with AsyncClient(transport=ASGITransport(app=app), base_url=_ORIGIN) as client:
            for endpoint in ("start", "pow"):
                bad = await client.post(
                    "/api/v1/auth/" + endpoint,
                    content=b"{}" + b"x" * 256_000,
                    headers=headers,
                )
                self.assertEqual(bad.status_code, 403, endpoint)
                self.assertEqual(bad.headers["cache-control"], "no-store")
                self.assertNotIn("set-cookie", bad.headers)
                self.assertEqual(provider.starts, 0)
                self.assertEqual(native.pow_calls, 0)
            self.assertFalse(store.values)
            started = await client.post(
                "/api/v1/auth/start",
                content=b"{}",
                headers=headers,
            )
            self.assertEqual(started.status_code, 201)
            for altered in (
                {**headers, "Transfer-Encoding": "chunked"},
                {**headers, "Authorization": "Bearer untrusted"},
            ):
                denied = await client.post("/api/v1/auth/pow", content=b"{}", headers=altered)
                self.assertEqual(denied.status_code, 403)
                self.assertEqual(native.pow_calls, 0)
            good = await client.post(
                "/api/v1/auth/pow",
                content=b"{}",
                headers=headers,
            )
            self.assertEqual(good.status_code, 200)
            self.assertEqual(native.pow_calls, 1)

    async def test_parallel_pow_once_and_logout_deletes_marker(self) -> None:
        store = AsyncValkeyStub()
        sessions = OidcBrowserSessionStore(
            password=SecretStr("f" * 64),
            client=store,
        )
        provider = LocalProvider()
        native = LocalRauthyInit()
        app = FastAPI()
        app.include_router(
            native_login_start_router(
                provider=provider,
                transactions=sessions,
                native_init=native,
                test_only_local_origin=_ORIGIN,
            )
        )
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url=_ORIGIN,
        ) as client:
            headers = {"Origin": _ORIGIN}
            first = await client.post("/api/v1/auth/start", json={}, headers=headers)
            self.assertEqual(first.status_code, 201)
            cookie = client.cookies.get("__Host-briareus_native_transaction")
            self.assertIsNotNone(cookie)
            replies = await asyncio.gather(
                *(client.post("/api/v1/auth/pow", json={}, headers=headers) for _ in range(8))
            )
            statuses = [result.status_code for result in replies]
            self.assertEqual(statuses.count(200), 1)
            self.assertEqual(statuses.count(409), 7)
            self.assertEqual(native.pow_calls, 1)
            self.assertTrue(
                any(
                    answer.json().get("error", {}).get("code") == "NATIVE_POW_ALREADY_RESERVED"
                    for answer in replies
                    if answer.status_code == 409
                )
            )
            self.assertIn(sessions._key("native-pow", cookie), store.values)
            refreshed = await client.post("/api/v1/auth/start", json={}, headers=headers)
            self.assertEqual(refreshed.status_code, 201)
            self.assertNotIn(sessions._key("native-init", cookie), store.values)
            self.assertNotIn(sessions._key("native-pow", cookie), store.values)
            other = client.cookies.get("__Host-briareus_native_transaction")
            self.assertNotEqual(other, cookie)
            self.assertEqual(
                (await client.post("/api/v1/auth/pow", json={}, headers=headers)).status_code,
                200,
            )
            self.assertEqual(native.pow_calls, 2)
            await sessions.delete_native_init(state=other)
            self.assertNotIn(sessions._key("native-init", other), store.values)
            self.assertNotIn(sessions._key("native-pow", other), store.values)
            after = await client.post("/api/v1/auth/pow", json={}, headers=headers)
            self.assertEqual(after.status_code, 401)

    async def test_native_init_claim_is_atomic_and_never_reusable(self) -> None:
        store = AsyncValkeyStub()
        sessions = OidcBrowserSessionStore(password=SecretStr("f" * 64), client=store)
        state = "S" * 48
        await sessions.save_native_init(
            state=state,
            nonce="N" * 48,
            verifier="V" * 48,
            issuer=_ISSUER,
            client_id=_CLIENT,
            csrf=SecretStr("C" * 32),
            provider_cookie=SecretStr("__Host-RauthySession=" + "X" * 90),
            seconds=200,
        )
        reserved = await sessions.reserve_native_pow(state=state, issuer=_ISSUER, client_id=_CLIENT)
        self.assertTrue(reserved)
        self.assertTrue(
            await sessions.confirm_native_pow(state=state, issuer=_ISSUER, client_id=_CLIENT)
        )
        claimed = await asyncio.gather(
            *(
                sessions.consume_native_init(state=state, issuer=_ISSUER, client_id=_CLIENT)
                for _ in range(8)
            )
        )
        self.assertEqual(sum(item is not None for item in claimed), 1)
        won = next(item for item in claimed if item is not None)
        self.assertEqual(won.state, state)
        self.assertEqual(won.issuer, _ISSUER)
        self.assertEqual(won.verifier.get_secret_value(), "V" * 48)
        self.assertEqual(won.csrf.get_secret_value(), "C" * 32)
        self.assertNotIn("X" * 90, repr(won))
        self.assertTrue(await sessions.native_claim_is_current(won))
        self.assertNotIn("X" * 90, store.values[sessions._key("native-init", state)])
        self.assertNotIn(sessions._key("native-pow", state), store.values)

    async def test_losing_claim_cannot_steal_the_winners_pow_marker(self) -> None:
        store = DelayedInitReply()
        sessions = OidcBrowserSessionStore(password=SecretStr("f" * 64), client=store)
        state = "S" * 48
        await sessions.save_native_init(
            state=state,
            nonce="N" * 48,
            verifier="V" * 48,
            issuer=_ISSUER,
            client_id=_CLIENT,
            csrf=SecretStr("C" * 32),
            provider_cookie=SecretStr("__Host-RauthySession=" + "X" * 90),
            seconds=120,
        )
        self.assertTrue(
            await sessions.reserve_native_pow(state=state, issuer=_ISSUER, client_id=_CLIENT)
        )
        self.assertTrue(
            await sessions.confirm_native_pow(state=state, issuer=_ISSUER, client_id=_CLIENT)
        )
        winning = asyncio.create_task(
            sessions.consume_native_init(state=state, issuer=_ISSUER, client_id=_CLIENT)
        )
        try:
            await asyncio.wait_for(store.claimed.wait(), timeout=2)
            losing = await sessions.consume_native_init(
                state=state, issuer=_ISSUER, client_id=_CLIENT
            )
            self.assertIsNone(losing)
            self.assertEqual(
                json.loads(store.values[sessions._key("native-init", state)])["stage"], "claimed"
            )
        finally:
            store.deliver.set()
            original = await asyncio.wait_for(winning, timeout=2)
        self.assertIsNotNone(original)
        self.assertTrue(await sessions.native_claim_is_current(original))
        await sessions.delete_native_init(state=state)
        self.assertFalse(store.values)

    async def test_native_init_issuer_mismatch_burns_pending(self) -> None:
        store = AsyncValkeyStub()
        sessions = OidcBrowserSessionStore(password=SecretStr("f" * 64), client=store)
        state = "S" * 48
        await sessions.save_native_init(
            state=state,
            nonce="N" * 48,
            verifier="V" * 48,
            issuer=_ISSUER,
            client_id=_CLIENT,
            csrf=SecretStr("C" * 32),
            provider_cookie=SecretStr("__Host-RauthySession=" + "X" * 90),
            seconds=200,
        )
        self.assertTrue(
            await sessions.reserve_native_pow(state=state, issuer=_ISSUER, client_id=_CLIENT)
        )
        self.assertTrue(
            await sessions.confirm_native_pow(state=state, issuer=_ISSUER, client_id=_CLIENT)
        )
        mismatch = await sessions.consume_native_init(
            state=state, issuer="https://evil.invalid/auth/v1", client_id=_CLIENT
        )
        self.assertIsNone(mismatch)
        replay = await sessions.consume_native_init(state=state, issuer=_ISSUER, client_id=_CLIENT)
        self.assertIsNone(replay)
        self.assertFalse(store.values)

    async def test_claim_without_issued_pow_burns_pending_init(self) -> None:
        store = AsyncValkeyStub()
        sessions = OidcBrowserSessionStore(password=SecretStr("f" * 64), client=store)
        state = "S" * 48
        await sessions.save_native_init(
            state=state,
            nonce="N" * 48,
            verifier="V" * 48,
            issuer=_ISSUER,
            client_id=_CLIENT,
            csrf=SecretStr("C" * 32),
            provider_cookie=SecretStr("__Host-RauthySession=" + "X" * 90),
            seconds=120,
        )
        skipped_pow = await sessions.consume_native_init(
            state=state, issuer=_ISSUER, client_id=_CLIENT
        )
        self.assertIsNone(skipped_pow)
        self.assertFalse(
            await sessions.reserve_native_pow(state=state, issuer=_ISSUER, client_id=_CLIENT)
        )
        self.assertFalse(store.values)

    async def test_provider_failure_burns_reservation(self) -> None:
        store = AsyncValkeyStub()
        native = FailingRauthyInit()
        sessions = OidcBrowserSessionStore(password=SecretStr("f" * 64), client=store)
        app = FastAPI()
        app.include_router(
            native_login_start_router(
                provider=LocalProvider(),
                transactions=sessions,
                native_init=native,
                test_only_local_origin=_ORIGIN,
            )
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url=_ORIGIN) as client:
            headers = {"Origin": _ORIGIN}
            start = await client.post("/api/v1/auth/start", json={}, headers=headers)
            self.assertEqual(start.status_code, 201)
            denied = await client.post("/api/v1/auth/pow", json={}, headers=headers)
            self.assertEqual(denied.status_code, 503)
            repeated = await client.post("/api/v1/auth/pow", json={}, headers=headers)
            self.assertEqual(repeated.status_code, 409)
            self.assertEqual(native.pow_calls, 1)

    async def test_logout_during_upstream_pow_never_delivers_challenge(self) -> None:
        store = AsyncValkeyStub()
        native = BlockingRauthyInit()
        sessions = OidcBrowserSessionStore(password=SecretStr("f" * 64), client=store)
        app = FastAPI()
        app.include_router(
            native_login_start_router(
                provider=LocalProvider(),
                transactions=sessions,
                native_init=native,
                test_only_local_origin=_ORIGIN,
            )
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url=_ORIGIN) as client:
            headers = {"Origin": _ORIGIN}
            start = await client.post("/api/v1/auth/start", json={}, headers=headers)
            self.assertEqual(start.status_code, 201)
            state = client.cookies.get("__Host-briareus_native_transaction")
            self.assertIsNotNone(state)
            task = asyncio.create_task(client.post("/api/v1/auth/pow", json={}, headers=headers))
            try:
                await asyncio.wait_for(native.started.wait(), timeout=3)
                await sessions.delete_native_init(state=state)
            finally:
                native.proceed.set()
            rejected = await asyncio.wait_for(task, timeout=3)
            self.assertEqual(rejected.status_code, 401)
            self.assertNotIn("challenge", rejected.json())
            self.assertEqual(native.pow_calls, 1)

    async def test_noeviction_oom_does_not_issue_init_cookie_or_pow_challenge(self) -> None:
        for failed_kind in ("native-init", "native-pow"):
            store = WriteExhaustedValkey(failed_kind)
            native = LocalRauthyInit()
            app = FastAPI()
            app.include_router(
                native_login_start_router(
                    provider=LocalProvider(),
                    transactions=OidcBrowserSessionStore(
                        password=SecretStr("f" * 64), client=store
                    ),
                    native_init=native,
                    test_only_local_origin=_ORIGIN,
                )
            )
            async with AsyncClient(transport=ASGITransport(app=app), base_url=_ORIGIN) as client:
                initial = await client.post(
                    "/api/v1/auth/start", json={}, headers={"Origin": _ORIGIN}
                )
                if failed_kind == "native-init":
                    self.assertEqual(initial.status_code, 503)
                    self.assertNotIn("set-cookie", initial.headers)
                    self.assertFalse(store.values)
                else:
                    self.assertEqual(initial.status_code, 201)
                    challenge = await client.post(
                        "/api/v1/auth/pow", json={}, headers={"Origin": _ORIGIN}
                    )
                    self.assertEqual(challenge.status_code, 503)
                    self.assertNotIn("challenge", challenge.json())
                    self.assertNotIn("set-cookie", challenge.headers)
                    self.assertFalse(any(":native-pow:" in key for key in store.values))
                self.assertEqual(native.pow_calls, 0)

    async def test_unconfigured_native_routes_fail_closed_consistently(self) -> None:
        configs = (
            {},
            {
                "provider": RauthyOidcAdapter(issuer=_ISSUER + "/", client_id=_CLIENT),
                "native_init": LocalRauthyInit(),
                "test_only_local_origin": _ORIGIN,
            },
        )
        with patch.dict(
            "os.environ",
            {
                "OIDC_ISSUER": "",
                "OIDC_CLIENT_ID": "",
                "OIDC_SESSION_VALKEY_PASSWORD": "",
                "RAUTHY_ADMIN_API_KEY": "",
            },
        ):
            for kwargs in configs:
                with self.subTest(configured_provider=bool(kwargs)):
                    app = create_control_panel_api(**kwargs)
                    async with AsyncClient(
                        transport=ASGITransport(app=app),
                        base_url=_ORIGIN,
                    ) as client:
                        for endpoint in (
                            "/api/v1/auth/start",
                            "/api/v1/auth/pow",
                        ):
                            result = await client.post(
                                endpoint, json={}, headers={"Origin": _ORIGIN}
                            )
                            self.assertEqual(result.status_code, 503)

    async def test_missing_pending_cookie_does_not_issue_pow(self) -> None:
        native = LocalRauthyInit()
        app = FastAPI()
        app.include_router(
            native_login_start_router(
                provider=LocalProvider(),
                transactions=OidcBrowserSessionStore(
                    password=SecretStr("f" * 64), client=AsyncValkeyStub()
                ),
                native_init=native,
                test_only_local_origin=_ORIGIN,
            )
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url=_ORIGIN) as client:
            response = await client.post("/api/v1/auth/pow", json={}, headers={"Origin": _ORIGIN})
            self.assertEqual(response.status_code, 401)
            self.assertEqual(native.pow_calls, 0)


if __name__ == "__main__":
    unittest.main()
