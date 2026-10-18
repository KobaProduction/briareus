"""Pinned Rauthy native first-factor replies never imply Briareus login.

These fixtures contain only public/challenge metadata, no credentials,
provider session cookies, actual users, signed token or real authorization.
"""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from control_panel_api._rauthy_native_protocol import (
    NativeProviderProtocolUnavailable,
    PrivateNativeLoginStep,
    interpret_native_authorize,
    interpret_native_otp_finish,
    interpret_native_otp_start,
)

_STATE = "S" * 48
_CODE = "C" * 64
_LOCAL_ISSUER = "https://localhost:18444/auth/v1/"
_LOCAL_CALLBACK = "https://127.0.0.1:18446/api/auth/oidc/callback"
_PUBLIC_ISSUER = "https://briareus.koba-nexus.ru/auth/v1/"
_PUBLIC_CALLBACK = "https://briareus.koba-nexus.ru/api/auth/oidc/callback"
_CLOCK = datetime(2026, 10, 15, 0, 0, tzinfo=UTC)


def classify(
    status: int,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    issuer: str = _LOCAL_ISSUER,
    callback: str = _LOCAL_CALLBACK,
) -> PrivateNativeLoginStep:
    return interpret_native_authorize(
        status_code=status,
        headers={} if headers is None else headers,
        body=body,
        expected_callback=callback,
        expected_state=_STATE,
        expected_issuer=issuer,
        now=_CLOCK,
    )


class NativeChallengeDecoderTests(unittest.TestCase):
    def test_oidc_callback_is_pending_not_authenticated(self) -> None:
        for issuer, callback in (
            (_LOCAL_ISSUER, _LOCAL_CALLBACK),
            (_PUBLIC_ISSUER, _PUBLIC_CALLBACK),
        ):
            with self.subTest(issuer=issuer):
                query = f"?code={_CODE}&state={_STATE}&iss={quote(issuer, safe='')}"
                step = classify(
                    202,
                    headers={"Location": callback + query},
                    issuer=issuer,
                    callback=callback,
                )
                self.assertEqual(step.state, "oauth_callback_pending")
                self.assertIsNotNone(step.secret)
                self.assertNotIn(_CODE, repr(step))
                self.assertFalse(hasattr(step, "authenticated"))

    def test_oidc_callback_cross_issuer_duplicate_and_foreign_rejected(self) -> None:
        valid = f"?code={_CODE}&state={_STATE}&iss=" + quote(_LOCAL_ISSUER, safe="")
        for kwargs in (
            {"issuer": _LOCAL_ISSUER, "callback": _PUBLIC_CALLBACK},
            {"issuer": _PUBLIC_ISSUER, "callback": _LOCAL_CALLBACK},
            {
                "headers": {
                    "Location": _LOCAL_CALLBACK + valid,
                    "location": _LOCAL_CALLBACK + valid,
                },
            },
            {"headers": {"Location": _LOCAL_CALLBACK + valid + "&state=X"}},
            {"headers": {"Location": "http://127.0.0.1:18446/" + valid}},
            {"headers": {"Location": _LOCAL_CALLBACK + "?code=wrong"}},
        ):
            with (
                self.subTest(case=str(list(kwargs.keys()))),
                self.assertRaises(NativeProviderProtocolUnavailable),
            ):
                classify(202, **kwargs)

    def test_mfa_and_tos_are_pending_not_login(self) -> None:
        entries = (
            (
                200,
                {"code": "K" * 48, "active_otps": [{"otp_id": "id1", "otp_kind": "time"}]},
                "otp_pending",
            ),
            (
                200,
                {"code": "W" * 48, "exp": 120},
                "webauthn_pending",
            ),
            (
                206,
                {"tos_await_code": "T" * 48},
                "tos_pending",
            ),
        )
        for code, value, expected in entries:
            with self.subTest(stage=expected):
                step = classify(code, body=json.dumps(value).encode())
                self.assertEqual(step.state, expected)
                if expected == "webauthn_pending":
                    self.assertEqual(step.expires_at, int(_CLOCK.timestamp()) + 120)
                if expected == "otp_pending":
                    self.assertEqual(step.private_otp_ids[0].get_secret_value(), "id1")
                    self.assertNotIn("id1", repr(step))
                else:
                    self.assertEqual(step.private_otp_ids, ())
                self.assertIsNotNone(step.secret)
                self.assertFalse(hasattr(step, "authenticated"))

    def test_malformed_and_oversized_mfa_rejected(self) -> None:
        now = int(_CLOCK.timestamp())
        invalid = (
            b'{"code":"A","active_otps":[]}',
            json.dumps({"code": "W" * 48, "exp": 0}).encode(),
            json.dumps({"code": "W" * 48, "exp": True}).encode(),
            json.dumps({"code": "W" * 48, "exp": "120"}).encode(),
            json.dumps({"code": "W" * 48, "exp": 601}).encode(),
            json.dumps({"code": "W" * 48, "exp": now + 601}).encode(),
            json.dumps(
                {"code": "K" * 48, "active_otps": [{"otp_id": "1", "otp_kind": "unsupported"}]}
            ).encode(),
            (
                b'{"code":"'
                + b"K" * 48
                + b'","exp":'
                + str(now + 120).encode()
                + b',"exp":'
                + str(now + 120).encode()
                + b"}"
            ),
            b"X" * 8193,
        )
        for data in invalid:
            with (
                self.subTest(length=len(data)),
                self.assertRaises(NativeProviderProtocolUnavailable),
            ):
                classify(200, body=data)

    def test_exact_upstream_otp_start_is_secret_server_only(self) -> None:
        # Reviewed against upstream Rauthy v0.37.1:
        # src/api/src/users.rs post_otp_auth_start_login and
        # src/api_types/src/users.rs OtpAuthStartResponse.
        deadline = int((_CLOCK + timedelta(minutes=5)).timestamp())
        secret = "K" * 48
        result = interpret_native_otp_start(
            status_code=200,
            content_type="application/json",
            body=json.dumps({"code": secret, "exp": deadline}).encode(),
            now=_CLOCK,
        )
        self.assertEqual(result.expires_at, deadline)
        self.assertEqual(result.secret.get_secret_value(), secret)
        self.assertNotIn(secret, repr(result))
        self.assertFalse(hasattr(result, "authenticated"))
        for code, mime, raw in (
            (201, "application/json", json.dumps({"code": secret, "exp": deadline}).encode()),
            (200, "text/plain", json.dumps({"code": secret, "exp": deadline}).encode()),
            (200, "application/json", json.dumps({"code": "K" * 47, "exp": deadline}).encode()),
            (200, "application/json", json.dumps({"code": secret, "exp": True}).encode()),
            (
                200,
                "application/json",
                json.dumps({"code": secret, "exp": deadline + 3600}).encode(),
            ),
            (200, "application/json", json.dumps({"code": secret, "exp": deadline - 600}).encode()),
            (
                200,
                "application/json",
                json.dumps({"code": secret, "exp": deadline, "user_id": "foreign"}).encode(),
            ),
            (
                200,
                "application/json",
                b'{"code":"'
                + secret.encode()
                + b'","code":"'
                + secret.encode()
                + b'","exp":'
                + str(deadline).encode()
                + b"}",
            ),
            (200, "application/json", b'{"code":"' + secret.encode() + b'","exp":NaN}'),
        ):
            with (
                self.subTest(status=code, content_type=mime, body=raw[:50]),
                self.assertRaises(NativeProviderProtocolUnavailable),
            ):
                interpret_native_otp_start(
                    status_code=code, content_type=mime, body=raw, now=_CLOCK
                )

    def test_upstream_otp_finish_requires_exact_json_location_and_signed_code_exchange(
        self,
    ) -> None:
        # Rauthy v0.37.1 OtpAdditionalData::Login responds with 202,
        # Location AND JSON {loc}; this is only a pending OAuth callback.
        location = (
            _LOCAL_CALLBACK
            + "?code="
            + _CODE
            + "&state="
            + _STATE
            + "&iss="
            + quote(_LOCAL_ISSUER, safe="")
        )

        def finish(
            status: int, body: bytes, location_header: str | None = location, **extra: str
        ) -> PrivateNativeLoginStep:
            headers = {"Content-Type": "application/json", **extra}
            if location_header is not None:
                headers["Location"] = location_header
            return interpret_native_otp_finish(
                status_code=status,
                headers=headers,
                body=body,
                expected_callback=_LOCAL_CALLBACK,
                expected_state=_STATE,
                expected_issuer=_LOCAL_ISSUER,
                now=_CLOCK,
            )

        accepted = finish(202, json.dumps({"loc": location}).encode())
        self.assertEqual(accepted.state, "oauth_callback_pending")
        self.assertIsNotNone(accepted.secret)
        self.assertNotIn(_CODE, repr(accepted))
        self.assertFalse(hasattr(accepted, "authenticated"))
        self.assertEqual(
            finish(206, json.dumps({"tos_await_code": "T" * 48}).encode()).state,
            "tos_pending",
        )
        self.assertEqual(finish(205, b"").state, "account_update_required")
        for status, raw, location_header, extra in (
            (202, json.dumps({"loc": location}).encode(), None, {}),
            (202, json.dumps({"loc": "https://foreign.invalid/"}).encode(), location, {}),
            (202, json.dumps({"loc": location, "user_id": "foreign"}).encode(), location, {}),
            (
                202,
                b'{"loc":"' + location.encode() + b'","loc":"' + location.encode() + b'"}',
                location,
                {},
            ),
            (202, json.dumps({"loc": location}).encode(), location + "&state=changed", {}),
            (
                202,
                json.dumps({"loc": location}).encode(),
                location,
                {"content-type": "application/json"},
            ),
            (
                206,
                json.dumps({"tos_await_code": "T" * 48}).encode(),
                location,
                {"content-type": "application/unknown"},
            ),
        ):
            with (
                self.subTest(status=status, data=raw[:50]),
                self.assertRaises(NativeProviderProtocolUnavailable),
            ):
                finish(status, raw, location_header, **extra)

    def test_rate_limit_requires_bounded_provider_timestamp(self) -> None:
        result = classify(
            429,
            headers={"x-retry-not-before": str(int((_CLOCK + timedelta(seconds=60)).timestamp()))},
        )
        self.assertEqual(result.state, "rate_limited")
        self.assertIsNone(result.secret)
        for header in (
            {},
            {"x-retry-not-before": "tomorrow"},
            {"x-retry-not-before": "999999999999999"},
        ):
            with self.assertRaises(NativeProviderProtocolUnavailable):
                classify(429, headers=header)

    def test_errors_are_not_success_or_signed_identity(self) -> None:
        self.assertEqual(classify(401).state, "credentials_rejected")
        self.assertEqual(classify(400).state, "request_rejected")
        self.assertEqual(classify(403).state, "provider_access_denied")
        for status in (201, 204, 302, 500, 503):
            with (
                self.subTest(status=status),
                self.assertRaises(NativeProviderProtocolUnavailable),
            ):
                classify(status)


if __name__ == "__main__":
    unittest.main()
