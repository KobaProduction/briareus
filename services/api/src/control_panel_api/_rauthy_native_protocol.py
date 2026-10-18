"""Pinned Rauthy v0.37.1 native-login challenge decoder; not identity proof.

Reviewed against upstream tag v0.37.1 SHA ce35a70fbc43203b1a6910d3db30389228825f46:
- src/api/src/oidc.rs GET/POST /oidc/authorize and first-factor states;
- src/api/src/lib.rs map_auth_step;
- src/data/src/entity/auth_codes.rs emits code+state+iss callback Location;
- src/api_types/src/users.rs OtpLoginResponse/WebauthnLoginResponse;
- src/api_types/src/tos.rs ToSAwaitLoginResponse;
- frontend/src/routes/oidc/authorize/+page.svelte handleAuthRes.

This decoder is not authentication, has no password endpoint, and never
mints/accepts a Briareus browser cookie. All challenge/redirect values must
remain server-held within a future provider-session/CSRF/PoW store and the
existing independently signed OIDC code+PKCE callback verifier.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from ._api_paths import REGISTERED_RAUTHY_CALLBACK_PATH
from ._oidc_origin_policy import LOCAL_RAUTHY_ISSUER, LOCAL_TEST_ORIGIN, PUBLIC_ORIGIN

_MAX_REPLY = 8192
_MAX_LOCATION = 8192
_CODE = re.compile(r"[A-Za-z0-9_-]{16,256}\Z", flags=re.ASCII)
_STATE = re.compile(r"[A-Za-z0-9_-]{16,256}\Z", flags=re.ASCII)


@dataclass(frozen=True, slots=True)
class PrivateNativeOtpStart:
    """Private provider-issued OTP challenge, not a browser/MFA credential.

    Rauthy /users/otp_start creates a fresh 48-alphanumeric one-time code.
    A future BFF continuation must escrow this code and the original
    provider session/PKCE state in protected Valkey, never return it in UI.
    """

    secret: SecretStr
    expires_at: int


class NativeProviderProtocolUnavailable(Exception):
    """Unexpected upstream status/response cannot grant a user session."""


class _OtpSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    otp_id: str = Field(min_length=1, max_length=128)
    otp_kind: Literal["email", "phone", "time"]


class _OtpChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    code: str = Field(min_length=16, max_length=256)
    active_otps: tuple[_OtpSource, ...] = Field(min_length=1, max_length=10)


class _WebauthnChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    code: str = Field(min_length=16, max_length=256)
    exp: int = Field(strict=True, ge=1, le=600)


class _TosChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tos_await_code: str = Field(min_length=16, max_length=256)
    force_accept: bool | None = None


@dataclass(frozen=True, slots=True)
class PrivateNativeInitSession:
    """Pinned Rauthy POST /oidc/session Init proof, not a logged-in User."""

    csrf_token: SecretStr
    provider_cookie_header: SecretStr
    expires_at: datetime


def parse_native_session_init(
    *,
    status_code: int,
    content_type: str,
    body: bytes,
    set_cookie_headers: tuple[str, ...],
    now: datetime | None = None,
) -> PrivateNativeInitSession:
    """Parse the supported native-UI JSON init route; never call it twice to refresh."""
    from http.cookies import SimpleCookie

    clock = datetime.now(UTC) if now is None else now
    if (
        clock.tzinfo is None
        or status_code != 201
        or content_type.split(";", 1)[0].lower() != "application/json"
        or not isinstance(body, bytes)
        or not 1 <= len(body) <= 8192
        or not isinstance(set_cookie_headers, tuple)
        or len(set_cookie_headers) != 1
    ):
        raise NativeProviderProtocolUnavailable("Rauthy Init reply unavailable")
    value = _bounded_json(body)
    if (
        not isinstance(value, dict)
        or value.get("state") != "Init"
        or not isinstance(value.get("id"), str)
        or not 1 <= len(value["id"]) <= 128
        or not isinstance(value.get("csrf_token"), str)
        or re.fullmatch(r"[A-Za-z0-9]{32}", value["csrf_token"], flags=re.ASCII) is None
        or value.get("user_id") is not None
    ):
        raise NativeProviderProtocolUnavailable("untrusted Rauthy Init identity")
    try:
        expires = datetime.fromisoformat(value["exp"].replace("Z", "+00:00"))
    except (ValueError, TypeError, KeyError, AttributeError):
        raise NativeProviderProtocolUnavailable("invalid Init expiration") from None
    if expires.tzinfo is None or not clock < expires <= clock + timedelta(days=2):
        raise NativeProviderProtocolUnavailable("Rauthy Init expired or unbounded")
    try:
        cookies: SimpleCookie[str] = SimpleCookie()
        cookies.load(set_cookie_headers[0])
        if len(cookies) != 1 or "__Host-RauthySession" not in cookies:
            raise ValueError("missing single provider session")
        item = cookies["__Host-RauthySession"]
        if (
            item["path"] != "/"
            or item["domain"]
            or not item["secure"]
            or not item["httponly"]
            or item["samesite"].lower() != "lax"
            or not 32 <= len(item.value) <= 4096
            or not item.value.isascii()
            or any(char.isspace() for char in item.value)
        ):
            raise ValueError("malformed provider cookie")
    except (CookieError, ValueError, TypeError):
        raise NativeProviderProtocolUnavailable("Rauthy Init provider cookie invalid") from None
    return PrivateNativeInitSession(
        csrf_token=SecretStr(value["csrf_token"]),
        provider_cookie_header=SecretStr("__Host-RauthySession=" + item.value),
        expires_at=expires,
    )


@dataclass(frozen=True, slots=True)
class PrivateNativeProviderSession:
    """Rauthy provider-only session/CSRF; never a browser or Platform grant."""

    csrf_token: SecretStr
    provider_cookie_header: SecretStr


class _RauthyCsrfTemplate(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._inside = False
        self._values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "template" and dict(attrs).get("id") == "tpl_csrf_token":
            if self._inside or self._values:
                raise NativeProviderProtocolUnavailable("duplicate Rauthy CSRF template")
            self._inside = True
            self._values.append("")

    def handle_data(self, data: str) -> None:
        if self._inside:
            self._values[-1] += data
            if len(self._values[-1]) > 128:
                raise NativeProviderProtocolUnavailable("Rauthy CSRF template too long")

    def handle_endtag(self, tag: str) -> None:
        if tag == "template":
            self._inside = False

    def csrf_token(self) -> SecretStr:
        if self._inside or len(self._values) != 1:
            raise NativeProviderProtocolUnavailable("missing Rauthy session CSRF template")
        value = self._values[0].strip()
        if re.fullmatch(r"[A-Za-z0-9]{32}", value, flags=re.ASCII) is None:
            raise NativeProviderProtocolUnavailable("untrusted Rauthy CSRF token shape")
        return SecretStr(value)


def parse_native_initial_session(
    *,
    status_code: int,
    content_type: str,
    html: bytes,
    set_cookie_headers: tuple[str, ...],
) -> PrivateNativeProviderSession:
    """Decode pinned Rauthy 0.37.1 GET /oidc/authorize without rendering UI.

    Provider session cookies must later be escrowed by the BFF per one-time
    transaction, NOT retained on a shared HTTP client's global cookie jar,
    forwarded to an external browser or mistaken for Briareus identity.
    """
    if (
        status_code != 200
        or content_type.split(";", 1)[0].lower() != "text/html"
        or not isinstance(html, bytes)
        or not 1 <= len(html) <= 262_144
        or not isinstance(set_cookie_headers, tuple)
        or not 2 <= len(set_cookie_headers) <= 6
    ):
        raise NativeProviderProtocolUnavailable("Rauthy initial provider session unavailable")
    try:
        parser = _RauthyCsrfTemplate()
        parser.feed(html.decode("utf-8"))
        parser.close()
        csrf = parser.csrf_token()
        provider_cookies: dict[str, str] = {}
        for header in set_cookie_headers:
            if not isinstance(header, str) or not 1 <= len(header) <= 8192:
                raise NativeProviderProtocolUnavailable("invalid provider cookie header")
            parsed: SimpleCookie[str] = SimpleCookie()
            parsed.load(header)
            if len(parsed) != 1:
                raise NativeProviderProtocolUnavailable("ambiguous provider cookie header")
            name, item = next(iter(parsed.items()))
            if (
                name not in {"__Host-RauthySession", "__Host-rbid"}
                or name in provider_cookies
                or item["path"] != "/"
                or item["domain"]
                or not item["secure"]
                or not item["httponly"]
                or item["samesite"].lower() != "lax"
                or not 16 <= len(item.value) <= 4096
                or any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in item.value)
            ):
                raise NativeProviderProtocolUnavailable("untrusted provider session cookie")
            provider_cookies[name] = item.value
        if set(provider_cookies) != {"__Host-RauthySession", "__Host-rbid"}:
            raise NativeProviderProtocolUnavailable("required Rauthy session cookie missing")
    except (UnicodeDecodeError, CookieError, ValueError, TypeError):
        raise NativeProviderProtocolUnavailable("malformed Rauthy initial session") from None
    return PrivateNativeProviderSession(
        csrf_token=csrf,
        provider_cookie_header=SecretStr(
            "; ".join(
                f"{name}={provider_cookies[name]}"
                for name in ("__Host-rbid", "__Host-RauthySession")
            )
        ),
    )


@dataclass(frozen=True, slots=True)
class PrivateNativeLoginStep:
    """Server-internal status; NEVER a public authenticated-user result."""

    state: Literal[
        "oauth_callback_pending",
        "otp_pending",
        "webauthn_pending",
        "tos_pending",
        "account_update_required",
        "client_mfa_required",
        "rate_limited",
        "credentials_rejected",
        "request_rejected",
        "provider_access_denied",
    ]
    # OAuth authorization code, MFA and ToS code are provider-sensitive.
    secret: SecretStr | None = None
    challenge_kinds: tuple[Literal["email", "phone", "time"], ...] = ()
    # OTP provider IDs never appear in browser JSON. A future continuation
    # may choose a bounded public INDEX but must resolve the original secret
    # OTP ID from server-only escrow before calling /users/otp_start.
    private_otp_ids: tuple[SecretStr, ...] = ()
    provider_cookie: SecretStr | None = None
    csrf_token: SecretStr | None = None
    retry_not_before: int | None = None
    expires_at: int | None = None


def _bounded_json(raw: bytes) -> object:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= _MAX_REPLY:
        raise NativeProviderProtocolUnavailable("untrusted Rauthy challenge size")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate Rauthy challenge key")
            result[name] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-JSON numeric constant: {value}")

    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)
    except (UnicodeDecodeError, TypeError, ValueError):
        raise NativeProviderProtocolUnavailable("invalid Rauthy challenge JSON") from None


def _valid_code(value: str) -> bool:
    return isinstance(value, str) and _CODE.fullmatch(value) is not None


def _single_header(headers: Mapping[str, str], name: str) -> str | None:
    matches = [
        value for key, value in headers.items() if isinstance(key, str) and key.casefold() == name
    ]
    if len(matches) > 1:
        raise NativeProviderProtocolUnavailable("ambiguous upstream authorization header")
    if matches and not isinstance(matches[0], str):
        raise NativeProviderProtocolUnavailable("non-text provider header")
    return matches[0] if matches else None


def interpret_native_authorize(
    *,
    status_code: int,
    headers: Mapping[str, str],
    body: bytes,
    expected_callback: str,
    expected_state: str,
    expected_issuer: str,
    now: datetime | None = None,
) -> PrivateNativeLoginStep:
    """Classify ONE upstream POST /oidc/authorize response, fail closed.

    A 202 means an OAuth code is available for independent PKCE redemption.
    It is NOT the same as signed identity or Platform membership. MFA,
    pending ToS and update flows can never imply authenticated Briareus UI.
    """
    clock = datetime.now(UTC) if now is None else now
    if clock.tzinfo is None or not isinstance(body, bytes):
        raise NativeProviderProtocolUnavailable("invalid callback parsing context")
    approved_pairs = frozenset(
        {
            (
                PUBLIC_ORIGIN + "/auth/v1/",
                PUBLIC_ORIGIN + REGISTERED_RAUTHY_CALLBACK_PATH,
            ),
            (
                LOCAL_RAUTHY_ISSUER + "/",
                LOCAL_TEST_ORIGIN + REGISTERED_RAUTHY_CALLBACK_PATH,
            ),
        }
    )
    if (
        not _valid_code(expected_state)
        or (expected_issuer, expected_callback) not in approved_pairs
    ):
        raise NativeProviderProtocolUnavailable(
            "OAuth issuer/callback pair was not independently approved"
        )
    if status_code == 202:
        redirect = _single_header(headers, "location")
        if (
            body
            or not redirect
            or len(redirect) > _MAX_LOCATION
            or any(ord(ch) <= 32 or ord(ch) == 127 for ch in redirect)
        ):
            raise NativeProviderProtocolUnavailable("unexpected accepted redirect body")
        if not isinstance(redirect, str):
            raise NativeProviderProtocolUnavailable("missing OAuth callback redirect")
        parsed, exact = urlsplit(redirect), urlsplit(expected_callback)
        if (
            exact.query
            or exact.fragment
            or parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or (parsed.scheme, parsed.netloc, parsed.path)
            != (exact.scheme, exact.netloc, exact.path)
        ):
            raise NativeProviderProtocolUnavailable("upstream OAuth callback crossed origin")
        try:
            query_pairs = parse_qsl(parsed.query, strict_parsing=True, keep_blank_values=True)
        except ValueError:
            raise NativeProviderProtocolUnavailable("invalid OAuth callback query") from None
        if len(query_pairs) != 3 or {key for key, _value in query_pairs} != {
            "code",
            "state",
            "iss",
        }:
            raise NativeProviderProtocolUnavailable("duplicate or foreign OAuth parameter")
        query = dict(query_pairs)
        if (
            query.get("state") != expected_state
            or query.get("iss") != expected_issuer
            or not isinstance(query.get("code"), str)
            or re.fullmatch(r"[A-Za-z0-9]{64}", query["code"], flags=re.ASCII) is None
        ):
            raise NativeProviderProtocolUnavailable("untrusted OAuth code/state/issuer")
        return PrivateNativeLoginStep(
            state="oauth_callback_pending",
            secret=SecretStr(redirect),
        )
    if status_code == 200:
        challenge = _bounded_json(body)
        if not isinstance(challenge, dict):
            raise NativeProviderProtocolUnavailable("Rauthy MFA challenge not an object")
        try:
            if "active_otps" in challenge:
                otp = _OtpChallenge.model_validate(challenge)
                if not _valid_code(otp.code):
                    raise ValueError("invalid OTP challenge code")
                return PrivateNativeLoginStep(
                    "otp_pending",
                    SecretStr(otp.code),
                    tuple(item.otp_kind for item in otp.active_otps),
                    tuple(SecretStr(item.otp_id) for item in otp.active_otps),
                )
            webauthn = _WebauthnChallenge.model_validate(challenge)
            if not _valid_code(webauthn.code):
                raise ValueError("invalid WebAuthn challenge code")
            return PrivateNativeLoginStep(
                "webauthn_pending",
                SecretStr(webauthn.code),
                expires_at=int(clock.timestamp()) + webauthn.exp,
            )
        except ValueError:
            raise NativeProviderProtocolUnavailable("malformed Rauthy MFA challenge") from None
    if status_code == 206:
        try:
            pending = _TosChallenge.model_validate(_bounded_json(body))
        except ValueError:
            raise NativeProviderProtocolUnavailable("malformed Rauthy ToS continuation") from None
        if not _valid_code(pending.tos_await_code):
            raise NativeProviderProtocolUnavailable("invalid Rauthy ToS challenge code")
        return PrivateNativeLoginStep("tos_pending", SecretStr(pending.tos_await_code))
    if status_code == 205:
        return PrivateNativeLoginStep("account_update_required")
    if status_code == 406:
        return PrivateNativeLoginStep("client_mfa_required")
    if status_code == 429:
        raw_retry = _single_header(headers, "x-retry-not-before") or ""
        if not raw_retry.isdecimal() or not 1 <= len(raw_retry) <= 15:
            raise NativeProviderProtocolUnavailable("Rauthy retry boundary missing")
        retry = int(raw_retry)
        if not int(clock.timestamp()) - 10 <= retry <= int(clock.timestamp()) + 86400:
            raise NativeProviderProtocolUnavailable("Rauthy retry boundary invalid")
        return PrivateNativeLoginStep("rate_limited", retry_not_before=retry)
    if status_code == 401:
        return PrivateNativeLoginStep("credentials_rejected")
    if status_code == 400:
        return PrivateNativeLoginStep("request_rejected")
    if status_code == 403:
        return PrivateNativeLoginStep("provider_access_denied")
    raise NativeProviderProtocolUnavailable("unknown Rauthy login response; no session allowed")


def merge_native_provider_cookies(*, original: SecretStr, updates: tuple[str, ...]) -> SecretStr:
    """Keep only validated Rauthy host-only cookies in private transaction.

    The pinned upstream AuthStep::AwaitOtpCode returns a RauthyMfa cookie;
    BrowserId middleware may rotate __Host-rbid. Never expose either to UI
    or accept unrelated browser/vendor cookies as verified upstream state.
    """
    allowed = {"__Host-RauthySession", "__Host-RauthyMfa", "__Host-rbid"}
    if not isinstance(original, SecretStr) or not isinstance(updates, tuple) or len(updates) > 3:
        raise NativeProviderProtocolUnavailable("invalid provider session cookie update")
    result: dict[str, str] = {}
    for item in original.get_secret_value().split("; "):
        name, separator, value = item.partition("=")
        if (
            not separator
            or name not in allowed
            or name in result
            or not 16 <= len(value) <= 4096
            or not value.isascii()
            or any(ord(ch) <= 32 or ord(ch) > 126 for ch in value)
        ):
            raise NativeProviderProtocolUnavailable("malformed original provider cookies")
        result[name] = value
    if "__Host-RauthySession" not in result:
        raise NativeProviderProtocolUnavailable("original Rauthy session missing")
    updated: set[str] = set()
    for header in updates:
        if not isinstance(header, str) or not 1 <= len(header) <= 8192:
            raise NativeProviderProtocolUnavailable("invalid provider Set-Cookie size")
        try:
            cookies: SimpleCookie[str] = SimpleCookie()
            cookies.load(header)
            if len(cookies) != 1:
                raise ValueError("ambiguous provider Set-Cookie")
            name, morsel = next(iter(cookies.items()))
            if (
                name not in allowed
                or name in updated
                or morsel["path"] != "/"
                or morsel["domain"]
                or not morsel["secure"]
                or not morsel["httponly"]
                or morsel["samesite"].lower() != "lax"
                or not 16 <= len(morsel.value) <= 4096
                or not morsel.value.isascii()
                or any(ord(ch) <= 32 or ord(ch) > 126 for ch in morsel.value)
            ):
                raise ValueError("invalid protected provider cookie attributes")
            result[name] = morsel.value
            updated.add(name)
        except (CookieError, ValueError, TypeError):
            raise NativeProviderProtocolUnavailable("untrusted Rauthy cookie rotation") from None
    return SecretStr(
        "; ".join(
            f"{name}={result[name]}"
            for name in ("__Host-RauthySession", "__Host-rbid", "__Host-RauthyMfa")
            if name in result
        )
    )


def native_provider_csrf(*, original: SecretStr, headers: Mapping[str, str]) -> SecretStr:
    """Rauthy can rotate the 32-byte session CSRF between password and MFA."""
    candidate = _single_header(headers, "x-csrf-token")
    if candidate is None:
        return original
    if re.fullmatch(r"[A-Za-z0-9]{32}", candidate, flags=re.ASCII) is None:
        raise NativeProviderProtocolUnavailable("invalid rotated provider CSRF")
    return SecretStr(candidate)


def interpret_native_otp_start(
    *, status_code: int, content_type: str, body: bytes, now: datetime | None = None
) -> PrivateNativeOtpStart:
    """Review Rauthy v0.37.1 POST /users/otp_start, no BFF activation.

    This is a private provider reply only; do not return its code to browser.
    Caller must independently bind the upstream request to the original
    protected Rauthy session, `MfaPurpose::Login` code and selected OTP ID.
    """
    clock = datetime.now(UTC) if now is None else now
    if (
        not isinstance(clock, datetime)
        or clock.tzinfo is None
        or status_code != 200
        or not isinstance(content_type, str)
        or content_type.split(";", 1)[0].lower() != "application/json"
    ):
        raise NativeProviderProtocolUnavailable("OTP start not accepted by Rauthy")
    parsed = _bounded_json(body)
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"code", "exp"}
        or not isinstance(parsed["code"], str)
        or re.fullmatch(r"[A-Za-z0-9]{48}", parsed["code"], re.ASCII) is None
        or type(parsed["exp"]) is not int
        or not int(clock.timestamp()) < parsed["exp"] <= int(clock.timestamp()) + 900
    ):
        raise NativeProviderProtocolUnavailable("untrusted Rauthy OTP start challenge")
    return PrivateNativeOtpStart(SecretStr(parsed["code"]), parsed["exp"])


def interpret_native_otp_finish(
    *,
    status_code: int,
    headers: Mapping[str, str],
    body: bytes,
    expected_callback: str,
    expected_state: str,
    expected_issuer: str,
    now: datetime | None = None,
) -> PrivateNativeLoginStep:
    """Review exact Rauthy /users/otp_finish Login and pending ToS states.

    Source v0.37.1 OtpAdditionalData::Login returns 202 with *both* Location
    and JSON {loc}; its callback is checked by the SAME code/state/issuer
    verifier as first-factor. The response still is NOT signed authentication.
    Only a subsequent existing OIDC code+PKCE/Userinfo exchange can create a
    private Briareus browser session. No public MFA endpoint is activated.
    """
    if status_code == 202:
        if _single_header(headers, "content-type") not in {
            "application/json",
            "application/json; charset=utf-8",
        }:
            raise NativeProviderProtocolUnavailable("Rauthy OTP finish media type rejected")
        parsed = _bounded_json(body)
        location = _single_header(headers, "location")
        if (
            not isinstance(parsed, dict)
            or set(parsed) != {"loc"}
            or not isinstance(parsed["loc"], str)
            or not isinstance(location, str)
            or parsed["loc"] != location
        ):
            raise NativeProviderProtocolUnavailable("Rauthy OTP finish redirect disagreement")
        return interpret_native_authorize(
            status_code=202,
            headers={"Location": location},
            body=b"",
            expected_callback=expected_callback,
            expected_state=expected_state,
            expected_issuer=expected_issuer,
            now=now,
        )
    if status_code == 206 and _single_header(headers, "content-type") not in {
        "application/json",
        "application/json; charset=utf-8",
    }:
        raise NativeProviderProtocolUnavailable("Rauthy OTP ToS media type rejected")
    return interpret_native_authorize(
        status_code=status_code,
        headers=headers,
        body=body,
        expected_callback=expected_callback,
        expected_state=expected_state,
        expected_issuer=expected_issuer,
        now=now,
    )
