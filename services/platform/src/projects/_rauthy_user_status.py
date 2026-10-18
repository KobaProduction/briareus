"""Pinned Rauthy v0.37.1 private Users:read status; no IAM claims as grants.

Upstream contract reviewed at sebadob/rauthy tag v0.37.1, git ce35a70f:
- src/api/src/users.rs GET /users/{id} validates Users:read API-Key.
- src/api_types/src/users.rs UserResponse: id, enabled, user_expires.
- src/service/src/token_set.rs ID-token sub is user.id.
- src/common/src/utils.rs new_store_id() is 24 alphanumeric characters.

A read-only scoped key is supplied ONLY by the trusted Platform process.
Never derive a Rauthy Admin credential or URL from a browser session.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import (
    HTTPHandler,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from pydantic import SecretStr

from common.platform_db import PlatformDatabase
from projects._oidc_membership_projection import PlatformOidcMembershipProjection
from projects._rauthy_user_links import (
    PlatformCurrentSubjectLinkReader,
    VerifiedRauthyUserStatus,
)

_INTERNAL_BASE = "http://briareus-rauthy:8080"
_LOCAL_SANDBOX_BASE = "https://localhost:18444"
_PUBLIC_ISSUER = (
    "https://127.0.0.1/auth/v1/"
    if os.environ.get("BRIAREUS_LOCAL_TESTING") == "1"
    else "https://briareus.koba-nexus.ru/auth/v1/"
)
_LOCAL_SANDBOX_ISSUER = "https://localhost:18444/auth/v1/"
_USERS_BY_ID = "/auth/v1/users/"
_ID = re.compile(r"[A-Za-z0-9]{24}\Z", flags=re.ASCII)
_MAX_JSON = 65_536
_FRESH_SECONDS = 10


class RauthyUserStatusUnavailable(Exception):
    """Private upstream Users:read privilege or user status not trusted."""


@dataclass(frozen=True, slots=True)
class PrivateUserResponse:
    status: int
    content_type: str
    body: bytes


class RauthyUserPrivateTransport(Protocol):
    async def read_user(self, *, subject: str) -> PrivateUserResponse:
        """Fixed, private, authenticated read only. Must never redirect."""
        ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        raise RauthyUserStatusUnavailable("Rauthy private Users API redirected")


class FixedRauthyUsersTransport:
    """Only the exact private DNS host; no system proxy, redirect or user URL."""

    def __init__(
        self,
        *,
        users_read_api_key: SecretStr,
        test_only_local_ca_pem: str | None = None,
    ) -> None:
        if not isinstance(users_read_api_key, SecretStr):
            raise ValueError("private scoped Rauthy Users:read key required")
        key = users_read_api_key.get_secret_value()
        if (
            not 1 <= len(key) <= 4096
            or not key.isascii()
            or any(ch.isspace() or ord(ch) < 33 or ord(ch) == 127 for ch in key)
        ):
            raise ValueError("private Rauthy User read key syntax unsafe")
        self._key = users_read_api_key
        if test_only_local_ca_pem is None:
            self._url = _INTERNAL_BASE
            self._tls_context = None
        else:
            # No trust_env, certificate bypass or caller-controlled host.
            # This is ONLY the independent disposable localhost Rauthy.
            if (
                not isinstance(test_only_local_ca_pem, str)
                or not 256 <= len(test_only_local_ca_pem) <= 8192
                or "-----BEGIN CERTIFICATE-----" not in test_only_local_ca_pem
                or "-----BEGIN PRIVATE KEY-----" in test_only_local_ca_pem
            ):
                raise ValueError("local Rauthy TLS certificate required")
            try:
                self._tls_context = ssl.create_default_context(cadata=test_only_local_ca_pem)
            except (ssl.SSLError, ValueError):
                raise ValueError("untrusted disposable Rauthy certificate") from None
            self._url = _LOCAL_SANDBOX_BASE

    def _read_sync(self, subject: str, *, by_email: bool = False) -> PrivateUserResponse:
        # No arbitrary URL or request-supplied host is ever contacted.
        target = (
            self._url
            + (_USERS_BY_ID + "email/" if by_email else _USERS_BY_ID)
            + quote(subject, safe="")
        )
        request = Request(
            target,
            method="GET",
            headers={
                "Authorization": "API-Key " + self._key.get_secret_value(),
                "Accept": "application/json",
            },
        )
        handler = (
            HTTPSHandler(context=self._tls_context)
            if self._tls_context is not None
            else HTTPHandler()
        )
        opener = build_opener(ProxyHandler({}), handler, _NoRedirect())
        try:
            with opener.open(request, timeout=3.0) as response:
                if response.status != 200:
                    return PrivateUserResponse(response.status, "", b"")
                if response.headers.get_content_type() != "application/json":
                    raise RauthyUserStatusUnavailable("private Rauthy Users response not JSON")
                body = response.read(_MAX_JSON + 1)
                if len(body) > _MAX_JSON:
                    raise RauthyUserStatusUnavailable("Rauthy Users response over maximum")
                return PrivateUserResponse(200, "application/json", body)
        except HTTPError as exc:
            # An upstream 404 means account deleted, not permission. Never
            # consume the full error body or leak metadata from the IdP.
            return PrivateUserResponse(exc.code, "", b"")
        except (OSError, URLError, ValueError) as exc:
            raise RauthyUserStatusUnavailable("private Rauthy Users API unavailable") from exc

    async def read_user(self, *, subject: str) -> PrivateUserResponse:
        if not isinstance(subject, str) or _ID.fullmatch(subject) is None:
            raise RauthyUserStatusUnavailable("noncanonical Rauthy subject")
        try:
            return await asyncio.wait_for(asyncio.to_thread(self._read_sync, subject), timeout=3.5)
        except TimeoutError:
            raise RauthyUserStatusUnavailable("Rauthy Users API timed out") from None

    async def read_by_email(self, *, email: str) -> PrivateUserResponse:
        # Pinned Rauthy GET /users/email/{email}; same Users:read authority.
        if (
            not isinstance(email, str)
            or not 3 <= len(email) <= 254
            or "@" not in email
            or any(ord(c) < 33 for c in email)
        ):
            raise RauthyUserStatusUnavailable("Invalid provider email selector")
        return await asyncio.wait_for(
            asyncio.to_thread(self._read_sync, email, by_email=True), timeout=3.5
        )


def _without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("duplicate Rauthy Users API JSON field")
        parsed[key] = value
    return parsed


class FileRauthyUsersTransport:
    """Read an owner-provisioned key lazily, never from request data or ENV."""

    def __init__(self, key_file: str) -> None:
        if key_file != "/var/lib/briareus-platform/rauthy-users-read.key":
            raise ValueError("Exact Platform-owned provider key file required")
        self.path = Path(key_file)

    def _key(self) -> SecretStr:
        info = self.path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 1000 or info.st_mode & 0o077:
            raise RauthyUserStatusUnavailable("Platform provider key is not privately provisioned")
        if not 1 <= info.st_size <= 4096:
            raise RauthyUserStatusUnavailable("Platform provider key size invalid")
        return SecretStr(self.path.read_text().strip())

    async def read_user(self, *, subject: str) -> PrivateUserResponse:
        key = await asyncio.to_thread(self._key)
        return await FixedRauthyUsersTransport(users_read_api_key=key).read_user(subject=subject)

    async def read_by_email(self, *, email: str) -> PrivateUserResponse:
        reader = FixedRauthyUsersTransport(users_read_api_key=await asyncio.to_thread(self._key))
        return await reader.read_by_email(email=email)


class CurrentRauthyUserStatusReader:
    """Return only exact enabled/current status; discard all provider PII."""

    def __init__(
        self,
        *,
        private_transport: RauthyUserPrivateTransport,
        test_only_local_issuer: bool = False,
    ) -> None:
        if private_transport is None:
            raise ValueError("trusted Rauthy private Users transport required")
        if type(test_only_local_issuer) is not bool:
            raise ValueError("local provider selector must be an explicit bool")
        self._transport = private_transport
        self._issuer = _LOCAL_SANDBOX_ISSUER if test_only_local_issuer else _PUBLIC_ISSUER

    async def current_status(self, *, issuer: str, subject: str) -> VerifiedRauthyUserStatus:
        # Issuer pin is supplied by the verified Rauthy session or signed
        # service owner, NOT taken from a client JWT URL/Host.
        if (
            not isinstance(issuer, str)
            or issuer != self._issuer
            or not isinstance(subject, str)
            or _ID.fullmatch(subject) is None
        ):
            raise RauthyUserStatusUnavailable("Rauthy issuer or subject not approved")
        try:
            result = await self._transport.read_user(subject=subject)
        except Exception:
            raise RauthyUserStatusUnavailable("private Users:read status unavailable") from None
        if not isinstance(result, PrivateUserResponse):
            raise RauthyUserStatusUnavailable("untrusted Rauthy Users response")
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=_FRESH_SECONDS)
        if result.status == 404:
            return VerifiedRauthyUserStatus(issuer, subject, False, expires_at)
        if (
            result.status != 200
            or result.content_type.split(";", 1)[0] != "application/json"
            or not isinstance(result.body, bytes)
            or not 1 <= len(result.body) <= _MAX_JSON
        ):
            raise RauthyUserStatusUnavailable("Rauthy Users:read not verified")
        try:
            data = json.loads(result.body, object_pairs_hook=_without_duplicate_keys)
        except (UnicodeDecodeError, ValueError, TypeError):
            raise RauthyUserStatusUnavailable("Rauthy Users body invalid") from None
        if not isinstance(data, dict):
            raise RauthyUserStatusUnavailable("Rauthy User record not an object")
        enabled = data.get("enabled")
        user_expiry = data.get("user_expires")
        if (
            data.get("id") != subject
            or type(enabled) is not bool
            or (
                user_expiry is not None
                and (type(user_expiry) is not int or not 1 <= user_expiry <= 2**63 - 1)
            )
        ):
            raise RauthyUserStatusUnavailable("Rauthy User identity/status mismatch")
        # Proof must expire no later than the provider account itself.
        # An account expiring in 1s must not grant 10s of stale Project access.
        if user_expiry is not None:
            try:
                account_expiry = datetime.fromtimestamp(user_expiry, tz=UTC)
            except (OverflowError, OSError, ValueError):
                raise RauthyUserStatusUnavailable("Rauthy account expiry invalid") from None
            active = enabled and account_expiry > now
            if active:
                expires_at = min(expires_at, account_expiry)
        else:
            active = enabled

        # Display-only provider profile; never persist credentials or IdP roles.
        def label(value: object) -> str | None:
            if not isinstance(value, str):
                return None
            value = value.strip()
            return value if 0 < len(value) <= 255 and not any(ord(c) < 32 for c in value) else None

        email = label(data.get("email"))
        name = (
            label(
                " ".join(
                    filter(None, (label(data.get("given_name")), label(data.get("family_name"))))
                )
            )
            or email
        )
        return VerifiedRauthyUserStatus(issuer, subject, active, expires_at, name, email)


def platform_user_membership_with_rauthy(
    *,
    database: PlatformDatabase,
    users_read_api_key: SecretStr | None = None,
    users_read_key_file: str | None = None,
    test_only_local_ca_pem: str | None = None,
) -> PlatformOidcMembershipProjection:
    """Construct a source-qualified Platform projection, never auto-create it."""
    if (users_read_api_key is None) == (users_read_key_file is None):
        raise ValueError("Exactly one owner-provisioned provider key source required")
    private_transport = (
        FileRauthyUsersTransport(users_read_key_file)
        if users_read_key_file is not None
        else FixedRauthyUsersTransport(
            users_read_api_key=users_read_api_key,
            test_only_local_ca_pem=test_only_local_ca_pem,
        )
    )
    status_reader = CurrentRauthyUserStatusReader(
        private_transport=private_transport,
        test_only_local_issuer=test_only_local_ca_pem is not None,
    )
    links = PlatformCurrentSubjectLinkReader(
        database=database,
        rauthy_status=status_reader,
    )
    return PlatformOidcMembershipProjection(database=database, subject_links=links)
