"""Rauthy OpenID Connect discovery through standards, not private APIs.

This is an upstream Identity adapter, NOT an alternate issuer, password store,
or a grant authority. Public configuration may be forwarded to the browser;
privileged Rauthy Admin REST remains a separate, unexposed integration.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from time import monotonic
from urllib.parse import urlencode, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, SecretStr, ValidationError

from ._local_provider_transport import provider_http_client
from ._oidc_id_token import (
    OidcIdentityRejected,
    VerifiedOidcIdentity,
    verify_rauthy_id_token,
)
from ._oidc_origin_policy import validate_files_resource_intent
from ._oidc_resource import PrivateOidcResourceCredential, verify_resource_credential


@dataclass(frozen=True, slots=True)
class VerifiedOidcLogin:
    identity: VerifiedOidcIdentity
    resource: PrivateOidcResourceCredential | None


class OidcProviderUnavailable(Exception):
    """Issuer is unconfigured, unavailable, or returned untrusted metadata."""


class OidcDiscovery(BaseModel):
    model_config = ConfigDict(extra="ignore")

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    code_challenge_methods_supported: list[str] = Field(default_factory=list)
    response_types_supported: list[str] = Field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PublicOidcConfiguration:
    issuer: str
    client_id: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None


@dataclass(frozen=True, slots=True)
class OidcAuthorizationAttempt:
    """Pending provider login, not authenticated User or Session proof."""

    authorization_url: str
    state: str
    nonce: str
    code_verifier: SecretStr
    redirect_uri: str
    expires_at: datetime
    resource_audience: str | None = None


class UnverifiedOidcTokenResponse(BaseModel):
    """Upstream tokens: NOT a verified actor or platform permission."""

    model_config = ConfigDict(extra="ignore")

    access_token: SecretStr = Field(min_length=40)
    id_token: SecretStr = Field(min_length=40)
    token_type: str
    expires_in: int = Field(strict=True, gt=0, le=86_400)
    _request_started: datetime = PrivateAttr(default_factory=lambda: datetime.now(UTC))

    @property
    def deadline(self) -> datetime:
        return self._request_started + timedelta(seconds=self.expires_in)


def _pkce_s256(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )


def _is_https_url(value: str) -> bool:
    try:
        url = urlsplit(value)
    except ValueError:
        return False
    return (
        url.scheme == "https"
        and bool(url.hostname)
        and url.username is None
        and url.password is None
        and not url.fragment
        and not url.query
    )


def _rauthy_endpoint(issuer: str, url: str, name: str) -> bool:
    """Restrict token/JWKS/authorize/userinfo to this exact Rauthy issuer."""
    if not _is_https_url(issuer) or not _is_https_url(url):
        return False
    authority = urlsplit(issuer)
    endpoint = urlsplit(url)
    return (
        authority.netloc == endpoint.netloc
        and endpoint.path == authority.path.rstrip("/") + "/oidc/" + name
    )


def _unique_oidc_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate OIDC Userinfo field")
        result[key] = value
    return result


class RauthyOidcAdapter:
    """Fetch OIDC metadata once per bounded TTL; never proxy credentials."""

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        http_client: httpx.AsyncClient | None = None,
        cache_seconds: float = 300.0,
        resource_audience: str | None = None,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._client_id = client_id
        validate_files_resource_intent(
            issuer=self._issuer, client_id=client_id, resource_audience=resource_audience
        )
        self._resource_audience = resource_audience
        if not _is_https_url(self._issuer) or not client_id or not client_id.strip():
            raise ValueError("OIDC requires a real HTTPS issuer and client ID")
        self._client = http_client or provider_http_client(
            timeout=5.0, follow_redirects=False, trust_env=False
        )
        self._owns_client = http_client is None
        self._cache_seconds = max(1.0, cache_seconds)
        self._cached: OidcDiscovery | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def resource_audience(self) -> str | None:
        return self._resource_audience

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def discovery(self) -> OidcDiscovery:
        if self._cached is not None and monotonic() < self._expires_at:
            return self._cached
        async with self._lock:
            if self._cached is not None and monotonic() < self._expires_at:
                return self._cached
            try:
                response = await self._client.get(
                    f"{self._issuer}/.well-known/openid-configuration",
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                metadata = OidcDiscovery.model_validate(response.json())
            except (httpx.HTTPError, ValidationError, ValueError, TypeError) as exc:
                raise OidcProviderUnavailable("OIDC issuer discovery unavailable") from exc
            if (
                metadata.issuer.rstrip("/") != self._issuer
                or not _rauthy_endpoint(self._issuer, metadata.authorization_endpoint, "authorize")
                or not _rauthy_endpoint(self._issuer, metadata.token_endpoint, "token")
                or not _rauthy_endpoint(self._issuer, metadata.jwks_uri, "certs")
                or metadata.userinfo_endpoint is None
                or not _rauthy_endpoint(self._issuer, metadata.userinfo_endpoint, "userinfo")
                or "code" not in metadata.response_types_supported
                or "S256" not in metadata.code_challenge_methods_supported
            ):
                raise OidcProviderUnavailable(
                    "OIDC issuer metadata violates pinned Rauthy PKCE endpoints"
                )
            self._cached = metadata
            self._expires_at = monotonic() + self._cache_seconds
            return metadata

    async def prepare_authorization_code(self, *, redirect_uri: str) -> OidcAuthorizationAttempt:
        """Create an upstream code+PKCE request for a verified public client.

        A trusted BFF must store the verifier/state/nonce privately until a
        one-time callback. The redirect URI comes from approved config, never
        caller-controlled Host or query parameters.
        """
        if not _is_https_url(redirect_uri):
            raise ValueError("approved HTTPS OIDC callback required")
        provider = await self.discovery()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._client_id,
                "redirect_uri": redirect_uri,
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "code_challenge": _pkce_s256(verifier),
                "code_challenge_method": "S256",
                **({"resource": self._resource_audience} if self._resource_audience else {}),
            }
        )
        return OidcAuthorizationAttempt(
            authorization_url=f"{provider.authorization_endpoint}?{query}",
            state=state,
            nonce=nonce,
            code_verifier=SecretStr(verifier),
            redirect_uri=redirect_uri,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            resource_audience=self._resource_audience,
        )

    async def exchange_authorization_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: SecretStr,
        resource_audience: str | None = None,
    ) -> UnverifiedOidcTokenResponse:
        """Redeem code against verified Rauthy without making local JWTs.

        Trusted caller must atomically consume the matching one-time state
        before use. Returned tokens are not verified login or access grants:
        ID-token signature/issuer/audience/nonce and current Platform
        membership still need independent verification.
        """
        verifier = code_verifier.get_secret_value()
        if (
            resource_audience != self._resource_audience
            or not isinstance(code, str)
            or not 1 <= len(code) <= 4096
            or any(ch.isspace() for ch in code)
            or not _is_https_url(redirect_uri)
            or re.fullmatch(r"[A-Za-z0-9_-]{43,128}", verifier) is None
        ):
            raise ValueError("invalid code or trusted PKCE transaction")
        provider = await self.discovery()
        request_started = datetime.now(UTC)
        try:
            response = await self._client.post(
                provider.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self._client_id,
                    "code_verifier": verifier,
                    **({"resource": resource_audience} if resource_audience else {}),
                },
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            if (
                len(response.content) > 65_536
                or response.headers.get("content-type", "").split(";", 1)[0].lower()
                != "application/json"
            ):
                raise OidcProviderUnavailable("OIDC token response malformed")
            token = UnverifiedOidcTokenResponse.model_validate(
                json.loads(response.content, object_pairs_hook=_unique_oidc_fields)
            )
            if token.token_type.lower() != "bearer":
                raise OidcProviderUnavailable("OIDC token type unsupported")
            token._request_started = request_started
            return token
        except (httpx.HTTPError, ValidationError, ValueError, TypeError) as exc:
            raise OidcProviderUnavailable("OIDC token exchange unavailable") from exc

    async def verify_exchanged_id_token(
        self,
        *,
        tokens: UnverifiedOidcTokenResponse,
        expected_nonce: str,
    ) -> VerifiedOidcIdentity:
        """Verify real Rauthy signature before trusting a returned identity."""
        metadata = await self.discovery()
        return await verify_rauthy_id_token(
            tokens.id_token,
            expected_nonce=expected_nonce,
            issuer=metadata.issuer,
            client_id=self._client_id,
            jwks_uri=metadata.jwks_uri,
            client=self._client,
        )

    async def verify_current_userinfo(
        self,
        *,
        tokens: UnverifiedOidcTokenResponse,
        identity: VerifiedOidcIdentity,
    ) -> None:
        """Ask pinned Rauthy if this exact signed ID-token subject is active.

        Rauthy 0.37.1 userinfo validates bearer token, JTI revocation,
        current User.enabled and User.check_expired() before returning
        sub=user.id. No userinfo roles/email/group data is retained.
        This is identity freshness, NEVER Briareus Platform permission.
        """
        if (
            not isinstance(identity, VerifiedOidcIdentity)
            or identity.issuer.rstrip("/") != self._issuer
            or identity.client_id != self._client_id
            or not isinstance(identity.subject, str)
            or not re.fullmatch(r"[A-Za-z0-9]{24}", identity.subject, re.ASCII)
            or identity.expires_at <= datetime.now(UTC)
        ):
            raise OidcIdentityRejected("Rauthy Userinfo signed subject unavailable")
        raw = tokens.access_token.get_secret_value()
        if (
            not isinstance(raw, str)
            or not 40 <= len(raw) <= 8192
            or not raw.isascii()
            or any(character.isspace() for character in raw)
        ):
            raise OidcIdentityRejected("Rauthy bearer not suitable for Userinfo")
        metadata = await self.discovery()
        try:
            response = await self._client.get(
                metadata.userinfo_endpoint,
                headers={
                    "Authorization": "Bearer " + raw,
                    "Accept": "application/json",
                },
                follow_redirects=False,
            )
        except (httpx.HTTPError, ValueError):
            raise OidcProviderUnavailable("Rauthy Userinfo endpoint unavailable") from None
        if response.status_code in (401, 403):
            raise OidcIdentityRejected("Rauthy Userinfo rejected current user")
        if (
            response.status_code != 200
            or not 1 <= len(response.content) <= 65_536
            or response.headers.get("content-type", "").split(";", 1)[0].lower()
            != "application/json"
        ):
            raise OidcProviderUnavailable("Rauthy Userinfo response unavailable")
        try:
            info = json.loads(
                response.content,
                object_pairs_hook=_unique_oidc_fields,
            )
        except (ValueError, UnicodeDecodeError, TypeError):
            raise OidcIdentityRejected("Rauthy Userinfo response malformed") from None
        if (
            not isinstance(info, dict)
            or info.get("sub") != identity.subject
            or info.get("id") != identity.subject
        ):
            raise OidcIdentityRejected("Rauthy Userinfo subject mismatch")

    async def authenticate_authorization_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: SecretStr,
        expected_nonce: str,
        expected_issuer: str,
        resource_audience: str | None,
    ) -> VerifiedOidcLogin:
        """Complete a consumed original PKCE transaction, without Platform grants."""
        if (
            expected_issuer.rstrip("/") != self.issuer
            or resource_audience != self.resource_audience
        ):
            raise OidcIdentityRejected("original OAuth intent no longer matches this realm")
        tokens = await self.exchange_authorization_code(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
            resource_audience=resource_audience,
        )
        identity = await self.verify_exchanged_id_token(
            tokens=tokens, expected_nonce=expected_nonce
        )
        if identity.issuer != expected_issuer:
            raise OidcIdentityRejected("callback issuer does not match signed issuer")
        await self.verify_current_userinfo(tokens=tokens, identity=identity)
        identity = replace(identity, expires_at=min(identity.expires_at, tokens.deadline))
        resource = None
        if resource_audience is not None:
            metadata = await self.discovery()
            resource = await verify_resource_credential(
                token=tokens.access_token,
                identity=identity,
                resource_audience=resource_audience,
                token_deadline=tokens.deadline,
                jwks_uri=metadata.jwks_uri,
                client=self._client,
            )
            identity = replace(identity, expires_at=min(identity.expires_at, resource.expires_at))
        if identity.expires_at <= datetime.now(UTC):
            raise OidcIdentityRejected("OAuth identity expired before private session creation")
        return VerifiedOidcLogin(identity, resource)

    async def public_configuration(self) -> PublicOidcConfiguration:
        metadata = await self.discovery()
        return PublicOidcConfiguration(
            issuer=metadata.issuer,
            client_id=self._client_id,
            authorization_endpoint=metadata.authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            jwks_uri=metadata.jwks_uri,
            userinfo_endpoint=metadata.userinfo_endpoint,
        )
