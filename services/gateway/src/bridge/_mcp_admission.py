"""MCP Gateway ingress authentication only: no Project/Cedar decision here.

The private identity verifier validates the real Rauthy resource access token
and binds its verified issuer/audience/token to a short lived proof. Gateway
never reads user roles, Project mappings, grants, actions or resource policies.
Each Hand separately validates the original token and asks Authorization/Cedar
for the exact protected effect. An unconfigured verifier denies by default.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from starlette.requests import Request
from starlette.responses import JSONResponse

from .single_origin import MCP_MODULES

_HAND_TARGETS = {name: f"http://briareus-{name}:8000/mcp" for name in MCP_MODULES}
_PUBLIC_ORIGIN = "https://briareus.koba-nexus.ru"
_RAUTHY_ISSUER = _PUBLIC_ORIGIN + "/auth/v1/"
_VERIFY_TIMEOUT_SECONDS = 5


@dataclass(frozen=True, slots=True)
class VerifiedMcpAuthentication:
    """Bound result from an independently trusted real resource-token verifier.

    The trusted port MUST verify Rauthy signing keys, issuer, access-token
    purpose, audience, expiry and current revocation status. The Gateway
    accepts only this short-lived token-bound evidence and never exposes it
    in a header, trace or downstream payload.
    """

    issuer: str
    audience: str
    bearer_sha256: str
    authenticated_at: datetime
    expires_at: datetime


class McpInvalidToken(Exception):
    """Trusted verifier reports an invalid or revoked signed access token."""


class TrustedGatewayAuthenticationPort(Protocol):
    """Independent real Rauthy identity verification, not Cedar policy.

    Must be installed by a trusted supervisor with independently verified
    provider credentials/JWKS/revocation. No ENV flag, unauthenticated HTTP
    endpoint, Docker DNS, client header or self-declared JWT is authority.
    """

    async def authenticate(
        self, *, bearer: str, resource_audience: str
    ) -> VerifiedMcpAuthentication: ...


class McpAdmissionRejected(Exception):
    """Bounded public transport refusal, not an operation/Cedar decision."""

    def __init__(self, code: str, status_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ConnectionAdmission:
    """Fixed Hand route with an unverified incoming access token."""

    hand: str
    bearer: str

    @property
    def target(self) -> str:
        return _HAND_TARGETS[self.hand]

    @property
    def resource_audience(self) -> str:
        return f"{_PUBLIC_ORIGIN}/hands/{self.hand}/mcp"


def admission_error(code: str, status: int) -> JSONResponse:
    return JSONResponse(
        {"code": code},
        status_code=status,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


def parse_connection_admission(request: Request) -> ConnectionAdmission:
    """Validate only MCP transport, fixed route and Bearer syntax.

    Do not read Project, AgentSession, grant revision or effect rights.
    Optional original selectors remain UNTRUSTED and are checked at the Hand.
    """
    hand = request.url.path.removeprefix("/hands/").removesuffix("/mcp")
    canonical = f"/hands/{hand}/mcp"
    if (
        hand not in _HAND_TARGETS
        or request.url.path != canonical
        or request.scope.get("raw_path") != canonical.encode("ascii")
    ):
        raise McpAdmissionRejected("MCP_MODULE_UNKNOWN", 404)
    if request.scope.get("query_string", b"") != b"":
        raise McpAdmissionRejected("MCP_CONTEXT_INVALID", 400)
    if request.method != "POST":
        raise McpAdmissionRejected("MCP_METHOD_UNSUPPORTED", 405)
    if request.headers.getlist("cookie"):
        raise McpAdmissionRejected("MCP_COOKIE_NOT_ALLOWED", 400)
    authorizations = request.headers.getlist("authorization")
    if len(authorizations) != 1:
        raise McpAdmissionRejected("MCP_BEARER_REQUIRED", 401)
    bearer = authorizations[0]
    if (
        not bearer.startswith("Bearer ")
        or len(bearer) > 8192
        or bearer.count(" ") != 1
        or not bearer[7:]
        or any(char.isspace() for char in bearer[7:])
    ):
        raise McpAdmissionRejected("MCP_BEARER_REQUIRED", 401)
    return ConnectionAdmission(hand, bearer)


def _is_current_proof(proof: object, *, bearer: str, resource_audience: str) -> bool:
    if type(proof) is not VerifiedMcpAuthentication:
        return False
    now = datetime.now(UTC)
    digest = hashlib.sha256(bearer.encode("ascii")).hexdigest()
    return (
        proof.issuer == _RAUTHY_ISSUER
        and proof.audience == resource_audience
        and isinstance(proof.bearer_sha256, str)
        and hmac.compare_digest(proof.bearer_sha256, digest)
        and type(proof.authenticated_at) is datetime
        and type(proof.expires_at) is datetime
        and proof.authenticated_at.tzinfo is not None
        and proof.expires_at.tzinfo is not None
        and now - timedelta(seconds=15) <= proof.authenticated_at <= now + timedelta(seconds=2)
        and now < proof.expires_at <= now + timedelta(days=1)
    )


async def authenticate_mcp_connection(
    private: TrustedGatewayAuthenticationPort | None, admission: ConnectionAdmission
) -> JSONResponse | None:
    """Deny without valid verified identity; never invoke a Cedar policy."""
    if private is None:
        return admission_error("MCP_AUTHENTICATION_UNAVAILABLE", 503)
    try:
        proof = await asyncio.wait_for(
            private.authenticate(
                bearer=admission.bearer,
                resource_audience=admission.resource_audience,
            ),
            timeout=_VERIFY_TIMEOUT_SECONDS,
        )
    except McpInvalidToken:
        return admission_error("MCP_IDENTITY_UNVERIFIED", 401)
    except Exception:
        return admission_error("MCP_AUTHENTICATION_UNAVAILABLE", 503)
    if not _is_current_proof(
        proof, bearer=admission.bearer, resource_audience=admission.resource_audience
    ):
        return admission_error("MCP_IDENTITY_UNVERIFIED", 401)
    return None
