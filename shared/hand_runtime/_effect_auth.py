"""Verified resource token and fresh per-tool Authorization admission.

No OAuth signer, private Cedar policy, fallback Permit, or owner API is held
here. Caller-supplied Project/AgentSession/revision are untrusted selectors.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

import httpx2
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token, get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from mcp_types import CallToolRequestParams

_ISSUER = "https://briareus.koba-nexus.ru/auth/v1/"
_JWKS = "https://briareus.koba-nexus.ru/auth/v1/oidc/certs"
_DECIDE = "http://briareus-authorization:8000/internal/v1/authorization/decide"
_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "EdDSA"})
_ACTIONS = {
    "files": "files.read",
    "terminal": "terminal.execute",
    "web": "web.access",
    "svc": "integrations.use",
    "reverse": "analysis.import",
    "infrastructure": "integrations.use",
}
_DIAGNOSTICS = frozenset({"hand_status", "hand_source_summary"})
_CONFIG_KEYS = (
    "MCP_RESOURCE_ISSUER",
    "MCP_RESOURCE_JWKS_URI",
    "MCP_RESOURCE_AUDIENCE",
    "MCP_RESOURCE_SIGNING_ALGORITHM",
)


@dataclass(frozen=True, slots=True)
class ResourceTrust:
    """Trusted provider metadata; never derived from the incoming JWT."""

    issuer: str
    jwks_uri: str
    audience: str
    signing_algorithm: str

    @classmethod
    def from_environment(
        cls, hand: str, environment: Mapping[str, str] | None = None
    ) -> ResourceTrust | None:
        if hand not in _ACTIONS:
            raise ValueError("unrecognized MCP Hand")
        config = os.environ if environment is None else environment
        values = [config.get(key, "").strip() for key in _CONFIG_KEYS]
        if not any(values):
            return None
        if not all(values):
            raise ValueError("incomplete MCP resource trust configuration")
        issuer, jwks_uri, audience, signing_algorithm = values
        if issuer != _ISSUER or jwks_uri != _JWKS:
            raise ValueError("MCP issuer/JWKS do not match verified provider authority")
        if (
            audience == "briareus-control-panel"
            or not 1 <= len(audience) <= 128
            or audience != audience.strip()
            or any(character.isspace() for character in audience)
        ):
            raise ValueError("MCP resource audience is missing or invalid")
        if signing_algorithm not in _ALGORITHMS:
            raise ValueError("unverified MCP access-token signing algorithm")
        if urlsplit(jwks_uri).scheme != "https":
            raise ValueError("MCP JWKS must be HTTPS")
        return cls(issuer, jwks_uri, audience, signing_algorithm)

    def verifier(self) -> JWTVerifier:
        return JWTVerifier(
            issuer=self.issuer,
            jwks_uri=self.jwks_uri,
            audience=self.audience,
            algorithm=self.signing_algorithm,
            ssrf_safe=True,
        )


class EffectAuthorizationMiddleware(Middleware):
    """Guard each protected FastMCP tools/call independently, no caching."""

    def __init__(self, hand: str) -> None:
        if hand not in _ACTIONS:
            raise ValueError("unrecognized MCP Hand")
        self.hand = hand
        self.action = _ACTIONS[hand]

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, object],
    ) -> object:
        name = context.message.name
        if name in _DIAGNOSTICS:
            return await call_next(context)
        if name != "hand_permission_probe":
            raise ToolError("MCP_TOOL_NOT_REGISTERED")
        await self._check_current_permit()
        return await call_next(context)

    async def _check_current_permit(self) -> None:
        # Authentication middleware must have verified the signed current HTTP
        # JWT and audience; raw Authorization is never sufficient on its own.
        verified = get_access_token()
        if verified is None or not verified.token:
            raise ToolError("MCP_IDENTITY_UNVERIFIED")
        try:
            request = get_http_request()
        except RuntimeError as exc:
            raise ToolError("MCP_HTTP_CONTEXT_REQUIRED") from exc
        bearer = request.headers.getlist("authorization")
        if (
            len(bearer) != 1
            or bearer[0] != f"Bearer {verified.token}"
            or request.headers.getlist("cookie")
        ):
            raise ToolError("MCP_IDENTITY_UNVERIFIED")
        try:
            project_uuid = self._uuid_selector(request.headers.getlist("x-briareus-project-uuid"))
            session_uuid = self._uuid_selector(
                request.headers.getlist("x-briareus-agent-session-uuid")
            )
            revisions = request.headers.getlist("x-briareus-grant-revision")
            if len(revisions) != 1 or not revisions[0].isascii() or not revisions[0].isdecimal():
                raise ValueError("missing or invalid revision")
            revision = int(revisions[0])
            if not 1 <= revision <= 2**63 - 1:
                raise ValueError("revision outside range")
        except (ValueError, OverflowError) as exc:
            raise ToolError("MCP_CONTEXT_INVALID") from exc
        body = {
            "project_uuid": str(project_uuid),
            "agent_session_uuid": str(session_uuid),
            "action": self.action,
            "expected_grant_revision": revision,
        }
        try:
            async with httpx2.AsyncClient(
                follow_redirects=False, trust_env=False, timeout=5
            ) as client:
                response = await client.post(
                    _DECIDE,
                    json=body,
                    headers={"Authorization": bearer[0], "Accept": "application/json"},
                )
        except (httpx2.HTTPError, TimeoutError) as exc:
            raise ToolError("MCP_AUTHORIZATION_UNAVAILABLE") from exc
        if response.status_code == 401:
            raise ToolError("MCP_IDENTITY_UNVERIFIED")
        if response.status_code == 403:
            raise ToolError("MCP_ACCESS_DENIED")
        if response.status_code != 200:
            raise ToolError("MCP_AUTHORIZATION_UNAVAILABLE")
        try:
            permit = response.json()
        except ValueError as exc:
            raise ToolError("MCP_AUTHORIZATION_UNAVAILABLE") from exc
        if permit != {"allowed": True}:
            raise ToolError("MCP_AUTHORIZATION_UNAVAILABLE")

    @staticmethod
    def _uuid_selector(values: list[str]) -> UUID:
        if len(values) != 1 or not 1 <= len(values[0]) <= 64:
            raise ValueError("exactly one UUID required")
        result = UUID(values[0])
        if result.version != 4 or str(result) != values[0].lower():
            raise ValueError("canonical UUIDv4 required")
        return result
