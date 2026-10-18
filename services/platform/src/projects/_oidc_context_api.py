"""Private current Platform projection, never a public OAuth/login endpoint.

Peer evidence is independently verified by an explicitly injected transport
adapter; a client-supplied issuer/subject does NOT authenticate a person or
authorize SQL visibility. Default release exposes only unavailable status.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ._oidc_membership_projection import (
    CurrentRauthyPlatformMembership,
    PlatformOidcMembershipProjection,
    PlatformSubjectLinkUnavailable,
)

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class PlatformContextQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    issuer: str = Field(min_length=12, max_length=512)
    subject: str = Field(min_length=1, max_length=256)
    project_uuid: UUID | None = None

    @field_validator("project_uuid")
    @classmethod
    def v4(cls, value: UUID | None) -> UUID | None:
        if value is not None and value.version != 4:
            raise ValueError("Project must be UUIDv4")
        return value


@dataclass(frozen=True, slots=True)
class VerifiedPanelContextPeer:
    """Trusted private API peer + delegated verified Rauthy browser identity."""

    service_audience: Literal["briareus:platform"]
    consumer: Literal["control-panel-api"]
    issuer: str
    subject: str
    expires_at: datetime
    project_uuid: UUID | None = None


class TrustedPanelContextAttestor(Protocol):
    async def verify(
        self, request: Request, query: PlatformContextQuery
    ) -> VerifiedPanelContextPeer:
        """Attest authenticated service transport AND delegated subject."""
        ...


class PanelContextNotAuthenticated(Exception):
    """No valid service/subject attestation was presented."""


class PanelContextOwnerUnavailable(Exception):
    """Trusted peer or Platform SQL authority cannot produce a fresh context."""


def current_platform_context_router(
    *,
    projection: PlatformOidcMembershipProjection | None,
    attestor: TrustedPanelContextAttestor | None,
    resolve_projection: Callable[[], PlatformOidcMembershipProjection | None] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/internal/v1/platform/oidc", tags=["platform-private"])

    def denied(status: int, code: str) -> JSONResponse:
        return JSONResponse({"error": {"code": code}}, status_code=status, headers=_NO_STORE)

    @router.post("/current", include_in_schema=False)
    async def current(query: PlatformContextQuery, request: Request) -> JSONResponse:
        source = resolve_projection() if resolve_projection is not None else projection
        if source is None or attestor is None:
            return denied(503, "PLATFORM_TRUST_NOT_CONFIGURED")
        if request.headers.getlist("cookie") or len(request.headers.getlist("authorization")) != 1:
            return denied(401, "PLATFORM_SERVICE_PROOF_REQUIRED")
        try:
            verified = await attestor.verify(request, query)
        except PanelContextNotAuthenticated:
            return denied(401, "PLATFORM_SERVICE_PROOF_REQUIRED")
        except Exception:
            return denied(503, "PLATFORM_TRUST_UNAVAILABLE")
        now = datetime.now(UTC)
        if (
            not isinstance(verified, VerifiedPanelContextPeer)
            or verified.service_audience != "briareus:platform"
            or verified.consumer != "control-panel-api"
            or verified.issuer != query.issuer
            or verified.subject != query.subject
            or verified.project_uuid != query.project_uuid
            or not isinstance(verified.expires_at, datetime)
            or verified.expires_at.tzinfo is None
            or not now < verified.expires_at <= now + timedelta(seconds=30)
        ):
            return denied(403, "PLATFORM_SERVICE_SCOPE_DENIED")
        try:
            if query.project_uuid is None:
                result = await source.resolve(issuer=query.issuer, subject=query.subject)
            else:
                result = await source.resolve_project(
                    issuer=query.issuer, subject=query.subject, project_uuid=query.project_uuid
                )
        except PlatformSubjectLinkUnavailable:
            return denied(503, "PLATFORM_SOURCE_UNAVAILABLE")
        except Exception:
            return denied(503, "PLATFORM_SOURCE_UNAVAILABLE")
        if result is None:
            return denied(403, "PLATFORM_MEMBERSHIP_REQUIRED")
        # The owner SQL/Rauthy User lookup can block beyond a once-valid
        # private service peer proof. Never return even a scoped User/Project
        # projection after the attested service authority has expired.
        now = datetime.now(UTC)
        if verified.expires_at <= now:
            return denied(503, "PLATFORM_TRUST_UNAVAILABLE")
        if (
            not isinstance(result, CurrentRauthyPlatformMembership)
            or result.issuer != verified.issuer
            or result.subject != verified.subject
            or not isinstance(result.user_id, UUID)
            or result.user_id.version != 4
            or result.enabled is not True
            or result.role not in {"user", "operator"}
            or not isinstance(result.expires_at, datetime)
            or result.expires_at.tzinfo is None
            or result.expires_at <= now
            or (
                query.project_uuid is not None
                and (
                    len(result.projects) != 1
                    or result.projects[0].project_id != query.project_uuid
                    or len(result.teams) > 1
                )
            )
        ):
            return denied(503, "PLATFORM_SOURCE_INVALID_RESPONSE")

        return JSONResponse(
            {
                "issuer": result.issuer,
                "subject": result.subject,
                "user_uuid": str(result.user_id),
                "enabled": True,
                "role": result.role,
                "name": result.name,
                "email": result.email,
                "expires_at": min(result.expires_at, verified.expires_at).isoformat(),
                "teams": [
                    {
                        "team_uuid": str(team.team_id),
                        "owner": team.owner,
                        "name": team.name,
                    }
                    for team in result.teams
                ],
                "projects": [
                    {
                        "project_uuid": str(project.project_id),
                        "name": project.name,
                        "owner_kind": project.owner_kind,
                        "owner_uuid": str(project.owner_id),
                        "permissions": list(project.permissions),
                    }
                    for project in result.projects
                ],
            },
            headers=_NO_STORE,
        )

    return router
