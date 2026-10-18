"""Cookie-authenticated Briareus Platform context, distinct from Rauthy identity.

Only a real trusted Platform owner adapter may bind an external Rauthy subject
to a current active Briareus User and visible Team/Project memberships.
The Control Panel API never infers Briareus privileges from OAuth claims.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal, Protocol
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ._api_paths import AUTH_API_PREFIX
from ._oidc_browser import (
    _SID_COOKIE,
    _TOKEN,
    OidcBrowserSessionStore,
    OidcSessionStoreUnavailable,
    PanelOidcSession,
    _strict_browser_cookies,
)
from ._oidc_origin_policy import PUBLIC_ORIGIN, local_browser_host, resolve_browser_origin

if TYPE_CHECKING:
    from ._oidc_approvals import ApprovalManagementPort
    from ._oidc_catalog import TrustedCatalogReadPort
    from ._oidc_files_content import TrustedFilesContentOwner


_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_MAX_PROOF_AGE = timedelta(seconds=30)
_MAX_RELATIONS = 100


@dataclass(frozen=True, slots=True)
class PlatformTeamContext:
    team_uuid: UUID
    owner: bool
    name: str | None = None


@dataclass(frozen=True, slots=True)
class PlatformProjectContext:
    project_uuid: UUID
    owner_kind: Literal["user", "team"]
    owner_uuid: UUID
    permissions: tuple[Literal["use_resources", "approve_agent_session"], ...]
    name: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedPlatformUser:
    """Owner-verified, bounded and fresh membership snapshot."""

    issuer: str
    subject: str
    user_uuid: UUID
    enabled: bool
    role: Literal["user", "operator"]
    expires_at: datetime
    teams: tuple[PlatformTeamContext, ...]
    projects: tuple[PlatformProjectContext, ...]
    name: str | None = None
    email: str | None = None


class CurrentPlatformUserSource(Protocol):
    async def resolve(self, *, issuer: str, subject: str) -> ResolvedPlatformUser | None:
        """Use trusted server-to-server Platform owner proof, not HTTP claims."""
        ...

    async def resolve_project(
        self, *, issuer: str, subject: str, project_uuid: UUID
    ) -> ResolvedPlatformUser | None:
        """Read exact current owner membership, independent of inventory size."""
        ...


class CurrentPlatformContext(Protocol):
    async def __call__(
        self, request: Request, project_uuid: UUID | None = None
    ) -> tuple[PanelOidcSession, ResolvedPlatformUser] | JSONResponse: ...


class PlatformMembershipUnavailable(Exception):
    """Trusted current Platform identity/membership proof cannot be obtained."""


def platform_membership_router(
    sessions: OidcBrowserSessionStore,
    *,
    source: CurrentPlatformUserSource | None,
    approval_source: ApprovalManagementPort | None = None,
    catalog_source: TrustedCatalogReadPort | None = None,
    files_content_source: TrustedFilesContentOwner | None = None,
    resource_audience: str | None = None,
    test_only_local_origin: str | None = None,
    expected_issuer: str | None = None,
    expected_client_id: str | None = None,
    management_peer: object | None = None,
) -> APIRouter:
    if (expected_issuer is None) != (expected_client_id is None):
        raise ValueError("OIDC membership realm must bind issuer and client together")
    if expected_issuer is not None and (
        not expected_issuer.startswith("https://") or not expected_client_id
    ):
        raise ValueError("invalid OIDC membership realm")
    expected_host = local_browser_host(test_only_local_origin)
    router = APIRouter()

    def fail(status: int, code: str) -> JSONResponse:
        return JSONResponse({"error": {"code": code}}, status_code=status, headers=_NO_STORE)

    async def current_context(
        request: Request,
        project_uuid: UUID | None = None,
    ) -> tuple[PanelOidcSession, ResolvedPlatformUser] | JSONResponse:
        if expected_host is not None and request.headers.getlist("host") != [expected_host]:
            return fail(403, "LOCAL_OIDC_BROWSER_HOST_MISMATCH")
        handles = _strict_browser_cookies(request)
        sid = handles.get(_SID_COOKIE, "") if handles is not None else ""
        if _TOKEN.fullmatch(sid) is None:
            return fail(401, "OIDC_SESSION_REQUIRED")
        try:
            session = await sessions.get_session(sid)
        except OidcSessionStoreUnavailable:
            return fail(503, "OIDC_SESSION_STORE_UNAVAILABLE")
        if session is None:
            return fail(401, "OIDC_SESSION_EXPIRED")
        if expected_issuer is not None and (
            session.issuer.rstrip("/") != expected_issuer.rstrip("/")
            or session.client_id != expected_client_id
        ):
            try:
                await sessions.delete_session(sid)
            except OidcSessionStoreUnavailable:
                return fail(503, "OIDC_STALE_SESSION_REVOCATION_UNAVAILABLE")
            response = fail(401, "OIDC_SESSION_REALM_MISMATCH")
            response.delete_cookie(
                _SID_COOKIE, path="/", secure=True, httponly=True, samesite="lax"
            )
            return response
        if source is None:
            return fail(503, "PLATFORM_MEMBERSHIP_SOURCE_UNAVAILABLE")
        try:
            if project_uuid is None:
                proof = await source.resolve(issuer=session.issuer, subject=session.subject)
            else:
                if project_uuid.version != 4:
                    return fail(403, "PROJECT_ACCESS_DENIED")
                proof = await source.resolve_project(
                    issuer=session.issuer, subject=session.subject, project_uuid=project_uuid
                )
        except PlatformMembershipUnavailable:
            return fail(503, "PLATFORM_MEMBERSHIP_SOURCE_UNAVAILABLE")
        except Exception:
            # Don't leak owner internals, nor treat an unknown backend error
            # as permission. A peer failure cannot open the Control Panel.
            return fail(503, "PLATFORM_MEMBERSHIP_SOURCE_UNAVAILABLE")
        if proof is None:
            return fail(403, "PLATFORM_MEMBERSHIP_REQUIRED")

        now = datetime.now(UTC)
        if (
            not isinstance(proof, ResolvedPlatformUser)
            or proof.issuer != session.issuer
            or proof.subject != session.subject
            or not isinstance(proof.user_uuid, UUID)
            or proof.user_uuid.version != 4
            or proof.enabled is not True
            or proof.role not in {"user", "operator"}
            or not isinstance(proof.expires_at, datetime)
            or proof.expires_at.tzinfo is None
            or proof.expires_at <= now
            or session.expires_at <= now
            or proof.expires_at > now + _MAX_PROOF_AGE
            or not isinstance(proof.teams, tuple)
            or not isinstance(proof.projects, tuple)
            or len(proof.teams) > _MAX_RELATIONS
            or len(proof.projects) > _MAX_RELATIONS
        ):
            return fail(403, "PLATFORM_MEMBERSHIP_NOT_CURRENT")
        if project_uuid is not None and (
            len(proof.projects) != 1
            or not isinstance(proof.projects[0], PlatformProjectContext)
            or proof.projects[0].project_uuid != project_uuid
            or len(proof.teams) > 1
        ):
            return fail(503, "PLATFORM_MEMBERSHIP_PROOF_INVALID")
        seen_teams: set[UUID] = set()
        for team in proof.teams:
            if (
                not isinstance(team, PlatformTeamContext)
                or not isinstance(team.team_uuid, UUID)
                or team.team_uuid.version != 4
                or team.team_uuid in seen_teams
                or type(team.owner) is not bool
            ):
                return fail(503, "PLATFORM_MEMBERSHIP_PROOF_INVALID")
            seen_teams.add(team.team_uuid)
        seen_projects: set[UUID] = set()
        for project in proof.projects:
            if (
                not isinstance(project, PlatformProjectContext)
                or not isinstance(project.project_uuid, UUID)
                or not isinstance(project.owner_uuid, UUID)
                or project.project_uuid.version != 4
                or project.owner_uuid.version != 4
                or project.project_uuid in seen_projects
                or project.owner_kind not in {"user", "team"}
                or (project.owner_kind == "user" and project.owner_uuid != proof.user_uuid)
                or (project.owner_kind == "team" and project.owner_uuid not in seen_teams)
                or not isinstance(project.permissions, tuple)
                or len(project.permissions) > 2
                or len(set(project.permissions)) != len(project.permissions)
                or any(
                    item not in {"use_resources", "approve_agent_session"}
                    for item in project.permissions
                )
                or (
                    "approve_agent_session" in project.permissions
                    and not (
                        proof.role == "operator"
                        or (project.owner_kind == "user" and project.owner_uuid == proof.user_uuid)
                        or (
                            project.owner_kind == "team"
                            and any(
                                t.team_uuid == project.owner_uuid and t.owner for t in proof.teams
                            )
                        )
                    )
                )
            ):
                return fail(503, "PLATFORM_MEMBERSHIP_PROOF_INVALID")
            seen_projects.add(project.project_uuid)

        return session, proof

    @router.get(AUTH_API_PREFIX + "/me")
    async def current_user(request: Request, project_uuid: UUID | None = None) -> JSONResponse:
        if request.query_params and (
            set(request.query_params) != {"project_uuid"}
            or len(request.query_params.getlist("project_uuid")) != 1
            or project_uuid is None
            or project_uuid.version != 4
            or request.query_params["project_uuid"] != str(project_uuid)
        ):
            return fail(422, "PLATFORM_PROJECT_INVALID")
        context = await current_context(request, project_uuid)
        if isinstance(context, JSONResponse):
            return context
        session, proof = context
        return JSONResponse(
            {
                "authenticated": True,
                "authority": "platform",
                "rauthy": {"issuer": proof.issuer, "subject": proof.subject},
                "user": {
                    "id": str(proof.user_uuid),
                    "role": proof.role,
                    "enabled": True,
                    "name": proof.name,
                    "email": proof.email,
                },
                "teams": [
                    {
                        "id": str(item.team_uuid),
                        "owner": item.owner,
                        "name": item.name,
                    }
                    for item in proof.teams
                ],
                "projects": [
                    {
                        "id": str(item.project_uuid),
                        "name": item.name,
                        "owner": {
                            "kind": item.owner_kind,
                            "id": str(item.owner_uuid),
                        },
                        "permissions": list(item.permissions),
                    }
                    for item in proof.projects
                ],
                "expires_at": min(proof.expires_at, session.expires_at).isoformat(),
            },
            headers=_NO_STORE,
        )

    from ._platform_management import platform_management_router

    router.include_router(
        platform_management_router(
            current_context=current_context,
            peer=management_peer,
            browser_origin=resolve_browser_origin(
                test_origin=test_only_local_origin,
                provider_issuer=expected_issuer,
                provider_client=expected_client_id,
            )
            if expected_issuer
            else PUBLIC_ORIGIN,
        )
    )

    # Imported only after the identity DTO is defined to avoid cyclic
    # module initialization; approval endpoints share the exact same proof.
    from ._oidc_approvals import approval_management_router

    router.include_router(
        approval_management_router(
            current_context=current_context,
            owner=approval_source,
            test_only_local_origin=test_only_local_origin,
        )
    )
    from ._oidc_catalog import oidc_catalog_router

    router.include_router(
        oidc_catalog_router(current_context=current_context, catalog=catalog_source)
    )
    from ._oidc_files_content import files_content_router

    router.include_router(
        files_content_router(
            current_context=current_context,
            sessions=sessions,
            resource_audience=resource_audience,
            expected_client_id=expected_client_id,
            owner=files_content_source,
            test_only_local_origin=test_only_local_origin,
        )
    )
    return router
