"""Platform-owned current Team/Project membership for a verified Rauthy link.

This read model does not authenticate a browser, create User accounts or infer
an internal user UUID from a Rauthy sub. Only a trusted owner-supplied binding
can supply that link; no default binding or public route is installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from sqlalchemy import and_, or_, select

from common.platform_db import PlatformDatabase
from projects._persistence import ProjectRow
from teams._persistence import TeamMembershipRow, TeamRow

_MAX_VISIBLE = 100
_MAX_BINDING_AGE = timedelta(seconds=30)


class PlatformSubjectLinkUnavailable(Exception):
    """No authenticated and current external-subject/Briareus-User authority."""


@dataclass(frozen=True, slots=True)
class CurrentRauthyUserLink:
    issuer: str
    subject: str
    user_id: UUID
    enabled: bool
    role: Literal["user", "operator"]
    revision: int
    expires_at: datetime
    name: str | None = None
    email: str | None = None


class TrustedRauthyUserLinkPort(Protocol):
    async def current_link(self, *, issuer: str, subject: str) -> CurrentRauthyUserLink | None:
        """Fetch authoritative operator-provisioned link, never infer from sub."""
        ...


@dataclass(frozen=True, slots=True)
class PlatformTeamMembership:
    team_id: UUID
    owner: bool
    name: str | None = None


@dataclass(frozen=True, slots=True)
class PlatformProjectMembership:
    project_id: UUID
    owner_kind: Literal["user", "team"]
    owner_id: UUID
    permissions: tuple[Literal["use_resources", "approve_agent_session"], ...]
    name: str | None = None


@dataclass(frozen=True, slots=True)
class CurrentRauthyPlatformMembership:
    issuer: str
    subject: str
    user_id: UUID
    role: Literal["user", "operator"]
    enabled: bool
    expires_at: datetime
    teams: tuple[PlatformTeamMembership, ...]
    projects: tuple[PlatformProjectMembership, ...]
    name: str | None = None
    email: str | None = None


class PlatformOidcMembershipProjection:
    """Read only briareus_platform; no Identity/Access DB, no owner mutation."""

    def __init__(
        self, *, database: PlatformDatabase, subject_links: TrustedRauthyUserLinkPort
    ) -> None:
        if database.engine.url.database != "briareus_platform" or subject_links is None:
            raise ValueError("Platform OIDC projection needs its own DB and signed User link")
        self._db = database
        self._links = subject_links

    async def _current_link(self, *, issuer: str, subject: str) -> CurrentRauthyUserLink | None:
        if not issuer.startswith("https://") or not 1 <= len(subject) <= 256:
            raise PlatformSubjectLinkUnavailable("invalid trusted issuer or subject")
        try:
            link = await self._links.current_link(issuer=issuer, subject=subject)
        except Exception:
            raise PlatformSubjectLinkUnavailable("signed Rauthy subject link unavailable") from None
        if link is None:
            return None
        now = datetime.now(UTC)
        if (
            not isinstance(link, CurrentRauthyUserLink)
            or link.issuer != issuer
            or link.subject != subject
            or not isinstance(link.user_id, UUID)
            or link.user_id.version != 4
            or type(link.revision) is not int
            or link.revision < 1
            or link.role not in {"user", "operator"}
            or type(link.enabled) is not bool
            or not isinstance(link.expires_at, datetime)
            or link.expires_at.tzinfo is None
            or link.expires_at <= now
            or link.expires_at > now + _MAX_BINDING_AGE
        ):
            raise PlatformSubjectLinkUnavailable("signed Rauthy subject link invalid")
        if not link.enabled:
            return None

        return link

    async def resolve(self, *, issuer: str, subject: str) -> CurrentRauthyPlatformMembership | None:
        link = await self._current_link(issuer=issuer, subject=subject)
        if link is None:
            return None

        async with self._db.transaction() as session:
            # Active memberships only. A disabled/suspended User must already
            # be rejected by the signed binding authority, before SQL.
            team_rows = list(
                await session.execute(
                    select(TeamRow, TeamMembershipRow)
                    .join(
                        TeamMembershipRow,
                        TeamMembershipRow.team_id == TeamRow.id,
                    )
                    .where(
                        TeamMembershipRow.user_id == link.user_id,
                        TeamMembershipRow.active.is_(True),
                    )
                    .order_by(TeamRow.id)
                    .limit(_MAX_VISIBLE + 1)
                )
            )
            if len(team_rows) > _MAX_VISIBLE:
                raise PlatformSubjectLinkUnavailable("Team membership projection over limit")
            teams = tuple(
                PlatformTeamMembership(
                    team_id=team.id,
                    owner=team.owner_user_id == link.user_id,
                    name=team.name,
                )
                for team, member in team_rows
            )
            team_ids = tuple(item.team_id for item in teams)
            project_owner_filter = ProjectRow.owner_user_id == link.user_id
            if team_ids:
                project_owner_filter = or_(
                    project_owner_filter,
                    ProjectRow.owner_team_id.in_(team_ids),
                )
            projects = list(
                await session.scalars(
                    select(ProjectRow)
                    .where(
                        project_owner_filter,
                        ProjectRow.lifecycle_status == "active",
                    )
                    .order_by(ProjectRow.id)
                    .limit(_MAX_VISIBLE + 1)
                )
            )
            if len(projects) > _MAX_VISIBLE:
                raise PlatformSubjectLinkUnavailable("Project projection over limit")
            team_by_id = {item.team_id: item for item in teams}
            result: list[PlatformProjectMembership] = []
            for project in projects:
                personal = project.owner_user_id == link.user_id
                if personal:
                    owner_kind: Literal["user", "team"] = "user"
                    owner_id = link.user_id
                    approve = True
                elif project.owner_team_id in team_by_id:
                    owner_kind = "team"
                    owner_id = project.owner_team_id
                    approve = team_by_id[owner_id].owner
                else:
                    raise PlatformSubjectLinkUnavailable("foreign Project in own DB projection")
                result.append(
                    PlatformProjectMembership(
                        project_id=project.id,
                        name=project.name,
                        owner_kind=owner_kind,
                        owner_id=owner_id,
                        permissions=(
                            ("use_resources", "approve_agent_session")
                            if approve
                            else ("use_resources",)
                        ),
                    )
                )

        # Ensure one trusted snapshot is still time-bounded after SQL.
        if link.expires_at <= datetime.now(UTC):
            raise PlatformSubjectLinkUnavailable("Rauthy User binding expired during read")
        return CurrentRauthyPlatformMembership(
            issuer=issuer,
            subject=subject,
            user_id=link.user_id,
            role=link.role,
            enabled=True,
            expires_at=link.expires_at,
            teams=teams,
            projects=tuple(result),
            name=link.name,
            email=link.email,
        )

    async def resolve_project(
        self, *, issuer: str, subject: str, project_uuid: UUID
    ) -> CurrentRauthyPlatformMembership | None:
        """Address one Project and its current membership in one own-DB SELECT.

        Inventory limits never determine access. The User link remains a
        separate current authority; SQL returns no unrelated Team/Project.
        """
        if not isinstance(project_uuid, UUID) or project_uuid.version != 4:
            raise PlatformSubjectLinkUnavailable("invalid exact Project selector")
        link = await self._current_link(issuer=issuer, subject=subject)
        if link is None:
            return None
        async with self._db.transaction() as session:
            row = (
                await session.execute(
                    select(ProjectRow, TeamRow, TeamMembershipRow)
                    .outerjoin(TeamRow, TeamRow.id == ProjectRow.owner_team_id)
                    .outerjoin(
                        TeamMembershipRow,
                        and_(
                            TeamMembershipRow.team_id == TeamRow.id,
                            TeamMembershipRow.user_id == link.user_id,
                            TeamMembershipRow.active.is_(True),
                        ),
                    )
                    .where(
                        ProjectRow.id == project_uuid,
                        ProjectRow.lifecycle_status == "active",
                        or_(
                            ProjectRow.owner_user_id == link.user_id,
                            TeamMembershipRow.user_id == link.user_id,
                        ),
                    )
                )
            ).one_or_none()
            if row is None:
                return None
            project, team, member = row
            teams: tuple[PlatformTeamMembership, ...] = ()
            if project.owner_user_id == link.user_id and project.owner_team_id is None:
                owner_kind: Literal["user", "team"] = "user"
                owner_id = link.user_id
                approve = True
            elif (
                project.owner_user_id is None
                and team is not None
                and member is not None
                and team.id == project.owner_team_id == member.team_id
                and member.user_id == link.user_id
                and member.active is True
            ):
                owner_kind = "team"
                owner_id = team.id
                approve = team.owner_user_id == link.user_id
                teams = (PlatformTeamMembership(team.id, approve, team.name),)
            else:
                raise PlatformSubjectLinkUnavailable("exact Project owner scope invalid")
            membership = PlatformProjectMembership(
                project_id=project.id,
                name=project.name,
                owner_kind=owner_kind,
                owner_id=owner_id,
                permissions=(
                    ("use_resources", "approve_agent_session") if approve else ("use_resources",)
                ),
            )
        if link.expires_at <= datetime.now(UTC):
            raise PlatformSubjectLinkUnavailable("Rauthy User binding expired during exact read")
        return CurrentRauthyPlatformMembership(
            issuer=issuer,
            subject=subject,
            user_id=link.user_id,
            role=link.role,
            enabled=True,
            expires_at=link.expires_at,
            teams=teams,
            projects=(membership,),
            name=link.name,
            email=link.email,
        )
