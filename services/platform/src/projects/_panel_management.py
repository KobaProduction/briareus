"""Human Platform administration over the authenticated Panel peer only.

Rauthy remains the profile/credential authority. Only the Platform operator
can link an existing provider account; no provider roles become app roles.
Writes, idempotency evidence, audit and outbox commit in one owner transaction.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import select, text

from common.platform_db import PlatformDatabase
from teams._persistence import TeamMembershipRow, TeamRow

from ._control_ledger import OwnerAuditRow, OwnerOutboxRow
from ._oidc_context_api import PanelContextNotAuthenticated
from ._persistence import ProjectRow
from ._rauthy_user_links import RauthyUserLinkRow
from ._rauthy_user_status import _ID, CurrentRauthyUserStatusReader

Action = Literal[
    "inventory",
    "team.create",
    "team.rename",
    "team.member.add",
    "team.member.remove",
    "project.create",
    "project.rename",
    "user.link",
]
HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class ManagementQuery(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    issuer: str = Field(min_length=12, max_length=512)
    subject: str = Field(min_length=1, max_length=256)
    operation_uuid: UUID
    action: Action
    data: dict[str, object] = Field(default_factory=dict, max_length=6)

    @field_validator("operation_uuid")
    @classmethod
    def operation_v4(cls, value: UUID) -> UUID:
        if value.version != 4:
            raise ValueError("Operation must be UUIDv4")
        return value


class ManagementError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code


def identifier(value: object) -> UUID:
    try:
        result = UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise ManagementError(422, "INVALID_IDENTIFIER") from None
    if result.version != 4 or str(result) != value:
        raise ManagementError(422, "INVALID_IDENTIFIER")
    return result


def name(value: object) -> str:
    if not isinstance(value, str):
        raise ManagementError(422, "NAME_REQUIRED")
    result = value.strip()
    if not 1 <= len(result) <= 255 or any(ord(c) < 32 or ord(c) == 127 for c in result):
        raise ManagementError(422, "NAME_INVALID")
    return result


def fingerprint(payload: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


class PlatformAdministration:
    def __init__(self, database: PlatformDatabase, projection: object, provider: object) -> None:
        self.db, self.projection, self.provider = database, projection, provider
        self.status = CurrentRauthyUserStatusReader(private_transport=provider)

    async def profile(self, issuer: str, subject: str) -> dict[str, object]:
        status = await self.status.current_status(issuer=issuer, subject=subject)
        return {"name": status.name, "email": status.email, "enabled": status.active}

    async def execute(self, query: ManagementQuery, deadline: datetime) -> dict[str, object]:
        actor = await self.projection.resolve(issuer=query.issuer, subject=query.subject)
        if actor is None or actor.role != "operator":
            raise ManagementError(403, "PLATFORM_OPERATOR_REQUIRED")
        deadline = min(deadline, actor.expires_at)
        if query.action == "inventory":
            if query.data:
                raise ManagementError(422, "COMMAND_FIELDS_INVALID")
            async with self.db.transaction() as tx:
                users = list(
                    await tx.scalars(
                        select(RauthyUserLinkRow)
                        .where(RauthyUserLinkRow.issuer == query.issuer)
                        .order_by(RauthyUserLinkRow.user_id)
                        .limit(101)
                    )
                )
                teams = list(
                    await tx.scalars(select(TeamRow).order_by(TeamRow.name, TeamRow.id).limit(101))
                )
                projects = list(
                    await tx.scalars(
                        select(ProjectRow)
                        .where(ProjectRow.lifecycle_status == "active")
                        .order_by(ProjectRow.name, ProjectRow.id)
                        .limit(101)
                    )
                )
                members = list(
                    await tx.scalars(
                        select(TeamMembershipRow)
                        .where(
                            TeamMembershipRow.team_id.in_([t.id for t in teams[:100]]),
                            TeamMembershipRow.active.is_(True),
                        )
                        .limit(1001)
                    )
                )
            gate = asyncio.Semaphore(8)

            async def describe(user: RauthyUserLinkRow) -> dict[str, object]:
                async with gate:
                    profile = await self.profile(query.issuer, user.subject)
                    return {
                        "id": str(user.user_id),
                        "role": user.briareus_role,
                        "enabled": user.active and profile["enabled"],
                        "name": profile["name"],
                        "email": profile["email"],
                    }

            async with asyncio.timeout(6):
                people = await asyncio.gather(*(describe(u) for u in users[:100]))
            if datetime.now(UTC) >= deadline:
                raise ManagementError(503, "PLATFORM_AUTHORITY_EXPIRED")
            return {
                "users": people,
                "teams": [
                    {
                        "id": str(t.id),
                        "name": t.name,
                        "owner_user_id": str(t.owner_user_id),
                        "member_ids": [str(m.user_id) for m in members[:1000] if m.team_id == t.id],
                    }
                    for t in teams[:100]
                ],
                "projects": [
                    {
                        "id": str(p.id),
                        "name": p.name,
                        "owner_user_id": str(p.owner_user_id) if p.owner_user_id else None,
                        "owner_team_id": str(p.owner_team_id) if p.owner_team_id else None,
                    }
                    for p in projects[:100]
                ],
                "truncated": len(users) > 100
                or len(teams) > 100
                or len(projects) > 100
                or len(members) > 1000,
            }

        fields = {
            "team.create": {"name"},
            "team.rename": {"id", "expected_name", "name"},
            "team.member.add": {"id", "user_id"},
            "team.member.remove": {"id", "user_id"},
            "project.create": {"name", "team_id"},
            "project.rename": {"id", "expected_name", "name"},
            "user.link": {"email"},
        }
        if set(query.data) != fields[query.action]:
            raise ManagementError(422, "COMMAND_FIELDS_INVALID")
        digest = fingerprint(query.model_dump(mode="json"))
        async with self.db.transaction() as tx:
            await tx.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:operation, 0))"),
                {"operation": str(query.operation_uuid)},
            )
            link = await tx.get(RauthyUserLinkRow, actor.user_id, with_for_update=True)
            if (
                link is None
                or not link.active
                or link.briareus_role != "operator"
                or link.version < 1
            ):
                raise ManagementError(403, "PLATFORM_OPERATOR_REQUIRED")
            previous = await tx.get(OwnerAuditRow, query.operation_uuid)
            if previous is not None:
                if (
                    previous.actor_user_id != actor.user_id
                    or previous.details.get("fingerprint") != digest
                ):
                    raise ManagementError(409, "OPERATION_CONFLICT")
                if datetime.now(UTC) >= deadline:
                    raise ManagementError(503, "PLATFORM_AUTHORITY_EXPIRED")
                return previous.details["outcome"]

            provider_user = None
            if query.action == "user.link":
                email = name(query.data["email"])
                response = await self.provider.read_by_email(email=email)
                if response.status == 404:
                    raise ManagementError(404, "RAUTHY_USER_NOT_FOUND")
                if response.status != 200:
                    raise ManagementError(503, "RAUTHY_USER_LOOKUP_UNAVAILABLE")
                document = json.loads(response.body)
                subject = document.get("id")
                if not isinstance(subject, str) or _ID.fullmatch(subject) is None:
                    raise ManagementError(503, "RAUTHY_USER_INVALID")
                provider_user = await self.status.current_status(
                    issuer=query.issuer, subject=subject
                )
                if (
                    not provider_user.active
                    or not provider_user.email
                    or provider_user.email.casefold() != email.casefold()
                ):
                    raise ManagementError(409, "RAUTHY_USER_NOT_ACTIVE")
                deadline = min(deadline, provider_user.expires_at)

            data = query.data
            outcome: dict[str, object]
            if query.action == "team.create":
                team = TeamRow(
                    id=uuid4(),
                    name=name(data["name"]),
                    owner_user_id=actor.user_id,
                    resource_revision=0,
                )
                tx.add(team)
                await tx.flush()
                tx.add(
                    TeamMembershipRow(
                        id=uuid4(), team_id=team.id, user_id=actor.user_id, active=True
                    )
                )
                outcome = {"id": str(team.id), "name": team.name}
            elif query.action.startswith("team."):
                team = await tx.get(TeamRow, identifier(data["id"]), with_for_update=True)
                if team is None:
                    raise ManagementError(404, "TEAM_NOT_FOUND")
                if query.action == "team.rename":
                    if data["expected_name"] != team.name:
                        raise ManagementError(409, "NAME_CHANGED")
                    team.name = name(data["name"])
                else:
                    user_id = identifier(data["user_id"])
                    target = await tx.get(RauthyUserLinkRow, user_id)
                    if target is None or not target.active or target.issuer != query.issuer:
                        raise ManagementError(404, "USER_NOT_FOUND")
                    if query.action == "team.member.remove" and user_id == team.owner_user_id:
                        raise ManagementError(409, "TEAM_OWNER_REQUIRED")
                    member = await tx.scalar(
                        select(TeamMembershipRow)
                        .where(
                            TeamMembershipRow.team_id == team.id,
                            TeamMembershipRow.user_id == user_id,
                        )
                        .with_for_update()
                    )
                    active = query.action == "team.member.add"
                    if member is None:
                        if not active:
                            raise ManagementError(404, "MEMBER_NOT_FOUND")
                        tx.add(
                            TeamMembershipRow(
                                id=uuid4(), team_id=team.id, user_id=user_id, active=True
                            )
                        )
                    else:
                        member.active = active
                    team.resource_revision += 1
                outcome = {"id": str(team.id), "name": team.name}
            elif query.action == "project.create":
                team_id = identifier(data["team_id"]) if data["team_id"] is not None else None
                if (
                    team_id is not None
                    and await tx.get(TeamRow, team_id, with_for_update=True) is None
                ):
                    raise ManagementError(404, "TEAM_NOT_FOUND")
                project = ProjectRow(
                    id=uuid4(),
                    name=name(data["name"]),
                    lifecycle_status="active",
                    owner_user_id=actor.user_id if team_id is None else None,
                    owner_team_id=team_id,
                    resource_revision=0,
                )
                tx.add(project)
                outcome = {"id": str(project.id), "name": project.name}
            elif query.action == "project.rename":
                project = await tx.get(ProjectRow, identifier(data["id"]), with_for_update=True)
                if project is None or project.lifecycle_status != "active":
                    raise ManagementError(404, "PROJECT_NOT_FOUND")
                if data["expected_name"] != project.name:
                    raise ManagementError(409, "NAME_CHANGED")
                project.name = name(data["name"])
                outcome = {"id": str(project.id), "name": project.name}
            else:
                target = await tx.scalar(
                    select(RauthyUserLinkRow).where(
                        RauthyUserLinkRow.issuer == query.issuer,
                        RauthyUserLinkRow.subject == provider_user.subject,
                    )
                )
                if target is None:
                    now = datetime.now(UTC)
                    target = RauthyUserLinkRow(
                        user_id=uuid4(),
                        issuer=query.issuer,
                        subject=provider_user.subject,
                        briareus_role="user",
                        active=True,
                        version=1,
                        created_at=now,
                        updated_at=now,
                    )
                    tx.add(target)
                elif not target.active:
                    raise ManagementError(409, "USER_SUSPENDED")
                outcome = {"id": str(target.user_id), "name": provider_user.name}
            tx.add(
                OwnerAuditRow(
                    id=query.operation_uuid,
                    operation_uuid=query.operation_uuid,
                    actor_user_id=actor.user_id,
                    project_id=None,
                    action="panel." + query.action,
                    object_id=outcome["id"],
                    owner_revision="panel-management-v1",
                    details={"fingerprint": digest, "outcome": outcome},
                )
            )
            tx.add(
                OwnerOutboxRow(
                    operation_uuid=query.operation_uuid,
                    event_name="panel." + query.action,
                    owner_revision="panel-management-v1",
                    event_payload={"id": outcome["id"]},
                )
            )
            await tx.flush()
            if datetime.now(UTC) >= deadline:
                raise ManagementError(503, "PLATFORM_AUTHORITY_EXPIRED")
        if datetime.now(UTC) >= deadline:
            raise ManagementError(503, "OPERATION_OUTCOME_UNKNOWN")
        return outcome


def management_router(resolve_service: object, authority: object) -> APIRouter:
    router = APIRouter()

    @router.post("/internal/v1/platform/manage", include_in_schema=False)
    async def manage(request: Request) -> JSONResponse:
        try:
            service = resolve_service()
            if service is None or authority is None:
                raise ManagementError(503, "PLATFORM_MANAGEMENT_UNAVAILABLE")
            if (
                request.scope.get("briareus.unix_peer_uid") != 1001
                or request.headers.getlist("cookie")
                or len(request.headers.getlist("authorization")) != 1
            ):
                raise ManagementError(401, "PLATFORM_SERVICE_PROOF_REQUIRED")
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 8192:
                    raise ManagementError(413, "COMMAND_TOO_LARGE")
            query = ManagementQuery.model_validate_json(body)
            deadline = await authority.verify_management(request, query.model_dump(mode="json"))
            result = await service.execute(query, deadline)
            return JSONResponse(result, headers=HEADERS)
        except ManagementError as error:
            return JSONResponse(
                {"error": {"code": error.code}}, status_code=error.status, headers=HEADERS
            )
        except PanelContextNotAuthenticated:
            return JSONResponse(
                {"error": {"code": "PLATFORM_SERVICE_PROOF_REQUIRED"}},
                status_code=401,
                headers=HEADERS,
            )
        except ValidationError:
            return JSONResponse(
                {"error": {"code": "COMMAND_INVALID"}}, status_code=422, headers=HEADERS
            )
        except Exception:
            return JSONResponse(
                {"error": {"code": "PLATFORM_MANAGEMENT_UNAVAILABLE"}},
                status_code=503,
                headers=HEADERS,
            )

    return router
