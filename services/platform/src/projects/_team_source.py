"""Team-owner-only membership and ownership transitions, without a fake Project.

Team state is atomic in briareus_platform. Target User enabled status comes
from a fresh Identity-signed receipt and is rechecked before transaction end.
Source is NOT publicly mounted before C1-B2/C2 reviewer approval.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from common.owner_team_contracts import (
    CurrentTeamOwnerPort,
    SignedTeamProofs,
    TeamOwnerCommandDTO,
    TeamOwnerProofAuthority,
    VerifiedTeamOperation,
    require_current_team,
)
from common.owner_transactions import OwnerCommandOutcome
from common.platform_db import PlatformDatabase
from common.platform_errors import AccessDenied, Conflict, InvalidInput
from projects._control_ledger import OwnerAuditRow, OwnerCommandRow, OwnerOutboxRow
from projects._current_state import team_state
from teams._persistence import TeamMembershipRow, TeamRow


class TeamOwnerSource:
    def __init__(
        self,
        db: PlatformDatabase,
        authority: TeamOwnerProofAuthority,
        current: CurrentTeamOwnerPort,
        *,
        encryption_key: SecretStr,
    ) -> None:
        if db.engine.url.database != "briareus_platform" or current is None:
            raise RuntimeError("Team membership must have its own Control database and trust")
        self.db = db
        self.authority = authority
        self.current = current
        self.cipher = Fernet(encryption_key.get_secret_value().encode())

    async def _live(
        self, request: TeamOwnerCommandDTO, proofs: SignedTeamProofs
    ) -> VerifiedTeamOperation:
        initial = self.authority.verify(request, proofs)
        live = await require_current_team(self.authority, self.current, request)
        if (
            initial.actor_role != live.actor_role
            or initial.identity_epoch != live.identity_epoch
            or initial.team_epoch != live.team_epoch
            or initial.access_epoch != live.access_epoch
        ):
            raise AccessDenied("Team current User/owner authority was revoked")
        return live

    async def _target_enabled(self, request: TeamOwnerCommandDTO, target_id: UUID) -> int:
        try:
            import asyncio

            async with asyncio.timeout(3):
                receipt = await self.current.fetch_target_identity(request, target_id)
            return self.authority.verify_target(request, target_id, receipt)
        except Exception:
            raise AccessDenied("target User is not currently signed as active") from None

    async def _status(
        self, request: TeamOwnerCommandDTO, proofs: SignedTeamProofs
    ) -> OwnerCommandOutcome | None:
        await self._live(request, proofs)
        async with self.db.transaction() as tx:
            row = await tx.scalar(
                select(OwnerCommandRow)
                .where(
                    OwnerCommandRow.actor_scope == str(request.caller_user_id),
                    OwnerCommandRow.project_scope == f"team:{request.team_id}",
                    OwnerCommandRow.operation == request.operation,
                    OwnerCommandRow.key == request.idempotency_key,
                )
                .with_for_update()
            )
            if row is None:
                return None
            if (
                row.operation_uuid != request.operation_uuid
                or row.fingerprint != request.payload_sha256
            ):
                raise Conflict("Team command key reused with different signed payload")
            if row.state in {"pending", "unknown"}:
                return OwnerCommandOutcome(row.operation_uuid, "UNKNOWN", None)
            if row.state != "completed" or row.encrypted_outcome is None:
                raise Conflict("Team operation is not verified as completed")
            try:
                body = json.loads(self.cipher.decrypt(row.encrypted_outcome.encode()))
                if not isinstance(body, dict):
                    raise ValueError("non-object command result")
            except (InvalidToken, UnicodeDecodeError, ValueError, TypeError):
                raise Conflict("Team original encrypted command result unavailable") from None
            return OwnerCommandOutcome(row.operation_uuid, "COMMITTED", body)

    async def _execute(
        self,
        request: TeamOwnerCommandDTO,
        proofs: SignedTeamProofs,
        mutation: Callable[[AsyncSession, VerifiedTeamOperation], Awaitable[dict[str, object]]],
        *,
        event: str,
        subject: UUID,
    ) -> OwnerCommandOutcome:
        decision = await self._live(request, proofs)
        try:
            async with self.db.transaction() as tx:
                await tx.execute(
                    text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                    {"scope": f"briareus:platform:{request.operation_uuid}"},
                )
                previous_phases = list(
                    await tx.scalars(
                        select(OwnerCommandRow)
                        .where(
                            OwnerCommandRow.operation_uuid == request.operation_uuid,
                        )
                        .with_for_update()
                    )
                )
                for phase_row in previous_phases:
                    if (
                        phase_row.actor_scope != str(request.caller_user_id)
                        or phase_row.project_scope != f"team:{request.team_id}"
                        or phase_row.key != request.idempotency_key
                    ):
                        raise AccessDenied("Team original UUID must retain actor, Team and key")
                    if phase_row.operation != request.operation and phase_row.state != "completed":
                        raise AccessDenied("Team phase cannot bypass unresolved previous command")
                row = await tx.scalar(
                    select(OwnerCommandRow)
                    .where(
                        OwnerCommandRow.actor_scope == str(request.caller_user_id),
                        OwnerCommandRow.project_scope == f"team:{request.team_id}",
                        OwnerCommandRow.operation == request.operation,
                        OwnerCommandRow.key == request.idempotency_key,
                    )
                    .with_for_update()
                )
                if row is not None:
                    if (
                        row.fingerprint != request.payload_sha256
                        or row.operation_uuid != request.operation_uuid
                    ):
                        raise Conflict("Team Idempotency-Key has a different original intent")
                    if row.state in {"pending", "unknown"}:
                        return OwnerCommandOutcome(row.operation_uuid, "UNKNOWN", None)
                    if row.state != "completed" or row.encrypted_outcome is None:
                        raise Conflict("Team original command has no completed outcome")
                    try:
                        replay = json.loads(self.cipher.decrypt(row.encrypted_outcome.encode()))
                        if not isinstance(replay, dict):
                            raise ValueError("non-object result")
                    except (InvalidToken, UnicodeDecodeError, ValueError, TypeError):
                        raise Conflict("Team original encrypted result unavailable") from None
                    return OwnerCommandOutcome(row.operation_uuid, "COMMITTED", replay)
                row = OwnerCommandRow(
                    operation_uuid=request.operation_uuid,
                    actor_scope=str(request.caller_user_id),
                    project_scope=f"team:{request.team_id}",
                    operation=request.operation,
                    key=request.idempotency_key,
                    fingerprint=request.payload_sha256,
                    expected_owner_revision=str(request.expected_team_revision),
                    state="pending",
                    expires_at=datetime.now(UTC) + timedelta(days=7),
                )
                tx.add(row)
                await tx.flush()
                result = await mutation(tx, decision)
                verified = await require_current_team(self.authority, self.current, request)
                if (
                    verified.identity_epoch != decision.identity_epoch
                    or verified.team_epoch != decision.team_epoch
                    or verified.access_epoch != decision.access_epoch
                    or verified.actor_role != decision.actor_role
                ):
                    raise AccessDenied("Team source owner version changed before commit")
                row.state = "completed"
                row.updated_at = datetime.now(UTC)
                row.encrypted_outcome = self.cipher.encrypt(
                    json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
                ).decode()
                tx.add(
                    OwnerOutboxRow(
                        operation_uuid=request.operation_uuid,
                        event_name=event,
                        owner_revision=str(request.expected_team_revision),
                        event_payload={
                            "team_id": str(request.team_id),
                            "actor_user_id": str(request.caller_user_id),
                            "subject_id": str(subject),
                            "operation_uuid": str(request.operation_uuid),
                        },
                    )
                )
                tx.add(
                    OwnerAuditRow(
                        operation_uuid=request.operation_uuid,
                        actor_user_id=request.caller_user_id,
                        project_id=None,
                        action=event,
                        object_id=str(subject),
                        owner_revision=str(request.expected_team_revision),
                        details={
                            "team_id": str(request.team_id),
                            "operation_uuid": str(request.operation_uuid),
                        },
                    )
                )
                return OwnerCommandOutcome(request.operation_uuid, "COMMITTED", result)
        except IntegrityError:
            previous = await self._status(request, proofs)
            if previous is None:
                raise
            return previous

    @staticmethod
    async def _owner_team(
        tx: AsyncSession,
        command: TeamOwnerCommandDTO,
        decision: VerifiedTeamOperation,
    ) -> TeamRow:
        team = await tx.scalar(
            select(TeamRow).where(TeamRow.id == command.team_id).with_for_update()
        )
        if team is None or team_state(team) != command.expected_team_revision:
            raise Conflict("Team owner revision does not match signed current authority")
        if decision.actor_role != "superuser" and team.owner_user_id != command.caller_user_id:
            raise AccessDenied("only current Team owner may manage Team membership")
        return team

    async def add_member(
        self, command: TeamOwnerCommandDTO, proofs: SignedTeamProofs, *, target: UUID
    ) -> OwnerCommandOutcome:
        if command.operation != "team.member.add" or target.version != 4:
            raise InvalidInput("Team add-member requires signed active User UUID")
        self.authority.check_payload(command, {"target_user_id": str(target)})
        target_revision = await self._target_enabled(command, target)

        async def mutation(tx: AsyncSession, decision: VerifiedTeamOperation) -> dict[str, object]:
            team = await self._owner_team(tx, command, decision)
            if await self._target_enabled(command, target) != target_revision:
                raise AccessDenied("target Identity revision changed before Team membership commit")
            member = await tx.scalar(
                select(TeamMembershipRow)
                .where(
                    TeamMembershipRow.team_id == team.id,
                    TeamMembershipRow.user_id == target,
                )
                .with_for_update()
            )
            if member is None:
                member = TeamMembershipRow(team_id=team.id, user_id=target, active=True)
                tx.add(member)
            elif member.active:
                raise Conflict("Team member already active")
            else:
                member.active = True
            team.resource_revision += 1
            return {
                "team_id": str(team.id),
                "member_user_id": str(target),
                "state": format(team_state(team), "064x"),
                "resource_revision": team.resource_revision,
                "active": True,
            }

        return await self._execute(
            command, proofs, mutation, event="team.member_added", subject=target
        )

    async def remove_member(
        self, command: TeamOwnerCommandDTO, proofs: SignedTeamProofs, *, target: UUID
    ) -> OwnerCommandOutcome:
        if command.operation != "team.member.remove" or target.version != 4:
            raise InvalidInput("Team remove-member requires original User UUID")
        self.authority.check_payload(command, {"target_user_id": str(target)})

        async def mutation(tx: AsyncSession, decision: VerifiedTeamOperation) -> dict[str, object]:
            team = await self._owner_team(tx, command, decision)
            if team.owner_user_id == target:
                raise AccessDenied("current Team owner cannot be removed")
            member = await tx.scalar(
                select(TeamMembershipRow)
                .where(
                    TeamMembershipRow.team_id == team.id,
                    TeamMembershipRow.user_id == target,
                )
                .with_for_update()
            )
            if member is None or not member.active:
                raise Conflict("Team membership is already inactive or absent")
            member.active = False
            team.resource_revision += 1
            return {
                "team_id": str(team.id),
                "member_user_id": str(target),
                "state": format(team_state(team), "064x"),
                "resource_revision": team.resource_revision,
                "active": False,
            }

        return await self._execute(
            command, proofs, mutation, event="team.member_removed", subject=target
        )

    async def transfer_owner(
        self,
        command: TeamOwnerCommandDTO,
        proofs: SignedTeamProofs,
        *,
        target: UUID,
        confirmed: bool,
    ) -> OwnerCommandOutcome:
        if command.operation != "team.owner.transfer" or target.version != 4 or not confirmed:
            raise InvalidInput("Team owner transfer needs current User and explicit confirmation")
        self.authority.check_payload(command, {"target_user_id": str(target), "confirmed": True})
        target_revision = await self._target_enabled(command, target)

        async def mutation(tx: AsyncSession, decision: VerifiedTeamOperation) -> dict[str, object]:
            team = await self._owner_team(tx, command, decision)
            if team.owner_user_id == target:
                raise Conflict("target is already Team owner")
            member = await tx.scalar(
                select(TeamMembershipRow)
                .where(
                    TeamMembershipRow.team_id == team.id,
                    TeamMembershipRow.user_id == target,
                    TeamMembershipRow.active.is_(True),
                )
                .with_for_update()
            )
            if member is None or await self._target_enabled(command, target) != target_revision:
                raise AccessDenied("Team successor must be currently active Identity and member")
            team.owner_user_id = target
            team.resource_revision += 1
            return {
                "team_id": str(team.id),
                "owner_user_id": str(target),
                "state": format(team_state(team), "064x"),
                "resource_revision": team.resource_revision,
            }

        return await self._execute(
            command, proofs, mutation, event="team.owner_transferred", subject=target
        )
