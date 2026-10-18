"""Control DB-local, source-verified Project/Agent operations.

Business SQL never joins Identity, Access, Resource Catalog or provider data.
Identity+Control+Access current signed proofs are checked by trusted private
source before this service; C1-B2/C2 public endpoint activation remains off.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents._persistence import AgentIdentityRow
from common.owner_contracts import (
    SignedOwnerProofs,
    VerifiedOwnerOperation,
    require_signed_payload,
)
from common.owner_transactions import OwnerCommandOutcome, OwnerLocalCommandExecutor
from common.platform_db import PlatformDatabase
from common.platform_errors import AccessDenied, Conflict, InvalidInput
from projects._current_state import project_state
from projects._persistence import ProjectRow
from teams._persistence import TeamMembershipRow, TeamRow


@dataclass(frozen=True, slots=True)
class VerifiedProjectDeleteImpact:
    owner: Literal["resources", "files", "runtime", "reverse"]
    project_id: UUID
    fenced_control_revision: int
    zero_active_effects: bool
    observed_at: datetime
    receipt_digest: str


class TrustedProjectDeleteImpactPort(Protocol):
    async def verify_current_impact(
        self,
        *,
        project_id: UUID,
        fenced_control_revision: int,
        owner: Literal["resources", "files", "runtime", "reverse"],
    ) -> VerifiedProjectDeleteImpact:
        """Signed owner-state attestation; MUST reject stale Control fences."""
        ...


class ControlSourceService:
    def __init__(
        self,
        database: PlatformDatabase,
        commands: OwnerLocalCommandExecutor,
        *,
        delete_impact: TrustedProjectDeleteImpactPort | None = None,
    ) -> None:
        if database.engine.url.database != "briareus_platform" or commands.owner != "platform":
            raise RuntimeError("Control service cannot use a shared or foreign database")
        self.database = database
        self.commands = commands
        self.delete_impact = delete_impact

    @staticmethod
    async def _project(tx: AsyncSession, decision: VerifiedOwnerOperation) -> ProjectRow:
        request = decision.request
        row = await tx.scalar(
            select(ProjectRow).where(ProjectRow.id == request.project_id).with_for_update()
        )
        if (
            row is None
            or project_state(row) != request.expected_control_revision
            or row.lifecycle_status != "active"
        ):
            raise Conflict("active Project ownership revision unavailable or changed")
        return row

    @staticmethod
    async def _authorized_member(
        tx: AsyncSession, decision: VerifiedOwnerOperation, project: ProjectRow
    ) -> bool:
        if project.lifecycle_status != "active":
            return False
        actor = decision.request.caller_user_id
        if decision.actor_role == "superuser":
            return True
        if project.owner_user_id is not None:
            return project.owner_user_id == actor
        if project.owner_team_id is None:
            return False
        member = await tx.scalar(
            select(TeamMembershipRow.id)
            .where(
                TeamMembershipRow.team_id == project.owner_team_id,
                TeamMembershipRow.user_id == actor,
                TeamMembershipRow.active.is_(True),
            )
            .with_for_update()
        )
        return member is not None

    async def move_personal_to_team(
        self, decision: VerifiedOwnerOperation, proofs: SignedOwnerProofs, *, team_id: UUID
    ) -> OwnerCommandOutcome:
        if decision.request.operation != "project.transfer_to_team" or team_id.version != 4:
            raise InvalidInput("transfer requires reviewed Project and Team UUID")
        require_signed_payload(decision.request, {"team_id": str(team_id)})

        async def mutate(tx: AsyncSession) -> dict[str, object]:
            project = await self._project(tx, decision)
            actor = decision.request.caller_user_id
            if project.owner_user_id != actor and decision.actor_role != "superuser":
                raise AccessDenied("only personal Project owner may move a Project")
            if project.owner_team_id is not None:
                raise Conflict("Team Project cannot be inserted into another Team")
            team = await tx.get(TeamRow, team_id, with_for_update=True)
            membership = await tx.scalar(
                select(TeamMembershipRow.id)
                .where(
                    TeamMembershipRow.team_id == team_id,
                    TeamMembershipRow.user_id == actor,
                    TeamMembershipRow.active.is_(True),
                )
                .with_for_update()
            )
            if team is None or membership is None:
                raise AccessDenied("recipient Team current membership unavailable")
            project.owner_user_id = None
            project.owner_team_id = team_id
            project.resource_revision += 1
            return {
                "project_id": str(project.id),
                "owner_team_id": str(team_id),
                "state": format(project_state(project), "064x"),
                "resource_revision": project.resource_revision,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="project.transferred_to_team",
            target=str(decision.request.project_id),
        )

    async def withdraw_team_project(
        self, decision: VerifiedOwnerOperation, proofs: SignedOwnerProofs
    ) -> OwnerCommandOutcome:
        if decision.request.operation != "project.withdraw_from_team":
            raise InvalidInput("unexpected operation")
        require_signed_payload(decision.request, {})

        async def mutate(tx: AsyncSession) -> dict[str, object]:
            project = await self._project(tx, decision)
            if project.owner_team_id is None:
                raise Conflict("Project is not Team-owned")
            team = await tx.get(TeamRow, project.owner_team_id, with_for_update=True)
            if team is None or (
                team.owner_user_id != decision.request.caller_user_id
                and decision.actor_role != "superuser"
            ):
                raise AccessDenied("only current Team owner can withdraw Project")
            project.owner_user_id = team.owner_user_id
            project.owner_team_id = None
            project.resource_revision += 1
            return {
                "project_id": str(project.id),
                "owner_user_id": str(team.owner_user_id),
                "state": format(project_state(project), "064x"),
                "resource_revision": project.resource_revision,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutate,
            event="project.withdrawn_from_team",
            target=str(decision.request.project_id),
        )

    async def create_agent(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        *,
        name: str,
        parent_agent_id: UUID | None = None,
    ) -> OwnerCommandOutcome:
        if (
            decision.request.operation != "agent.create"
            or not (1 <= len(name.strip()) <= 255)
            or (parent_agent_id is not None and parent_agent_id.version != 4)
        ):
            raise InvalidInput("invalid AgentIdentity command")
        require_signed_payload(
            decision.request,
            {
                "name": name.strip(),
                "parent_agent_id": str(parent_agent_id) if parent_agent_id else None,
            },
        )

        async def mutate(tx: AsyncSession) -> dict[str, object]:
            project = await self._project(tx, decision)
            if not await self._authorized_member(tx, decision, project):
                raise AccessDenied("Project membership revoked")
            if parent_agent_id is not None:
                parent = await tx.get(AgentIdentityRow, parent_agent_id)
                if parent is None or parent.project_id != project.id or not parent.enabled:
                    raise AccessDenied("parent AgentIdentity is not active in this Project")
            row = AgentIdentityRow(
                id=uuid4(),
                project_id=project.id,
                parent_agent_id=parent_agent_id,
                name=name.strip(),
                enabled=True,
                version=1,
            )
            tx.add(row)
            project.resource_revision += 1
            return {
                "agent_id": str(row.id),
                "project_id": str(project.id),
                "resource_revision": project.resource_revision,
            }

        return await self.commands.execute_local(
            decision, proofs, mutate, event="agent.created", target=str(decision.request.project_id)
        )

    @staticmethod
    async def _require_project_owner(
        tx: AsyncSession, decision: VerifiedOwnerOperation, row: ProjectRow
    ) -> None:
        if decision.actor_role == "superuser":
            return
        actor = decision.request.caller_user_id
        if row.owner_user_id is not None:
            if row.owner_user_id == actor:
                return
            raise AccessDenied("only personal Project owner may prepare deletion")
        if row.owner_team_id is None:
            raise AccessDenied("Project has no verified current owner")
        team = await tx.scalar(
            select(TeamRow).where(TeamRow.id == row.owner_team_id).with_for_update()
        )
        member = await tx.scalar(
            select(TeamMembershipRow.id)
            .where(
                TeamMembershipRow.team_id == row.owner_team_id,
                TeamMembershipRow.user_id == actor,
                TeamMembershipRow.active.is_(True),
            )
            .with_for_update()
        )
        if team is None or team.owner_user_id != actor or member is None:
            raise AccessDenied("only current active Team owner may delete Team Project")

    async def prepare_project_delete(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        *,
        confirmed: bool,
    ) -> OwnerCommandOutcome:
        if decision.request.operation != "project.delete.prepare" or not confirmed:
            raise InvalidInput("Project delete requires an explicit signed prepare confirmation")
        require_signed_payload(decision.request, {"confirmed": True})

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await self._project(tx, decision)
            await self._require_project_owner(tx, decision, row)
            row.lifecycle_status = "deleting"
            row.resource_revision += 1
            # THIS IS A FENCE, NOT A FILE/RESOURCE/NATIVE DELETE.
            # Later current Control-issued authorizations deny non-active
            # Projects. Each external owner must durably attest its absence.
            return {
                "project_id": str(row.id),
                "lifecycle_status": row.lifecycle_status,
                "fenced_control_revision": project_state(row),
                "resource_revision": row.resource_revision,
                "reconciliation_required": True,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="project.delete_preparing",
            target=str(decision.request.project_id),
        )

    async def confirm_project_delete(
        self,
        decision: VerifiedOwnerOperation,
        proofs: SignedOwnerProofs,
        *,
        fenced_control_revision: int,
    ) -> OwnerCommandOutcome:
        """Finalize Control tombstone only after every durable owner is empty.

        No physical deletion is performed by Control. Native Files/Runtime/
        Reverse/Resource owners retain their own cleanup and backup contracts.
        """
        if (
            decision.request.operation != "project.delete.confirm"
            or fenced_control_revision != decision.request.expected_control_revision
            or self.delete_impact is None
        ):
            raise AccessDenied("Project deletion requires original fence and all signed owners")
        require_signed_payload(
            decision.request,
            {
                "fenced_control_revision": fenced_control_revision,
            },
        )
        verified: dict[str, VerifiedProjectDeleteImpact] = {}
        for owner in ("resources", "files", "runtime", "reverse"):
            try:
                import asyncio

                async with asyncio.timeout(3):
                    receipt = await self.delete_impact.verify_current_impact(
                        project_id=decision.request.project_id,
                        fenced_control_revision=fenced_control_revision,
                        owner=owner,
                    )
            except Exception:
                raise AccessDenied("all durable deletion owner receipts must be current") from None
            if (
                not isinstance(receipt, VerifiedProjectDeleteImpact)
                or receipt.owner != owner
                or receipt.project_id != decision.request.project_id
                or receipt.fenced_control_revision != fenced_control_revision
                or not receipt.zero_active_effects
                or receipt.observed_at.tzinfo is None
                or receipt.observed_at > datetime.now(UTC)
                or datetime.now(UTC) - receipt.observed_at > timedelta(seconds=20)
                or len(receipt.receipt_digest) != 64
                or any(c not in "0123456789abcdef" for c in receipt.receipt_digest)
            ):
                raise AccessDenied("owner deletion impact not signed at current fence")
            verified[owner] = receipt

        async def mutation(tx: AsyncSession) -> dict[str, object]:
            row = await tx.scalar(
                select(ProjectRow)
                .where(ProjectRow.id == decision.request.project_id)
                .with_for_update()
            )
            if (
                row is None
                or row.lifecycle_status != "deleting"
                or project_state(row) != fenced_control_revision
                or row.resource_revision != decision.request.expected_control_resource_revision
            ):
                raise AccessDenied("Project is not fenced for owner deletion")
            await self._require_project_owner(tx, decision, row)
            if any(
                datetime.now(UTC) - receipt.observed_at > timedelta(seconds=20)
                for receipt in verified.values()
            ):
                raise AccessDenied("owner deletion proof expired while acquiring Control lock")
            row.lifecycle_status = "deleted"
            row.resource_revision += 1
            return {
                "project_id": str(row.id),
                "lifecycle_status": row.lifecycle_status,
                "state": format(project_state(row), "064x"),
                "resource_revision": row.resource_revision,
                "native_artifacts_removed": False,
                "physical_cleanup_verified": False,
            }

        return await self.commands.execute_local(
            decision,
            proofs,
            mutation,
            event="project.delete_finalized",
            target=str(decision.request.project_id),
        )
