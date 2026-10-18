"""Current Control Project/Team membership decision from ONLY briareus_platform.

The caller's User role and credential revision must already be attested by an
independent current Identity issuer. No JWT/Project ID alone grants resources.
This source is not mounted until independently accepted mTLS/Unix C1-B2/C2.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol, cast
from uuid import UUID

from pydantic import SecretStr
from sqlalchemy import select

from common.owner_contracts import (
    OwnerAuthorityUnavailable,
    OwnerCommandDTO,
    TrustedOwnerServicePeerPort,
    VerifiedOwnerServicePeer,
)
from common.owner_proof_signing import OwnerVerifiedSourceSnapshot, SourceOwnerSigner
from common.platform_db import PlatformDatabase
from projects._current_state import membership_state, project_state, team_state
from projects._persistence import ProjectRow
from teams._persistence import TeamMembershipRow, TeamRow


@dataclass(frozen=True, slots=True)
class VerifiedControlActor:
    """Already verified by current Identity issuer; never a request body."""

    user_id: UUID
    role: Literal["user", "superuser"]
    credential_version: int
    recipient_service_id: UUID
    expires_at: datetime


class TrustedControlActorSource(Protocol):
    def verify_actor(
        self, evidence: object, *, service_peer: VerifiedOwnerServicePeer
    ) -> VerifiedControlActor:
        """Must verify fresh signed Identity proof and original delegation."""
        ...


class ControlOwnerProofReader:
    def __init__(
        self,
        database: PlatformDatabase,
        signer: SourceOwnerSigner,
        peers: TrustedOwnerServicePeerPort,
        actor_source: TrustedControlActorSource,
    ) -> None:
        if (
            database.engine.url.database != "briareus_platform"
            or peers is None
            or actor_source is None
        ):
            raise RuntimeError("Control proof must use own DB and trusted Identity/peer sources")
        self.db = database
        self.signer = signer
        self.peers = peers
        self.actors = actor_source

    async def issue_project_scope(
        self,
        command: OwnerCommandDTO,
        *,
        peer_evidence: object,
        delegated_actor_evidence: object,
    ) -> SecretStr:
        try:
            peer = self.peers.verify_peer(peer_evidence)
            actor = self.actors.verify_actor(delegated_actor_evidence, service_peer=peer)
        except Exception:
            raise OwnerAuthorityUnavailable(
                "Control trusted peer/current User proof unavailable"
            ) from None
        if (
            peer.audience != "briareus:platform"
            or peer.expires_at <= datetime.now(UTC)
            or actor.user_id != command.caller_user_id
            or actor.credential_version != command.expected_identity_revision
            or actor.recipient_service_id != peer.service_id
            or actor.expires_at.tzinfo is None
            or actor.expires_at <= datetime.now(UTC)
        ):
            raise OwnerAuthorityUnavailable("Control actor Identity/current peer not scoped")
        async with self.db.transaction() as tx:
            project = await tx.scalar(
                select(ProjectRow).where(ProjectRow.id == command.project_id).with_for_update()
            )
            expected_state = (
                "deleting" if command.operation == "project.delete.confirm" else "active"
            )
            if (
                project is None
                or project_state(project) != command.expected_control_revision
                or project.resource_revision != command.expected_control_resource_revision
                or project.lifecycle_status != expected_state
            ):
                raise OwnerAuthorityUnavailable("Control Project revision/lifecycle changed")
            owner_user = project.owner_user_id
            owner_team = project.owner_team_id
            if (owner_user is None) == (owner_team is None):
                raise OwnerAuthorityUnavailable(
                    "Control exclusive Project ownership invariant failed"
                )
            scope_team_id: UUID | None = owner_team
            team_version: int | None = None
            team_resource_revision: int | None = None
            membership_version: int | None = None
            team_owner_id: UUID | None = None
            member_active = False
            if command.operation == "project.transfer_to_team" and owner_user is not None:
                # Recipient Team must be explicitly selected; it is NOT an
                # implicit current Project owner or inherited secret scope.
                scope_team_id = command.expected_team_id
                if scope_team_id is None:
                    raise OwnerAuthorityUnavailable("Project transfer needs signed target Team")
            if scope_team_id is not None:
                team = await tx.scalar(
                    select(TeamRow).where(TeamRow.id == scope_team_id).with_for_update()
                )
                if team is None:
                    raise OwnerAuthorityUnavailable("authoritative Team no longer exists")
                member = await tx.scalar(
                    select(TeamMembershipRow)
                    .where(
                        TeamMembershipRow.team_id == scope_team_id,
                        TeamMembershipRow.user_id == actor.user_id,
                        TeamMembershipRow.active.is_(True),
                    )
                    .with_for_update()
                )
                member_active = member is not None
                membership_version = membership_state(member) if member is not None else None
                team_version = team_state(team)
                team_resource_revision = team.resource_revision
                team_owner_id = team.owner_user_id
            if (
                scope_team_id != command.expected_team_id
                or team_version != command.expected_team_revision
                or team_resource_revision != command.expected_team_resource_revision
            ):
                raise OwnerAuthorityUnavailable("Control Team or resource revisions changed")
            is_project_owner = owner_user == actor.user_id
            is_team_owner = owner_team is not None and team_owner_id == actor.user_id
            elevated = actor.role == "superuser"
            privileged = command.operation in {
                "project.delete.prepare",
                "project.delete.confirm",
                "project.withdraw_from_team",
                "project.transfer_to_team",
            }
            if command.operation == "project.transfer_to_team":
                permitted = (is_project_owner or elevated) and member_active
            elif command.operation == "project.withdraw_from_team":
                permitted = is_team_owner or elevated
            elif command.operation in {"project.delete.prepare", "project.delete.confirm"}:
                permitted = elevated or is_project_owner or (is_team_owner and member_active)
            elif privileged:
                permitted = False
            else:
                permitted = (
                    elevated or is_project_owner or (owner_team is not None and member_active)
                )
            if not permitted:
                raise OwnerAuthorityUnavailable("current Control membership/owner scope denied")
            snapshot = OwnerVerifiedSourceSnapshot(
                owner="platform",
                caller_user_id=actor.user_id,
                project_id=project.id,
                agent_session_uuid=command.session_uuid,
                owner_revision=project_state(project),
                active=True,
                role=actor.role,
                capabilities=(command.operation,),
                control_resource_revision=project.resource_revision,
                project_lifecycle=cast(
                    Literal["active", "deleting", "deleted"], project.lifecycle_status
                ),
                team_id=scope_team_id,
                team_revision=team_version,
                team_resource_revision=team_resource_revision,
                epoch_components=(
                    str(project.id),
                    str(project_state(project)),
                    str(project.resource_revision),
                    str(owner_user or owner_team),
                    project.lifecycle_status,
                    str(scope_team_id or "none"),
                    str(team_version or "none"),
                    str(team_resource_revision or "none"),
                    str(membership_version or "none"),
                    str(member_active),
                    str(team_owner_id or "none"),
                    str(actor.user_id),
                    actor.role,
                ),
            )
            return self.signer.sign_project(command, snapshot)
