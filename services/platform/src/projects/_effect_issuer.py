"""Control source-only R13 v1 signed current Project ownership/action decision.

Only Control SQL; membership, Project version, lifecycle and source revision
are freshly verified in one owner-local read transaction. OS/C2 activation
and runtime consumer wiring remain independent gates.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from common.owner_contracts import OwnerAuthorityUnavailable, TrustedOwnerServicePeerPort
from common.owner_effect_authorization import (
    OwnerEffectAuthoritySnapshot,
    OwnerEffectDecisionSigner,
    OwnerEffectIntent,
    SignedOwnerDecision,
    canonical_project_access_revision,
    derive_source_epoch,
)
from common.platform_db import PlatformDatabase
from projects._control_proof_reader import TrustedControlActorSource
from projects._current_state import membership_state, project_state, team_state
from projects._persistence import ProjectRow
from teams._persistence import TeamMembershipRow, TeamRow


class ControlEffectIssuer:
    def __init__(
        self,
        database: PlatformDatabase,
        signer: OwnerEffectDecisionSigner,
        peers: TrustedOwnerServicePeerPort,
        actors: TrustedControlActorSource,
    ) -> None:
        if (
            database.engine.url.database != "briareus_platform"
            or signer.owner != "platform"
            or peers is None
            or actors is None
        ):
            raise RuntimeError("Control effect decision requires current Control and C2")
        self.database = database
        self.signer = signer
        self.peers = peers
        self.actors = actors

    async def decide(
        self, intent: OwnerEffectIntent, *, peer_evidence: object, delegated_actor_evidence: object
    ) -> SignedOwnerDecision:
        try:
            peer = self.peers.verify_peer(peer_evidence)
            actor = self.actors.verify_actor(delegated_actor_evidence, service_peer=peer)
        except Exception:
            raise OwnerAuthorityUnavailable(
                "current Control effect actor/peer unavailable"
            ) from None
        now = datetime.now(UTC)
        if (
            peer.audience != "briareus:platform"
            or peer.service_id != intent.recipient_service_id
            or peer.instance_uuid != intent.recipient_instance_uuid
            or peer.expires_at <= now
            or actor.user_id != intent.actor_id
            or actor.credential_version < 1
            or actor.recipient_service_id != peer.service_id
            or actor.expires_at.tzinfo is None
            or actor.expires_at <= now
        ):
            raise OwnerAuthorityUnavailable("Control source actor/recipient mismatch")
        async with self.database.transaction() as tx:
            project = await tx.scalar(
                select(ProjectRow).where(ProjectRow.id == intent.project_id).with_for_update()
            )
            if (
                project is None
                or project.lifecycle_status != "active"
                or project.resource_revision < 0
                or (project.owner_user_id is None) == (project.owner_team_id is None)
            ):
                raise OwnerAuthorityUnavailable("current Control Project transfer/owner invalid")
            team: TeamRow | None = None
            membership: TeamMembershipRow | None = None
            if project.owner_team_id is not None:
                team = await tx.scalar(
                    select(TeamRow).where(TeamRow.id == project.owner_team_id).with_for_update()
                )
                if team is None:
                    raise OwnerAuthorityUnavailable("current Team ownership unavailable")
                membership = await tx.scalar(
                    select(TeamMembershipRow)
                    .where(
                        TeamMembershipRow.team_id == team.id,
                        TeamMembershipRow.user_id == actor.user_id,
                        TeamMembershipRow.active.is_(True),
                    )
                    .with_for_update()
                )
            is_admin = actor.role == "superuser"
            is_personal = (
                project.owner_user_id is not None and project.owner_user_id == actor.user_id
            )
            is_member = membership is not None
            if not (is_admin or is_personal or (team is not None and is_member)):
                raise OwnerAuthorityUnavailable("actor not authorized for current Project/Team")
            if intent.action == "infrastructure.read" and not is_admin:
                raise OwnerAuthorityUnavailable("infrastructure access requires current superuser")
            if intent.action == "files.manage" and not (
                is_admin
                or is_personal
                or (team is not None and team.owner_user_id == actor.user_id)
            ):
                raise OwnerAuthorityUnavailable("Files ownership management denied")
            owner_id: UUID = team.id if team is not None else project.id
            revision = canonical_project_access_revision(
                project_id=project.id,
                project_version=project_state(project),
                resource_revision=project.resource_revision,
                owner_user_id=project.owner_user_id,
                owner_team_id=project.owner_team_id,
                team_version=team_state(team) if team is not None else None,
                team_resource_revision=team.resource_revision if team is not None else None,
                membership_revision=membership_state(membership)
                if membership is not None
                else None,
                actor_user_id=actor.user_id,
                identity_credential_revision=actor.credential_version,
                role=actor.role,
                lifecycle_status=project.lifecycle_status,
            )
            snapshot = OwnerEffectAuthoritySnapshot(
                owner="platform",
                intent=intent,
                issued_from_owner_db="briareus_platform",
                state_version=project_state(project),
                revoke_epoch=project.resource_revision
                + (team.resource_revision if team is not None else 0),
                authority_epoch=derive_source_epoch(
                    "platform",
                    str(project.id),
                    project_state(project),
                    project.resource_revision,
                    str(owner_id),
                    team_state(team) if team is not None else 0,
                    team.resource_revision if team is not None else 0,
                    membership_state(membership) if membership is not None else 0,
                    actor.credential_version,
                    actor.role,
                    project.lifecycle_status,
                ),
                active=True,
                project_revision=revision,
                owner_scope="team" if team is not None else "project",
                owner_id=owner_id,
                granted_actions=(intent.action,),
                transfer_pending=False,
                source_expires_at=actor.expires_at,
            )
            return self.signer.sign(snapshot, recipient=peer)
