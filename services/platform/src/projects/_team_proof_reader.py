"""Control-issued Team-only decisions from current Team and membership SQL.

No Team ID is substituted for a Project ID; this method never opens a
foreign Identity/Access DB or trusts a projected scope event as a permission.
Transport/Identity delegation remain mandatory injected C1-B2/C2 ports.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import SecretStr
from sqlalchemy import select

from common.owner_contracts import OwnerAuthorityUnavailable, TrustedOwnerServicePeerPort
from common.owner_proof_signing import OwnerVerifiedTeamSnapshot, SourceOwnerSigner
from common.owner_team_contracts import TeamOwnerCommandDTO
from common.platform_db import PlatformDatabase
from projects._control_proof_reader import TrustedControlActorSource
from projects._current_state import membership_state, team_state
from teams._persistence import TeamMembershipRow, TeamRow


class ControlTeamProofReader:
    def __init__(
        self,
        database: PlatformDatabase,
        signer: SourceOwnerSigner,
        peers: TrustedOwnerServicePeerPort,
        actors: TrustedControlActorSource,
    ) -> None:
        if database.engine.url.database != "briareus_platform" or peers is None or actors is None:
            raise RuntimeError("Team proof issuer requires Control owner and signed Identity actor")
        self.db = database
        self.signer = signer
        self.peers = peers
        self.actors = actors

    async def issue_team_owner_proof(
        self,
        command: TeamOwnerCommandDTO,
        *,
        peer_evidence: object,
        delegated_actor_evidence: object,
    ) -> SecretStr:
        try:
            peer = self.peers.verify_peer(peer_evidence)
            actor = self.actors.verify_actor(delegated_actor_evidence, service_peer=peer)
        except Exception:
            raise OwnerAuthorityUnavailable(
                "trusted Team service/Identity actor unavailable"
            ) from None
        if (
            peer.audience != "briareus:platform"
            or peer.expires_at <= datetime.now(UTC)
            or actor.user_id != command.caller_user_id
            or actor.recipient_service_id != peer.service_id
            or actor.credential_version != command.expected_identity_revision
            or actor.expires_at.tzinfo is None
            or actor.expires_at <= datetime.now(UTC)
        ):
            raise OwnerAuthorityUnavailable("Team source signer actor/peer not current")
        async with self.db.transaction() as tx:
            team = await tx.scalar(
                select(TeamRow).where(TeamRow.id == command.team_id).with_for_update()
            )
            if team is None or team_state(team) != command.expected_team_revision:
                raise OwnerAuthorityUnavailable("authoritative Team revision changed")
            member = await tx.scalar(
                select(TeamMembershipRow)
                .where(
                    TeamMembershipRow.team_id == command.team_id,
                    TeamMembershipRow.user_id == actor.user_id,
                    TeamMembershipRow.active.is_(True),
                )
                .with_for_update()
            )
            if actor.role != "superuser" and (
                team.owner_user_id != actor.user_id or member is None
            ):
                raise OwnerAuthorityUnavailable(
                    "Team owner action not authorized by current Control"
                )
            snapshot = OwnerVerifiedTeamSnapshot(
                owner="platform",
                caller_user_id=actor.user_id,
                team_id=team.id,
                owner_revision=team_state(team),
                active=True,
                role=actor.role,
                capabilities=(command.operation,),
                epoch_components=(
                    str(team.id),
                    str(team_state(team)),
                    str(team.resource_revision),
                    str(team.owner_user_id),
                    str(membership_state(member)) if member is not None else "superuser",
                    str(actor.user_id),
                    actor.role,
                ),
            )
            return self.signer.sign_team(command, snapshot)
