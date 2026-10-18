"""Read-only authoritative owner SQL proof producers for signed private RPC.

Each producer opens ONLY its own database. Its caller must first be an
independently attested mTLS/Unix service peer; no browser, UUID-only request,
project projection or caller-provided role can mint an authorization proof.
Physical transport/OS acceptance remains C1-B2/C2 gated and unmounted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Literal, Protocol, cast
from uuid import UUID

from projects._current_state import membership_state, project_state, team_state
from pydantic import SecretStr
from sqlalchemy import select

from authorization._session_persistence import ProjectAgentSessionRow
from common.owner_contracts import (
    OwnerAuthorityUnavailable,
    OwnerCommandDTO,
    TrustedOwnerServicePeerPort,
    VerifiedOwnerServicePeer,
)
from common.owner_proof_signing import OwnerVerifiedSourceSnapshot, SourceOwnerSigner
from common.platform_db import PlatformDatabase
from identity._persistence import UserRow
from projects._persistence import ProjectRow
from teams._persistence import TeamMembershipRow, TeamRow


@dataclass(frozen=True, slots=True)
class VerifiedDelegatedHuman:
    """Result of independent C2 human delegation verifier, not request JSON."""

    actor_user_id: UUID
    project_id: UUID
    session_uuid: UUID
    service_id: UUID
    instance_uuid: UUID
    operation_uuid: UUID
    operation: str
    payload_sha256: str
    credential_version: int
    expires_at: datetime


class TrustedHumanDelegationVerifier(Protocol):
    def verify_delegation(
        self,
        evidence: object,
        *,
        peer: VerifiedOwnerServicePeer,
        operation: OwnerCommandDTO,
    ) -> VerifiedDelegatedHuman:
        """MUST verify independent human identity/attested OAuth/Admin origin."""
        ...


class _PrivateOwnerProofBase:
    def __init__(
        self,
        *,
        db: PlatformDatabase,
        signer: SourceOwnerSigner,
        expected_db: str,
        issuer_owner: Literal["identity", "platform", "access"],
        peer_verifier: TrustedOwnerServicePeerPort,
        delegation_verifier: TrustedHumanDelegationVerifier,
    ) -> None:
        if (
            db.engine.url.database != expected_db
            or peer_verifier is None
            or delegation_verifier is None
        ):
            raise OwnerAuthorityUnavailable("owner issuer has foreign database or missing peer")
        self.db = db
        self._issuer_owner = issuer_owner
        self.signer = signer
        self.peer_verifier = peer_verifier
        self.delegation_verifier = delegation_verifier

    def _require_peer(
        self,
        evidence: object,
        human_evidence: object,
        request: OwnerCommandDTO,
    ) -> VerifiedDelegatedHuman:
        try:
            peer = self.peer_verifier.verify_peer(evidence)
            delegated = self.delegation_verifier.verify_delegation(
                human_evidence, peer=peer, operation=request
            )
            if (
                peer.audience != f"briareus:{self._issuer_owner}"
                or peer.expires_at <= datetime.now(UTC)
                or not isinstance(delegated, VerifiedDelegatedHuman)
                or delegated.service_id != peer.service_id
                or delegated.instance_uuid != peer.instance_uuid
                or delegated.actor_user_id != request.caller_user_id
                or delegated.project_id != request.project_id
                or delegated.session_uuid != request.session_uuid
                or delegated.operation_uuid != request.operation_uuid
                or delegated.operation != request.operation
                or delegated.payload_sha256 != request.payload_sha256
                or delegated.credential_version != request.expected_identity_revision
                or delegated.expires_at.tzinfo is None
                or delegated.expires_at <= datetime.now(UTC)
            ):
                raise OwnerAuthorityUnavailable("peer-bound current human delegation denied")
            return delegated
        except Exception:
            raise OwnerAuthorityUnavailable(
                "trusted human delegation and peer unavailable"
            ) from None


class CurrentIdentityProofSource(_PrivateOwnerProofBase):
    """Authoritative enabled User/role/credential version, no Control join."""

    def __init__(
        self,
        db: PlatformDatabase,
        signer: SourceOwnerSigner,
        peer_verifier: TrustedOwnerServicePeerPort,
        delegation_verifier: TrustedHumanDelegationVerifier,
    ) -> None:
        super().__init__(
            db=db,
            signer=signer,
            expected_db="briareus_identity",
            issuer_owner="identity",
            peer_verifier=peer_verifier,
            delegation_verifier=delegation_verifier,
        )

    async def sign(
        self,
        request: OwnerCommandDTO,
        peer_evidence: object,
        human_delegation_evidence: object,
    ) -> SecretStr:
        self._require_peer(peer_evidence, human_delegation_evidence, request)
        async with self.db.transaction() as tx:
            user = await tx.scalar(select(UserRow).where(UserRow.id == request.caller_user_id))
            if (
                user is None
                or not user.enabled
                or user.deleted_at is not None
                or user.credential_version != request.expected_identity_revision
                or user.role not in {"user", "superuser"}
            ):
                raise OwnerAuthorityUnavailable("current Identity account disabled or stale")
            snapshot = OwnerVerifiedSourceSnapshot(
                owner="identity",
                caller_user_id=user.id,
                project_id=request.project_id,
                agent_session_uuid=request.session_uuid,
                owner_revision=user.credential_version,
                active=True,
                role=cast(Literal["user", "superuser"], user.role),
                capabilities=(),
                control_resource_revision=None,
                project_lifecycle=None,
                team_id=request.expected_team_id,
                team_revision=None,
                team_resource_revision=None,
                epoch_components=(
                    str(user.id),
                    str(user.credential_version),
                    user.role,
                    str(user.enabled),
                    str(user.deleted_at),
                ),
            )
            return self.signer.sign_project(request, snapshot)


class CurrentControlProofSource(_PrivateOwnerProofBase):
    """Authoritative Project ownership, Team membership, lifecycle and fences."""

    def __init__(
        self,
        db: PlatformDatabase,
        signer: SourceOwnerSigner,
        peer_verifier: TrustedOwnerServicePeerPort,
        delegation_verifier: TrustedHumanDelegationVerifier,
    ) -> None:
        super().__init__(
            db=db,
            signer=signer,
            expected_db="briareus_platform",
            issuer_owner="platform",
            peer_verifier=peer_verifier,
            delegation_verifier=delegation_verifier,
        )

    async def sign(
        self,
        request: OwnerCommandDTO,
        peer_evidence: object,
        human_delegation_evidence: object,
    ) -> SecretStr:
        self._require_peer(peer_evidence, human_delegation_evidence, request)
        async with self.db.transaction() as tx:
            project = await tx.scalar(select(ProjectRow).where(ProjectRow.id == request.project_id))
            expected_lifecycle = (
                "deleting" if request.operation == "project.delete.confirm" else "active"
            )
            if (
                project is None
                or project_state(project) != request.expected_control_revision
                or project.resource_revision != request.expected_control_resource_revision
                or project.lifecycle_status != expected_lifecycle
            ):
                raise OwnerAuthorityUnavailable("Control Project current version unavailable")
            team_version: int | None = None
            team_resource_version: int | None = None
            team_epoch = "personal"
            if project.owner_team_id is not None:
                team = await tx.scalar(select(TeamRow).where(TeamRow.id == project.owner_team_id))
                member = await tx.scalar(
                    select(TeamMembershipRow).where(
                        TeamMembershipRow.team_id == project.owner_team_id,
                        TeamMembershipRow.user_id == request.caller_user_id,
                        TeamMembershipRow.active.is_(True),
                    )
                )
                if team is None or member is None:
                    raise OwnerAuthorityUnavailable("Control Team membership unavailable")
                team_version, team_resource_version = team_state(team), team.resource_revision
                team_epoch = (
                    f"{team.id}:{team_state(team)}:{team.resource_revision}:"
                    f"{membership_state(member)}"
                )
            elif project.owner_user_id != request.caller_user_id:
                # Global superuser recovery uses a separately accepted, explicit
                # operator protocol; Project UUID ownership alone is not proof.
                raise OwnerAuthorityUnavailable("personal Project caller ownership absent")
            if (
                request.expected_team_id != project.owner_team_id
                or request.expected_team_revision != team_version
                or request.expected_team_resource_revision != team_resource_version
            ):
                raise OwnerAuthorityUnavailable("Control Team/Project fencing revision differs")
            # Operations requiring an owner (not ordinary member) stay closed
            # unless owner of the Project or current Team owner is verified.
            if request.operation in {
                "project.transfer_to_team",
                "project.withdraw_from_team",
                "project.delete.prepare",
                "project.delete.confirm",
            }:
                if project.owner_team_id is not None and (
                    team is None or team.owner_user_id != request.caller_user_id
                ):
                    raise OwnerAuthorityUnavailable("current Team owner required")
                if project.owner_user_id is not None and (
                    project.owner_user_id != request.caller_user_id
                ):
                    raise OwnerAuthorityUnavailable("current personal owner required")
            snapshot = OwnerVerifiedSourceSnapshot(
                owner="platform",
                caller_user_id=request.caller_user_id,
                project_id=request.project_id,
                agent_session_uuid=request.session_uuid,
                owner_revision=project_state(project),
                active=True,
                role=None,
                capabilities=(request.operation,),
                control_resource_revision=project.resource_revision,
                project_lifecycle=cast(
                    Literal["active", "deleting", "deleted"], project.lifecycle_status
                ),
                team_id=project.owner_team_id,
                team_revision=team_version,
                team_resource_revision=team_resource_version,
                epoch_components=(
                    str(project.id),
                    str(project_state(project)),
                    str(project.resource_revision),
                    project.lifecycle_status,
                    str(request.caller_user_id),
                    team_epoch,
                ),
            )
            return self.signer.sign_project(request, snapshot)


class CurrentAccessProofSource(_PrivateOwnerProofBase):
    """Only Access DB may attest AgentSession grant, expiry and revoke epoch."""

    _GRANTS: ClassVar[dict[str, str]] = {
        "files.write.reserve": "files.write",
        "files.write.dispatch": "files.write",
        "files.write.reconcile": "files.write",
        "credential.reserve": "integrations.use",
        "catalog.variable.reserve": "variables.use",
        "catalog.variable.redeem": "variables.use",
        "credential.redeem": "integrations.use",
        "catalog.integrations.list": "integrations.use",
        "catalog.variables.list": "variables.use",
        "catalog.integration.create": "integrations.use",
        "catalog.integration.rotate": "integrations.use",
        "catalog.integration.revoke": "integrations.use",
        "catalog.variable.create": "variables.use",
        "catalog.variable.rotate": "variables.use",
        "catalog.variable.revoke": "variables.use",
        "reverse.import.reserve": "analysis.import",
        "reverse.import.dispatch": "analysis.import",
        "reverse.import.reconcile": "analysis.import",
        "agent.create": "agents.manage",
        "runtime.terminal.job.queue": "terminal.execute",
        "runtime.web.job.queue": "web.access",
        "runtime.reverse.job.queue": "analysis.import",
        "runtime.terminal.job.dispatch": "terminal.execute",
        "runtime.web.job.dispatch": "web.access",
        "runtime.reverse.job.dispatch": "analysis.import",
        "runtime.terminal.job.reconcile": "terminal.execute",
        "runtime.web.job.reconcile": "web.access",
        "runtime.reverse.job.reconcile": "analysis.import",
    }
    _OWNER_ONLY: frozenset[str] = frozenset(
        {
            "project.transfer_to_team",
            "project.withdraw_from_team",
            "project.delete.prepare",
            "project.delete.confirm",
        }
    )

    def __init__(
        self,
        db: PlatformDatabase,
        signer: SourceOwnerSigner,
        peer_verifier: TrustedOwnerServicePeerPort,
        delegation_verifier: TrustedHumanDelegationVerifier,
    ) -> None:
        super().__init__(
            db=db,
            signer=signer,
            expected_db="briareus_access",
            issuer_owner="access",
            peer_verifier=peer_verifier,
            delegation_verifier=delegation_verifier,
        )

    async def sign(
        self,
        request: OwnerCommandDTO,
        peer_evidence: object,
        human_delegation_evidence: object,
    ) -> SecretStr:
        self._require_peer(peer_evidence, human_delegation_evidence, request)
        if request.operation not in self._GRANTS:
            # Session creation/approval, quota configuration, runtime command
            # kinds and operator-only transfers need a separate ADMIN+service
            # issuer with explicit signed permission, never guessed a grant.
            raise OwnerAuthorityUnavailable("Access operation lacks approved session grant map")
        async with self.db.transaction() as tx:
            session = await tx.scalar(
                select(ProjectAgentSessionRow).where(
                    ProjectAgentSessionRow.session_uuid == request.session_uuid,
                    ProjectAgentSessionRow.project_id == request.project_id,
                )
            )
            if (
                session is None
                or session.status != "active"
                or session.version != request.expected_access_revision
                or session.hard_expires_at <= datetime.now(UTC)
            ):
                raise OwnerAuthorityUnavailable("Access AgentSession expired or revoked")
            operations = session.grants.get("operations", ())
            if (
                not isinstance(operations, list)
                or self._GRANTS[request.operation] not in operations
            ):
                raise OwnerAuthorityUnavailable("Access AgentSession operation is not granted")
            snapshot = OwnerVerifiedSourceSnapshot(
                owner="access",
                caller_user_id=request.caller_user_id,
                project_id=request.project_id,
                agent_session_uuid=session.session_uuid,
                owner_revision=session.version,
                active=True,
                role=None,
                capabilities=(request.operation,),
                control_resource_revision=None,
                project_lifecycle=None,
                team_id=request.expected_team_id,
                team_revision=None,
                team_resource_revision=None,
                epoch_components=(
                    str(session.session_uuid),
                    str(session.version),
                    str(session.project_id),
                    str(session.hard_expires_at),
                    str(request.caller_user_id),
                    self._GRANTS[request.operation],
                ),
            )
            return self.signer.sign_project(request, snapshot)
