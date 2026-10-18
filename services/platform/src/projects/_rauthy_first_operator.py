"""One-time first Platform operator bootstrap after greenfield DB creation.

No OAuth subject, password or Rauthy admin group automatically creates
Briareus privileges. An independently verified out-of-band enrollment
decision must name the exact EXISTING Rauthy admin subject. This capability
is never exposed as a public route, and cannot restore a locked-out instance.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from sqlalchemy import select, text

from common.owner_registry import owner_metadata
from common.platform_db import PlatformDatabase
from projects._rauthy_user_links import (
    CurrentRauthyUserLink,
    RauthyUserLinkRow,
    TrustedRauthyUserStatusPort,
    VerifiedRauthyUserStatus,
)
from projects._rauthy_user_status import _ID, _LOCAL_SANDBOX_ISSUER, _PUBLIC_ISSUER

# Reserved for this owner-local one-time bootstrap; not the Alembic coordinator.
_BOOTSTRAP_NAMESPACE = 146536
_BOOTSTRAP_LOCK = 1


@dataclass(frozen=True, slots=True)
class VerifiedFirstOperatorApproval:
    """Independent operator-control evidence, NEVER Rauthy ID-token content."""

    operation_uuid: UUID
    user_uuid: UUID
    rauthy_issuer: str
    rauthy_subject: str
    audience: Literal["briareus:platform:first-operator"]
    provider_admin_verified: bool
    independent_owner_approval: bool
    bootstrap_project_uuid: UUID
    bootstrap_project_name: str
    expires_at: datetime


class TrustedFirstOperatorAuthority(Protocol):
    async def verify(self, evidence: object) -> VerifiedFirstOperatorApproval:
        """Verify operator-approved signed proof and true Rauthy admin status."""
        ...


class FirstOperatorBootstrapDenied(Exception):
    """One-time initial operator proof or empty database condition failed."""


class FirstOperatorBootstrapUnavailable(Exception):
    """Cannot independently validate active Rauthy admin or owner database."""


class FirstOperatorBootstrap:
    def __init__(
        self,
        *,
        database: PlatformDatabase,
        authority: TrustedFirstOperatorAuthority,
        rauthy_status: TrustedRauthyUserStatusPort,
    ) -> None:
        if (
            database.engine.url.database != "briareus_platform"
            or authority is None
            or rauthy_status is None
        ):
            raise ValueError("first operator bootstrap requires trusted own-DB and provider ports")
        self._db = database
        self._authority = authority
        self._status = rauthy_status

    async def enroll_once(self, *, signed_evidence: object) -> CurrentRauthyUserLink:
        try:
            verified = await self._authority.verify(signed_evidence)
        except Exception:
            raise FirstOperatorBootstrapDenied("signed first-operator approval required") from None
        now = datetime.now(UTC)
        if (
            not isinstance(verified, VerifiedFirstOperatorApproval)
            or not isinstance(verified.operation_uuid, UUID)
            or verified.operation_uuid.version != 4
            or not isinstance(verified.user_uuid, UUID)
            or verified.user_uuid.version != 4
            or verified.audience != "briareus:platform:first-operator"
            or verified.rauthy_issuer not in {_PUBLIC_ISSUER, _LOCAL_SANDBOX_ISSUER}
            or not isinstance(verified.rauthy_subject, str)
            or _ID.fullmatch(verified.rauthy_subject) is None
            or verified.provider_admin_verified is not True
            or verified.independent_owner_approval is not True
            or not isinstance(verified.bootstrap_project_uuid, UUID)
            or verified.bootstrap_project_uuid.version != 4
            or not isinstance(verified.bootstrap_project_name, str)
            or not 1 <= len(verified.bootstrap_project_name) <= 255
            or verified.bootstrap_project_name != verified.bootstrap_project_name.strip()
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in verified.bootstrap_project_name
            )
            or not isinstance(verified.expires_at, datetime)
            or verified.expires_at.tzinfo is None
            or not now < verified.expires_at <= now + timedelta(seconds=30)
        ):
            raise FirstOperatorBootstrapDenied("fresh independently approved Rauthy admin required")

        try:
            active = await self._status.current_status(
                issuer=verified.rauthy_issuer, subject=verified.rauthy_subject
            )
        except Exception:
            raise FirstOperatorBootstrapUnavailable("provider user status unavailable") from None
        now = datetime.now(UTC)
        if (
            not isinstance(active, VerifiedRauthyUserStatus)
            or active.issuer != verified.rauthy_issuer
            or active.subject != verified.rauthy_subject
            or active.active is not True
            or not isinstance(active.expires_at, datetime)
            or active.expires_at.tzinfo is None
            or not now < active.expires_at <= now + timedelta(seconds=30)
        ):
            raise FirstOperatorBootstrapDenied("existing active Rauthy admin subject required")

        # The verified provider status and owner approval were fetched BEFORE
        # entering SQL; no outbound requests under the owner transaction lock.
        from projects._control_ledger import OwnerAuditRow, OwnerOutboxRow
        from projects._current_state import project_state
        from projects._persistence import ProjectRow

        # A failed/partial Development reset can leave audit, scopes, agent
        # identities or command history even when User/Team/Project are empty.
        # Future Platform-owned tables must not silently bypass this first-
        # operator guard. This is deliberately ONE-TIME (11 bounded SELECTs
        # on the current reviewed Platform metadata), never per login.
        tables = tuple(owner_metadata("platform").sorted_tables)
        if not tables or not {"control.rauthy_user_links", "projects.projects", "teams.teams"} <= {
            table.fullname for table in tables
        }:
            raise FirstOperatorBootstrapUnavailable("Platform owner schema unavailable")
        try:
            async with self._db.transaction() as tx:
                # Serialize *all* first-operator attempts, including distinct
                # subjects. SELECT ... FOR UPDATE on an EMPTY table cannot
                # protect the negative fact under READ COMMITTED.
                await tx.execute(
                    text("SELECT pg_advisory_xact_lock(:namespace, :lock_id)"),
                    {"namespace": _BOOTSTRAP_NAMESPACE, "lock_id": _BOOTSTRAP_LOCK},
                )
                # This must be an entirely new Platform trust root. A
                # supposedly empty first-operator target with ANY retained
                # Platform data is not safe to adopt, including agent IDs,
                # owner audit/outbox and realtime cursors. Never truncate or
                # repair it in an authentication-sensitive transaction.
                for table in tables:
                    if await tx.scalar(select(1).select_from(table).limit(1)) is not None:
                        raise FirstOperatorBootstrapDenied(
                            "first operator requires wholly empty Platform owner"
                        )
                if verified.expires_at <= datetime.now(UTC) or active.expires_at <= datetime.now(
                    UTC
                ):
                    raise FirstOperatorBootstrapDenied("bootstrap signed proof expired")
                now = datetime.now(UTC)
                row = RauthyUserLinkRow(
                    user_id=verified.user_uuid,
                    issuer=verified.rauthy_issuer,
                    subject=verified.rauthy_subject,
                    briareus_role="operator",
                    active=True,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                tx.add(row)
                project = ProjectRow(
                    id=verified.bootstrap_project_uuid,
                    name=verified.bootstrap_project_name,
                    lifecycle_status="active",
                    owner_user_id=verified.user_uuid,
                    owner_team_id=None,
                    resource_revision=0,
                    created_at=now,
                )
                tx.add(project)
                await tx.flush()
                tx.add(
                    OwnerAuditRow(
                        operation_uuid=verified.operation_uuid,
                        actor_user_id=None,
                        project_id=None,
                        action="user.first_operator_bootstrapped",
                        object_id=str(row.user_id),
                        owner_revision="rauthy-link-v1",
                        details={"source": "independent-operator-approval"},
                    )
                )
                tx.add(
                    OwnerAuditRow(
                        operation_uuid=verified.operation_uuid,
                        actor_user_id=None,
                        project_id=project.id,
                        action="project.first_operator_workspace_bootstrapped",
                        object_id=str(project.id),
                        owner_revision=format(project_state(project), "064x"),
                        details={"owner_user_id": str(verified.user_uuid)},
                    )
                )
                tx.add(
                    OwnerOutboxRow(
                        operation_uuid=verified.operation_uuid,
                        event_name="project.first_operator_workspace_bootstrapped",
                        owner_revision=format(project_state(project), "064x"),
                        event_payload={
                            "project_id": str(project.id),
                            "owner_user_id": str(verified.user_uuid),
                        },
                    )
                )
                tx.add(
                    OwnerOutboxRow(
                        operation_uuid=verified.operation_uuid,
                        event_name="user.first_operator_bootstrapped",
                        owner_revision="rauthy-link-v1",
                        event_payload={
                            "user_id": str(row.user_id),
                            "revision": 1,
                        },
                    )
                )
                # SQL flush or advisory-lock contention may consume the
                # short upstream status/independent owner proof TTL. Abort
                # the WHOLE User+Project+audit/outbox transaction if either
                # has expired before the commit boundary.
                commit_boundary = datetime.now(UTC)
                if verified.expires_at <= commit_boundary or active.expires_at <= commit_boundary:
                    raise FirstOperatorBootstrapDenied(
                        "first operator proof expired during Platform transaction"
                    )
            # PostgreSQL COMMIT itself is awaited outside the last in-tx
            # deadline check. If proof expires while commit completes,
            # the write may ALREADY exist. Never acknowledge stale operator
            # authority; recovery must inspect current Platform state using
            # fresh separately signed proof, not retry with a new identity.
            if min(verified.expires_at, active.expires_at) <= datetime.now(UTC):
                raise FirstOperatorBootstrapUnavailable(
                    "first operator outcome indeterminate after proof expiry"
                )
            return CurrentRauthyUserLink(
                issuer=verified.rauthy_issuer,
                subject=verified.rauthy_subject,
                user_id=verified.user_uuid,
                enabled=True,
                role="operator",
                revision=1,
                expires_at=min(active.expires_at, verified.expires_at),
            )
        except FirstOperatorBootstrapDenied:
            raise
        except Exception:
            raise FirstOperatorBootstrapUnavailable("own Platform database unavailable") from None
