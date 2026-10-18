"""Operator-enrolled Briareus identity links to upstream Rauthy subjects.

This is a Platform membership reference, NOT an IdP account/password record.
No public registration, email matching, OAuth claim role assignment or
automatic user UUID creation is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Integer,
    String,
    UniqueConstraint,
    select,
)
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import ControlBase, PlatformDatabase
from projects._oidc_membership_projection import (
    CurrentRauthyUserLink,
    PlatformSubjectLinkUnavailable,
)

_MAX_STATUS_SECONDS = 30


class RauthyUserLinkRow(ControlBase):
    """Current Platform mapping; no password, tokens, refresh or IdP groups."""

    __tablename__ = "rauthy_user_links"
    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_rauthy_user_subject"),
        CheckConstraint("briareus_role IN ('user','operator')", name="ck_rauthy_user_link_role"),
        CheckConstraint("version >= 1", name="ck_rauthy_user_link_version"),
        {"schema": "control"},
    )

    user_id: Mapped[UUID] = mapped_column(primary_key=True)
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(256))
    briareus_role: Mapped[str] = mapped_column(String(16))
    active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


@dataclass(frozen=True, slots=True)
class VerifiedRauthyUserStatus:
    """Fresh result of server-only upstream user-status API, not an ID token."""

    issuer: str
    subject: str
    active: bool
    expires_at: datetime
    name: str | None = None
    email: str | None = None


class TrustedRauthyUserStatusPort(Protocol):
    async def current_status(self, *, issuer: str, subject: str) -> VerifiedRauthyUserStatus:
        """Call a server-held scoped Rauthy Admin Users:read authority."""
        ...


class PlatformCurrentSubjectLinkReader:
    """Read only briareus_platform and trusted provider status (no mutations)."""

    def __init__(
        self,
        *,
        database: PlatformDatabase,
        rauthy_status: TrustedRauthyUserStatusPort,
    ) -> None:
        if database.engine.url.database != "briareus_platform" or rauthy_status is None:
            raise ValueError("Platform link reader requires own DB and real upstream status")
        self._database = database
        self._status = rauthy_status

    async def current_link(self, *, issuer: str, subject: str) -> CurrentRauthyUserLink | None:
        # The issuer comes from the already verified Rauthy browser session,
        # but its current provider user lifecycle must still be checked.
        if not issuer.startswith("https://") or not 1 <= len(subject) <= 256:
            raise PlatformSubjectLinkUnavailable("invalid issuer or Rauthy subject")

        try:
            verified = await self._status.current_status(issuer=issuer, subject=subject)
        except Exception:
            raise PlatformSubjectLinkUnavailable("upstream User status unavailable") from None
        now = datetime.now(UTC)
        if (
            not isinstance(verified, VerifiedRauthyUserStatus)
            or verified.issuer != issuer
            or verified.subject != subject
            or type(verified.active) is not bool
            or not isinstance(verified.expires_at, datetime)
            or verified.expires_at.tzinfo is None
            or not now < verified.expires_at <= now + timedelta(seconds=_MAX_STATUS_SECONDS)
        ):
            raise PlatformSubjectLinkUnavailable("upstream User status not current")
        if not verified.active:
            return None

        async with self._database.transaction() as session:
            link = await session.scalar(
                select(RauthyUserLinkRow).where(
                    RauthyUserLinkRow.issuer == issuer,
                    RauthyUserLinkRow.subject == subject,
                )
            )
            if link is None or not link.active:
                return None
            if (
                link.user_id.version != 4
                or link.version < 1
                or link.briareus_role not in {"user", "operator"}
            ):
                raise PlatformSubjectLinkUnavailable("Platform user link invalid")
            # Backend can only read this operator-provisioned role; neither
            # the IdP account/group nor cookie can upgrade the Platform role.
            result = CurrentRauthyUserLink(
                issuer=issuer,
                subject=subject,
                user_id=link.user_id,
                enabled=True,
                role=link.briareus_role,
                revision=link.version,
                expires_at=verified.expires_at,
                name=verified.name,
                email=verified.email,
            )

        if verified.expires_at <= datetime.now(UTC):
            raise PlatformSubjectLinkUnavailable("User status expired during DB projection")
        return result


@dataclass(frozen=True, slots=True)
class VerifiedOperatorEnrollment:
    """Already authenticated, scoped operator decision, NEVER browser JSON."""

    operation_uuid: UUID
    approver_uuid: UUID
    user_uuid: UUID
    issuer: str
    subject: str
    role: Literal["user", "operator"]
    can_manage_users: bool
    can_assign_operator: bool
    expires_at: datetime


class TrustedOperatorEnrollmentPort(Protocol):
    async def verify(self, evidence: object) -> VerifiedOperatorEnrollment:
        """Verify signed operator/admin authority from real current owner."""
        ...


class OperatorEnrollmentDenied(Exception):
    """Untrusted or insufficient operator authority for this User binding."""


class OperatorEnrollmentConflict(Exception):
    """A User ID or Rauthy subject is already bound incompatibly."""


class PlatformRauthyEnrollmentService:
    """Operator-only durable binding, not an open user signup endpoint."""

    def __init__(
        self,
        *,
        database: PlatformDatabase,
        decisions: TrustedOperatorEnrollmentPort,
        rauthy_status: TrustedRauthyUserStatusPort,
    ) -> None:
        if (
            database.engine.url.database != "briareus_platform"
            or decisions is None
            or rauthy_status is None
        ):
            raise ValueError("operator enrollment needs owner DB, proof and upstream")
        self._db = database
        self._decisions = decisions
        self._status = rauthy_status

    async def enroll(self, *, signed_evidence: object) -> CurrentRauthyUserLink:
        try:
            decision = await self._decisions.verify(signed_evidence)
        except Exception:
            raise OperatorEnrollmentDenied("verified operator enrollment required") from None
        now = datetime.now(UTC)
        if (
            not isinstance(decision, VerifiedOperatorEnrollment)
            or not isinstance(decision.operation_uuid, UUID)
            or decision.operation_uuid.version != 4
            or not isinstance(decision.approver_uuid, UUID)
            or decision.approver_uuid.version != 4
            or not isinstance(decision.user_uuid, UUID)
            or decision.user_uuid.version != 4
            or not decision.issuer.startswith("https://")
            or not 1 <= len(decision.issuer) <= 512
            or not 1 <= len(decision.subject) <= 256
            or decision.role not in {"user", "operator"}
            or decision.can_manage_users is not True
            or (
                decision.role == "operator"
                and (
                    decision.can_assign_operator is not True
                    or decision.approver_uuid == decision.user_uuid
                )
            )
            or not isinstance(decision.expires_at, datetime)
            or decision.expires_at.tzinfo is None
            or not now < decision.expires_at <= now + timedelta(seconds=30)
        ):
            raise OperatorEnrollmentDenied("fresh scoped operator approval unavailable")

        try:
            current = await self._status.current_status(
                issuer=decision.issuer, subject=decision.subject
            )
        except Exception:
            raise PlatformSubjectLinkUnavailable("upstream account status unavailable") from None
        now = datetime.now(UTC)
        if (
            not isinstance(current, VerifiedRauthyUserStatus)
            or current.issuer != decision.issuer
            or current.subject != decision.subject
            or current.active is not True
            or not isinstance(current.expires_at, datetime)
            or current.expires_at.tzinfo is None
            or not now < current.expires_at <= now + timedelta(seconds=30)
        ):
            raise OperatorEnrollmentDenied("current active Rauthy User required")

        # No external I/O while holding Platform database locks.
        from projects._control_ledger import OwnerAuditRow, OwnerOutboxRow

        async with self._db.transaction() as tx:
            row = await tx.scalar(
                select(RauthyUserLinkRow)
                .where(
                    RauthyUserLinkRow.issuer == decision.issuer,
                    RauthyUserLinkRow.subject == decision.subject,
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if row is not None:
                # Safe repeat of an existing exact enrollment, no reactivation.
                if (
                    row.user_id != decision.user_uuid
                    or row.briareus_role != decision.role
                    or not row.active
                ):
                    raise OperatorEnrollmentConflict("subject already bound to another User/role")
            else:
                row = RauthyUserLinkRow(
                    user_id=decision.user_uuid,
                    issuer=decision.issuer,
                    subject=decision.subject,
                    briareus_role=decision.role,
                    active=True,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                tx.add(row)
                await tx.flush()
                tx.add(
                    OwnerAuditRow(
                        operation_uuid=decision.operation_uuid,
                        actor_user_id=decision.approver_uuid,
                        project_id=None,
                        action="user.rauthy_linked",
                        object_id=str(decision.user_uuid),
                        owner_revision=f"rauthy-link-v{row.version}",
                        details={"role": decision.role},
                    )
                )
                tx.add(
                    OwnerOutboxRow(
                        operation_uuid=decision.operation_uuid,
                        event_name="user.rauthy_linked",
                        owner_revision=f"rauthy-link-v{row.version}",
                        event_payload={
                            "user_id": str(decision.user_uuid),
                            "revision": row.version,
                        },
                    )
                )
            # The Platform row lock and flush can consume the short-lived
            # independently signed operator proof or live Rauthy User status.
            # Abort the ENTIRE binding + audit + outbox transaction instead
            # of committing a newly privileged User on expired authority.
            commit_boundary = datetime.now(UTC)
            if decision.expires_at <= commit_boundary or current.expires_at <= commit_boundary:
                raise OperatorEnrollmentDenied(
                    "operator enrollment proof expired during Platform transaction"
                )
            result = CurrentRauthyUserLink(
                issuer=decision.issuer,
                subject=decision.subject,
                user_id=row.user_id,
                enabled=row.active,
                role=row.briareus_role,
                revision=row.version,
                expires_at=min(current.expires_at, decision.expires_at),
            )
        # Return only after the own-DB transaction commits its audit and outbox.
        return result  # noqa: RET504


@dataclass(frozen=True, slots=True)
class VerifiedOperatorSuspension:
    """Separate signed operator action; never a bearer-only target UUID."""

    operation_uuid: UUID
    approver_uuid: UUID
    target_user_uuid: UUID
    expected_link_version: int
    can_manage_users: bool
    expires_at: datetime


class TrustedOperatorSuspensionPort(Protocol):
    async def verify(self, evidence: object) -> VerifiedOperatorSuspension:
        """Verify independently scoped, current signed user-disable authority."""
        ...


class PlatformRauthySuspensionService:
    """Revoke Briareus User access without touching Rauthy IdP passwords."""

    def __init__(
        self, *, database: PlatformDatabase, decisions: TrustedOperatorSuspensionPort
    ) -> None:
        if database.engine.url.database != "briareus_platform" or decisions is None:
            raise ValueError("suspension requires own DB and trusted operator port")
        self._db = database
        self._decisions = decisions

    async def suspend(self, *, signed_evidence: object) -> int:
        try:
            decision = await self._decisions.verify(signed_evidence)
        except Exception:
            raise OperatorEnrollmentDenied("verified operator suspension required") from None
        now = datetime.now(UTC)
        if (
            not isinstance(decision, VerifiedOperatorSuspension)
            or not isinstance(decision.operation_uuid, UUID)
            or decision.operation_uuid.version != 4
            or not isinstance(decision.approver_uuid, UUID)
            or decision.approver_uuid.version != 4
            or not isinstance(decision.target_user_uuid, UUID)
            or decision.target_user_uuid.version != 4
            or type(decision.expected_link_version) is not int
            or decision.expected_link_version < 1
            or decision.can_manage_users is not True
            or not isinstance(decision.expires_at, datetime)
            or decision.expires_at.tzinfo is None
            or not now < decision.expires_at <= now + timedelta(seconds=30)
        ):
            raise OperatorEnrollmentDenied("current signed suspension scope invalid")

        from projects._control_ledger import OwnerAuditRow, OwnerOutboxRow

        async with self._db.transaction() as tx:
            row = await tx.scalar(
                select(RauthyUserLinkRow)
                .where(RauthyUserLinkRow.user_id == decision.target_user_uuid)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if row is None or not row.active or row.version != decision.expected_link_version:
                raise OperatorEnrollmentConflict("User link already changed or unavailable")
            if row.briareus_role == "operator":
                # Disabling existing operators requires a distinct owner-reviewed
                # last-operator/recovery contract, not the generic users scope.
                raise OperatorEnrollmentDenied("operator suspension needs separate recovery gate")
            # Revalidate AFTER waiting for the target User row lock.
            # An expired signed suspension order may not mutate grants.
            if decision.expires_at <= datetime.now(UTC):
                raise OperatorEnrollmentDenied(
                    "signed suspension proof expired during Platform lock wait"
                )
            row.active = False
            row.version += 1
            row.updated_at = datetime.now(UTC)
            tx.add(
                OwnerAuditRow(
                    operation_uuid=decision.operation_uuid,
                    actor_user_id=decision.approver_uuid,
                    project_id=None,
                    action="user.rauthy_link_suspended",
                    object_id=str(row.user_id),
                    owner_revision=f"rauthy-link-v{row.version}",
                    details={},
                )
            )
            tx.add(
                OwnerOutboxRow(
                    operation_uuid=decision.operation_uuid,
                    event_name="user.rauthy_link_suspended",
                    owner_revision=f"rauthy-link-v{row.version}",
                    event_payload={"user_id": str(row.user_id), "revision": row.version},
                )
            )
            if decision.expires_at <= datetime.now(UTC):
                raise OperatorEnrollmentDenied(
                    "signed suspension proof expired before Platform commit"
                )
            return row.version
