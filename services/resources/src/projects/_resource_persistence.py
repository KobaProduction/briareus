"""Scoped reusable resources; independent aggregate with Team OR Project FK.

Resource storage is a separate schema. Team and Project stay separate domain
aggregates, connected only by validated references and application ports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import CatalogBase


class ResourceOwnerColumns:
    owner_team_id: Mapped[UUID | None] = mapped_column(nullable=True)
    owner_project_id: Mapped[UUID | None] = mapped_column(nullable=True)


OWNER_XOR = "(owner_team_id IS NOT NULL) <> (owner_project_id IS NOT NULL)"


class IntegrationRow(ResourceOwnerColumns, CatalogBase):
    __tablename__ = "integrations"
    __table_args__ = (
        CheckConstraint(OWNER_XOR, name="ck_integration_owner_xor"),
        Index(
            "uq_integration_team_alias",
            "owner_team_id",
            "alias_key",
            unique=True,
            postgresql_where=text("owner_team_id IS NOT NULL AND deleted_at IS NULL"),
        ),
        Index(
            "uq_integration_project_alias",
            "owner_project_id",
            "alias_key",
            unique=True,
            postgresql_where=text("owner_project_id IS NOT NULL AND deleted_at IS NULL"),
        ),
        Index("ix_integration_provider", "provider", "auth_type"),
        {"schema": "resources"},
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    alias: Mapped[str] = mapped_column(String(128))
    alias_key: Mapped[str] = mapped_column(String(128))
    provider: Mapped[str] = mapped_column(String(32))
    auth_type: Mapped[str] = mapped_column(String(32))
    provider_settings: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    encrypted_credential: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CredentialLeaseRow(CatalogBase):
    """DB-enforced single-use, version-fenced handle. NEVER a bearer for end users."""

    __tablename__ = "credential_leases"
    __table_args__ = (
        CheckConstraint("kind IN ('integration','variable')", name="ck_lease_resource_kind"),
        CheckConstraint(
            "(service_id IS NULL AND service_instance_uuid IS NULL AND operation_uuid IS NULL)"
            " OR (service_id IS NOT NULL AND service_instance_uuid IS NOT NULL"
            " AND operation_uuid IS NOT NULL)",
            name="ck_lease_service_operation_owner",
        ),
        UniqueConstraint(
            "project_id",
            "service_id",
            "service_instance_uuid",
            "operation_uuid",
            name="uq_credential_service_operation",
        ),
        Index("ix_credential_lease_expiry", "expires_at"),
        {"schema": "resources"},
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column()
    user_id: Mapped[UUID] = mapped_column()
    session_uuid: Mapped[UUID] = mapped_column()
    resource_id: Mapped[UUID] = mapped_column(nullable=False)
    kind: Mapped[str] = mapped_column(String(16))
    owner_scope: Mapped[str] = mapped_column(String(16))
    owner_id: Mapped[UUID] = mapped_column(nullable=False)
    resource_version: Mapped[int] = mapped_column(Integer)
    # Service-bound leases are never redeemable by the legacy in-process
    # User-only private port. Both service and delegation must be live.
    service_id: Mapped[UUID | None] = mapped_column(nullable=True)
    service_instance_uuid: Mapped[UUID | None] = mapped_column(nullable=True)
    operation_uuid: Mapped[UUID | None] = mapped_column(nullable=True)
    service_audience: Mapped[str | None] = mapped_column(String(64))
    correlation_id: Mapped[UUID | None] = mapped_column()
    project_state_hash: Mapped[str] = mapped_column(String(64))
    project_resource_revision: Mapped[int] = mapped_column(Integer)
    team_state_hash: Mapped[str | None] = mapped_column(String(64))
    team_resource_revision: Mapped[int | None] = mapped_column(Integer)
    session_version: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    redeemed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VariableRow(ResourceOwnerColumns, CatalogBase):
    __tablename__ = "variables"
    __table_args__ = (
        CheckConstraint(OWNER_XOR, name="ck_variable_owner_xor"),
        CheckConstraint(
            "(is_secret AND encrypted_value IS NOT NULL AND plain_value IS NULL)"
            " OR (NOT is_secret AND encrypted_value IS NULL AND plain_value IS NOT NULL)",
            name="ck_variable_secret_storage",
        ),
        Index(
            "uq_variable_team_key",
            "owner_team_id",
            "name_key",
            unique=True,
            postgresql_where=text("owner_team_id IS NOT NULL AND deleted_at IS NULL"),
        ),
        Index(
            "uq_variable_project_key",
            "owner_project_id",
            "name_key",
            unique=True,
            postgresql_where=text("owner_project_id IS NOT NULL AND deleted_at IS NULL"),
        ),
        {"schema": "resources"},
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name_key: Mapped[str] = mapped_column(String(128))
    plain_value: Mapped[str | None] = mapped_column(Text)
    encrypted_value: Mapped[str | None] = mapped_column(Text)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExternalOperationRow(CatalogBase):
    """One irreversible provider effect per explicit operation identity.

    A recorded 'dispatched' or 'unknown' outcome MUST NOT auto-execute again.
    """

    __tablename__ = "external_operations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('reserved', 'dispatched', 'succeeded', 'unknown')",
            name="ck_external_operation_status",
        ),
        UniqueConstraint(
            "actor_id",
            "project_id",
            "operation",
            "idempotency_digest",
            name="uq_external_operation_identity",
        ),
        UniqueConstraint(
            "project_id",
            "service_id",
            "instance_uuid",
            "operation_uuid",
            name="uq_external_service_operation",
        ),
        Index("ix_external_unknown", "status", "created_at"),
        Index(
            "uq_external_uncertain_effect",
            "project_id",
            "resource_id",
            "operation",
            "request_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('dispatched','unknown')"),
        ),
        {"schema": "resources"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    actor_id: Mapped[UUID] = mapped_column()
    project_id: Mapped[UUID] = mapped_column()
    session_uuid: Mapped[UUID] = mapped_column()
    resource_id: Mapped[UUID] = mapped_column(
        ForeignKey("resources.integrations.id", ondelete="RESTRICT")
    )
    resource_version: Mapped[int] = mapped_column(Integer)
    service_id: Mapped[UUID] = mapped_column(nullable=False)
    instance_uuid: Mapped[UUID] = mapped_column(nullable=False)
    operation_uuid: Mapped[UUID] = mapped_column(nullable=False)
    operation: Mapped[str] = mapped_column(String(128))
    idempotency_digest: Mapped[str] = mapped_column(String(64))
    request_fingerprint: Mapped[str] = mapped_column(String(64))
    result_sha256: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="reserved")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
