"""Projects owns the exclusive User/Team owner reference."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import ControlBase


class ProjectRow(ControlBase):
    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint(
            "(owner_user_id IS NOT NULL) <> (owner_team_id IS NOT NULL)",
            name="ck_project_exclusive_owner",
        ),
        CheckConstraint(
            "lifecycle_status IN ('active','deleting','deleted')",
            name="ck_project_lifecycle_status",
        ),
        Index("ix_project_owner_user", "owner_user_id"),
        Index("ix_project_owner_team", "owner_team_id"),
        {"schema": "projects"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255))
    lifecycle_status: Mapped[str] = mapped_column(
        String(12), default="active", server_default="active", nullable=False
    )
    owner_user_id: Mapped[UUID | None] = mapped_column()
    owner_team_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("teams.teams.id", ondelete="RESTRICT")
    )
    resource_revision: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
