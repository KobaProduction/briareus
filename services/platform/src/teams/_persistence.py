"""Teams owns Team and membership rows (separate from Project ownership)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from common.platform_db import ControlBase


class TeamRow(ControlBase):
    __tablename__ = "teams"
    __table_args__ = {"schema": "teams"}  # noqa: RUF012
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255))
    owner_user_id: Mapped[UUID] = mapped_column(index=True)
    resource_revision: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class TeamMembershipRow(ControlBase):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("team_id", "user_id", name="uq_team_membership_user"),
        Index("ix_membership_user_active", "user_id", "active"),
        {"schema": "teams"},
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    team_id: Mapped[UUID] = mapped_column(
        ForeignKey("teams.teams.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[UUID] = mapped_column()
    active: Mapped[bool] = mapped_column(Boolean, default=True)
