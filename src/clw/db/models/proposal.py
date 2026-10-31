"""change_proposals (v0.1, SD-054): a change an agent asked for, never executed in v0.1.

The migration 20261105_change_proposals is the source of truth for the
constraints and guards: written by the broker for a running agent session of
the same tenant only, and never changed. The binding is target_id and
request_sha256; the target_* columns are a display snapshot of tenant data.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from clw.db.base import Base


class ChangeProposal(Base):
    __tablename__ = "change_proposals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("runs.id"), nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    operation: Mapped[str] = mapped_column(Text, nullable=False)
    target_id: Mapped[str] = mapped_column(String(36), nullable=False)
    request: Mapped[dict] = mapped_column(JSONB, nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_reason: Mapped[str] = mapped_column(Text, nullable=False)
    lookup_status: Mapped[str] = mapped_column(Text, nullable=False)
    target_display_name: Mapped[str | None] = mapped_column(Text)
    target_upn: Mapped[str | None] = mapped_column(Text)
    target_account_enabled: Mapped[bool | None] = mapped_column(Boolean)
    looked_up_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
