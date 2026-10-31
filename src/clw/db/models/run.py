"""runs: one row per task run (Task 12, SD-032).

The tenant, task, manifest digest, profile (id, version, digest), mode and
actor are fixed when the run is created; the migration's guard trigger
refuses any later change to them, refuses leaving a terminal status, and
allows only the lifecycle transitions below. The run token is stored as its
SHA-256 only. The migration 20261021_runs is the source of truth for
constraints.

  queued  -> running | failed
  running -> halted | completed | failed | timed_out
  halted  -> failed | timed_out
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from clw.db.base import Base

RUN_STATUSES = ("queued", "running", "halted", "completed", "failed", "timed_out")
TERMINAL_STATUSES = ("completed", "failed", "timed_out")


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False)
    task_id: Mapped[str] = mapped_column(Text, nullable=False)
    task_manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_id: Mapped[str] = mapped_column(Text, nullable=False)
    profile_version: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    auth_mode: Mapped[str] = mapped_column(Text, nullable=False)
    actor_user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("workbench_users.id"), nullable=False)
    actor_oid: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_tid: Mapped[str] = mapped_column(String(36), nullable=False)
    params: Mapped[dict] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    run_token_sha256: Mapped[str | None] = mapped_column(String(64), unique=True)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict | None] = mapped_column(JSONB)
    outcome: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set once, by the redaction procedure, when result is cleared (SD-037; 20261025_result_redaction).
    result_redacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # 'task' (a built-in task) or 'script' (an approved script; SD-043, 20261103_scripts).
    kind: Mapped[str] = mapped_column(Text, nullable=False, server_default="task")
    script_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("scripts.id"))
    approval_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("script_approvals.id"))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
