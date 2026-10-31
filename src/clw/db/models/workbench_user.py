"""workbench_users: who may sign in, per tenant, and with which role.

A person is identified by (tenant_id, oid) from a verified ID token; `id` is
the internal user ID carried as the session `sub`. The migration
20261020_tenants_users is the source of truth for constraints.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from clw.db.base import Base
from clw.db.models.tenant import GUID_PATTERN


class WorkbenchUser(Base):
    __tablename__ = "workbench_users"
    __table_args__ = (
        UniqueConstraint("tenant_id", "oid", name="uq_workbench_users_tenant_oid"),
        CheckConstraint(f"oid ~ '{GUID_PATTERN}'", name="ck_workbench_users_oid_guid"),
        CheckConstraint("role IN ('analyst', 'security_lead')", name="ck_workbench_users_role"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False)
    oid: Mapped[str] = mapped_column(String(36), nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
