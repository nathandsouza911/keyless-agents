"""tenants: the Entra tenants registered with the workbench.

`id` is the Entra tenant ID (lowercase GUID). Sign-in is refused for a tenant
that is not registered or not `active` (SD-029). The migration
20261020_tenants_users is the source of truth for constraints.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from clw.db.base import Base

GUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint(f"id ~ '{GUID_PATTERN}'", name="ck_tenants_id_guid"),
        CheckConstraint("status IN ('active', 'disabled')", name="ck_tenants_status"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
