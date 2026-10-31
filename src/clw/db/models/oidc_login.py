"""oidc_logins: one row per started sign-in, claimed at most once (SD-029).

Only SHA-256 hashes are stored: of the `state` sent to Microsoft, of the
`nonce` sent to Microsoft, and of the browser-binding value kept in the
HttpOnly login cookie. Nothing here lets a database reader complete a
sign-in. The migration 20261020_tenants_users is the source of truth for
constraints.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from clw.db.base import Base

_HEX64 = "^[0-9a-f]{64}$"


class OidcLogin(Base):
    __tablename__ = "oidc_logins"
    __table_args__ = (
        CheckConstraint(f"state_hash ~ '{_HEX64}'", name="ck_oidc_logins_state_hash"),
        CheckConstraint(f"nonce_hash ~ '{_HEX64}'", name="ck_oidc_logins_nonce_hash"),
        CheckConstraint(f"binding_hash ~ '{_HEX64}'", name="ck_oidc_logins_binding_hash"),
    )

    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    binding_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
