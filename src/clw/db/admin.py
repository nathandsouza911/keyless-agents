"""Operator commands on the database, run with the owner role (SD-038).

provision_roles   create or update the api, broker and runner roles from the
                  database URLs those services use (the URL is the single
                  place a component's credential lives), with exactly the
                  privileges in clw.db.roles: every earlier privilege of the
                  role in this database is revoked first, so re-running
                  leaves it exact. A password change takes effect at once.
add_tenant        register an Entra tenant (sign-in is refused otherwise)
add_member        give (tenant, oid) workbench membership with a role

Nothing here prints or logs a password.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.db.roles import COMPONENTS, Component, grant_statements, identifier

_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_ROLES = ("analyst", "security_lead")


class AdminRefused(Exception):
    """Nothing was changed. The message says why (never a secret)."""


@dataclass(frozen=True, slots=True)
class Credential:
    component: Component
    role: str
    password: str  # never printed

    def __repr__(self) -> str:
        return f"Credential({self.component!r}, role={self.role!r})"


def credential_from_url(component: Component, url: str) -> Credential:
    parts = urlsplit(url)
    if not parts.scheme.startswith("postgresql") or not parts.username or not parts.password:
        raise AdminRefused(f"{component}: database URL needs a postgresql scheme, a user and a password")
    role = unquote(parts.username)
    try:
        identifier(role)
    except ValueError:
        raise AdminRefused(f"{component}: role name must be lowercase letters, digits and '_'") from None
    password = unquote(parts.password)
    if len(password) < 16:
        raise AdminRefused(f"{component}: password must be at least 16 characters")
    return Credential(component, role, password)


async def provision_roles(sessionmaker: async_sessionmaker[AsyncSession], credentials: list[Credential]) -> list[str]:
    """The roles provisioned, in order. All or nothing (one transaction)."""
    if sorted(c.component for c in credentials) != sorted(COMPONENTS):
        raise AdminRefused("give exactly one credential for each of api, broker and runner")
    if len({c.role for c in credentials}) != len(credentials):
        raise AdminRefused("each component needs its own role")
    async with sessionmaker() as session:
        async with session.begin():
            owner, database = (await session.execute(text("SELECT current_user, current_database()"))).one()
            database = identifier(database)
            for cred in credentials:
                if cred.role == owner:
                    raise AdminRefused(f"{cred.component}: must not use the owner role")
                attrs = (await session.execute(text(
                    "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls FROM pg_roles WHERE rolname = :r"),
                    {"r": cred.role})).first()
                if attrs is not None and any(attrs):
                    raise AdminRefused(f"{cred.component}: role {cred.role} has administrative attributes")
                verb = "CREATE ROLE %I LOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L"                     if attrs is None else "ALTER ROLE %I LOGIN NOINHERIT PASSWORD %L"
                await _set_password(session, cred, verb)
                # Only where the role holds something (table or column ACL): a blanket
                # REVOKE would turn every default privilege list into an explicit one.
                held = (await session.execute(text(
                    "SELECT DISTINCT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attacl IS NOT NULL "
                    "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') "
                    "AND (EXISTS (SELECT 1 FROM aclexplode(c.relacl) x WHERE x.grantee = to_regrole(:r)) "
                    "  OR EXISTS (SELECT 1 FROM aclexplode(a.attacl) y WHERE y.grantee = to_regrole(:r)))"),
                    {"r": cred.role})).scalars().all()
                for relation in held:
                    await session.execute(text(f'REVOKE ALL ON TABLE public."{identifier(relation)}" FROM {cred.role}'))
                await session.execute(text(f"REVOKE ALL ON SCHEMA public FROM {cred.role}"))
                await session.execute(text(f'REVOKE ALL ON DATABASE "{database}" FROM {cred.role}'))
                for grant in grant_statements(cred.component, role=cred.role, database=database):
                    await session.execute(text(grant))
    return [c.role for c in credentials]


async def _set_password(session: AsyncSession, cred: Credential, verb: str) -> None:
    """CREATE/ALTER ROLE with the password. Any database error is replaced by a
    fixed message: SQLAlchemy errors quote the statement and its parameters,
    which hold the password."""
    failed = False
    try:
        statement = (await session.execute(
            text("SELECT format(CAST(:f AS text), CAST(:r AS text), CAST(:p AS text))"),
            {"f": verb, "r": cred.role, "p": cred.password})).scalar_one()
        # Raw driver SQL: text() would read a ':' in the password as a bind parameter.
        await (await session.connection()).exec_driver_sql(statement)
    except Exception:  # noqa: BLE001 - never let the error text (and the password) out
        failed = True
    if failed:
        raise AdminRefused(f"{cred.component}: the database refused to create or update role {cred.role}")


def _guid(name: str, value: str) -> str:
    if not (isinstance(value, str) and _GUID.match(value)):
        raise AdminRefused(f"{name} must be a lowercase GUID")
    return value


async def add_tenant(sessionmaker: async_sessionmaker[AsyncSession], *, tenant_id: str, display_name: str) -> bool:
    """True if created, False if it was already registered (unchanged)."""
    tenant_id = _guid("tenant", tenant_id)
    if not (isinstance(display_name, str) and 0 < len(display_name) <= 200 and display_name.isprintable()):
        raise AdminRefused("name must be 1 to 200 printable characters")
    async with sessionmaker() as session:
        async with session.begin():
            created = (await session.execute(text(
                "INSERT INTO tenants (id, display_name, status) VALUES (:t, :n, 'active') "
                "ON CONFLICT (id) DO NOTHING RETURNING id"), {"t": tenant_id, "n": display_name})).first()
    return created is not None


async def add_member(sessionmaker: async_sessionmaker[AsyncSession], *, tenant_id: str, oid: str, role: str) -> bool:
    """True if created, False if (tenant, oid) was already a member (unchanged)."""
    tenant_id, oid = _guid("tenant", tenant_id), _guid("oid", oid)
    if role not in _ROLES:
        raise AdminRefused("role must be analyst or security_lead")
    async with sessionmaker() as session:
        async with session.begin():
            if (await session.execute(text("SELECT 1 FROM tenants WHERE id = :t"), {"t": tenant_id})).first() is None:
                raise AdminRefused("tenant is not registered (tenant-add first)")
            created = (await session.execute(text(
                "INSERT INTO workbench_users (id, tenant_id, oid, role) VALUES (:u, :t, :o, :r) "
                "ON CONFLICT (tenant_id, oid) DO NOTHING RETURNING id"),
                {"u": uuid.uuid4(), "t": tenant_id, "o": oid, "r": role})).first()
    return created is not None
