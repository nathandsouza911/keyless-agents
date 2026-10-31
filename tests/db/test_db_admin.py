"""Operator database commands (SD-038): role provisioning from the shared
definition (clw.db.roles), and tenant/member registration."""

from __future__ import annotations

import asyncio
import json
import secrets
import uuid

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.cli import FAILED, OK, main
from clw.db import admin
from tests.db.conftest import TEST_DB, _dsn_for

pytestmark = pytest.mark.pg


@pytest.fixture
async def owner_maker(pg_dsn):
    engine = create_async_engine(pg_dsn.replace("postgresql://", "postgresql+asyncpg://", 1))
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest.fixture
async def creds(admin_conn):
    suffix = uuid.uuid4().hex[:8]
    made = {c: admin.Credential(c, f"prov_{c}_{suffix}", secrets.token_urlsafe(24)) for c in ("api", "broker", "runner")}
    yield made
    for cred in made.values():
        if await admin_conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", cred.role):
            await admin_conn.execute(f"DROP OWNED BY {cred.role}")
            await admin_conn.execute(f"DROP ROLE {cred.role}")


async def _as(cred: admin.Credential, password: str | None = None):
    return await asyncpg.connect(_dsn_for(TEST_DB, user=cred.role, password=password or cred.password))


async def _can(conn, sql: str) -> bool:
    try:
        async with conn.transaction():
            await conn.execute(sql)
            raise _Rollback
    except _Rollback:
        return True
    except asyncpg.InsufficientPrivilegeError:
        return False


class _Rollback(Exception):
    pass


CHECKS = {
    "read tenants": "SELECT 1 FROM tenants",
    "read memberships": "SELECT 1 FROM workbench_users",
    "start a sign-in": "INSERT INTO oidc_logins (state_hash, nonce_hash, binding_hash) "
                       "VALUES (repeat('a', 64), repeat('b', 64), repeat('c', 64))",
    "read runs": "SELECT 1 FROM runs",
    "end a run": "UPDATE runs SET status = status WHERE false",
    "store a result": "UPDATE runs SET result = result WHERE false",
    "set a deadline": "UPDATE runs SET deadline_at = deadline_at WHERE false",
    "redact": "UPDATE runs SET result_redacted_at = result_redacted_at WHERE false",
    "insert a run token": "INSERT INTO runs (id, run_token_sha256) VALUES (gen_random_uuid(), repeat('a', 64))",
    "read audit": "SELECT 1 FROM audit_events",
    "add a tenant": "INSERT INTO tenants (id, display_name, status) VALUES ('x', 'x', 'active')",
    "create a table": "CREATE TABLE public.planted (x int)",
    "read value keys": "SELECT 1 FROM audit_value_keys",
}
EXPECTED = {
    "api": {"read tenants", "read memberships", "start a sign-in", "read runs", "read audit"},
    "broker": {"read runs", "end a run", "read audit", "read value keys"},
    "runner": {"read runs", "end a run", "store a result", "set a deadline", "read audit"},
}


async def _privileges(cred) -> set[str]:
    conn = await _as(cred)
    try:
        return {name for name, sql in CHECKS.items() if await _can(conn, sql)}
    finally:
        await conn.close()


async def test_each_role_gets_exactly_its_components_privileges(owner_maker, creds):
    assert await admin.provision_roles(owner_maker, list(creds.values())) == [c.role for c in creds.values()]
    for component, cred in creds.items():
        assert await _privileges(cred) == EXPECTED[component], component


async def test_reprovisioning_rotates_the_password_and_removes_stray_privileges(admin_conn, owner_maker, creds):
    await admin.provision_roles(owner_maker, list(creds.values()))
    broker = creds["broker"]
    await admin_conn.execute(f"GRANT SELECT, INSERT ON tenants TO {broker.role}")  # drift
    rotated = admin.Credential("broker", broker.role, secrets.token_urlsafe(24))
    await admin.provision_roles(owner_maker, [creds["api"], rotated, creds["runner"]])
    with pytest.raises(asyncpg.InvalidPasswordError):
        await _as(broker)
    assert await _privileges(rotated) == EXPECTED["broker"]


async def test_the_roles_have_no_administrative_attributes(admin_conn, owner_maker, creds):
    await admin.provision_roles(owner_maker, list(creds.values()))
    rows = await admin_conn.fetch(
        "SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolinherit, rolcanlogin "
        "FROM pg_roles WHERE rolname = ANY($1)", [c.role for c in creds.values()])
    assert [tuple(r) for r in rows] == [(False, False, False, False, False, False, True)] * 3


@pytest.mark.parametrize("problem", ["missing", "duplicate", "owner"])
async def test_provisioning_refuses_bad_input_and_changes_nothing(admin_conn, owner_maker, creds, problem):
    given = list(creds.values())
    if problem == "missing":
        given = given[:2]
    elif problem == "duplicate":
        given[1] = admin.Credential("broker", given[0].role, given[1].password)
    else:
        owner = await admin_conn.fetchval("SELECT current_user")
        given[2] = admin.Credential("runner", owner, given[2].password)
    with pytest.raises(admin.AdminRefused):
        await admin.provision_roles(owner_maker, given)
    assert not await admin_conn.fetchval("SELECT count(*) FROM pg_roles WHERE rolname = ANY($1)",
                                         [creds["api"].role, creds["broker"].role])


async def test_provisioning_refuses_a_role_with_administrative_attributes(admin_conn, owner_maker, creds):
    await admin_conn.execute(f"CREATE ROLE {creds['runner'].role} LOGIN CREATEROLE")
    with pytest.raises(admin.AdminRefused, match="administrative"):
        await admin.provision_roles(owner_maker, list(creds.values()))


@pytest.mark.parametrize("url, match", [
    ("mysql://u:p@h/db", "postgresql"), ("postgresql+asyncpg://h/db", "user and a password"),
    ("postgresql+asyncpg://Bad-Name:aaaaaaaaaaaaaaaaaaaa@h/db", "lowercase"),
    ("postgresql+asyncpg://ok_role:short@h/db", "16 characters"),
])
def test_credentials_come_only_from_well_formed_urls(url, match):
    with pytest.raises(admin.AdminRefused, match=match):
        admin.credential_from_url("api", url)


def test_a_credential_never_shows_its_password():
    cred = admin.credential_from_url("api", "postgresql+asyncpg://ok_role:s3cret-password-xyz%3A1@h/db")
    assert cred.password == "s3cret-password-xyz:1" and "s3cret" not in repr(cred)


# ------------------------------------------------------------ tenants, members


async def test_tenant_and_member_registration_is_idempotent(admin_conn, owner_maker):
    tid, oid = str(uuid.uuid4()), str(uuid.uuid4())
    assert await admin.add_tenant(owner_maker, tenant_id=tid, display_name="Dev tenant") is True
    assert await admin.add_tenant(owner_maker, tenant_id=tid, display_name="Other name") is False
    assert await admin.add_member(owner_maker, tenant_id=tid, oid=oid, role="analyst") is True
    assert await admin.add_member(owner_maker, tenant_id=tid, oid=oid, role="security_lead") is False
    row = await admin_conn.fetchrow("SELECT t.display_name, t.status, u.role FROM tenants t "
                                    "JOIN workbench_users u ON u.tenant_id = t.id WHERE t.id = $1", tid)
    assert tuple(row) == ("Dev tenant", "active", "analyst")  # existing rows are never changed


@pytest.mark.parametrize("kwargs, match", [
    ({"tenant_id": "NOT-A-GUID", "oid": str(uuid.uuid4()), "role": "analyst"}, "tenant"),
    ({"tenant_id": str(uuid.uuid4()), "oid": "x", "role": "analyst"}, "oid"),
    ({"tenant_id": str(uuid.uuid4()), "oid": str(uuid.uuid4()), "role": "admin"}, "role"),
    ({"tenant_id": str(uuid.uuid4()), "oid": str(uuid.uuid4()), "role": "analyst"}, "not registered"),
])
async def test_bad_members_are_refused(owner_maker, kwargs, match):
    with pytest.raises(admin.AdminRefused, match=match):
        await admin.add_member(owner_maker, **kwargs)


@pytest.fixture
def cli_env(monkeypatch, pg_dsn):
    from clw.common import config
    from clw.db import session

    monkeypatch.setenv("DATABASE_URL", pg_dsn.replace("postgresql://", "postgresql+asyncpg://", 1))
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()
    yield monkeypatch
    config.get_settings.cache_clear()
    session.get_sessionmaker.cache_clear()


async def test_the_cli_provisions_from_the_service_urls(cli_env, creds, capsys):
    for component, cred in creds.items():
        cli_env.setenv(f"CLW_{component.upper()}_DATABASE_URL",
                       f"postgresql+asyncpg://{cred.role}:{cred.password}@postgres:5432/clw")
    assert await asyncio.to_thread(main, ["db-provision-roles"]) == OK
    out = capsys.readouterr().out
    assert json.loads(out) == {"provisioned": [c.role for c in creds.values()]}
    assert all(c.password not in out for c in creds.values())
    assert await _privileges(creds["api"]) == EXPECTED["api"]


async def test_the_cli_registers_tenants_and_members(cli_env, capsys):
    tid, oid = str(uuid.uuid4()), str(uuid.uuid4())
    assert await asyncio.to_thread(main, ["tenant-add", "--tenant", tid, "--name", "Dev"]) == OK
    assert await asyncio.to_thread(main, ["member-add", "--tenant", tid, "--oid", oid, "--role", "analyst"]) == OK
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["created"] is True
    assert await asyncio.to_thread(main, ["member-add", "--tenant", str(uuid.uuid4()), "--oid", oid,
                                          "--role", "analyst"]) == FAILED


async def test_a_database_error_never_reveals_the_password(owner_maker, creds, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncConnection

    async def refuse(self, statement, *args, **kwargs):
        raise RuntimeError(f"boom: {statement}")  # an error that quotes the statement, password included

    monkeypatch.setattr(AsyncConnection, "exec_driver_sql", refuse)
    with pytest.raises(admin.AdminRefused) as raised:
        await admin.provision_roles(owner_maker, list(creds.values()))
    rendered = f"{raised.value!s} {raised.value!r} {raised.value.__context__!r} {raised.value.__cause__!r}"
    assert creds["api"].password not in rendered
