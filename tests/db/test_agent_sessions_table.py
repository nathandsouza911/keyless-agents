"""Agent sessions in the runs table (migration 20261104_agent_sessions, SD-049).

The api starts and ends agent sessions only through two SECURITY DEFINER
functions that touch agent-session rows only. These tests run as a role
provisioned with the api's grants alone (clw.db.roles), so they prove what
the api itself can and cannot do: in particular, it cannot end, start or
otherwise change a task or script run.
"""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import timedelta

import asyncpg
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from clw.audit.writer import AuditWriter
from clw.db import admin
from tests.db.broker_fixtures import MANIFEST, add_tenant, start_run
from tests.db.conftest import TEST_DB, _dsn_for

pytestmark = pytest.mark.pg

_RANDOM = object()
REFUSED = (asyncpg.exceptions.CheckViolationError, asyncpg.exceptions.ForeignKeyViolationError,
           asyncpg.exceptions.UniqueViolationError, asyncpg.exceptions.NotNullViolationError)


@pytest.fixture
async def roles(pg_dsn, admin_conn):
    """Freshly provisioned api, broker and runner roles; yields connections as each."""
    engine = create_async_engine(pg_dsn.replace("postgresql://", "postgresql+asyncpg://", 1))
    maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    suffix = uuid.uuid4().hex[:8]
    creds = [admin.Credential(c, f"as_{c}_{suffix}", secrets.token_urlsafe(24)) for c in ("api", "broker", "runner")]
    await admin.provision_roles(maker, creds)
    conns = {c.component: await asyncpg.connect(_dsn_for(TEST_DB, user=c.role, password=c.password)) for c in creds}
    yield conns
    for conn in conns.values():
        await conn.close()
    for cred in creds:
        await admin_conn.execute(f"DROP OWNED BY {cred.role}")
        await admin_conn.execute(f"DROP ROLE {cred.role}")
    await engine.dispose()


@pytest.fixture
async def api(roles):
    return roles["api"]


async def _start(conn, tenant, *, ttl: int = 3600, token_hash=_RANDOM, session_id=None, actor=None):
    tid, user_id, oid = tenant
    if token_hash is _RANDOM:
        token_hash = secrets.token_hex(32)
    if actor is not None:
        user_id, oid = actor
    session_id = session_id or uuid.uuid4()
    deadline = await conn.fetchval(
        "SELECT clw_start_agent_session($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        session_id, tid, MANIFEST.id, MANIFEST.sha256, MANIFEST.profile.id, MANIFEST.profile.version,
        MANIFEST.profile.sha256, "app_only", user_id, oid, token_hash, ttl)
    return session_id, deadline


async def _end(conn, run_id, tid, status="completed", outcome="revoked") -> bool:
    return await conn.fetchval("SELECT clw_end_agent_session($1, $2, $3, $4)", run_id, tid, status, outcome)


async def _row(admin_conn, run_id):
    return await admin_conn.fetchrow("SELECT * FROM runs WHERE id = $1", run_id)


# --- starting ------------------------------------------------------------------

async def test_the_api_starts_a_session_already_running_with_its_deadline(api, admin_conn):
    tenant, token_hash = await add_tenant(admin_conn), secrets.token_hex(32)
    session_id, deadline = await _start(api, tenant, ttl=3600, token_hash=token_hash)
    row = await _row(admin_conn, session_id)
    assert (row["kind"], row["status"], row["run_token_sha256"]) == ("agent_session", "running", token_hash)
    assert row["deadline_at"] == deadline
    assert row["deadline_at"] - row["started_at"] == timedelta(seconds=3600)
    assert (row["tenant_id"], row["actor_tid"], row["actor_oid"]) == (tenant[0], tenant[0], tenant[2])
    assert json.loads(row["params"]) == {} and row["script_id"] is None and row["approval_id"] is None


@pytest.mark.parametrize("ttl", [60, 8 * 3600])
async def test_the_ttl_bounds_are_inclusive(api, admin_conn, ttl):
    await _start(api, await add_tenant(admin_conn), ttl=ttl)


@pytest.mark.parametrize("ttl", [59, 8 * 3600 + 1, 0, -60, None])
async def test_a_ttl_outside_one_minute_to_eight_hours_is_refused(api, admin_conn, ttl):
    with pytest.raises(REFUSED):
        await _start(api, await add_tenant(admin_conn), ttl=ttl)


@pytest.mark.parametrize("token_hash", [None, "not-hex", "E" * 64])
async def test_a_session_needs_a_valid_token_hash(api, admin_conn, token_hash):
    with pytest.raises(REFUSED):
        await _start(api, await add_tenant(admin_conn), token_hash=token_hash)


async def test_the_actor_must_be_a_member_of_the_sessions_tenant(api, admin_conn):
    tenant, other = await add_tenant(admin_conn), await add_tenant(admin_conn)
    with pytest.raises(REFUSED):
        await _start(api, tenant, actor=(other[1], other[2]))


async def test_a_capability_hash_cannot_be_reused_by_a_second_session(api, admin_conn):
    tenant, token_hash = await add_tenant(admin_conn), secrets.token_hex(32)
    await _start(api, tenant, token_hash=token_hash)
    with pytest.raises(REFUSED):
        await _start(api, tenant, token_hash=token_hash)


# --- what the api cannot do -------------------------------------------------------

@pytest.mark.parametrize("assignment", [
    "status = 'failed', outcome = 'x', run_token_sha256 = NULL, ended_at = now()",
    "status = 'completed'", "run_token_sha256 = NULL", f"run_token_sha256 = '{'a' * 64}'",
    "deadline_at = now() + interval '1 day'", "outcome = 'x'", "result = '{}'::jsonb",
])
async def test_the_api_cannot_update_any_run(api, admin_conn, sessionmaker, assignment):
    tenant = await add_tenant(admin_conn)
    task_run, _ = await start_run(admin_conn, AuditWriter(sessionmaker), tenant)
    session_id, _ = await _start(api, tenant)
    for run_id in (uuid.UUID(task_run), session_id):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await api.execute(f"UPDATE runs SET {assignment} WHERE id = $1", run_id)


async def test_the_api_cannot_insert_a_running_run_or_a_token(api, admin_conn):
    tid, user_id, oid = await add_tenant(admin_conn)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await api.execute(
            """INSERT INTO runs (id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version,
                                 profile_sha256, auth_mode, actor_user_id, actor_oid, actor_tid, params, status,
                                 run_token_sha256, deadline_at)
               VALUES ($1, $2, $3, $4, $5, 1, $6, 'app_only', $7, $8, $2, '{}'::jsonb, 'running', $9,
                       now() + interval '5 minutes')""",
            uuid.uuid4(), tid, MANIFEST.id, MANIFEST.sha256, MANIFEST.profile.id, MANIFEST.profile.sha256,
            user_id, oid, secrets.token_hex(32))


async def test_the_api_cannot_end_a_task_run(api, admin_conn, sessionmaker):
    tenant = await add_tenant(admin_conn)
    task_run, _ = await start_run(admin_conn, AuditWriter(sessionmaker), tenant)
    before = await _row(admin_conn, uuid.UUID(task_run))
    for status, outcome in (("completed", "revoked"), ("failed", "revoked_during_request")):
        assert await _end(api, uuid.UUID(task_run), tenant[0], status, outcome) is False
    after = await _row(admin_conn, uuid.UUID(task_run))
    assert after["status"] == "running" and after["run_token_sha256"] == before["run_token_sha256"]
    assert after == before


async def test_the_api_cannot_end_a_queued_task_run(api, admin_conn):
    tid, user_id, oid = await add_tenant(admin_conn)
    run_id = uuid.uuid4()
    await admin_conn.execute(
        """INSERT INTO runs (id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version,
                             profile_sha256, auth_mode, actor_user_id, actor_oid, actor_tid, params, status)
           VALUES ($1, $2, $3, $4, $5, 1, $6, 'app_only', $7, $8, $2, '{}'::jsonb, 'queued')""",
        run_id, tid, MANIFEST.id, MANIFEST.sha256, MANIFEST.profile.id, MANIFEST.profile.sha256, user_id, oid)
    assert await _end(api, run_id, tid) is False
    assert (await _row(admin_conn, run_id))["status"] == "queued"


@pytest.mark.parametrize("component", ["broker", "runner"])
async def test_only_the_api_may_call_the_session_functions(roles, admin_conn, component):
    tenant = await add_tenant(admin_conn)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await _start(roles[component], tenant)
    session_id, _ = await _start(roles["api"], tenant)
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await _end(roles[component], session_id, tenant[0])


# --- ending ------------------------------------------------------------------------

async def test_revoking_a_session_ends_it_and_clears_the_token(api, admin_conn):
    tenant = await add_tenant(admin_conn)
    session_id, _ = await _start(api, tenant)
    assert await _end(api, session_id, tenant[0]) is True
    row = await _row(admin_conn, session_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"]) == ("completed", "revoked", None)
    assert json.loads(row["result"]) == {"session": "revoked"} and row["ended_at"] is not None


async def test_a_session_revoked_during_a_request_ends_failed_without_a_result(api, admin_conn):
    tenant = await add_tenant(admin_conn)
    session_id, _ = await _start(api, tenant)
    assert await _end(api, session_id, tenant[0], "failed", "revoked_during_request") is True
    row = await _row(admin_conn, session_id)
    assert (row["status"], row["outcome"], row["run_token_sha256"], row["result"]) == (
        "failed", "revoked_during_request", None, None)


async def test_another_tenants_session_cannot_be_ended(api, admin_conn):
    tenant, other = await add_tenant(admin_conn), await add_tenant(admin_conn)
    session_id, _ = await _start(api, tenant)
    assert await _end(api, session_id, other[0]) is False
    assert (await _row(admin_conn, session_id))["status"] == "running"


async def test_an_ended_session_cannot_be_ended_again(api, admin_conn):
    tenant = await add_tenant(admin_conn)
    session_id, _ = await _start(api, tenant)
    assert await _end(api, session_id, tenant[0]) is True
    assert await _end(api, session_id, tenant[0], "failed", "revoked_during_request") is False
    assert (await _row(admin_conn, session_id))["status"] == "completed"


@pytest.mark.parametrize("status, outcome", [
    ("completed", "succeeded"), ("failed", "revoked"), ("timed_out", "revoked"), ("running", "revoked"),
    ("completed", None), (None, "revoked"),
])
async def test_only_the_two_session_endings_are_accepted(api, admin_conn, status, outcome):
    tenant = await add_tenant(admin_conn)
    session_id, _ = await _start(api, tenant)
    with pytest.raises(asyncpg.CheckViolationError):
        await _end(api, session_id, tenant[0], status, outcome)
    assert (await _row(admin_conn, session_id))["status"] == "running"



async def test_a_disabled_tenant_cannot_start_a_session(api, admin_conn):
    # SD-055 (review F2): the function itself refuses, whatever the api checked at sign-in.
    tenant = await add_tenant(admin_conn)
    await admin_conn.execute("UPDATE tenants SET status = 'disabled' WHERE id = $1", tenant[0])
    with pytest.raises(asyncpg.CheckViolationError):
        await _start(api, tenant)
