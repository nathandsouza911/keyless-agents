"""change_proposals in the database (migration 20261105_change_proposals, SD-054).

Run as roles provisioned with the deployment's grants: only the broker can
file a proposal, only for a running agent session of the same tenant; nobody
can change one; the snapshot is present exactly when the lookup found a user.
"""

from __future__ import annotations

import json
import secrets
import uuid

import asyncpg
import pytest

from clw.audit.writer import AuditWriter
from tests.db.broker_fixtures import add_tenant, start_run
from tests.db.test_agent_sessions_table import _end, _start, roles  # noqa: F401 (fixture)

pytestmark = pytest.mark.pg

TARGET = "0f8fad5b-d9cb-469f-a165-70867728950e"


async def _file(conn, tenant_id: str, session_id, **changes) -> uuid.UUID:
    values = {"id": uuid.uuid4(), "tenant_id": tenant_id, "session_id": session_id, "action": "disable_user",
              "operation": "users.update", "target_id": TARGET,
              "request": json.dumps({"method": "PATCH", "path": f"/v1.0/users/{TARGET}",
                                     "body": {"accountEnabled": False}}),
              "request_sha256": secrets.token_hex(32), "agent_reason": "dormant for 200 days",
              "lookup_status": "found", "target_display_name": "Dana", "target_upn": "dana@contoso.test",
              "target_account_enabled": True} | changes
    columns = ", ".join([*values, "looked_up_at"])
    placeholders = ", ".join([f"${i}" + ("::jsonb" if k == "request" else "") for i, k in enumerate(values, 1)]
                             + ["now()"])
    await conn.execute(f"INSERT INTO change_proposals ({columns}) VALUES ({placeholders})", *values.values())
    return values["id"]


@pytest.fixture
async def session(roles, admin_conn):
    tenant = await add_tenant(admin_conn)
    session_id, _ = await _start(roles["api"], tenant)
    return tenant, session_id


async def test_the_broker_files_a_proposal_for_a_running_agent_session(roles, admin_conn, session):
    tenant, session_id = session
    proposal = await _file(roles["broker"], tenant[0], session_id)
    row = await admin_conn.fetchrow("SELECT * FROM change_proposals WHERE id = $1", proposal)
    assert (row["lookup_status"], row["target_display_name"], row["looked_up_at"] is not None) == (
        "found", "Dana", True)


@pytest.mark.parametrize("component", ["api", "runner"])
async def test_only_the_broker_can_file_one(roles, session, component):
    tenant, session_id = session
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await _file(roles[component], tenant[0], session_id)


async def test_the_api_can_read_proposals(roles, session):
    tenant, session_id = session
    await _file(roles["broker"], tenant[0], session_id)
    assert await roles["api"].fetchval("SELECT count(*) FROM change_proposals WHERE session_id = $1", session_id) == 1


@pytest.mark.parametrize("component", ["api", "broker", "runner"])
@pytest.mark.parametrize("statement", ["UPDATE change_proposals SET agent_reason = 'x' WHERE id = $1",
                                       "UPDATE change_proposals SET target_id = target_id WHERE id = $1",
                                       "DELETE FROM change_proposals WHERE id = $1"])
async def test_nobody_can_change_or_delete_a_proposal(roles, session, component, statement):
    tenant, session_id = session
    proposal = await _file(roles["broker"], tenant[0], session_id)
    with pytest.raises((asyncpg.InsufficientPrivilegeError, asyncpg.CheckViolationError)):
        await roles[component].execute(statement, proposal)


async def test_even_the_owner_cannot_change_one(admin_conn, roles, session):
    tenant, session_id = session
    proposal = await _file(roles["broker"], tenant[0], session_id)
    with pytest.raises(asyncpg.CheckViolationError):
        await admin_conn.execute("UPDATE change_proposals SET lookup_status = 'not_found', target_display_name = NULL, "
                                 "target_upn = NULL, target_account_enabled = NULL WHERE id = $1", proposal)


async def test_not_for_another_tenants_session(roles, admin_conn, session):
    _, session_id = session
    other = await add_tenant(admin_conn)
    with pytest.raises(asyncpg.CheckViolationError):
        await _file(roles["broker"], other[0], session_id)


async def test_not_for_an_ended_session(roles, session):
    tenant, session_id = session
    assert await _end(roles["api"], session_id, tenant[0]) is True
    with pytest.raises(asyncpg.CheckViolationError):
        await _file(roles["broker"], tenant[0], session_id)


async def test_not_for_a_task_run(roles, admin_conn, sessionmaker):
    tenant = await add_tenant(admin_conn)
    run_id, _ = await start_run(admin_conn, AuditWriter(sessionmaker), tenant)
    with pytest.raises(asyncpg.CheckViolationError):
        await _file(roles["broker"], tenant[0], uuid.UUID(run_id))


async def test_a_not_found_proposal_carries_no_snapshot(roles, session):
    tenant, session_id = session
    await _file(roles["broker"], tenant[0], session_id, lookup_status="not_found", target_display_name=None,
                target_upn=None, target_account_enabled=None)
    with pytest.raises(asyncpg.CheckViolationError):
        await _file(roles["broker"], tenant[0], session_id, lookup_status="not_found")


@pytest.mark.parametrize("changes", [
    {"action": "delete_user"}, {"operation": "users.delete"}, {"target_id": "not-a-guid"},
    {"target_id": TARGET.upper()}, {"request_sha256": "x" * 64}, {"agent_reason": "x" * 501},
    {"lookup_status": "maybe"}, {"request": json.dumps(["not", "an", "object"])},
    {"target_display_name": "x" * 513},
])
async def test_malformed_proposals_are_refused(roles, session, changes):
    tenant, session_id = session
    with pytest.raises(asyncpg.CheckViolationError):
        await _file(roles["broker"], tenant[0], session_id, **changes)


async def test_the_request_must_be_for_the_object_shown(roles, session):
    # Security review F5 (2026-10-31): no writer can store one user's ID beside a request for another.
    tenant, session_id = session
    other = "11111111-2222-4333-8444-555555555555"
    for request in ({"method": "PATCH", "path": f"/v1.0/users/{other}", "body": {"accountEnabled": False}},
                    {"method": "PATCH", "path": f"/v1.0/users/{TARGET}", "body": {"accountEnabled": True}},
                    {"method": "DELETE", "path": f"/v1.0/users/{TARGET}", "body": {"accountEnabled": False}},
                    {"method": "PATCH", "path": f"/v1.0/users/{TARGET}", "body": {"accountEnabled": False,
                                                                                  "displayName": "x"}}):
        with pytest.raises(asyncpg.CheckViolationError):
            await _file(roles["broker"], tenant[0], session_id, request=json.dumps(request))
