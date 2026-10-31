"""Gate 1 L-1 (third review): text columns are bounded in UTF-8 bytes, by the
writer and, independently, by the database (direct inserts as the app role)."""

from __future__ import annotations

import json
import time
from dataclasses import replace

import asyncpg
import pytest

from clw.audit.events import MAX_REQUEST_TARGET_BYTES, MAX_TEXT_BYTES, PROTECTED_FIELDS, AuditEventInvalid
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditWriter

from tests.unit.audit.helpers import rehash, standard_events

pytestmark = pytest.mark.pg
COLS = [*PROTECTED_FIELDS, "record_hash"]


def _of_bytes(n: int, char: str = "a") -> str:
    """A string of exactly n UTF-8 bytes, built from ``char`` plus ASCII padding."""
    width = len(char.encode())
    return char * (n // width) + "a" * (n % width)


async def _raw_insert(conn, record):
    values = record.stored()
    args = [json.dumps(values[c]) if c == "details" else values[c] for c in COLS]
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(COLS))
    await conn.execute(f"INSERT INTO public.audit_events ({', '.join(COLS)}) VALUES ({placeholders})", *args)


async def _start(sessionmaker, chain_id, n=5):
    writer = AuditWriter(sessionmaker)
    return writer, [await writer.append(chain_id=chain_id, event={**e, "tenant_id": chain_id})
                    for e in standard_events()[:n]]


def _successor(head, **changes):
    base = replace(head, seq=head.seq + 1, previous_hash=head.record_hash, event_type="RUN_TIMED_OUT",
                   status="timed_out", run_id="run-x", task_id=None, task_manifest_sha256=None, profile_id=None,
                   profile_version=None, auth_mode=None, reason=None, operation=None, http_method=None,
                   path_template=None, request_target=None, decision_seq=None, attempt=None)
    return rehash(replace(base, **changes))


# Free-text fields that the hash/format constraints do not already bound.
DIRECT_FIELDS = ["reason", "outcome", "run_id", "task_id", "profile_id", "actor_oid", "actor_tid",
                 "operation", "path_template", "graph_request_id", "auth_mode", "http_method"]
# (task_manifest_sha256 already has the stricter hex constraint.)


@pytest.mark.parametrize("field", DIRECT_FIELDS)
@pytest.mark.parametrize("char", ["a", "é", "€", "😀"])
async def test_database_enforces_the_text_limit_in_utf8_bytes(app_sessionmaker, app_conn, chain_id, field, char):
    _, records = await _start(app_sessionmaker, chain_id, n=3)
    at_limit = _of_bytes(MAX_TEXT_BYTES, char)
    assert len(at_limit.encode()) == MAX_TEXT_BYTES
    over = at_limit + "a"
    with pytest.raises(asyncpg.CheckViolationError, match="ck_audit_events_text_bounds"):
        await _raw_insert(app_conn, _successor(records[-1], **{field: over}))
    await _raw_insert(app_conn, _successor(records[-1], **{field: at_limit}))  # exact limit stored


@pytest.mark.parametrize("char", ["a", "€"])
async def test_database_enforces_the_request_target_limit(app_sessionmaker, app_conn, chain_id, char):
    _, records = await _start(app_sessionmaker, chain_id, n=3)
    at_limit = _of_bytes(MAX_REQUEST_TARGET_BYTES, char)
    with pytest.raises(asyncpg.CheckViolationError, match="ck_audit_events_text_bounds"):
        await _raw_insert(app_conn, _successor(records[-1], request_target=at_limit + "a"))
    await _raw_insert(app_conn, _successor(records[-1], request_target=at_limit))


async def test_database_rejects_the_reviewers_huge_reason_quickly(app_sessionmaker, app_conn, chain_id):
    _, records = await _start(app_sessionmaker, chain_id, n=3)
    started = time.monotonic()
    with pytest.raises(asyncpg.CheckViolationError, match="ck_audit_events_text_bounds"):
        await _raw_insert(app_conn, _successor(records[-1], reason="x" * (50 * 1024 * 1024)))
    assert time.monotonic() - started < 30
    async with app_sessionmaker() as session:
        assert (await verify_chain(session, chain_id=chain_id)).valid


@pytest.mark.parametrize("n, ok", [(MAX_TEXT_BYTES - 1, True), (MAX_TEXT_BYTES, True), (MAX_TEXT_BYTES + 1, False)])
@pytest.mark.parametrize("char", ["a", "é", "😀"])
async def test_writer_enforces_the_same_limit_before_insert(app_sessionmaker, chain_id, n, ok, char):
    writer, _ = await _start(app_sessionmaker, chain_id, n=2)
    event = {**standard_events()[2], "tenant_id": chain_id, "operation": _of_bytes(n, char)}
    if ok:
        record = await writer.append(chain_id=chain_id, event=event)
        assert len(record.operation.encode()) == n
    else:
        with pytest.raises(AuditEventInvalid, match="operation exceeds 1024 UTF-8 bytes"):
            await writer.append(chain_id=chain_id, event=event)


async def test_writer_enforces_the_request_target_limit(app_sessionmaker, chain_id):
    writer, _ = await _start(app_sessionmaker, chain_id, n=4)
    base = {**standard_events()[4], "tenant_id": chain_id}
    prefix = "/v1.0/users?$filter="
    with pytest.raises(AuditEventInvalid, match="request_target exceeds 4096 UTF-8 bytes"):
        await writer.append(chain_id=chain_id, event={
            **base, "request_target": prefix + "a" * (MAX_REQUEST_TARGET_BYTES - len(prefix) + 1)})
    record = await writer.append(chain_id=chain_id, event={
        **base, "request_target": prefix + "a" * (MAX_REQUEST_TARGET_BYTES - len(prefix))})
    assert len(record.request_target.encode()) == MAX_REQUEST_TARGET_BYTES
