"""Third-round review regressions against real Postgres, as the app role:
N2 impossible timestamps / unrecoverable chain, N3 future timestamps,
N8 details size limit, and recovery success/failure paths (SD-016)."""

from __future__ import annotations

import json
import logging
from dataclasses import replace

import asyncpg
import pytest

from clw.audit.canonical import canonical_json
from clw.audit.events import MAX_DETAILS_BYTES, PROTECTED_FIELDS, AuditChainCompromised, AuditEventInvalid, AuditUnavailable
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditRecoveryIncomplete, AuditRecoveryRefused, AuditWriter

from tests.unit.audit.helpers import ev, rehash, standard_events

pytestmark = pytest.mark.pg
COLS = [*PROTECTED_FIELDS, "record_hash"]


def _events_for(chain_id):
    return [{**e, "tenant_id": chain_id} for e in standard_events()]


async def _raw_insert(conn, record, details_text=None):
    args = [(details_text if details_text is not None else json.dumps(v)) if c == "details" else v
            for c, v in record.stored().items()]
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(COLS))
    await conn.execute(f"INSERT INTO public.audit_events ({', '.join(COLS)}) VALUES ({placeholders})", *args)


async def _start(writer, chain_id, n=3):
    return [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)[:n]]


def _timeout_event(chain_id, **kw):
    return {**ev("RUN_TIMED_OUT", "timed_out"), "tenant_id": chain_id, **kw}


def _next_raw(head, **changes):
    """A hash-valid RUN_TIMED_OUT successor of head for a separate run (what an
    INSERT-capable attacker can build)."""
    from clw.audit.events import EVENT_FIELDS

    cleared = {f: None for f in EVENT_FIELDS if f not in ("tenant_id", "details", "event_type", "status", "run_id")}
    base = replace(head, **cleared, seq=head.seq + 1, previous_hash=head.record_hash, event_type="RUN_TIMED_OUT",
                   status="timed_out", run_id="run-x", details={})
    return rehash(replace(base, **changes))


def _second_run(chain_id):
    return [{**e, "run_id": "run-0002"} for e in _events_for(chain_id)[:2]]


# ------------------------------------------------------ N2: real timestamps


@pytest.mark.parametrize("stamp", [
    "9999-99-99T99:99:99.999999Z", "2026-02-30T09:00:00.000000Z", "2026-13-01T00:00:00.000000Z",
    "2026-10-14T24:00:00.000000Z", "2026-10-14T09:60:00.000000Z", "0000-01-01T00:00:00.000000Z",
])
async def test_database_rejects_impossible_timestamps(app_sessionmaker, app_conn, admin_conn, chain_id, stamp):
    assert await admin_conn.fetchval("SELECT public.clw_valid_created_at($1)", stamp) is False
    head = (await _start(AuditWriter(app_sessionmaker), chain_id))[-1]
    with pytest.raises(asyncpg.PostgresError):  # rejected by the CHECK or, first, by the trigger
        await _raw_insert(app_conn, _next_raw(head, created_at=stamp))


@pytest.mark.parametrize("stamp", ["2026-10-14T09:00:00.000000Z", "2024-02-29T23:59:59.999999Z",
                                   "2026-12-31T00:00:00.000000Z"])
async def test_database_validator_accepts_real_timestamps(admin_conn, stamp):
    assert await admin_conn.fetchval("SELECT public.clw_valid_created_at($1)", stamp) is True


@pytest.mark.parametrize("stamp", ["2026-10-14T09:00:00.000000Z\n", "2026-10-14 09:00:00.000000Z",
                                   "٢٠٢٦-10-14T09:00:00.000000Z", "2026-10-14T09:00:00Z"])
async def test_database_validator_rejects_malformed_shapes(admin_conn, stamp):
    assert await admin_conn.fetchval("SELECT public.clw_valid_created_at($1)", stamp) is False


async def test_reviewer_n2_brick_attempt_is_refused_by_the_database(app_sessionmaker, app_conn, chain_id):
    # exp_brick.py: the impossible timestamp can no longer be stored by the app role.
    head = (await _start(AuditWriter(app_sessionmaker), chain_id))[-1]
    bad = rehash(replace(head, seq=4, previous_hash=head.record_hash, created_at="9999-99-99T99:99:99.999999Z"))
    with pytest.raises(asyncpg.PostgresError):
        await _raw_insert(app_conn, bad)


async def _superuser_insert(admin_conn, record):
    """Insert as the superuser with this session's triggers off
    (session_replication_role, no schema change). CHECK constraints apply."""
    await admin_conn.execute("SET session_replication_role = replica")
    try:
        await _raw_insert(admin_conn, record)
    finally:
        await admin_conn.execute("SET session_replication_role = origin")


@pytest.fixture
async def impossible_timestamps_allowed(admin_conn, pg_dsn):
    """Lets the superuser plant a row with an impossible created_at, then puts
    the shared test database back exactly as production has it (fifth review
    I-2): the planted rows are removed and the constraint is re-created and
    validated, so later tests never run against a NOT VALID constraint."""
    await admin_conn.execute("ALTER TABLE audit_events DROP CONSTRAINT ck_audit_events_created_at_valid")
    try:
        yield
    finally:
        await admin_conn.execute("SET session_replication_role = replica")
        try:
            await admin_conn.execute("DELETE FROM audit_events WHERE NOT public.clw_valid_created_at(created_at)")
        finally:
            await admin_conn.execute("SET session_replication_role = origin")
        await admin_conn.execute("ALTER TABLE audit_events ADD CONSTRAINT ck_audit_events_created_at_valid "
                                 "CHECK (public.clw_valid_created_at(created_at))")


@pytest.mark.parametrize("stamp", ["9999-99-99T99:99:99.999999Z", "2099-12-31T23:59:59.999999Z"])
async def test_corrupt_head_timestamp_is_recoverable_and_never_inherited(
        app_sessionmaker, admin_conn, chain_id, stamp, impossible_timestamps_allowed):
    # Planted with privileges the app role does not have; recovery must still work
    # and later records must carry real database time.
    writer = AuditWriter(app_sessionmaker)
    head = (await _start(writer, chain_id))[-1]
    bad = _next_raw(head, created_at=stamp)
    await _superuser_insert(admin_conn, bad)

    with pytest.raises(AuditChainCompromised):
        await writer.append(chain_id=chain_id, event=_second_run(chain_id)[0])
    recovery = await writer.append_recovery(chain_id=chain_id, operator="op:alice", reason="INC-2",
                                            expected_head_hash=bad.record_hash)
    assert recovery.created_at < "2030" and recovery.created_at != stamp
    run2 = _second_run(chain_id)
    nxt = await writer.append(chain_id=chain_id, event=run2[0])
    after = await AuditWriter(app_sessionmaker).append(chain_id=chain_id, event=run2[1])
    assert nxt.created_at < "2030" and after.created_at >= nxt.created_at
    async with app_sessionmaker() as s:
        report = await verify_chain(s, chain_id=chain_id)
    assert not report.valid  # the corrupt record is still evidence of an incident
    later = {(e.seq, e.issue) for e in report.errors if e.seq > bad.seq}
    assert later == set(), later  # nothing after the recovery inherited a timestamp problem
    assert [(r.seq, r.valid) for r in report.recoveries] == [(recovery.seq, True)]


# ---------------------------------------------------- N3: future timestamps


async def test_database_rejects_created_at_more_than_5_minutes_ahead(app_sessionmaker, app_conn, admin_conn, chain_id):
    head = (await _start(AuditWriter(app_sessionmaker), chain_id))[-1]
    future = await admin_conn.fetchval(
        "SELECT to_char((clock_timestamp() + interval '6 minutes') AT TIME ZONE 'UTC', "
        "'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
    with pytest.raises(asyncpg.PostgresError, match="ahead of the database clock"):
        await _raw_insert(app_conn, _next_raw(head, created_at=future))


async def test_database_accepts_small_forward_skew(app_sessionmaker, app_conn, admin_conn, chain_id):
    head = (await _start(AuditWriter(app_sessionmaker), chain_id))[-1]
    soon = await admin_conn.fetchval(
        "SELECT to_char((clock_timestamp() + interval '4 minutes') AT TIME ZONE 'UTC', "
        "'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
    await _raw_insert(app_conn, _next_raw(head, created_at=soon))
    # The writer then adopts the in-window head stamp rather than going backwards.
    nxt = await AuditWriter(app_sessionmaker).append(chain_id=chain_id, event=_timeout_event(chain_id, run_id="run-0002"))
    assert nxt.created_at == soon


# ---------------------------------------------------------- N8: details size


async def test_compact_size_matches_python_definition(app_sessionmaker, admin_conn, chain_id):
    corpus = [
        {}, {"a": 1}, {"a": [1, 2, {"b": None}], "z": True, "m": False},
        {"unicode": "é€😀 ", "ctrl": "\x01\x1f\t\n\r\b\f", "quote": '"\\/'},
        {"k" * 50: ["x" * 100, -12345, 0, 9007199254740991]},
        {"nested": {"a": {"b": {"c": {"d": [[], {}]}}}}},
    ]
    writer = AuditWriter(app_sessionmaker)
    await _start(writer, chain_id, 2)
    for i, details in enumerate(corpus):
        record = await writer.append(chain_id=chain_id, event=_timeout_event(chain_id, run_id=f"r{i}", details=details))
        size = await admin_conn.fetchval(
            "SELECT public.clw_jsonb_compact_size(details) FROM audit_events WHERE chain_id=$1 AND seq=$2",
            chain_id, record.seq)
        assert size == len(canonical_json(details)), details


def _details_of_size(n: int) -> dict:
    # {"p":"xxxx"} has 8 bytes of overhead
    return {"p": "x" * (n - 8)}


@pytest.mark.parametrize("size, ok", [(2, True), (MAX_DETAILS_BYTES - 1, True), (MAX_DETAILS_BYTES, True),
                                      (MAX_DETAILS_BYTES + 1, False)])
async def test_writer_and_database_enforce_the_same_limit(app_sessionmaker, app_conn, chain_id, size, ok):
    details = {} if size == 2 else _details_of_size(size)
    assert len(canonical_json(details)) == size
    writer = AuditWriter(app_sessionmaker)
    head = (await _start(writer, chain_id, 2))[-1]
    if ok:
        await writer.append(chain_id=chain_id, event=_timeout_event(chain_id, details=details))
    else:
        with pytest.raises(AuditEventInvalid):
            await writer.append(chain_id=chain_id, event=_timeout_event(chain_id, details=details))
        with pytest.raises(asyncpg.PostgresError, match="details_bounds"):
            await _raw_insert(app_conn, replace(_next_raw(head), details=details, record_hash="0" * 64))


async def test_multibyte_characters_count_as_utf8_bytes(app_sessionmaker, chain_id):
    euro = "€"  # 3 bytes in UTF-8
    details = {"p": euro * ((MAX_DETAILS_BYTES - 8) // 3 + 1)}  # chars under the limit, bytes over it
    assert len(canonical_json(details)) > MAX_DETAILS_BYTES > len(json.dumps(details, ensure_ascii=False))
    writer = AuditWriter(app_sessionmaker)
    await _start(writer, chain_id, 2)
    with pytest.raises(AuditEventInvalid):
        await writer.append(chain_id=chain_id, event=_timeout_event(chain_id, details=details))


async def test_deep_but_small_details_within_limits_accepted(app_sessionmaker, chain_id):
    value = 1
    for _ in range(14):
        value = {"a": value}
    writer = AuditWriter(app_sessionmaker)
    await _start(writer, chain_id, 2)
    await writer.append(chain_id=chain_id, event=_timeout_event(chain_id, details=value))


async def test_huge_details_rejected_quickly_by_database(app_sessionmaker, app_conn, chain_id):
    # Reviewer N8: 26 MB previously took ~66 s of database CPU.
    head = (await _start(AuditWriter(app_sessionmaker), chain_id))[-1]
    # ~12 MB, 6 million elements: costly for the recursive depth/size checks,
    # so this only passes quickly if the cheap length pre-check runs first.
    huge = '{"a": [' + "1," * 6_000_000 + '1]}'
    # The bound is the database's own execution time (statement_timeout), not the wall clock: the
    # wall clock also counts building and sending 12 MB, which under parallel load exceeded a 5 s
    # bound (2 of 12 Linux runs, scripts/pg_stress.sh, 2026-10-31). The slow path is cancelled
    # (QueryCanceledError, not details_bounds), so it still fails this test.
    await app_conn.execute("SET statement_timeout = '3s'")
    try:
        with pytest.raises(asyncpg.PostgresError, match="details_bounds"):
            await _raw_insert(app_conn, replace(_next_raw(head), record_hash="0" * 64), details_text=huge)
    finally:
        await app_conn.execute("RESET statement_timeout")


# ------------------------------------------------- recovery failure paths


async def test_recovery_insert_failure_leaves_chain_blocked(app_sessionmaker, app_conn, admin_conn, chain_id):
    writer = AuditWriter(app_sessionmaker)
    head = (await _start(writer, chain_id))[-1]
    bad = replace(head, seq=4, previous_hash=head.record_hash, record_hash="0" * 64, status="bogus")
    await _raw_insert(app_conn, bad)
    await admin_conn.execute("REVOKE INSERT ON audit_events FROM clw_app_test")
    try:
        with pytest.raises(AuditUnavailable):
            await writer.append_recovery(chain_id=chain_id, operator="op", reason="x", expected_head_hash=bad.record_hash)
    finally:
        await admin_conn.execute("GRANT INSERT ON audit_events TO clw_app_test")
    with pytest.raises(AuditChainCompromised):
        await writer.append(chain_id=chain_id, event=_events_for(chain_id)[3])
    async with app_sessionmaker() as s:
        assert (await verify_chain(s, chain_id=chain_id)).recoveries == ()


async def test_recovery_reported_incomplete_if_chain_still_blocked_after_commit(app_sessionmaker, app_conn, chain_id, monkeypatch, caplog):
    import clw.audit.writer as writer_module

    writer = AuditWriter(app_sessionmaker)
    head = (await _start(writer, chain_id))[-1]
    bad = replace(head, seq=4, previous_hash=head.record_hash, record_hash="0" * 64, status="bogus")
    await _raw_insert(app_conn, bad)

    real = writer_module.blocking_findings
    calls = {"n": 0}

    def flaky(records, findings):
        calls["n"] += 1
        result = real(records, findings)
        if calls["n"] >= 3:  # the post-commit re-verification
            from clw.audit.chain import ChainError

            return [*result, ChainError(99, "hash_mismatch")]
        return result

    monkeypatch.setattr(writer_module, "blocking_findings", flaky)
    with caplog.at_level(logging.CRITICAL, logger="clw.audit.alert"):
        with pytest.raises(AuditRecoveryIncomplete):
            await writer.append_recovery(chain_id=chain_id, operator="op", reason="x", expected_head_hash=bad.record_hash)
    assert "audit_chain_recovery_incomplete" in caplog.text
    assert "audit_chain_recovery_recorded" not in caplog.text


async def test_recovery_refused_when_it_would_not_restore_appends(app_sessionmaker, app_conn, admin_conn, chain_id):
    # A finding the recovery cannot acknowledge (no seq) must not produce a
    # "successful" recovery: refused before anything is written.
    import clw.audit.writer as writer_module
    from clw.audit.chain import ChainError

    writer = AuditWriter(app_sessionmaker)
    head = (await _start(writer, chain_id))[-1]
    bad = replace(head, seq=4, previous_hash=head.record_hash, record_hash="0" * 64, status="bogus")
    await _raw_insert(app_conn, bad)
    real = writer_module.integrity_findings

    def with_unacknowledgeable(records, **kw):
        return [*real(records, **kw), ChainError(-1, "invalid_record", "synthetic")]

    import pytest as _pytest

    mp = _pytest.MonkeyPatch()
    mp.setattr(writer_module, "integrity_findings", with_unacknowledgeable)
    try:
        with pytest.raises(AuditRecoveryRefused, match="would not restore appends"):
            await writer.append_recovery(chain_id=chain_id, operator="op", reason="x", expected_head_hash=bad.record_hash)
    finally:
        mp.undo()
    assert await admin_conn.fetchval("SELECT count(*) FROM audit_events WHERE chain_id=$1", chain_id) == 4


# ------------------------------------------------------------ N9: cache bound


async def test_writer_anchor_cache_is_bounded(app_sessionmaker):
    import uuid

    writer = AuditWriter(app_sessionmaker, max_anchors=2)
    chains = [str(uuid.uuid4()) for _ in range(4)]
    for c in chains:
        await writer.append(chain_id=c, event=_events_for(c)[0])
    assert len(writer._anchors) == 2 and list(writer._anchors) == chains[2:]
    await writer.append(chain_id=chains[0], event=_events_for(chains[0])[1])  # evicted chain re-verified in full


async def test_writer_refuses_to_insert_a_record_that_fails_its_own_checks(app_sessionmaker, admin_conn, chain_id, monkeypatch):
    import clw.audit.writer as writer_module

    real = writer_module.next_record
    monkeypatch.setattr(writer_module, "next_record",
                        lambda *a, **kw: replace(real(*a, **kw), record_hash="1" * 64))
    with pytest.raises(AuditEventInvalid, match="fails its own checks"):
        await AuditWriter(app_sessionmaker).append(chain_id=chain_id, event=_events_for(chain_id)[0])
    assert await admin_conn.fetchval("SELECT count(*) FROM audit_events WHERE chain_id=$1", chain_id) == 0


# ------------------------------------------- M-2: durable timestamp anomalies


async def test_recovery_from_records_ahead_of_the_clock_survives_the_passage_of_time(
        app_sessionmaker, admin_conn, chain_id):
    """Gate 1 M-2, end to end as the app role: three records planted an hour
    ahead (what a database clock running fast would produce), refusal,
    recovery, further appends, then verification now, in two hours and in
    a day: the same findings, all acknowledged, nothing provisional."""
    from datetime import datetime, timedelta, timezone

    from clw.audit.chain import blocking_findings, integrity_findings, verify_records
    from clw.audit.verifier import load_chain
    from clw.common.timeutil import to_rfc3339_utc

    writer = AuditWriter(app_sessionmaker)
    head = (await _start(writer, chain_id))[-1]
    ahead = datetime.now(timezone.utc) + timedelta(hours=1)
    planted = []
    for i in range(3):
        head = _next_raw(head, created_at=to_rfc3339_utc(ahead + timedelta(seconds=i)),
                         run_id=f"run-fast-{i}")
        await _superuser_insert(admin_conn, head)
        planted.append(head.seq)

    with pytest.raises(AuditChainCompromised):
        await writer.append(chain_id=chain_id, event=_second_run(chain_id)[0])
    recovery = await writer.append_recovery(chain_id=chain_id, operator="op:alice", reason="INC-3",
                                            expected_head_hash=head.record_hash)
    acknowledged = sorted((a["seq"], a["issue"]) for a in recovery.details["acknowledged"])
    assert acknowledged == [(s, "created_at_in_future") for s in planted]
    for event in _second_run(chain_id):
        await AuditWriter(app_sessionmaker).append(chain_id=chain_id, event=event)

    async with app_sessionmaker() as s:
        records = await load_chain(s, chain_id=chain_id)
    now = datetime.now(timezone.utc)
    for delta in (timedelta(0), timedelta(hours=2), timedelta(days=1)):
        report = verify_records(records, chain_id=chain_id, now=now + delta)
        assert report.integrity_state == "recovered", delta
        assert not report.valid and report.provisional == ()
        assert sorted((e.seq, e.issue) for e in report.acknowledged) == acknowledged
        assert blocking_findings(records, integrity_findings(records, chain_id=chain_id, now=now + delta)) == []
        assert [(r.seq, r.valid) for r in report.recoveries] == [(recovery.seq, True)]
