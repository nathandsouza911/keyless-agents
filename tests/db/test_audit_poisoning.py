"""H2 regression: a poisoned chain stops all appends (fail closed, with an
actionable alert) until an explicit recovery is recorded, and is never
reported valid again. Attacks run as the least-privileged app role."""

from __future__ import annotations

import json
import logging
from dataclasses import replace

import pytest

from clw.audit.events import PROTECTED_FIELDS, AuditChainCompromised, AuditUnavailable
from clw.audit.verifier import verify_chain
from clw.audit.writer import AuditRecoveryRefused, AuditWriter

from tests.unit.audit.helpers import ev, rehash, standard_events

pytestmark = pytest.mark.pg
COLS = [*PROTECTED_FIELDS, "record_hash"]


def _events_for(chain_id):
    return [{**e, "tenant_id": chain_id} for e in standard_events()]


async def _raw_insert(conn, record):
    args = [json.dumps(v) if c == "details" else v for c, v in record.stored().items()]
    placeholders = ", ".join(f"${i + 1}" + ("::jsonb" if c == "details" else "") for i, c in enumerate(COLS))
    await conn.execute(f"INSERT INTO public.audit_events ({', '.join(COLS)}) VALUES ({placeholders})", *args)


async def _poison(app_conn, head):
    """poc_db section B: linked row, valid formats, bogus hash and status."""
    bad = replace(head, seq=head.seq + 1, previous_hash=head.record_hash, record_hash="0" * 64, status="bogus")
    await _raw_insert(app_conn, bad)
    return bad


async def _count(admin_conn, chain_id):
    return await admin_conn.fetchval("SELECT count(*) FROM audit_events WHERE chain_id = $1", chain_id)


async def test_reviewer_poc_b_poisoned_head_blocks_appends_and_alerts(app_sessionmaker, app_conn, admin_conn, chain_id, caplog):
    writer = AuditWriter(app_sessionmaker)
    records = [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)[:3]]
    await _poison(app_conn, records[-1])

    with caplog.at_level(logging.CRITICAL, logger="clw.audit.alert"):
        with pytest.raises(AuditChainCompromised) as info:
            await writer.append(chain_id=chain_id, event=_events_for(chain_id)[3])
    assert isinstance(info.value, AuditUnavailable)  # callers that fail closed on AuditUnavailable stop here
    assert (4, "hash_mismatch") in info.value.findings
    assert await _count(admin_conn, chain_id) == 4  # nothing appended after the poison
    alert = " ".join(r.getMessage() for r in caplog.records)
    assert chain_id in alert and "appends_refused" in alert and "audit-chain-recovery.md" in alert


async def test_refusal_persists_across_attempts_and_new_writers(app_sessionmaker, app_conn, chain_id):
    writer = AuditWriter(app_sessionmaker)
    records = [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)[:3]]
    await _poison(app_conn, records[-1])
    for w in (writer, writer, AuditWriter(app_sessionmaker), AuditWriter(app_sessionmaker)):
        with pytest.raises(AuditChainCompromised):
            await w.append(chain_id=chain_id, event=_events_for(chain_id)[3])


async def test_bad_record_buried_under_a_valid_one_is_still_detected(app_sessionmaker, app_conn, chain_id):
    # Attacker poisons, then appends a correctly hashed record on top so the head looks fine.
    writer = AuditWriter(app_sessionmaker)  # has an anchor at seq 3 after these appends
    records = [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)[:3]]
    bad = await _poison(app_conn, records[-1])
    cover = rehash(replace(records[-1], seq=5, previous_hash=bad.record_hash))
    await _raw_insert(app_conn, cover)
    for w in (writer, AuditWriter(app_sessionmaker)):  # incremental and full verification
        with pytest.raises(AuditChainCompromised) as info:
            await w.append(chain_id=chain_id, event=_events_for(chain_id)[3])
        assert (4, "hash_mismatch") in info.value.findings


async def test_alert_hook_is_called_and_its_failure_does_not_mask_refusal(app_sessionmaker, app_conn, chain_id):
    seen = []

    def hook(exc):
        seen.append(exc.chain_id)
        raise RuntimeError("pager down")

    writer = AuditWriter(app_sessionmaker, on_compromised=hook)
    records = [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)[:3]]
    await _poison(app_conn, records[-1])
    with pytest.raises(AuditChainCompromised):
        await writer.append(chain_id=chain_id, event=_events_for(chain_id)[3])
    assert seen == [chain_id]


# ---------------------------------------------------------------- recovery


async def _poisoned_chain(app_sessionmaker, app_conn, chain_id):
    writer = AuditWriter(app_sessionmaker)
    records = [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)[:3]]
    bad = await _poison(app_conn, records[-1])
    return writer, bad


async def test_recovery_requires_the_inspected_head(app_sessionmaker, app_conn, chain_id):
    writer, _ = await _poisoned_chain(app_sessionmaker, app_conn, chain_id)
    with pytest.raises(AuditRecoveryRefused):
        await writer.append_recovery(chain_id=chain_id, operator="op:alice", reason="x", expected_head_hash="1" * 64)


async def test_recovery_refused_on_a_clean_chain(app_sessionmaker, chain_id):
    writer = AuditWriter(app_sessionmaker)
    records = [await writer.append(chain_id=chain_id, event=e) for e in _events_for(chain_id)[:3]]
    with pytest.raises(AuditRecoveryRefused):
        await writer.append_recovery(chain_id=chain_id, operator="op:alice", reason="x",
                                     expected_head_hash=records[-1].record_hash)


async def test_recovery_resumes_appends_but_chain_stays_invalid(app_sessionmaker, app_conn, chain_id, caplog):
    writer, bad = await _poisoned_chain(app_sessionmaker, app_conn, chain_id)
    with caplog.at_level(logging.CRITICAL, logger="clw.audit.alert"):
        recovery = await writer.append_recovery(chain_id=chain_id, operator="op:alice",
                                                reason="row 4 written by compromised runner; creds rotated",
                                                expected_head_hash=bad.record_hash)
    assert recovery.event_type == "CHAIN_RECOVERY" and recovery.seq == 5
    assert {"seq": 4, "issue": "hash_mismatch"} in recovery.details["acknowledged"]
    assert "audit_chain_recovery_recorded" in caplog.text

    # Appends resume (fresh writer too); the run continues from where it was.
    await writer.append(chain_id=chain_id, event=_events_for(chain_id)[3])
    await AuditWriter(app_sessionmaker).append(chain_id=chain_id, event=_events_for(chain_id)[4])

    async with app_sessionmaker() as s:
        report = await verify_chain(s, chain_id=chain_id)
    assert not report.valid  # never trustworthy again
    assert (4, "hash_mismatch") in {(e.seq, e.issue) for e in report.acknowledged}


async def test_new_poison_after_recovery_blocks_again(app_sessionmaker, app_conn, chain_id):
    writer, bad = await _poisoned_chain(app_sessionmaker, app_conn, chain_id)
    await writer.append_recovery(chain_id=chain_id, operator="op:alice", reason="x", expected_head_hash=bad.record_hash)
    head = await writer.append(chain_id=chain_id, event=_events_for(chain_id)[3])
    await _poison(app_conn, head)
    with pytest.raises(AuditChainCompromised) as info:
        await writer.append(chain_id=chain_id, event=_events_for(chain_id)[4])
    assert (head.seq + 1, "hash_mismatch") in info.value.findings


async def test_forged_recovery_record_acknowledging_nothing_real_does_not_unblock(app_sessionmaker, app_conn, chain_id):
    # A recovery that acknowledges different findings than the real ones does not help.
    from clw.audit.chain import next_record
    from clw.common.timeutil import utc_now

    writer, bad = await _poisoned_chain(app_sessionmaker, app_conn, chain_id)
    fake = next_record(bad, chain_id=chain_id, created_at=utc_now(), event={
        "tenant_id": chain_id, "event_type": "CHAIN_RECOVERY", "status": "recorded", "reason": "x",
        "actor_oid": "attacker", "details": {"acknowledged": [{"seq": 2, "issue": "hash_mismatch"}],
                                             "observed_head_seq": 4, "observed_head_hash": bad.record_hash}})
    await _raw_insert(app_conn, fake)
    with pytest.raises(AuditChainCompromised):
        await writer.append(chain_id=chain_id, event=_events_for(chain_id)[3])


async def test_writers_with_skewed_local_clocks_use_the_database_clock_and_alert(app_sessionmaker, chain_id, caplog):
    # The database clock is authoritative; local clocks only feed drift alerts.
    from datetime import datetime, timezone

    ahead = AuditWriter(app_sessionmaker, clock=lambda: datetime(2030, 1, 1, tzinfo=timezone.utc))
    behind = AuditWriter(app_sessionmaker, clock=lambda: datetime(2020, 1, 1, tzinfo=timezone.utc))
    events = _events_for(chain_id)
    with caplog.at_level(logging.WARNING, logger="clw.audit.alert"):
        first = await ahead.append(chain_id=chain_id, event=events[0])
        second = await behind.append(chain_id=chain_id, event=events[1])
    assert first.created_at.startswith("2026") or first.created_at.startswith("2027")
    assert first.created_at <= second.created_at
    assert caplog.text.count("audit_clock_drift") >= 2
    async with app_sessionmaker() as s:
        assert (await verify_chain(s, chain_id=chain_id)).valid
