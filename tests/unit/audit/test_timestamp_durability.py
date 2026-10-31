"""Gate 1 M-2 (third review): timestamp findings must not depend on when the
chain is verified, recovery from a future timestamp must stay valid, and the
integrity states must be explicit."""

from __future__ import annotations

import random
from dataclasses import replace
from datetime import timedelta

import pytest

from clw.audit.chain import (
    blocking_findings,
    integrity_findings,
    next_record,
    recovery_record,
    verify_records,
)
from clw.audit.events import EventType

from tests.unit.audit.helpers import CHAIN, T0, build_chain, ev, rehash, standard_events

LATER = [timedelta(seconds=10), timedelta(hours=2), timedelta(days=1), timedelta(days=400)]


def _stamp(dt) -> str:
    from clw.common.timeutil import to_rfc3339_utc

    return to_rfc3339_utc(dt)  # strftime("%Y") is not zero-padded on glibc (L-C)


def _relink(records, start):
    out = list(records)
    for i in range(start, len(out)):
        out[i] = rehash(replace(out[i], previous_hash=out[i - 1].record_hash))
    return out


def _with_stamps(records, stamps: dict[int, str]):
    """Privileged edit: set created_at of the given seqs, then re-link."""
    out = list(records)
    first = min(stamps)
    for seq, value in stamps.items():
        out[seq - 1] = rehash(replace(out[seq - 1], created_at=value))
    return _relink(out, first) if first < len(out) else out


def _recover(records, now):
    blocking = blocking_findings(records, integrity_findings(records, chain_id=CHAIN, now=now))
    assert blocking, "nothing to recover"
    return [*records, recovery_record(records, blocking, chain_id=CHAIN, operator="oid-operator",
                                      reason="incident-1", created_at=now, now=now)]


def _append(records, event, at):
    return [*records, next_record(records[-1], chain_id=CHAIN, event={**event, "run_id": "run-0002"}, created_at=at)]


def _snapshot(records, now):
    report = verify_records(records, chain_id=CHAIN, now=now)
    blocking = blocking_findings(records, integrity_findings(records, chain_id=CHAIN, now=now))
    return {
        "errors": sorted((e.seq, e.issue) for e in report.errors),
        "acknowledged": sorted((e.seq, e.issue) for e in report.acknowledged),
        "blocking": sorted((f.seq, f.issue) for f in blocking),
        "state": report.integrity_state,
        "provisional": sorted((e.seq, e.issue) for e in report.provisional),
        "recoveries": [(r.seq, r.valid) for r in report.recoveries],
        "valid": report.valid,
    }


# --------------------------------------------- the reviewer's time bomb


@pytest.mark.parametrize("ahead", [timedelta(minutes=6), timedelta(hours=1), timedelta(days=30)])
def test_recovered_future_head_stays_recovered_as_time_passes(ahead):
    chain = build_chain(standard_events()[:3])
    chain = _with_stamps(chain, {3: _stamp(T0 + ahead)})
    t = T0 + timedelta(seconds=10)

    before = _snapshot(chain, t)
    assert before["state"] == "unrecovered"
    assert before["blocking"] == [(3, "created_at_in_future")]
    assert before["provisional"] == [(3, "created_at_in_future")]  # only the verifier's clock says so yet

    recovered = _recover(chain, t)
    recovered = _append(recovered, standard_events()[0], t + timedelta(seconds=1))
    recovered = _append(recovered, standard_events()[1], t + timedelta(seconds=2))
    expected = {
        "errors": [(3, "created_at_in_future")],
        "acknowledged": [(3, "created_at_in_future")],
        "blocking": [],
        "state": "recovered",
        "provisional": [],  # the recovery record is now the evidence
        "recoveries": [(4, True)],
        "valid": False,  # history is never presented as clean
    }
    for delta in LATER:
        assert _snapshot(recovered, T0 + delta) == expected, delta


def test_appends_after_recovery_do_not_change_historical_findings():
    chain = _with_stamps(build_chain(standard_events()[:3]), {3: _stamp(T0 + timedelta(hours=1))})
    t = T0 + timedelta(seconds=10)
    records = _recover(chain, t)
    baseline = _snapshot(records, t)
    for i, event in enumerate(standard_events() * 3):  # three more complete runs
        records = [*records, next_record(records[-1], chain_id=CHAIN, created_at=t + timedelta(seconds=i + 1),
                                         event={**event, "run_id": f"run-{i // 8 + 2:04d}"})]
        for delta in LATER:
            now = T0 + delta
            assert _snapshot(records, now)["acknowledged"] == baseline["acknowledged"]
            assert _snapshot(records, now)["blocking"] == []
            assert [e for e in _snapshot(records, now)["errors"] if e[0] <= 4] == baseline["errors"]


def test_several_records_ahead_are_all_acknowledged_and_stay_so():
    """A database clock that ran an hour fast for three records, then was
    corrected: only the newest is flagged before recovery (the others are
    vouched for by their successors); the recovery record exposes all three."""
    chain = build_chain(standard_events()[:6])
    fast = {seq: _stamp(T0 + timedelta(hours=1, seconds=seq)) for seq in (4, 5, 6)}
    chain = _with_stamps(chain, fast)
    t = T0 + timedelta(seconds=30)
    assert _snapshot(chain, t)["blocking"] == [(6, "created_at_in_future")]
    recovered = _recover(chain, t)
    acks = sorted((a["seq"], a["issue"]) for a in recovered[-1].details["acknowledged"])
    assert acks == [(4, "created_at_in_future"), (5, "created_at_in_future"), (6, "created_at_in_future")]
    for delta in LATER:
        snap = _snapshot(recovered, T0 + delta)
        assert snap["state"] == "recovered" and snap["blocking"] == [] and snap["provisional"] == []
        assert snap["acknowledged"] == acks


def test_records_ahead_at_the_start_of_a_chain_recover_durably():
    chain = build_chain(standard_events()[:3])
    chain = _with_stamps(chain, {s: _stamp(T0 + timedelta(hours=1, seconds=s)) for s in (1, 2, 3)})
    t = T0 + timedelta(seconds=30)
    assert _snapshot(chain, t)["state"] == "unrecovered"
    recovered = _recover(chain, t)
    for delta in LATER:
        snap = _snapshot(recovered, T0 + delta)
        assert snap["state"] == "recovered", (delta, snap)
        assert snap["acknowledged"] == [(1, "created_at_in_future"), (2, "created_at_in_future"),
                                        (3, "created_at_in_future")]


# ------------------------------------------------------- attribution


def test_backdated_record_in_the_middle_is_the_one_flagged():
    chain = _with_stamps(build_chain(), {6: _stamp(T0 - timedelta(hours=3))})
    for delta in LATER:
        errors = {(e.seq, e.issue) for e in verify_records(chain, chain_id=CHAIN, now=T0 + delta).errors}
        assert errors == {(6, "created_at_not_monotonic")}, delta


def test_spike_in_the_middle_is_the_one_flagged_whenever_verified():
    chain = _with_stamps(build_chain(), {4: _stamp(T0 + timedelta(hours=2))})
    for delta in [timedelta(0), *LATER]:
        errors = {(e.seq, e.issue) for e in verify_records(chain, chain_id=CHAIN, now=T0 + delta).errors}
        assert errors == {(4, "created_at_in_future")}, delta


def test_record_behind_a_non_recovery_successor_at_chain_start_is_not_blamed():
    # Without a trusted baseline only a recovery counts as evidence, so a
    # backdated record cannot make the honest first records look "ahead".
    chain = _with_stamps(build_chain(), {3: "2001-01-01T00:00:00.000000Z"})
    errors = {(e.seq, e.issue) for e in verify_records(chain, chain_id=CHAIN, now=T0).errors}
    assert errors == {(3, "created_at_not_monotonic")}


# ------------------------------------------------------------- states


def test_states_clean_unrecovered_recovered_and_invalid_recovery():
    t = T0 + timedelta(seconds=10)
    clean = build_chain(standard_events()[:3])
    assert _snapshot(clean, t)["state"] == "clean"

    bad = _with_stamps(clean, {3: _stamp(T0 + timedelta(hours=1))})
    assert _snapshot(bad, t)["state"] == "unrecovered"

    recovered = _recover(bad, t)
    assert _snapshot(recovered, t)["state"] == "recovered"

    forged = rehash(replace(recovered[-1], details={**recovered[-1].details, "observed_head_seq": 1}))
    invalid = [*bad, forged]
    snap = _snapshot(invalid, t)
    assert snap["state"] == "invalid_recovery"
    assert (4, "invalid_recovery") in snap["blocking"] and (3, "created_at_in_future") in snap["blocking"]
    assert snap["recoveries"] == [(4, False)]


def test_transition_errors_alone_leave_integrity_clean_but_chain_invalid():
    records = build_chain([ev("RUN_STARTED", "started", task_id="t", task_manifest_sha256="a" * 64,
                              profile_id="p", profile_version=1, auth_mode="app_only")])
    report = verify_records(records, chain_id=CHAIN, now=T0)
    assert report.integrity_state == "clean" and not report.valid


# ------------------------------------------------------- property check


def _random_chain(rng: random.Random):
    n = rng.randint(2, 14)
    records = build_chain([{**standard_events()[0], "run_id": f"run-{i:04d}"} for i in range(n)])
    stamps = {}
    for seq in range(1, n + 1):
        roll = rng.random()
        if roll < 0.15:
            stamps[seq] = _stamp(T0 + timedelta(minutes=rng.choice([6, 30, 90, 600])))
        elif roll < 0.25:
            stamps[seq] = _stamp(T0 - timedelta(minutes=rng.choice([1, 6, 60, 6000])))
    return _with_stamps(records, stamps) if stamps else records


@pytest.mark.parametrize("seed", range(300))
def test_findings_without_provisional_entries_never_change_with_time(seed):
    """Property: if a chain has no provisional findings when verified, every
    later verification reports exactly the same findings. After a recovery
    that restores appends, the same holds and appends stay unblocked."""
    rng = random.Random(seed)
    chain = _random_chain(rng)
    t = T0 + timedelta(seconds=30)
    first = _snapshot(chain, t)
    if not first["provisional"]:
        for delta in LATER:
            later = _snapshot(chain, T0 + delta)
            assert later["errors"] == first["errors"], (seed, delta)
    if first["blocking"]:
        recovered = _recover(chain, t)
        snap = _snapshot(recovered, t)
        if snap["blocking"]:
            return  # writer would refuse this recovery (tested elsewhere)
        assert snap["provisional"] == [] and snap["state"] == "recovered"
        for delta in LATER:
            assert _snapshot(recovered, T0 + delta) == snap, (seed, delta)


def test_recovery_records_are_the_only_evidence_without_a_baseline():
    # Record 1 is an hour ahead and record 2 is an ordinary successor. With no
    # trusted baseline, record 2 is not evidence, so record 1 is judged by the
    # verifier's clock (provisional) and record 2 is trusted. The recovery
    # record then makes the finding permanent.
    chain = _with_stamps(build_chain(standard_events()[:2]), {1: _stamp(T0 + timedelta(hours=1))})
    snap = _snapshot(chain, T0 + timedelta(seconds=10))
    assert snap["blocking"] == [(1, "created_at_in_future")] and snap["provisional"] == snap["blocking"]
    recovered = _recover(chain, T0 + timedelta(seconds=10))
    assert recovered[-1].event_type == EventType.CHAIN_RECOVERY
    for delta in LATER:
        assert _snapshot(recovered, T0 + delta)["state"] == "recovered"


def test_writer_self_check_rejects_a_record_ahead_of_the_authoritative_clock():
    # Defence in depth: next_record never produces such a record, but the
    # writer's self-check (record_local_findings with now=database time)
    # must still refuse one.
    from clw.audit.chain import record_local_findings

    record = next_record(None, chain_id=CHAIN, event=standard_events()[0], created_at=T0 + timedelta(minutes=6))
    assert ("created_at_in_future" in {p.issue for p in record_local_findings(record, CHAIN, now=T0)})
    assert not record_local_findings(record, CHAIN, now=T0 + timedelta(minutes=1))
    assert not record_local_findings(record, CHAIN)  # verification uses _timestamp_findings instead


def test_recovery_earlier_than_a_still_trusted_record_is_refused_until_the_clock_passes_it():
    # Records 1-3 at T0, record 4 an hour ahead. The clock is corrected to
    # T0-2min: record 3 (T0+2s) is within the skew window, so still trusted,
    # and a recovery at T0-2min would itself be out of order. The writer's
    # pre-insert check (remaining blocking findings) therefore refuses it.
    chain = _with_stamps(build_chain(standard_events()[:4]), {4: _stamp(T0 + timedelta(hours=1))})
    early = T0 - timedelta(minutes=2)
    attempt = _recover(chain, early)
    remaining = {(f.seq, f.issue) for f in blocking_findings(attempt, integrity_findings(attempt, chain_id=CHAIN, now=early))}
    assert (5, "created_at_not_monotonic") in remaining
    later = T0 + timedelta(seconds=10)
    assert _snapshot(_recover(chain, later), later)["state"] == "recovered"


def test_clock_stepped_back_before_every_record_recovers_and_flags_all_of_them():
    chain = build_chain(standard_events()[:4])
    early = T0 - timedelta(hours=3)
    recovered = _recover(chain, early)
    snap = _snapshot(recovered, early)
    assert snap["state"] == "recovered"
    assert snap["acknowledged"] == [(s, "created_at_in_future") for s in (1, 2, 3, 4)]


# ------------------------------------- F-2: behaviour while provisional


def _at(h, m):
    return T0.replace(hour=h, minute=m)


def _chain_with(stamps):
    records = build_chain([{**standard_events()[0], "run_id": f"run-{i:04d}"} for i in range(len(stamps))])
    return _with_stamps(records, {i + 1: _stamp(t) for i, t in enumerate(stamps)})


def test_findings_may_change_while_a_provisional_finding_exists():
    """Gate 1 F-2 (fourth review), the reviewer's adversarial example: with
    record 1 provisional, a later finding changes kind as the clock moves.
    This is the documented behaviour; once nothing is provisional the
    findings are stable."""
    chain = _chain_with([_at(11, 0), _at(7, 0), _at(10, 0), _at(9, 0)])
    early = _snapshot(chain, _at(9, 0))
    assert early["provisional"] == [(1, "created_at_in_future")]
    assert (3, "created_at_in_future") in early["errors"]
    late = _snapshot(chain, _at(11, 0))
    assert late["provisional"] == []
    assert (3, "created_at_not_monotonic") in late["errors"] and (3, "created_at_in_future") not in late["errors"]
    for delta in LATER:
        assert _snapshot(chain, _at(11, 0) + delta)["errors"] == late["errors"]


def test_recovery_written_while_the_clock_is_fast_can_change_state_but_only_while_provisional():
    """The reviewer's simulated sequence: a record written while the database
    clock ran an hour fast, a record at corrected time, a recovery while the
    clock is fast again, two more records. The state changes with the
    verifier's clock, and every verification whose state differs from the
    final one has provisional findings."""
    chain = _chain_with([_at(10, 3), _at(9, 14)])
    fast_now = _at(10, 14)
    chain = _recover(chain, fast_now)
    assert _snapshot(chain, fast_now)["blocking"] == []  # the writer's own check accepted it
    for i, t in enumerate([_at(10, 15), _at(10, 18)]):
        chain = [*chain, next_record(chain[-1], chain_id=CHAIN, created_at=t,
                                     event={**standard_events()[0], "run_id": f"w{i}"})]
    times = [_at(9, 20), _at(9, 50), _at(10, 0), _at(10, 30), _at(10, 30) + timedelta(days=1)]
    snaps = [_snapshot(chain, t) for t in times]
    assert snaps[0]["state"] == "invalid_recovery" and snaps[-1]["state"] == "recovered"
    for snap in snaps:
        if snap != snaps[-1]:
            assert snap["provisional"], snap


@pytest.mark.parametrize("seed", range(300))
def test_once_nothing_is_provisional_later_verifications_agree(seed):
    """Property (F-2 wording): across increasing verification times, from the
    first time with no provisional finding on, every snapshot is identical,
    including chains with a recovery written at a random (possibly fast)
    database time."""
    rng = random.Random(10_000 + seed)
    chain = _random_chain(rng)
    write_time = T0 + timedelta(minutes=rng.choice([0, 1, 30, 120]))
    first = _snapshot(chain, write_time)
    if first["blocking"]:
        attempt = _recover(chain, write_time)
        if not _snapshot(attempt, write_time)["blocking"]:
            chain = attempt
    times = sorted(T0 + timedelta(minutes=rng.randint(-120, 900)) for _ in range(6)) + [T0 + timedelta(days=400)]
    snaps = [_snapshot(chain, t) for t in times]
    stable_from = next((i for i, s in enumerate(snaps) if not s["provisional"]), None)
    if stable_from is not None:
        for later in snaps[stable_from + 1:]:
            assert later == snaps[stable_from], (seed, times)


# ------------------------------------------- F-5: recovery evidence


def _plus(records, stamp, run):
    """Append a record with an arbitrary (possibly out-of-order) timestamp,
    as a privileged writer could."""
    record = next_record(records[-1], chain_id=CHAIN, created_at=T0,
                         event={**standard_events()[0], "run_id": run})
    return [*records, rehash(replace(record, created_at=_stamp(stamp)))]


def test_without_a_baseline_the_earliest_later_recovery_is_the_evidence():
    """Record 1 is an hour ahead; recovery A (09:00) is the evidence. A later
    recovery B (10:30, after the clock has passed record 1) must not replace
    it: with B as the reference, record 1 would become trusted and A would
    be reported out of order."""
    chain = _chain_with([_at(10, 0)])
    chain = _recover(chain, _at(9, 0))                 # A, seq 2: acknowledges (1, in_future)
    chain = _plus(chain, _at(9, 1), "run-a")           # seq 3
    chain = _plus(chain, _at(8, 0), "run-b")           # seq 4: backdated
    chain = _recover(chain, _at(10, 30))               # B, seq 5: acknowledges (4, not_monotonic)
    for now in (_at(10, 31), _at(11, 0), _at(11, 0) + timedelta(days=1)):
        snap = _snapshot(chain, now)
        assert snap["state"] == "recovered", (now, snap)
        assert snap["acknowledged"] == [(1, "created_at_in_future"), (4, "created_at_not_monotonic")]
        assert snap["recoveries"] == [(2, True), (5, True)] and snap["provisional"] == []


def test_out_of_order_later_records_cannot_vouch_for_an_earlier_record():
    """Record 2 is ahead of the clock; the only later record is below the
    trusted baseline (backdated), so it cannot vouch for record 2. Record 2
    must be judged by the clock (provisional), not trusted."""
    chain = _chain_with([_at(9, 0), _at(10, 0), _at(8, 0)])
    snap = _snapshot(chain, _at(9, 10))
    assert snap["provisional"] == [(2, "created_at_in_future")]
    assert set(snap["errors"]) == {(2, "created_at_in_future"), (3, "created_at_not_monotonic")}


# ------------------------------------- L-C: years before 1000


@pytest.mark.parametrize("stamp, expected", [
    ("0500-01-01T00:10:00.000000Z", "0500-01-01T00:05:00.000000Z"),
    ("0999-12-31T23:59:59.999999Z", "0999-12-31T23:54:59.999999Z"),
    ("1000-01-01T00:04:00.000000Z", "0999-12-31T23:59:00.000000Z"),
    ("0001-01-01T00:10:00.000000Z", "0001-01-01T00:05:00.000000Z"),
    ("0001-01-01T00:04:00.000000Z", ""),  # nothing can be 5 minutes below year 1
])
def test_skew_bound_is_formatted_with_four_digit_years(stamp, expected):
    from clw.audit.chain import _minus_skew

    assert _minus_skew(stamp) == expected


def test_record_before_year_1000_is_judged_the_same_on_every_platform():
    """The reviewer's case: a year-500 record followed by a 2026 record is
    a backdated chain start (rule 1 for the later records does not apply:
    no baseline), not a record ahead of anything. On glibc the unpadded skew
    bound used to sort below the 2026 timestamp and flag it as ahead."""
    chain = _chain_with([T0.replace(year=500), T0, T0 + timedelta(seconds=1)])
    assert _snapshot(chain, T0)["errors"] == []
    chain = _chain_with([T0, T0.replace(year=500)])
    assert _snapshot(chain, T0)["errors"] == [(2, "created_at_not_monotonic")]


# ------------------------------------------- I-1 gaps 1 and 7 (fifth review)


@pytest.mark.parametrize("ahead, trusted", [
    (timedelta(minutes=5), True),                              # exactly the tolerance
    (timedelta(minutes=5, microseconds=1), False),             # one microsecond beyond
    (timedelta(minutes=4, seconds=59, microseconds=999999), True),
    (timedelta(0), True),
    (-timedelta(days=1), True),                                # an old cached position is fine
])
def test_cached_position_trust_boundary_is_exactly_five_minutes(ahead, trusted):
    from clw.audit.chain import Anchor
    from clw.audit.writer import AuditWriter

    anchor = Anchor(3, "a" * 64, _stamp(T0 + ahead))
    assert AuditWriter._anchor_trustworthy(anchor, T0) is trusted


@pytest.mark.parametrize("gap, evidence", [
    (timedelta(minutes=5), False),                             # exactly 5 minutes below: not evidence
    (timedelta(minutes=5, microseconds=1), True),              # more than 5 minutes below: evidence
])
def test_recovery_evidence_boundary_without_a_baseline(gap, evidence):
    """Rule 2 with no trusted baseline: a later recovery is evidence only if
    it is MORE than 5 minutes below the record."""
    ahead = T0 + timedelta(hours=1)
    chain = _chain_with([ahead])
    recovery_at = ahead - gap
    blocking = blocking_findings(chain, integrity_findings(chain, chain_id=CHAIN, now=T0))
    recovery = recovery_record(chain, blocking, chain_id=CHAIN, operator="op", reason="r",
                               created_at=recovery_at, now=recovery_at)
    # next_record copies a head timestamp up to 5 minutes ahead, so set the
    # boundary timestamp explicitly (as any INSERT-capable writer could).
    chain = [*chain, rehash(replace(recovery, created_at=_stamp(recovery_at)))]
    # Verify at a time when record 1 is no longer ahead of the clock, so only
    # chain evidence can flag it.
    findings = {(e.seq, e.issue, e.detail.startswith("provisional")) for e in
                verify_records(chain, chain_id=CHAIN, now=ahead + timedelta(hours=1)).errors}
    if evidence:
        assert (1, "created_at_in_future", False) in findings
    else:
        assert not any(seq == 1 and issue == "created_at_in_future" for seq, issue, _ in findings)
