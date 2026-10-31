"""Malformed input never crashes verification (L1); verifier checks schema
version and timestamps (H3). Includes the reviewer's poc_mem cases 4-7."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from clw.audit.canonical import CanonicalizationError, canonical_json
from clw.audit.chain import next_record, verify_records, verify_run_result

from .helpers import CHAIN, RESULT, T0, build_chain, rehash, standard_events


def issues_of(records):
    return {(e.seq, e.issue) for e in verify_records(records, chain_id=CHAIN).errors}


def _relink(records, start):
    out = list(records)
    for i in range(start, len(out)):
        out[i] = rehash(replace(out[i], previous_hash=out[i - 1].record_hash))
    return out


# ---------------------------------------------------- L1: never crash


def _deep(n):
    value = 1
    for _ in range(n):
        value = {"a": value}
    return value


@pytest.mark.parametrize("change", [
    {"seq": None}, {"seq": "1"}, {"seq": True}, {"seq": 1.5}, {"seq": ["unhashable"]}, {"seq": {"a": 1}},
    {"created_at": ["2026"]}, {"run_id": {"a": 1}}, {"decision_seq": ["x"]}, {"attempt": ["x"]},
    {"run_id": ["x"]}, {"details": ["x"]}, {"details": None}, {"details": _deep(3000)},
    {"created_at": None}, {"created_at": 12}, {"record_hash": None}, {"previous_hash": 7},
    {"event_type": None}, {"event_type": ["RUN_REQUESTED"]}, {"chain_id": None},
    {"schema_version": "2"}, {"schema_version": None},
])
def test_malformed_record_is_a_finding_not_a_crash(change):
    chain = build_chain()
    chain[0] = replace(chain[0], **change)
    report = verify_records(chain, chain_id=CHAIN)  # must not raise
    assert not report.valid


@pytest.mark.parametrize("change", [{"seq": True}, {"seq": "1"}])
def test_malformed_record_detected_even_when_rehashed(change):
    chain = build_chain()
    try:
        chain[0] = rehash(replace(chain[0], **change))
    except Exception:
        pytest.skip("unhashable change")
    assert not verify_records(chain, chain_id=CHAIN).valid


def test_deeply_nested_details_rejected_by_canonicalization_not_recursion():
    with pytest.raises(CanonicalizationError):
        canonical_json({"d": _deep(3000)})


def test_depth_limit_boundary():
    # Depth counts every value: _deep(n) is n nested objects plus a leaf, n + 1 levels.
    canonical_json(_deep(15))  # 16 levels: allowed
    with pytest.raises(CanonicalizationError):
        canonical_json(_deep(16))  # 17 levels: rejected


def test_record_level_limit_means_details_depth_at_most_15():
    # details sits one level below the record object that is hashed, so the
    # database constraint on details is MAX_DEPTH - 1 (migration 20261015).
    from .helpers import ev

    event = {**ev("RUN_TIMED_OUT", "timed_out"), "details": _deep(14)}  # details depth 15
    next_record(None, chain_id=CHAIN, event=event, created_at=T0)
    from clw.audit.events import AuditEventInvalid

    with pytest.raises(AuditEventInvalid):
        next_record(None, chain_id=CHAIN, event={**event, "details": _deep(15)}, created_at=T0)


@pytest.mark.parametrize("details", [["x"], None, "s", {"result_sha256": 5}])
def test_verify_run_result_with_malformed_details_is_a_mismatch(details):
    completion = replace(build_chain()[-1], details=details)
    assert verify_run_result(completion, RESULT) == "result_mismatch"


@pytest.mark.parametrize("stored", [None, ["x"], "s", {"x": 1.5}])
def test_verify_run_result_with_malformed_stored_result_is_a_mismatch(stored):
    assert verify_run_result(build_chain()[-1], stored) == "result_mismatch"


# --------------------------------------------- H3: version and timestamps


@pytest.mark.parametrize("version", [0, 1, 4, 999])
def test_unsupported_schema_version_rejected_even_if_rehashed(version):
    chain = build_chain()
    chain[0] = rehash(replace(chain[0], schema_version=version))
    chain = _relink(chain, 1)
    assert (1, "unsupported_schema_version") in issues_of(chain)


@pytest.mark.parametrize("stamp", [
    "not-a-timestamp", "2026-10-14T09:00:00Z", "2026-10-14T09:00:00.000000+00:00",
    "2026-13-14T09:00:00.000000Z", "2026-10-14 09:00:00.000000Z", "",
])
def test_malformed_created_at_rejected_even_if_rehashed(stamp):
    chain = build_chain()
    chain[0] = rehash(replace(chain[0], created_at=stamp))
    chain = _relink(chain, 1)
    assert (1, "invalid_created_at") in issues_of(chain)


def test_backwards_created_at_rejected_even_if_rehashed():
    chain = build_chain()
    chain[5] = rehash(replace(chain[5], created_at="1999-01-01T00:00:00.000000Z"))
    chain = _relink(chain, 6)
    assert (6, "created_at_not_monotonic") in issues_of(chain)


def test_equal_timestamps_are_allowed():
    events = standard_events()
    head, records = None, []
    for e in events:
        head = next_record(head, chain_id=CHAIN, event=e, created_at=T0)
        records.append(head)
    assert verify_records(records, chain_id=CHAIN).valid


def test_head_within_skew_window_is_adopted_to_keep_order():
    # Ordinary clock skew (< 5 minutes): the new record takes the head's stamp.
    first = next_record(None, chain_id=CHAIN, event=standard_events()[0], created_at=T0)
    second = next_record(first, chain_id=CHAIN, event=standard_events()[1], created_at=T0 - timedelta(minutes=4))
    assert second.created_at == first.created_at
    assert verify_records([first, second], chain_id=CHAIN).valid


def test_far_future_head_timestamp_is_never_copied():
    # N2/N3: a head more than 5 minutes ahead of the writer's clock is not
    # propagated; the new record keeps its own clock's value.
    first = next_record(None, chain_id=CHAIN, event=standard_events()[0], created_at=T0 + timedelta(hours=1))
    second = next_record(first, chain_id=CHAIN, event=standard_events()[1], created_at=T0)
    assert second.created_at == "2026-10-14T09:00:00.000000Z"


def test_invalid_head_timestamp_is_never_copied():
    first = rehash(replace(next_record(None, chain_id=CHAIN, event=standard_events()[0], created_at=T0),
                           created_at="9999-99-99T99:99:99.999999Z"))
    second = next_record(first, chain_id=CHAIN, event=standard_events()[1], created_at=T0)
    assert second.created_at == "2026-10-14T09:00:00.000000Z"


def test_future_timestamp_flagged_relative_to_verification_clock():
    first = next_record(None, chain_id=CHAIN, event=standard_events()[0], created_at=T0)
    assert verify_records([first], chain_id=CHAIN, now=T0 + timedelta(minutes=5)).valid  # boundary: allowed
    found = {(e.seq, e.issue) for e in verify_records([first], chain_id=CHAIN, now=T0 - timedelta(minutes=6)).errors}
    assert (1, "created_at_in_future") in found


def test_corrupt_timestamp_does_not_contaminate_later_records():
    # A later honest record is compared with the last trustworthy timestamp,
    # not with the corrupt one, so it gets no finding of its own.
    chain = build_chain()
    chain[3] = rehash(replace(chain[3], created_at="9999-12-31T23:59:59.999999Z"))
    chain = _relink(chain, 4)
    found = {(e.seq, e.issue) for e in verify_records(chain, chain_id=CHAIN).errors}
    assert (4, "created_at_in_future") in found
    assert not any(seq > 4 and issue.startswith("created_at") for seq, issue in found)


@pytest.mark.parametrize("stamp", [
    "٢٠٢٦-10-14T09:00:00.000000Z",  # Arabic-Indic digits
    "2026-10-14T09:00:00.000000Z\n",                      # trailing newline
    "2026-02-30T09:00:00.000000Z",                         # impossible date
    "0000-01-01T00:00:00.000000Z",
])
def test_non_ascii_trailing_newline_and_impossible_dates_rejected(stamp):
    from clw.audit.events import valid_created_at

    assert not valid_created_at(stamp)


def test_reviewer_poc_backdated_forgery_is_flagged():
    # poc_db section C: forged records backdated to 2001 after a 2026 head.
    chain = build_chain()[:2]
    forged = rehash(replace(chain[1], seq=3, previous_hash=chain[1].record_hash,
                            created_at="2001-01-01T00:00:00.000000Z", event_type="RUN_TIMED_OUT",
                            status="timed_out", task_id=None, task_manifest_sha256=None,
                            profile_id=None, profile_version=None, auth_mode=None))
    assert (3, "created_at_not_monotonic") in issues_of([*chain, forged])


def test_forgery_with_plausible_timestamps_is_not_detectable():
    # Residual risk RR-1 (threat-model §6), pinned: an INSERT-capable writer that
    # follows every rule produces records the verifier accepts. The chain proves
    # integrity after writing, not that the events happened.
    from .helpers import allow, ev, request, response

    events = standard_events()[:4] + [
        # A forger that follows every rule records the matching approved target too (RR-5 binds it).
        allow(op="users.delete", method="DELETE", template="/users/{user_id}",
              target="/v1.0/users/00000000-0000-0000-0000-000000000666"),
        request(5, 1, op="users.delete", method="DELETE", template="/users/{user_id}",
                target="/v1.0/users/00000000-0000-0000-0000-000000000666"),
        response(1, op="users.delete", http_status=204),
        ev("RUN_FAILED", "failed", reason="x"),
    ]
    assert verify_records(build_chain(events), chain_id=CHAIN).valid


@pytest.mark.parametrize("position", range(8))
@pytest.mark.parametrize("field", ["seq", "run_id", "attempt", "decision_seq", "operation", "created_at"])
def test_unhashable_values_anywhere_never_crash_verification(field, position):
    chain = build_chain()
    chain[position] = replace(chain[position], **{field: ["unhashable"]})
    assert not verify_records(chain, chain_id=CHAIN).valid


@pytest.mark.parametrize("field", ["seq", "run_id", "created_at"])
def test_findings_for_malformed_records_use_integer_seqs(field):
    # Findings feed checkpoints (sorted, canonicalized): their seq must be an int.
    chain = build_chain()
    chain[3] = replace(chain[3], **{field: ["unhashable"]})
    report = verify_records(chain, chain_id=CHAIN)
    assert all(isinstance(e.seq, int) and not isinstance(e.seq, bool) for e in (*report.errors, *report.acknowledged))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from clw.audit.checkpoint import sign_checkpoint

    from clw.audit.verifier import StoredRecord

    sign_checkpoint([StoredRecord.from_record(r) for r in chain], Ed25519PrivateKey.generate(),
                    chain_id=CHAIN, issued_at=T0, allow_invalid=True)
