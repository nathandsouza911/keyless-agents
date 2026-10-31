"""RESULT_REDACTED: record shape, chain rules and verify_run_result (SD-037)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from clw.audit.chain import result_sha256, verify_records, verify_run_result
from clw.audit.events import EVENT_FIELDS, AuditEventInvalid, EventType, validate_event

from .helpers import CHAIN, RESULT, RUN, build_chain, ev, rehash, standard_events

DIGEST = result_sha256(RESULT)


def redaction(run_id: str = RUN, digest: str = DIGEST, **kw) -> dict:
    return {"tenant_id": CHAIN, "event_type": "RESULT_REDACTED", "status": "recorded", "reason": "personal data",
            "actor_oid": "operator-1", "details": {"redacted_run_id": run_id, "result_sha256": digest}, **kw}


def issues(events):
    return {(e.seq, e.issue) for e in verify_records(build_chain(events), chain_id=CHAIN).errors}


# --------------------------------------------------------------- record shape


def test_a_redaction_after_its_completed_run_is_valid():
    report = verify_records(build_chain([*standard_events(), redaction()]), chain_id=CHAIN)
    assert report.valid and report.intents_without_outcome == ()


MALFORMED = [
    {"details": {"redacted_run_id": RUN}},
    {"details": {"result_sha256": DIGEST}},
    {"details": {"redacted_run_id": RUN, "result_sha256": DIGEST, "result": RESULT}},  # never the data itself
    {"details": {"redacted_run_id": RUN, "result_sha256": "A" * 64}},
    {"details": {"redacted_run_id": "", "result_sha256": DIGEST}},
    {"details": {"redacted_run_id": "r" * 129, "result_sha256": DIGEST}},
    {"reason": None},
    {"actor_oid": None},
    {"status": "redacted"},
    {"run_id": RUN},  # never part of a run
]


@pytest.mark.parametrize("change", MALFORMED)
def test_malformed_redactions_cannot_be_built(change):
    with pytest.raises(AuditEventInvalid):
        build_chain([*standard_events(), redaction() | change])


@pytest.mark.parametrize("change", MALFORMED)
def test_forged_malformed_redactions_are_found(change):
    # What a writer bypassing next_record does: edit the stored record, then re-hash it.
    records = build_chain([*standard_events(), redaction()])
    fields = {k: v for k, v in change.items()}
    records[-1] = rehash(replace(records[-1], **fields))
    report = verify_records(records, chain_id=CHAIN)
    assert "invalid_event_shape" in {e.issue for e in report.errors}


def test_validate_event_names_the_redaction_rule():
    record = build_chain([*standard_events(), redaction()])[-1]
    values = {f: getattr(record, f) for f in EVENT_FIELDS} | {"details": {}}
    assert any("RESULT_REDACTED" in p for p in validate_event(values, chain_id=CHAIN))


# ---------------------------------------------------------------- chain rules


def test_redaction_of_an_unknown_run_is_a_finding():
    assert issues([*standard_events(), redaction(run_id="run-9999")]) == {(9, "redaction_without_completed_run")}


def test_redaction_of_a_failed_run_is_a_finding():
    events = [*standard_events()[:2], ev("RUN_FAILED", "failed", reason="x"), redaction()]
    assert issues(events) == {(4, "redaction_without_completed_run")}


def test_redaction_before_the_completion_is_a_finding():
    events = standard_events()
    assert (8, "redaction_without_completed_run") in issues([*events[:7], redaction(), events[7]])


def test_redaction_with_another_digest_is_a_finding():
    assert issues([*standard_events(), redaction(digest="b" * 64)]) == {(9, "redaction_digest_mismatch")}


def test_a_second_redaction_of_the_same_run_is_a_finding():
    assert issues([*standard_events(), redaction(), redaction()]) == {(10, "result_already_redacted")}


def test_no_run_record_may_follow_its_redaction_either():
    # The run had ended already; the redaction does not reopen it.
    later = ev("OP_DECISION", "denied", operation="users.update", reason="not_in_manifest")
    assert issues([*standard_events(), redaction(), later]) == {(10, "event_after_run_end")}


# ------------------------------------------------------------ verify_run_result


def _completion_and_redaction(**kw):
    records = build_chain([*standard_events(), redaction(**kw)])
    return records[7], records[8]


def test_a_removed_result_with_its_redaction_is_redacted():
    completion, redacted = _completion_and_redaction()
    assert completion.event_type == EventType.RUN_COMPLETED
    assert verify_run_result(completion, None, redaction=redacted) == "redacted"


def test_a_redaction_never_vouches_for_a_result_still_present():
    completion, redacted = _completion_and_redaction()
    assert verify_run_result(completion, {"forged": True}, redaction=redacted) == "result_mismatch"
    assert verify_run_result(completion, RESULT, redaction=redacted) == "ok"


@pytest.mark.parametrize("kw", [{"digest": "c" * 64}, {"run_id": "run-other"}])
def test_a_redaction_of_something_else_does_not_count(kw):
    completion, redacted = _completion_and_redaction(**kw)
    assert verify_run_result(completion, None, redaction=redacted) == "result_mismatch"


def test_a_missing_result_without_a_redaction_is_a_mismatch():
    completion, _ = _completion_and_redaction()
    assert verify_run_result(completion, None) == "result_mismatch"


def test_only_a_redaction_record_counts_as_one():
    completion, redacted = _completion_and_redaction()
    impostor = replace(redacted, event_type="CHAIN_RECOVERY")
    assert verify_run_result(completion, None, redaction=impostor) == "result_mismatch"


def test_a_redaction_from_another_chain_does_not_count():
    completion, redacted = _completion_and_redaction()
    assert verify_run_result(completion, None, redaction=replace(redacted, chain_id="other")) == "result_mismatch"
