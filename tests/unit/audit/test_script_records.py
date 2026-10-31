"""Audit schema v3 script records and their chain rules (SD-040)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from clw.audit.chain import verify_records
from clw.audit.events import AuditEventInvalid

from .helpers import CHAIN, MANIFEST_SHA, build_chain, ev, rehash, standard_events

SCRIPT = "5" * 64
ANALYSIS = "6" * 64
MANIFEST = "7" * 64
BOOTSTRAP = "8" * 64


def tenant_event(event_type: str, status: str, **fields) -> dict:
    return {"tenant_id": CHAIN, "event_type": event_type, "status": status, **fields}


def submitted(sha: str = SCRIPT, by: str = "analyst-oid") -> dict:
    return tenant_event("SCRIPT_SUBMITTED", "submitted", actor_oid=by,
                        details={"script_sha256": sha, "script_bytes": 2048})


def analyzed(sha: str = SCRIPT) -> dict:
    return tenant_event("SCRIPT_ANALYZED", "analyzed",
                        details={"script_sha256": sha, "analysis_sha256": ANALYSIS, "analyser_version": "1"})


def approved(sha: str = SCRIPT, by: str = "lead-oid", approval: str = "appr-1") -> dict:
    return tenant_event("MANIFEST_APPROVED", "approved", actor_oid=by,
                        details={"script_sha256": sha, "manifest_sha256": MANIFEST, "approval_id": approval})


def script_run(approval: str = "appr-1", sha: str = SCRIPT, *, after: int = 0) -> list[dict]:
    """A script run: the standard run with a script RUN_STARTED, placed `after` earlier records."""
    events = standard_events()
    events[1] = events[1] | {"details": {"script_sha256": sha, "approval_id": approval, "bootstrap_sha256": BOOTSTRAP}}
    events[4] = events[4] | {"decision_seq": events[4]["decision_seq"] + after}
    return events


def issues(events):
    return {(e.seq, e.issue) for e in verify_records(build_chain(events), chain_id=CHAIN).errors}


def test_the_full_script_flow_is_valid():
    assert issues([submitted(), analyzed(), approved(), *script_run(after=3)]) == set()


@pytest.mark.parametrize("events, expected", [
    ([analyzed()], {(1, "analysis_without_submission")}),
    ([submitted(), approved()], {(2, "approval_without_analysis")}),
    ([submitted(by="same"), analyzed(), approved(by="same")], {(3, "approved_by_submitter")}),
    ([submitted(), analyzed(), approved(), approved()], {(4, "approval_already_recorded")}),
    ([submitted(), analyzed(), approved(sha="9" * 64)], {(3, "approval_without_analysis")}),
])
def test_script_record_order_and_separation_of_duties(events, expected):
    assert issues(events) == expected


def test_a_failed_analysis_does_not_allow_an_approval():
    failed = tenant_event("SCRIPT_ANALYZED", "failed", reason="parse_error",
                          details={"script_sha256": SCRIPT, "analyser_version": "1"})
    assert issues([submitted(), failed, approved()]) == {(3, "approval_without_analysis")}


@pytest.mark.parametrize("prefix, approval, sha", [
    ([], "appr-1", SCRIPT),                                         # no approval at all
    ([submitted(), analyzed(), approved()], "appr-2", SCRIPT),       # another approval id
    ([submitted(), analyzed(), approved()], "appr-1", "9" * 64),     # the approval is for another script
])
def test_a_script_run_needs_an_approval_of_that_script(prefix, approval, sha):
    start = len(prefix) + 2
    assert (start, "script_run_without_approval") in issues([*prefix, *script_run(approval, sha, after=len(prefix))])


def test_a_task_run_needs_no_approval():
    assert issues(standard_events()) == set()


@pytest.mark.parametrize("event", [
    submitted() | {"details": {"script_sha256": SCRIPT}},
    submitted() | {"actor_oid": None},
    submitted() | {"run_id": "run-0001"},
    analyzed() | {"details": {"script_sha256": SCRIPT}},
    tenant_event("SCRIPT_ANALYZED", "failed", details={"script_sha256": SCRIPT, "analyser_version": "1"}),
    approved() | {"details": {"script_sha256": SCRIPT, "manifest_sha256": "X" * 64, "approval_id": "a"}},
    approved() | {"status": "rejected"},
])
def test_malformed_script_records_cannot_be_written(event):
    with pytest.raises(AuditEventInvalid):
        build_chain([event])


def test_a_malformed_script_run_start_cannot_be_written():
    events = standard_events()
    events[1] = events[1] | {"details": {"script_sha256": SCRIPT}}
    with pytest.raises(AuditEventInvalid):
        build_chain(events)


def test_script_records_are_v3_only():
    chain = build_chain([submitted()])
    forged = rehash(replace(chain[0], schema_version=2))
    report = verify_records([forged], chain_id=CHAIN)
    assert "invalid_event_shape" in {e.issue for e in report.errors}


def test_v2_records_remain_valid_under_v2_rules():
    chain = [rehash(replace(r, schema_version=2)) for r in build_chain()]
    # Re-link: each record's previous_hash is the rehashed predecessor.
    linked, previous = [], "0" * 64
    for record in chain:
        record = rehash(replace(record, previous_hash=previous))
        linked.append(record)
        previous = record.record_hash
    assert verify_records(linked, chain_id=CHAIN).valid


def test_manifest_digest_constant_is_unrelated():
    assert MANIFEST_SHA != MANIFEST  # the task manifest digest and the script manifest digest are distinct values
