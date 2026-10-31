"""Run state machine and approval binding (SD-014, review findings M1 and L5).

Every invalid transition and every request/approval mismatch has a negative
test here, alongside the valid paths (allowed, denied, partial failure,
retries and pagination with fresh approvals).
"""

from __future__ import annotations

import pytest

from clw.audit.chain import verify_records

from .helpers import CHAIN, OP, allow, build_chain, deny, ev, request, response, standard_events

E = standard_events()
REQUESTED, STARTED, ALLOWED, CRED, REQ, RESP, DENIED, COMPLETED = E
FAILED = ev("RUN_FAILED", "failed", reason="x")


def report_for(events):
    return verify_records(build_chain(events), chain_id=CHAIN)


def issues(events):
    return {(e.seq, e.issue) for e in report_for(events).errors}


def assert_only(events, *expected):
    found = issues(events)
    assert found == set(expected), found


# ------------------------------------------------------------ valid paths


def test_standard_run_is_valid():
    assert report_for(E).valid and report_for(E).complete


def test_denied_only_run_is_valid():
    assert report_for([REQUESTED, STARTED, DENIED, FAILED]).valid


def test_retry_with_fresh_approval_is_valid():
    events = [REQUESTED, STARTED, ALLOWED, CRED, request(3, 1),
              response(1, status="failed", http_status=429, reason="throttled"),
              allow(), request(7, 2), response(2), COMPLETED]
    assert report_for(events).valid


def test_pagination_with_one_approval_per_page_is_valid():
    events = [REQUESTED, STARTED, CRED,
              allow(), request(4, 1), response(1),
              allow(), request(7, 2, target="/v1.0/users?$top=999&$skiptoken=abc"), response(2),
              COMPLETED]
    assert report_for(events).valid


def test_partial_failure_keeps_intent_visible():
    report = report_for([REQUESTED, STARTED, ALLOWED, CRED, REQ, ev("RUN_FAILED", "failed", reason="audit_unavailable")])
    assert report.valid and report.intents_without_outcome == (5,) and not report.complete


def test_failed_graph_response_is_valid_evidence():
    events = [REQUESTED, STARTED, ALLOWED, CRED, REQ,
              response(1, status="failed", http_status=403, reason="licence_required"),
              ev("RUN_FAILED", "failed", reason="licence_required")]
    assert report_for(events).valid


def test_timeout_before_start_is_valid():
    assert report_for([REQUESTED, ev("RUN_TIMED_OUT", "timed_out")]).valid


# ----------------------------------------------------- run ordering (L5)


def test_events_before_run_requested_are_rejected():
    assert_only([STARTED, ALLOWED], (1, "run_not_requested"), (2, "run_not_requested"))


def test_request_with_no_run_lifecycle_is_rejected():
    found = issues([ALLOWED, REQ, RESP, COMPLETED])
    assert {(1, "run_not_requested"), (2, "run_not_requested")} <= found


def test_run_requested_twice_is_rejected():
    assert_only([REQUESTED, REQUESTED], (2, "run_already_requested"))


def test_run_started_twice_is_rejected():
    assert_only([REQUESTED, STARTED, STARTED], (3, "run_already_started"))


def test_run_started_for_a_different_task_or_manifest_is_rejected():
    assert_only([REQUESTED, {**STARTED, "task_manifest_sha256": "b" * 64}], (2, "run_started_mismatch"))
    assert_only([REQUESTED, {**STARTED, "task_id": "other-task"}], (2, "run_started_mismatch"))


@pytest.mark.parametrize("event", [ALLOWED, DENIED, CRED, COMPLETED], ids=lambda e: e["event_type"])
def test_work_before_run_started_is_rejected(event):
    assert (2, "run_not_started") in issues([REQUESTED, event])


@pytest.mark.parametrize("event", [ALLOWED, CRED, REQ, RESP, FAILED, COMPLETED, STARTED],
                         ids=lambda e: e["event_type"])
def test_any_event_after_run_end_is_rejected(event):
    assert (5, "event_after_run_end") in issues([REQUESTED, STARTED, DENIED, FAILED, event])


def test_completion_with_unanswered_request_is_rejected():
    assert (6, "completed_with_outstanding_requests") in issues([REQUESTED, STARTED, ALLOWED, CRED, REQ, COMPLETED])


def test_credential_for_another_profile_is_rejected():
    assert (4, "credential_profile_mismatch") in issues(
        [REQUESTED, STARTED, ALLOWED, {**CRED, "profile_version": 2}, REQ, RESP, COMPLETED])


def test_request_without_any_credential_is_rejected():
    assert (4, "credential_not_acquired") in issues([REQUESTED, STARTED, ALLOWED, REQ, RESP, COMPLETED])


def test_request_after_credential_rejection_is_rejected():
    rejected = ev("CREDENTIAL_REJECTED", "rejected", profile_id=CRED["profile_id"], profile_version=1,
                  auth_mode="app_only", reason="permissions_extra")
    assert (5, "credential_not_acquired") in issues([REQUESTED, STARTED, ALLOWED, rejected, REQ, RESP, COMPLETED])


# ------------------------------------------------ approval binding (M1)


def _with_request(req, decision=ALLOWED):
    return [REQUESTED, STARTED, decision, CRED, req, RESP, COMPLETED]


def test_request_must_match_the_approved_method():
    assert (5, "request_does_not_match_decision") in issues(
        _with_request(request(3, 1, method="DELETE", template="/users")))


def test_request_must_match_the_approved_template():
    assert (5, "request_does_not_match_decision") in issues(
        _with_request(request(3, 1, template="/users/{user_id}",
                              target="/v1.0/users/00000000-0000-0000-0000-000000000001")))


@pytest.mark.parametrize("decision_seq, why", [(99, "missing"), (5, "self"), (6, "later"), (1, "not a decision")])
def test_request_must_cite_an_earlier_allowed_decision(decision_seq, why):
    assert (5, "request_without_allowed_decision") in issues(_with_request(request(decision_seq, 1))), why


def test_request_citing_a_denial_is_rejected():
    events = [REQUESTED, STARTED, deny(), CRED, request(3, 1), RESP, COMPLETED]
    assert (5, "request_without_allowed_decision") in issues(events)


def test_stale_approval_after_a_later_denial_is_rejected():
    events = [REQUESTED, STARTED, ALLOWED, CRED, deny(reason="deadline_exceeded"), request(3, 1), RESP, COMPLETED]
    assert (6, "request_without_allowed_decision") in issues(events)


def test_approval_superseded_by_a_newer_approval_must_not_be_reused():
    events = [REQUESTED, STARTED, ALLOWED, CRED, allow(), request(3, 1), RESP, COMPLETED]
    assert (6, "request_without_allowed_decision") in issues(events)


def test_one_approval_authorizes_only_one_attempt():
    events = [REQUESTED, STARTED, ALLOWED, CRED, request(3, 1), response(1), request(3, 2), response(2), COMPLETED]
    assert (7, "decision_already_used") in issues(events)


def test_fifty_attempts_on_one_approval_are_rejected():
    events = [REQUESTED, STARTED, ALLOWED, CRED] + [request(3, i) for i in range(1, 51)]
    found = issues(events)
    assert {(s, "decision_already_used") for s in range(6, 55)} <= found


def test_request_cannot_use_approval_for_another_operation():
    events = [REQUESTED, STARTED, ALLOWED, CRED, request(3, 1, op="users.other"), response(1, op="users.other"), COMPLETED]
    assert (5, "request_without_allowed_decision") in issues(events)


def test_request_cannot_use_another_runs_approval():
    other_run = [{**e, "run_id": "run-0002"} for e in (REQUESTED, STARTED)]
    events = [REQUESTED, STARTED, ALLOWED, CRED, *other_run, {**request(3, 1), "run_id": "run-0002"}]
    assert (7, "request_without_allowed_decision") in issues(events)


@pytest.mark.parametrize("attempt", [2, 3])
def test_attempt_numbers_must_be_sequential(attempt):
    assert (5, "attempt_out_of_order") in issues(_with_request(request(3, attempt)))


def test_response_without_request_is_rejected():
    assert (5, "response_without_request") in issues([REQUESTED, STARTED, ALLOWED, CRED, RESP])


def test_response_for_another_operation_is_rejected():
    assert (6, "response_without_request") in issues(
        [REQUESTED, STARTED, ALLOWED, CRED, REQ, response(1, op="users.other"), COMPLETED])


def test_duplicate_response_is_rejected():
    assert (7, "duplicate_response") in issues([REQUESTED, STARTED, ALLOWED, CRED, REQ, RESP, RESP, COMPLETED])


# -------------------------------------------- reviewer PoC (poc_mem / poc_mem2)


def test_reviewer_poc_denied_then_allowed_delete_to_foreign_host_is_rejected():
    # poc_mem case 1: shape rules refuse the foreign absolute target at write
    # time; a record carrying it in storage is an integrity finding.
    from dataclasses import replace

    from .helpers import rehash

    chain = build_chain([REQUESTED, STARTED, deny(), allow(), request(4, 1)])
    forged = rehash(replace(chain[-1], http_method="DELETE", path_template="/users/{id}",
                            request_target="https://evil.example/x"))
    report = verify_records([*chain[:-1], forged], chain_id=CHAIN)
    found = {(e.seq, e.issue) for e in report.errors}
    assert (5, "invalid_event_shape") in found
    assert (5, "request_does_not_match_decision") in found


def test_reviewer_poc_stale_allowed_after_later_denial_is_rejected():
    events = [REQUESTED, STARTED, ALLOWED, CRED, deny(reason="deadline_exceeded"), request(3, 1)]
    assert (6, "request_without_allowed_decision") in issues(events)


# ------------------------------------------- recovery acknowledgement (H2)

from dataclasses import replace as _replace

from clw.audit.chain import blocking_findings, integrity_findings

from .helpers import rehash as _rehash


def _poisoned_then_recovered(tamper_recovery: bool):
    chain = build_chain(E[:3])
    bad = _replace(chain[-1], seq=4, previous_hash=chain[-1].record_hash, record_hash="0" * 64, status="bogus")
    from clw.audit.chain import next_record

    recovery = next_record(bad, chain_id=CHAIN, created_at=__import__("tests.unit.audit.helpers", fromlist=["T0"]).T0,
                           event={"tenant_id": CHAIN, "event_type": "CHAIN_RECOVERY", "status": "recorded",
                                  "reason": "x", "actor_oid": "op",
                                  "details": {"acknowledged": [{"seq": 4, "issue": "hash_mismatch"},
                                                               {"seq": 4, "issue": "invalid_event_shape"}],
                                              "observed_head_seq": 4, "observed_head_hash": bad.record_hash}})
    if tamper_recovery:
        recovery = _replace(recovery, actor_oid="someone-else")  # recovery record's own hash now wrong
    return [*chain, bad, recovery]


def test_clean_recovery_acknowledges_exactly_the_listed_findings():
    records = _poisoned_then_recovered(tamper_recovery=False)
    findings = integrity_findings(records, chain_id=CHAIN)
    assert blocking_findings(records, findings) == []
    report = verify_records(records, chain_id=CHAIN)
    assert not report.valid  # acknowledged findings remain errors
    assert {(e.seq, e.issue) for e in report.acknowledged} == {(4, "hash_mismatch"), (4, "invalid_event_shape")}


def test_recovery_record_with_its_own_integrity_failure_acknowledges_nothing():
    records = _poisoned_then_recovered(tamper_recovery=True)
    blocking = {(f.seq, f.issue) for f in blocking_findings(records, integrity_findings(records, chain_id=CHAIN))}
    assert (4, "hash_mismatch") in blocking and (5, "hash_mismatch") in blocking
    assert verify_records(records, chain_id=CHAIN).acknowledged == ()


def test_recovery_cannot_acknowledge_a_later_record():
    records = _poisoned_then_recovered(tamper_recovery=False)
    rec = records[-1]
    forward = _rehash(_replace(rec, details={**rec.details, "acknowledged": [{"seq": 9, "issue": "hash_mismatch"}]}))
    assert (5, "invalid_recovery") in {(e.seq, e.issue) for e in verify_records([*records[:-1], forward], chain_id=CHAIN).errors}


# ------------------------------------ N4 recovery consistency and visibility


def _recovery_variant(**details_changes):
    records = _poisoned_then_recovered(tamper_recovery=False)
    rec = records[-1]
    return [*records[:-1], _rehash(_replace(rec, details={**rec.details, **details_changes}))]


@pytest.mark.parametrize("change", [
    {"observed_head_seq": 999},
    {"observed_head_seq": 3},
    {"observed_head_hash": "1" * 64},
    {"acknowledged": [{"seq": 2, "issue": "hash_mismatch"}]},       # finding that never existed
    {"acknowledged": [{"seq": 4, "issue": "seq_gap"}]},             # wrong issue at a real seq
])
def test_inconsistent_recovery_is_invalid_and_acknowledges_nothing(change):
    records = _recovery_variant(**change)
    report = verify_records(records, chain_id=CHAIN)
    assert (5, "invalid_recovery") in {(e.seq, e.issue) for e in report.errors}
    assert report.acknowledged == ()
    assert [(r.seq, r.valid) for r in report.recoveries] == [(5, False)]
    blocking = {(f.seq, f.issue) for f in blocking_findings(records, integrity_findings(records, chain_id=CHAIN))}
    assert (4, "hash_mismatch") in blocking


def test_recovery_acknowledging_nothing_real_never_leaves_chain_valid():
    # Reviewer N4e: previously reported valid=True with the recovery invisible.
    chain = build_chain(E[:3])
    from clw.audit.chain import next_record
    from .helpers import T0

    fake = next_record(chain[-1], chain_id=CHAIN, created_at=T0, event={
        "tenant_id": CHAIN, "event_type": "CHAIN_RECOVERY", "status": "recorded", "reason": "x", "actor_oid": "op",
        "details": {"acknowledged": [{"seq": 2, "issue": "hash_mismatch"}],
                    "observed_head_seq": 3, "observed_head_hash": chain[-1].record_hash}})
    report = verify_records([*chain, fake], chain_id=CHAIN)
    assert not report.valid
    assert [(r.seq, r.valid) for r in report.recoveries] == [(4, False)]


def test_valid_recovery_is_listed_with_operator_and_acknowledgements():
    report = verify_records(_poisoned_then_recovered(tamper_recovery=False), chain_id=CHAIN)
    [info] = report.recoveries
    assert info.valid and info.operator == "op" and (4, "hash_mismatch") in info.acknowledged


def test_second_recovery_may_acknowledge_an_invalid_first_recovery():
    records = _recovery_variant(observed_head_seq=999)  # invalid recovery at seq 5
    from clw.audit.chain import next_record
    from .helpers import T0

    second = next_record(records[-1], chain_id=CHAIN, created_at=T0, event={
        "tenant_id": CHAIN, "event_type": "CHAIN_RECOVERY", "status": "recorded", "reason": "y", "actor_oid": "op2",
        "details": {"acknowledged": [{"seq": 4, "issue": "hash_mismatch"}, {"seq": 4, "issue": "invalid_event_shape"},
                                     {"seq": 5, "issue": "invalid_recovery"}],
                    "observed_head_seq": 5, "observed_head_hash": records[-1].record_hash}})
    records = [*records, second]
    assert blocking_findings(records, integrity_findings(records, chain_id=CHAIN)) == []
    assert [(r.seq, r.valid) for r in verify_records(records, chain_id=CHAIN).recoveries] == [(5, False), (6, True)]


def test_recovery_cannot_pre_acknowledge_a_finding_that_appears_later():
    # Reviewer 2 test gap: acknowledgements must refer to findings that exist
    # BEFORE the recovery; a later bad record cannot be covered in advance.
    records = _poisoned_then_recovered(tamper_recovery=False)
    rec = records[-1]
    ahead = _rehash(_replace(rec, details={**rec.details, "acknowledged": [
        *rec.details["acknowledged"], {"seq": 6, "issue": "hash_mismatch"}]}))
    later_bad = _replace(ahead, seq=6, previous_hash=ahead.record_hash, record_hash="0" * 64,
                         event_type="RUN_TIMED_OUT", status="timed_out", actor_oid=None, reason=None, details={})
    chain = [*records[:-1], ahead, later_bad]
    findings = integrity_findings(chain, chain_id=CHAIN)
    assert (5, "invalid_recovery") in {(f.seq, f.issue) for f in findings}
    assert (6, "hash_mismatch") in {(f.seq, f.issue) for f in blocking_findings(chain, findings)}


# ---------------------------------------------- RR-5: the request target is bound (SD-039)


@pytest.mark.parametrize("target", [
    "/v1.0/users?$top=999&$select=signInActivity",       # a parameter added
    "/v1.0/users?$top=500",                               # a value changed
    "/v1.0/users",                                        # a parameter dropped
    "/v1.0/users?$select=id&$top=999",                    # a parameter added, before
    "/v1.0/users?$top=999&$skiptoken=abc&$expand=x",      # continuation plus another parameter
    "/v1.0/users?$top=999&$skiptoken=",                   # an empty continuation
    "/v1.0/users?$skiptoken=abc",                         # continuation without the approved query
])
def test_a_request_target_the_decision_did_not_approve_is_a_finding(target):
    events = [REQUESTED, STARTED, ALLOWED, CRED, request(3, 1, target=target), response(1), COMPLETED]
    assert_only(events, (5, "request_target_not_approved"))


def test_an_allowed_decision_without_an_approved_target_approves_nothing():
    events = [REQUESTED, STARTED, allow(details={}), CRED, request(3, 1), response(1), COMPLETED]
    assert_only(events, (5, "request_target_not_approved"))


def test_a_continuation_of_the_approved_target_is_valid():
    events = [REQUESTED, STARTED, CRED, allow(), request(4, 1), response(1),
              allow(), request(7, 2, target="/v1.0/users?$top=999&$skiptoken=X%2Bt%3D%3D"), response(2), COMPLETED]
    assert report_for(events).valid


def test_a_query_less_approved_target_continues_with_a_question_mark():
    events = [REQUESTED, STARTED, CRED, allow(target="/v1.0/users"), request(4, 1, target="/v1.0/users"), response(1),
              allow(target="/v1.0/users"), request(7, 2, target="/v1.0/users?$skiptoken=abc"), response(2), COMPLETED]
    assert report_for(events).valid
