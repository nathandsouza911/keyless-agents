"""Event-shape rules keep decision, attempt, response and outcome distinct (SD-014)."""

from __future__ import annotations

import pytest

from clw.audit.chain import next_record
from clw.audit.events import RULES, AuditEventInvalid, EventType

from .helpers import CHAIN, T0, build_chain, ev, standard_events


def test_every_event_type_has_a_rule():
    assert set(RULES) == set(EventType)


def test_standard_events_cover_the_four_evidence_kinds():
    kinds = {r.event_type for r in build_chain()}
    assert {"OP_DECISION", "GRAPH_REQUEST", "GRAPH_RESPONSE", "RUN_COMPLETED"} <= kinds


BASE = {e["event_type"] + ":" + e["status"]: e for e in standard_events()}
ALLOWED = BASE["OP_DECISION:allowed"]
DENIED = BASE["OP_DECISION:denied"]
REQUEST = BASE["GRAPH_REQUEST:attempted"]
RESPONSE = BASE["GRAPH_RESPONSE:succeeded"]
COMPLETED = BASE["RUN_COMPLETED:completed"]


@pytest.mark.parametrize(
    "event, why",
    [
        ({**ALLOWED, "reason": "looks fine"}, "allowed decision must have reason 'allowed'"),
        ({**DENIED, "reason": "allowed"}, "denied decision cannot claim reason 'allowed'"),
        ({**DENIED, "status": "maybe"}, "unknown decision status"),
        ({**ALLOWED, "http_status": 200}, "a decision cannot carry an HTTP status"),
        ({**ALLOWED, "decision_seq": 1}, "a decision cannot cite a decision"),
        ({**REQUEST, "decision_seq": None}, "an attempt must cite its allowing decision"),
        ({**REQUEST, "http_status": 200}, "an attempt cannot carry a response status"),
        ({**REQUEST, "attempt": 0}, "attempt numbers start at 1"),
        ({**REQUEST, "attempt": True}, "bool is not an int"),
        ({**REQUEST, "attempt": "1"}, "wrong type"),
        ({**REQUEST, "http_method": "TRACE"}, "unknown method"),
        ({**RESPONSE, "http_status": 403}, "succeeded needs 2xx"),
        ({**RESPONSE, "status": "failed", "http_status": 403}, "failed needs a reason"),
        ({**RESPONSE, "attempt": None}, "a response must cite its attempt"),
        ({**RESPONSE, "decision_seq": 3}, "a response cannot cite a decision"),
        ({**COMPLETED, "details": {}}, "completion must bind result_sha256"),
        ({**COMPLETED, "details": {"result_sha256": "ABC"}}, "digest must be 64 lowercase hex"),
        ({**COMPLETED, "http_status": 200}, "an outcome cannot carry an HTTP status"),
        ({**ALLOWED, "tenant_id": "another-tenant"}, "tenant must equal chain"),
        ({**ALLOWED, "run_id": None}, "every event belongs to a run"),
        ({**ALLOWED, "event_type": "OP_MAYBE"}, "unknown event type"),
        ({**ALLOWED, "surprise": 1}, "unknown field"),
        ({**ALLOWED, "details": {"x": 1.5}}, "floats are not canonical"),
        ({**ALLOWED, "seq": 7}, "chain-assigned fields cannot be supplied"),
        ({**ALLOWED, "previous_hash": "0" * 64}, "chain-assigned fields cannot be supplied"),
    ],
)
def test_invalid_events_are_refused(event, why):
    with pytest.raises(AuditEventInvalid):
        next_record(None, chain_id=CHAIN, event=event, created_at=T0)


def test_audit_event_invalid_is_an_audit_unavailable():
    # Callers that fail closed on AuditUnavailable also fail closed on bad events.
    from clw.audit.events import AuditUnavailable

    assert issubclass(AuditEventInvalid, AuditUnavailable)


def test_naive_created_at_refused():
    from datetime import datetime

    with pytest.raises((AuditEventInvalid, ValueError)):
        next_record(None, chain_id=CHAIN, event=ALLOWED, created_at=datetime(2026, 1, 1))


def test_valid_failed_response_and_timeout_accepted():
    next_record(None, chain_id=CHAIN, created_at=T0, event=ev(
        "GRAPH_RESPONSE", "failed", operation="x", attempt=1, duration_ms=5, reason="network_error"))
    next_record(None, chain_id=CHAIN, created_at=T0, event=ev("RUN_TIMED_OUT", "timed_out"))


# ------------------------------------------- schema v2: approval binding (M1)

from clw.audit.events import target_matches_template, valid_path_template


@pytest.mark.parametrize("missing", ["http_method", "path_template"])
def test_allowed_decision_must_name_what_it_authorizes(missing):
    with pytest.raises(AuditEventInvalid):
        next_record(None, chain_id=CHAIN, created_at=T0, event={**ALLOWED, missing: None})


def test_denied_decision_need_not_name_a_method():
    next_record(None, chain_id=CHAIN, created_at=T0, event=DENIED)


@pytest.mark.parametrize("target", [
    "/v1.0/users",
    "/v1.0/users?$top=999",
    "/v1.0/users?$select=id,displayName,signInActivity&$top=999",
    "/v1.0/users?$skiptoken=RFNwdAIAAQAAAB8wMDAw%3D",
])
def test_valid_targets_for_users_template(target):
    assert target_matches_template(target, "/users")


@pytest.mark.parametrize("target", [
    "https://evil.example/x", "//evil.example/v1.0/users", "/beta/users", "/V1.0/users", "/v1.0/Users",
    "/v1.0/users/", "/v1.0//users", "v1.0/users", "/v1.0/groups", "/v1.0/users#frag", "/v1.0/users?x=1 2",
    "/v1.0/users?", "/v1.0/users/../users", "/v1.0/users?a=b#c", "/v1.0/$batch", r"/v1.0/users\..\me", "",
])
def test_invalid_targets_for_users_template(target):
    assert not target_matches_template(target, "/users")


@pytest.mark.parametrize("target, ok", [
    ("/v1.0/users/00000000-0000-0000-0000-000000000001", True),
    ("/v1.0/users/me", True),  # template-level match only; GUID validation is the broker's (Task 7)
    ("/v1.0/users/..", False),
    ("/v1.0/users/.", False),
    ("/v1.0/users/a%2Fb", False),
    ("/v1.0/users/%2e%2e", False),
    ("/v1.0/users/a/b", False),
    ("/v1.0/users/", False),
])
def test_placeholder_matches_exactly_one_safe_segment(target, ok):
    assert target_matches_template(target, "/users/{user_id}") is ok


@pytest.mark.parametrize("template, ok", [
    ("/users", True), ("/users/{user_id}", True), ("/directoryRoles/{role_id}/members/$ref", True),
    ("/v1.0/users", False), ("users", False), ("/users/{ID}", False), ("/users/../x", False),
    ("/users/", False), ("//users", False), ("/users/{a}{b}", False), ("", False), (None, False),
])
def test_path_template_format(template, ok):
    assert valid_path_template(template) is ok


@pytest.mark.parametrize("target", ["https://evil.example/x", "/v2.0/users", "/v1.0/groups", "/Beta/users"])
def test_request_with_bad_target_is_refused_at_write_time(target):
    with pytest.raises(AuditEventInvalid):
        next_record(None, chain_id=CHAIN, created_at=T0, event={**REQUEST, "request_target": target})


def test_beta_targets_are_v3_only():
    # SD-040: a v3 record may name a /beta target (facade requests); v2 rules keep /v1.0 only,
    # and the named-operation path's own check (the default) stays /v1.0 only.
    from clw.audit.events import EVENT_FIELDS, validate_event

    values = {name: REQUEST.get(name) for name in EVENT_FIELDS} | {"request_target": "/beta/users", "details": {}}
    assert validate_event(values, chain_id=CHAIN, schema_version=3) == []
    assert validate_event(values, chain_id=CHAIN, schema_version=2)
    assert not target_matches_template("/beta/users", "/users")
    record = next_record(None, chain_id=CHAIN, created_at=T0, event={**REQUEST, "request_target": "/beta/users"})
    assert record.schema_version == 3


def test_failed_response_with_2xx_is_refused():
    with pytest.raises(AuditEventInvalid):
        next_record(None, chain_id=CHAIN, created_at=T0,
                    event={**RESPONSE, "status": "failed", "reason": "x", "http_status": 200})


# -------------------------------------------------- CHAIN_RECOVERY shape

RECOVERY = {
    "tenant_id": CHAIN, "event_type": "CHAIN_RECOVERY", "status": "recorded",
    "reason": "poisoned row inserted by compromised component", "actor_oid": "operator:alice",
    "details": {"acknowledged": [{"seq": 4, "issue": "hash_mismatch"}],
                "observed_head_seq": 4, "observed_head_hash": "0" * 64},
}


def test_valid_recovery_record_accepted():
    next_record(None, chain_id=CHAIN, created_at=T0, event=RECOVERY)


@pytest.mark.parametrize("change", [
    {"run_id": "run-0001"},
    {"actor_oid": None},
    {"reason": None},
    {"details": {**RECOVERY["details"], "acknowledged": []}},
    {"details": {**RECOVERY["details"], "acknowledged": [{"seq": "4", "issue": "x"}]}},
    {"details": {**RECOVERY["details"], "acknowledged": [{"seq": 4}]}},
    {"details": {k: v for k, v in RECOVERY["details"].items() if k != "observed_head_hash"}},
])
def test_malformed_recovery_records_refused(change):
    with pytest.raises(AuditEventInvalid):
        next_record(None, chain_id=CHAIN, created_at=T0, event={**RECOVERY, **change})


# ----------------------------------- N5 exact matching, N6 template safety


@pytest.mark.parametrize("template, target", [
    ("/users\n", "/v1.0/users\n"),
    ("/users", "/v1.0/users\n"),
    ("/users", "/v1.0/users?$top=1\n"),
    ("/{x}", "/v1.0/$batch"),
    ("/{x}", "/v1.0/users"),
    ("/users/{id}", "/v1.0/users/$count"),
    ("/users/{id}", "/v1.0/users/$ref"),
    ("/users/{id}", "/v1.0/users/$batch"),
    ("/users/{id}", "/v1.0/users/delta"),
    ("/users/{id}", "/v1.0/users/Delta"),
    ("/users/{id}", "/v1.0/users/microsoft.graph.delta"),
    ("/users/{id}", "/v1.0/users/..."),
    ("/users/{id}", "/v1.0/users/ａ"),  # fullwidth letter
])
def test_targets_rejected_for_reserved_or_newline_or_placeholder_only(template, target):
    assert not target_matches_template(target, template)


@pytest.mark.parametrize("template", ["/{x}", "/{x}/users", "/users\n", "/users/{id}\n"])
def test_templates_need_a_literal_first_segment_and_no_newline(template):
    assert not valid_path_template(template)


def test_template_literals_may_use_odata_segments():
    assert valid_path_template("/directoryRoles/{role_id}/members/$ref")
    assert target_matches_template("/v1.0/directoryRoles/00000000-0000-0000-0000-000000000001/members/$ref",
                                   "/directoryRoles/{role_id}/members/$ref")


def test_hex_and_timestamp_patterns_reject_trailing_newline():
    from clw.audit.events import HEX64_RE, valid_created_at

    assert HEX64_RE.fullmatch("a" * 64) and not HEX64_RE.fullmatch("a" * 64 + "\n")
    assert not valid_created_at("2026-10-14T09:00:00.000000Z\n")


def test_recovery_head_hash_with_trailing_newline_refused():
    bad = {**RECOVERY, "details": {**RECOVERY["details"], "observed_head_hash": "0" * 64 + "\n"}}
    with pytest.raises(AuditEventInvalid):
        next_record(None, chain_id=CHAIN, created_at=T0, event=bad)


# -------------------------------------------- N8 details size, unit level

from clw.audit.canonical import canonical_json as _cj
from clw.audit.events import MAX_DETAILS_BYTES


def _sized(n):
    return {"p": "x" * (n - 8)}


@pytest.mark.parametrize("size, ok", [(MAX_DETAILS_BYTES - 1, True), (MAX_DETAILS_BYTES, True), (MAX_DETAILS_BYTES + 1, False)])
def test_details_size_boundary(size, ok):
    details = _sized(size)
    assert len(_cj(details)) == size
    event = {**ev("RUN_TIMED_OUT", "timed_out"), "details": details}
    if ok:
        next_record(None, chain_id=CHAIN, created_at=T0, event=event)
    else:
        with pytest.raises(AuditEventInvalid, match="limit"):
            next_record(None, chain_id=CHAIN, created_at=T0, event=event)


def test_details_size_counts_utf8_bytes_not_characters():
    details = {"p": "€" * ((MAX_DETAILS_BYTES - 8) // 3 + 1)}  # chars under, bytes over
    with pytest.raises(AuditEventInvalid, match="limit"):
        next_record(None, chain_id=CHAIN, created_at=T0, event={**ev("RUN_TIMED_OUT", "timed_out"), "details": details})


def test_empty_details_allowed():
    next_record(None, chain_id=CHAIN, created_at=T0, event={**ev("RUN_TIMED_OUT", "timed_out"), "details": {}})
