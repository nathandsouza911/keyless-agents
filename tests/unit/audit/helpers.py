"""Builders for realistic audit chains used by the tamper tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from clw.audit.chain import compute_record_hash, next_record, result_sha256
from clw.audit.events import PROTECTED_FIELDS, AuditRecord
from clw.common.timeutil import to_rfc3339_utc

CHAIN = "11111111-1111-1111-1111-111111111111"
OTHER_CHAIN = "22222222-2222-2222-2222-222222222222"
RUN = "run-0001"
T0 = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
MANIFEST_SHA = "a" * 64
TARGET = "/v1.0/users?$top=999"  # the approved request target of the standard run
RESULT = {"dormant": [{"id": "u1", "upn": "a@contoso.test"}], "counts": {"dormant": 1}}


def ev(event_type: str, status: str, **fields) -> dict:
    return {"tenant_id": CHAIN, "event_type": event_type, "status": status, "run_id": RUN, **fields}


def standard_events() -> list[dict]:
    """A run with one allowed+executed op, one denied op, then completion.

    seq: 1 RUN_REQUESTED, 2 RUN_STARTED, 3 OP_DECISION allowed,
         4 CREDENTIAL_ACQUIRED, 5 GRAPH_REQUEST, 6 GRAPH_RESPONSE,
         7 OP_DECISION denied, 8 RUN_COMPLETED
    """
    return [
        ev("RUN_REQUESTED", "requested", task_id="dormant-account-investigation",
           task_manifest_sha256=MANIFEST_SHA, actor_oid="oid-analyst", actor_tid=CHAIN),
        ev("RUN_STARTED", "started", task_id="dormant-account-investigation",
           task_manifest_sha256=MANIFEST_SHA, profile_id="directory-read-auditlog-read",
           profile_version=1, auth_mode="app_only"),
        ev("OP_DECISION", "allowed", operation="users.list_with_sign_in_activity", reason="allowed",
           http_method="GET", path_template="/users", details={"request_target": TARGET}),
        ev("CREDENTIAL_ACQUIRED", "accepted", profile_id="directory-read-auditlog-read",
           profile_version=1, auth_mode="app_only"),
        ev("GRAPH_REQUEST", "attempted", operation="users.list_with_sign_in_activity", decision_seq=3,
           http_method="GET", path_template="/users", request_target="/v1.0/users?$top=999", attempt=1),
        ev("GRAPH_RESPONSE", "succeeded", operation="users.list_with_sign_in_activity", attempt=1,
           http_status=200, graph_request_id="req-1", item_count=12, duration_ms=340),
        ev("OP_DECISION", "denied", operation="users.update", reason="not_in_manifest"),
        ev("RUN_COMPLETED", "completed", outcome="completed",
           details={"result_sha256": result_sha256(RESULT), "counts": {"dormant": 1}}),
    ]


OP = "users.list_with_sign_in_activity"


def allow(op: str = OP, method: str = "GET", template: str = "/users", target: str | None = None, **kw) -> dict:
    """An allowed decision. Like the broker's, it records the approved target (RR-5, SD-039)."""
    if "details" not in kw:
        kw["details"] = {"request_target": target or (TARGET if template == "/users" else f"/v1.0{template}")}
    return ev("OP_DECISION", "allowed", operation=op, reason="allowed", http_method=method, path_template=template, **kw)


def deny(op: str = OP, reason: str = "not_in_manifest", **kw) -> dict:
    return ev("OP_DECISION", "denied", operation=op, reason=reason, **kw)


def request(decision_seq: int, attempt: int, op: str = OP, method: str = "GET", template: str = "/users",
            target: str = "/v1.0/users?$top=999", **kw) -> dict:
    return ev("GRAPH_REQUEST", "attempted", operation=op, decision_seq=decision_seq, http_method=method,
              path_template=template, request_target=target, attempt=attempt, **kw)


def response(attempt: int, op: str = OP, status: str = "succeeded", http_status: int | None = 200, **kw) -> dict:
    extra = {"reason": kw.pop("reason")} if "reason" in kw else {}
    return ev("GRAPH_RESPONSE", status, operation=op, attempt=attempt, http_status=http_status,
              duration_ms=10, **extra, **kw)


def build_chain(events: list[dict] | None = None, *, chain_id: str = CHAIN) -> list[AuditRecord]:
    records: list[AuditRecord] = []
    head = None
    for i, event in enumerate(events if events is not None else standard_events()):
        head = next_record(head, chain_id=chain_id, event=event, created_at=T0 + timedelta(seconds=i))
        records.append(head)
    return records


def mutate(value):
    """A different value of a plausible type for the field."""
    if value is None:
        return "tampered"
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, dict):
        return {**value, "tampered": True}
    if isinstance(value, str):
        try:  # timestamps stay well-formed: shift by one microsecond
            moved = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(microseconds=1)
            return to_rfc3339_utc(moved.replace(tzinfo=timezone.utc))
        except ValueError:
            return value + "x"
    raise TypeError(type(value))


def tamper(record: AuditRecord, field: str) -> AuditRecord:
    original = getattr(record, field)
    changed = mutate(original)
    assert changed != original, f"mutation of {field} was a no-op"
    return replace(record, **{field: changed})


def rehash(record: AuditRecord) -> AuditRecord:
    """What an attacker with write access does after editing a record."""
    return replace(record, record_hash=compute_record_hash({f: getattr(record, f) for f in PROTECTED_FIELDS}))
