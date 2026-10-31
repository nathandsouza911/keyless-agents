"""Audit event taxonomy and record shape (SD-005, SD-014).

Four kinds of evidence are kept distinct:
  authorization decision  OP_DECISION (an allowed decision names the method and
                          path template it authorizes), CREDENTIAL_ACQUIRED,
                          CREDENTIAL_REJECTED
  attempted operation     GRAPH_REQUEST   (write-ahead; consumes exactly one
                          allowed decision; target must match its template)
  Graph response          GRAPH_RESPONSE  (cites its request by run_id + attempt)
  verified outcome        RUN_COMPLETED (binds result_sha256), RUN_FAILED, RUN_TIMED_OUT
plus run lifecycle records RUN_REQUESTED / RUN_STARTED; CHAIN_RECOVERY, an
operator record acknowledging integrity findings; and RESULT_REDACTED, an
operator record that a completed run's stored result was removed (SD-037).
The last two are never part of a run (run_id is NULL).

This module holds record-local rules. Rules that span records (run ordering,
decision consumption) live in clw.audit.chain.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

# v2: approvals bind method + path template; request_target validated against
# the template. v1 records are not supported (none exist outside tests).
# v3 (SD-040): request targets may also start /beta (the version is part of the
# bound target), and the script records SCRIPT_SUBMITTED, SCRIPT_ANALYZED and
# MANIFEST_APPROVED exist. New records are written as v3; every record is
# validated under its own version's rules, so v2 records keep v2's.
SCHEMA_VERSION = 3
SUPPORTED_SCHEMA_VERSIONS = frozenset({2, 3})


class AuditUnavailable(RuntimeError):
    """An audit record could not be durably written. Callers must fail closed."""


class AuditEventInvalid(AuditUnavailable):
    """The event could not be recorded because it is malformed; fail closed."""


class AuditRunStateRefused(AuditEventInvalid):
    """The record would break its run's state machine (SD-034): the run has
    already ended (`run_ended`), it has already started (`run_already_started`),
    or a completion would leave a request unanswered (`outstanding_requests`).
    Nothing was written; fail closed."""

    def __init__(self, run_id: str, reason: str):
        self.run_id = run_id
        self.reason = reason
        super().__init__(f"run {run_id}: {reason}")


class AuditChainCompromised(AuditUnavailable):
    """The stored chain fails integrity checks; appends refused until recovery."""

    def __init__(self, chain_id: str, findings: list[tuple[int, str]]):
        self.chain_id = chain_id
        self.findings = findings
        super().__init__(
            f"audit chain {chain_id} failed integrity verification at "
            f"{findings[:5]}{'...' if len(findings) > 5 else ''}; appends refused. "
            f"Run `python -m clw.cli audit-verify --chain {chain_id}` and follow "
            f"docs/runbooks/audit-chain-recovery.md"
        )


class EventType(StrEnum):
    RUN_REQUESTED = "RUN_REQUESTED"
    RUN_STARTED = "RUN_STARTED"
    OP_DECISION = "OP_DECISION"
    CREDENTIAL_ACQUIRED = "CREDENTIAL_ACQUIRED"
    CREDENTIAL_REJECTED = "CREDENTIAL_REJECTED"
    GRAPH_REQUEST = "GRAPH_REQUEST"
    GRAPH_RESPONSE = "GRAPH_RESPONSE"
    RUN_COMPLETED = "RUN_COMPLETED"
    RUN_FAILED = "RUN_FAILED"
    RUN_TIMED_OUT = "RUN_TIMED_OUT"
    CHAIN_RECOVERY = "CHAIN_RECOVERY"
    RESULT_REDACTED = "RESULT_REDACTED"
    SCRIPT_SUBMITTED = "SCRIPT_SUBMITTED"
    SCRIPT_ANALYZED = "SCRIPT_ANALYZED"
    MANIFEST_APPROVED = "MANIFEST_APPROVED"


# Record types a schema version admits (RESULT_REDACTED was added under v2, SD-037).
V3_ONLY_EVENTS = frozenset({EventType.SCRIPT_SUBMITTED, EventType.SCRIPT_ANALYZED, EventType.MANIFEST_APPROVED})
# The API versions a request target may start with, per schema version.
TARGET_VERSIONS = {2: ("/v1.0",), 3: ("/v1.0", "/beta")}


TERMINAL_EVENTS = frozenset({EventType.RUN_COMPLETED, EventType.RUN_FAILED, EventType.RUN_TIMED_OUT})

PROTECTED_FIELDS: tuple[str, ...] = (
    "schema_version", "chain_id", "seq", "tenant_id", "event_type", "status", "reason", "outcome",
    "run_id", "task_id", "task_manifest_sha256", "profile_id", "profile_version", "auth_mode",
    "actor_oid", "actor_tid", "operation", "decision_seq", "http_method", "path_template",
    "request_target", "http_status", "graph_request_id", "attempt", "item_count", "duration_ms",
    "details", "created_at", "previous_hash",
)

CHAIN_ASSIGNED: frozenset[str] = frozenset({"schema_version", "chain_id", "seq", "created_at", "previous_hash"})
EVENT_FIELDS: tuple[str, ...] = tuple(f for f in PROTECTED_FIELDS if f not in CHAIN_ASSIGNED)

_STR, _INT, _DICT = "str", "int", "dict"
FIELD_TYPES: dict[str, str] = {
    "schema_version": _INT, "seq": _INT, "profile_version": _INT, "decision_seq": _INT,
    "http_status": _INT, "attempt": _INT, "item_count": _INT, "duration_ms": _INT,
    "details": _DICT,
}  # everything else is str

# All patterns are used with fullmatch() and spell digits as [0-9]: "$" would
# also match before a trailing newline, and \d matches non-ASCII digits.
CREATED_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}")

# Timestamps more than this far ahead of the authoritative clock are rejected
# for new records (writer and database) and flagged by the verifier. The
# authoritative clock is the PostgreSQL server's (see AuditWriter).
MAX_FUTURE_SKEW = timedelta(minutes=5)

# details limit: UTF-8 byte length of its compact JSON serialization (the
# canonical form; key order does not change the length). The database
# enforces the same quantity (clw_jsonb_compact_size, migration 20261016).
MAX_DETAILS_BYTES = 64 * 1024

# Text field limits (gate 1 finding L-1): UTF-8 byte length of the value.
# The database enforces the same bounds with octet_length() (migration
# 20261018_audit_text_limits; the database encoding is UTF-8).
MAX_TEXT_BYTES = 1024
MAX_REQUEST_TARGET_BYTES = 4096


def text_limit(name: str) -> int:
    return MAX_REQUEST_TARGET_BYTES if name == "request_target" else MAX_TEXT_BYTES


def text_too_long(name: str, value: object) -> bool:
    """True for a str longer than its limit in UTF-8 bytes. Lone surrogates
    cannot be encoded and are rejected by canonicalization instead."""
    if not isinstance(value, str):
        return False
    if len(value) * 4 <= text_limit(name):  # cheap bound: at most 4 bytes per code point
        return False
    return len(value.encode("utf-8", "surrogatepass")) > text_limit(name)


@dataclass(frozen=True)
class AuditRecord:
    schema_version: int
    chain_id: str
    seq: int
    tenant_id: str
    event_type: str
    status: str
    reason: str | None
    outcome: str | None
    run_id: str | None
    task_id: str | None
    task_manifest_sha256: str | None
    profile_id: str | None
    profile_version: int | None
    auth_mode: str | None
    actor_oid: str | None
    actor_tid: str | None
    operation: str | None
    decision_seq: int | None
    http_method: str | None
    path_template: str | None
    request_target: str | None
    http_status: int | None
    graph_request_id: str | None
    attempt: int | None
    item_count: int | None
    duration_ms: int | None
    details: dict = field(default_factory=dict)
    created_at: str = ""
    previous_hash: str = ""
    record_hash: str = ""

    def protected(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in PROTECTED_FIELDS}

    def stored(self) -> dict[str, object]:
        return {**self.protected(), "record_hash": self.record_hash}


@dataclass(frozen=True)
class _Rule:
    statuses: frozenset[str]
    required: frozenset[str]
    optional: frozenset[str] = frozenset()


_COMMON = frozenset({"tenant_id", "event_type", "status", "details"})
_RUN = frozenset({"run_id"})
_PROFILE = frozenset({"profile_id", "profile_version", "auth_mode"})
_TASK = frozenset({"task_id", "task_manifest_sha256"})

RULES: dict[str, _Rule] = {
    EventType.RUN_REQUESTED: _Rule(frozenset({"requested"}), _RUN | _TASK | {"actor_oid", "actor_tid"}),
    EventType.RUN_STARTED: _Rule(frozenset({"started"}), _RUN | _TASK | _PROFILE),
    EventType.OP_DECISION: _Rule(
        frozenset({"allowed", "denied"}), _RUN | {"operation", "reason"}, frozenset({"http_method", "path_template"})
    ),
    EventType.CREDENTIAL_ACQUIRED: _Rule(frozenset({"accepted"}), _RUN | _PROFILE),
    EventType.CREDENTIAL_REJECTED: _Rule(frozenset({"rejected"}), _RUN | _PROFILE | {"reason"}),
    EventType.GRAPH_REQUEST: _Rule(
        frozenset({"attempted"}),
        _RUN | {"operation", "decision_seq", "http_method", "path_template", "request_target", "attempt"},
    ),
    EventType.GRAPH_RESPONSE: _Rule(
        frozenset({"succeeded", "failed"}),
        _RUN | {"operation", "attempt", "duration_ms"},
        frozenset({"http_status", "graph_request_id", "item_count", "reason"}),
    ),
    EventType.RUN_COMPLETED: _Rule(frozenset({"completed"}), _RUN | {"outcome"}, frozenset({"item_count"})),
    EventType.RUN_FAILED: _Rule(frozenset({"failed"}), _RUN | {"reason"}, frozenset({"outcome"})),
    EventType.RUN_TIMED_OUT: _Rule(frozenset({"timed_out"}), _RUN, frozenset({"reason"})),
    EventType.CHAIN_RECOVERY: _Rule(frozenset({"recorded"}), frozenset({"reason", "actor_oid"})),
    # actor_oid names the operator; details name the run and the removed result's digest.
    EventType.RESULT_REDACTED: _Rule(frozenset({"recorded"}), frozenset({"reason", "actor_oid"})),
    # Script records (v3, SD-040): tenant-scoped like the two above. actor_oid is
    # the submitter or the approving security lead; details name the script.
    EventType.SCRIPT_SUBMITTED: _Rule(frozenset({"submitted"}), frozenset({"actor_oid"})),
    EventType.SCRIPT_ANALYZED: _Rule(frozenset({"analyzed", "failed"}), frozenset(), frozenset({"reason"})),
    EventType.MANIFEST_APPROVED: _Rule(frozenset({"approved"}), frozenset({"actor_oid"})),
}

_METHODS = frozenset({"GET", "POST", "PATCH", "PUT", "DELETE"})
_AUTH_MODES = frozenset({"app_only", "delegated"})

# Path templates: "/users", "/users/{user_id}", "/directoryRoles/{role_id}/members/$ref".
# The first segment must be a literal (a Graph collection), never a placeholder.
_LITERAL = r"[A-Za-z0-9$_-][A-Za-z0-9$._-]*"
_PLACEHOLDER = r"\{[a-z][a-z0-9_]*\}"
_TEMPLATE_RE = re.compile(rf"/{_LITERAL}(/(?:{_LITERAL}|{_PLACEHOLDER}))*")
# A placeholder value: unreserved characters only; no "%", "/", "$"; cannot
# start with "." (so "." and ".." are impossible).
_SEGMENT = r"[A-Za-z0-9_~-][A-Za-z0-9._~-]*"
# Placeholder values that would turn an entity lookup into a different Graph
# operation (delta query, function call, type cast).
_RESERVED_SEGMENT_VALUES = frozenset({"delta"})
_RESERVED_SEGMENT_PREFIXES = ("microsoft.graph.",)
_QUERY_RE = re.compile(r"[A-Za-z0-9$=&,._~:'()*+%-]+")
GRAPH_VERSION_PREFIX = "/v1.0"


def valid_path_template(template: object) -> bool:
    """Structural check of a template. Does NOT make a matching request safe:
    request targets are validated separately (target_matches_template) and,
    from Task 7, their query parameters by the operation registry."""
    return (
        isinstance(template, str)
        and bool(_TEMPLATE_RE.fullmatch(template))
        and not template.startswith("/v1.0")
    )


SKIPTOKEN = "$skiptoken"


def continues_approved_target(target: object, approved: object) -> bool:
    """RR-5 (SD-039): the recorded request target is the decision's approved
    target itself, or that target plus exactly one $skiptoken continuation and
    nothing else (the broker's canonical page target: the token is
    percent-encoded, so it holds no "&", and it is appended last). Both strings
    are the broker's own canonical form, so they are compared exactly."""
    if not (isinstance(target, str) and isinstance(approved, str) and approved):
        return False
    if target == approved:
        return True
    prefix = f"{approved}{'&' if '?' in approved else '?'}{SKIPTOKEN}="
    token = target[len(prefix):] if target.startswith(prefix) else ""
    return bool(token) and "&" not in token and "#" not in token


def target_matches_template(target: object, template: object, *, versions: tuple[str, ...] = ("/v1.0",)) -> bool:
    """request_target must be a relative path under one of ``versions`` (default
    /v1.0 only: the named-operation path) that fills ``template``.

    Placeholders match exactly one segment of unreserved characters; "%"
    is not allowed in the path, so encoded slashes or dots cannot appear.
    """
    if not (isinstance(target, str) and valid_path_template(template)):
        return False
    path, sep, query = target.partition("?")
    if sep and not _QUERY_RE.fullmatch(query):
        return False
    pattern = "(?:" + "|".join(re.escape(v) for v in versions) + ")" + "".join(
        "/" + (f"({_SEGMENT})" if part.startswith("{") else re.escape(part))
        for part in template.split("/")[1:]  # type: ignore[union-attr]
    )
    match = re.fullmatch(pattern, path)
    if match is None:
        return False
    for value in match.groups():
        lowered = value.lower()
        if lowered in _RESERVED_SEGMENT_VALUES or lowered.startswith(_RESERVED_SEGMENT_PREFIXES):
            return False
    return True


def _type_ok(name: str, value: object) -> bool:
    kind = FIELD_TYPES.get(name, _STR)
    if kind == _INT:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == _DICT:
        return isinstance(value, dict)
    return isinstance(value, str)


def valid_created_at(created_at: object) -> bool:
    return isinstance(created_at, str) and bool(CREATED_AT_RE.fullmatch(created_at)) and _parses(created_at)


def is_future(created_at: str, now: datetime) -> bool:
    """True if a valid created_at is more than MAX_FUTURE_SKEW ahead of now."""
    from clw.common.timeutil import to_rfc3339_utc

    return created_at > to_rfc3339_utc(now + MAX_FUTURE_SKEW)


def validate_chain_fields(values: Mapping[str, object], *, now: datetime | None = None) -> list[tuple[str, str]]:
    """Checks on chain-assigned fields. Returns (issue, detail) pairs.

    With ``now``, a valid created_at more than MAX_FUTURE_SKEW ahead of it is
    reported as created_at_in_future."""
    problems: list[tuple[str, str]] = []
    version = values.get("schema_version")
    if not (_type_ok("schema_version", version) and version in SUPPORTED_SCHEMA_VERSIONS):
        problems.append(("unsupported_schema_version", repr(version)))
    if not isinstance(values.get("chain_id"), str) or text_too_long("chain_id", values.get("chain_id")):
        problems.append(("invalid_record", "chain_id"))
    seq = values.get("seq")
    if not (_type_ok("seq", seq) and seq >= 1):  # type: ignore[operator]
        problems.append(("invalid_record", "seq"))
    created_at = values.get("created_at")
    if not valid_created_at(created_at):
        problems.append(("invalid_created_at", repr(created_at)[:60]))
    elif now is not None and is_future(created_at, now):  # type: ignore[arg-type]
        problems.append(("created_at_in_future", str(created_at)))
    for name in ("previous_hash", "record_hash"):
        if name in values and not (isinstance(values[name], str) and HEX64_RE.fullmatch(values[name])):  # type: ignore[arg-type]
            problems.append(("invalid_record", name))
    return problems


def _parses(created_at: str) -> bool:
    try:
        datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def validate_event(values: Mapping[str, object], *, chain_id: str, schema_version: int = SCHEMA_VERSION) -> list[str]:
    """Return problems with an event's fields; empty means valid.

    ``values`` must contain every name in EVENT_FIELDS (None where absent).
    ``schema_version`` selects the rules: a stored record is checked under its
    own version, a new record under the current one.
    """
    missing = [f for f in EVENT_FIELDS if f not in values]
    extra = [f for f in values if f not in PROTECTED_FIELDS and f != "record_hash"]
    if missing or extra:
        return [p for p in (f"missing fields {missing}" if missing else "",
                            f"unknown fields {extra}" if extra else "") if p]

    event_type = values["event_type"]
    rule = RULES.get(event_type) if isinstance(event_type, str) else None  # type: ignore[arg-type]
    if rule is None or (event_type in V3_ONLY_EVENTS and schema_version < 3):
        return [f"unknown event_type {event_type!r}"]

    problems: list[str] = []
    required = _COMMON | rule.required
    allowed = required | rule.optional
    for name in EVENT_FIELDS:
        value = values[name]
        if name in required and value is None:
            problems.append(f"{name} is required")
        elif name not in allowed and value is not None and not (name == "details" and value == {}):
            problems.append(f"{name} is not allowed on {event_type}")
        elif value is not None and not _type_ok(name, value):
            problems.append(f"{name} has the wrong type")
        elif text_too_long(name, value):
            problems.append(f"{name} exceeds {text_limit(name)} UTF-8 bytes")
    if problems:
        return problems

    status = values["status"]
    details = values["details"]
    problems += _details_size_problems(details)  # type: ignore[arg-type]
    if status not in rule.statuses:
        problems.append(f"status {status!r} not valid for {event_type}")
    if values["tenant_id"] != chain_id:
        problems.append("tenant_id must equal chain_id")
    for name in ("decision_seq", "attempt", "profile_version"):
        value = values.get(name)
        if isinstance(value, int) and value < 1:
            problems.append(f"{name} must be >= 1")
    for name in ("http_status", "item_count", "duration_ms"):
        value = values.get(name)
        if isinstance(value, int) and value < 0:
            problems.append(f"{name} must be >= 0")
    if values["http_method"] is not None and values["http_method"] not in _METHODS:
        problems.append("http_method not recognised")
    if values["path_template"] is not None and not valid_path_template(values["path_template"]):
        problems.append("path_template malformed")
    if values["auth_mode"] is not None and values["auth_mode"] not in _AUTH_MODES:
        problems.append("auth_mode not recognised")
    if values["task_manifest_sha256"] is not None and not HEX64_RE.fullmatch(values["task_manifest_sha256"]):  # type: ignore[arg-type]
        problems.append("task_manifest_sha256 must be 64 lowercase hex")

    if event_type == EventType.OP_DECISION:
        if (status == "allowed") != (values["reason"] == "allowed"):
            problems.append("OP_DECISION reason must be 'allowed' exactly when status is 'allowed'")
        if status == "allowed" and (values["http_method"] is None or values["path_template"] is None):
            problems.append("an allowed OP_DECISION must name the http_method and path_template it authorizes")
    elif event_type == EventType.GRAPH_REQUEST:
        versions = TARGET_VERSIONS.get(schema_version, ("/v1.0",))
        if not target_matches_template(values["request_target"], values["path_template"], versions=versions):
            problems.append(f"request_target must be a relative {' or '.join(versions)} path matching path_template")
    elif event_type == EventType.GRAPH_RESPONSE:
        code = values["http_status"]
        is_2xx = isinstance(code, int) and 200 <= code <= 299
        if status == "succeeded" and not is_2xx:
            problems.append("succeeded GRAPH_RESPONSE needs a 2xx http_status")
        if status == "failed":
            if values["reason"] is None:
                problems.append("failed GRAPH_RESPONSE needs a reason")
            if is_2xx:
                problems.append("failed GRAPH_RESPONSE cannot carry a 2xx http_status")
    elif event_type == EventType.RUN_COMPLETED:
        digest = details.get("result_sha256")  # type: ignore[union-attr]
        if not (isinstance(digest, str) and HEX64_RE.fullmatch(digest)):
            problems.append("RUN_COMPLETED needs details.result_sha256 (64 lowercase hex)")
    elif event_type == EventType.CHAIN_RECOVERY:
        problems += _recovery_problems(details)  # type: ignore[arg-type]
    elif event_type == EventType.RESULT_REDACTED:
        problems += _redaction_problems(details)  # type: ignore[arg-type]
    elif event_type in V3_ONLY_EVENTS:
        problems += _script_problems(event_type, status, values, details)  # type: ignore[arg-type]
    elif event_type == EventType.RUN_STARTED and isinstance(details, dict) and "script_sha256" in details:
        if not _shaped(details, {"script_sha256": "hex", "approval_id": "id", "bootstrap_sha256": "hex"}):
            problems.append("a script RUN_STARTED needs exactly details.script_sha256, approval_id, bootstrap_sha256")
    return problems


def details_size(details: dict) -> int:
    from clw.audit.canonical import canonical_json

    return len(canonical_json(details))


def _details_size_problems(details: dict) -> list[str]:
    from clw.audit.canonical import CanonicalizationError

    try:
        size = details_size(details)
    except CanonicalizationError as exc:
        return [f"details is not canonical JSON: {exc}"]
    return [f"details is {size} bytes; limit is {MAX_DETAILS_BYTES}"] if size > MAX_DETAILS_BYTES else []


def _shaped(details: dict, shape: Mapping[str, str]) -> bool:
    """Exactly these keys; "hex" values are 64 lowercase hex, "id" values 1-128 chars, "int" non-negative ints."""
    if set(details) != set(shape):
        return False
    for key, kind in shape.items():
        value = details[key]
        if kind == "hex" and not (isinstance(value, str) and HEX64_RE.fullmatch(value)):
            return False
        if kind == "id" and not (isinstance(value, str) and 0 < len(value) <= 128):
            return False
        if kind == "int" and not (_type_ok("seq", value) and value >= 0):
            return False
    return True


_SCRIPT_SHAPES = {
    EventType.SCRIPT_SUBMITTED: {"script_sha256": "hex", "script_bytes": "int"},
    EventType.SCRIPT_ANALYZED: {"script_sha256": "hex", "analysis_sha256": "hex", "analyser_version": "id"},
    EventType.MANIFEST_APPROVED: {"script_sha256": "hex", "manifest_sha256": "hex", "approval_id": "id"},
}


def _script_problems(event_type: str, status: object, values: Mapping[str, object], details: dict) -> list[str]:
    problems = []
    if values["run_id"] is not None:
        problems.append(f"{event_type} is never part of a run")
    shape = dict(_SCRIPT_SHAPES[event_type])  # type: ignore[index]
    if event_type == EventType.SCRIPT_ANALYZED and status == "failed":
        shape.pop("analysis_sha256")
        if values["reason"] is None:
            problems.append("a failed SCRIPT_ANALYZED needs a reason")
    if not _shaped(details, shape):
        problems.append(f"{event_type} needs exactly details {sorted(shape)}")
    return problems


def _redaction_problems(details: dict) -> list[str]:
    run_id, digest = details.get("redacted_run_id"), details.get("result_sha256")
    ok = (
        set(details) == {"redacted_run_id", "result_sha256"}
        and isinstance(run_id, str) and 0 < len(run_id) <= 128
        and isinstance(digest, str) and bool(HEX64_RE.fullmatch(digest))
    )
    return [] if ok else ["RESULT_REDACTED needs exactly details.redacted_run_id and result_sha256 (64 hex)"]


def _recovery_problems(details: dict) -> list[str]:
    acknowledged = details.get("acknowledged")
    ok = (
        isinstance(acknowledged, list)
        and len(acknowledged) > 0
        and all(
            isinstance(a, dict) and set(a) == {"seq", "issue"}
            and _type_ok("seq", a["seq"]) and a["seq"] >= 1 and isinstance(a["issue"], str)
            for a in acknowledged
        )
        and _type_ok("seq", details.get("observed_head_seq"))
        and isinstance(details.get("observed_head_hash"), str)
        and bool(HEX64_RE.fullmatch(details["observed_head_hash"]))
    )
    return [] if ok else ["CHAIN_RECOVERY needs details.acknowledged [{seq, issue}], observed_head_seq, observed_head_hash"]
