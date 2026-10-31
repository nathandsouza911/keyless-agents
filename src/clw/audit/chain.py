"""Hash chain construction and verification (SD-005, SD-006, SD-014).

record_hash = SHA-256( b"clw-audit-v1\\n" || canonical_json(all protected fields) )

Two layers of findings:
- integrity findings (record-local and link checks): the writer refuses to
  append while any are unacknowledged (H2); see integrity_findings().
- transition findings (run state machine, decision consumption): reported
  by verify_records(); they make a chain invalid but do not block writes.

What verification proves: the stored records are internally consistent and
unmodified since they were linked. It does NOT prove the recorded events
happened: any writer able to INSERT can append hash-consistent fabricated
records (threat-model §6, residual risk RR-1). It cannot detect tail
truncation or a full rewrite after the newest checkpoint (SD-006).
"""

from __future__ import annotations

import hashlib
import hmac
from bisect import bisect_left
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from clw.audit.canonical import CanonicalizationError, canonical_json
from clw.audit.events import (
    EVENT_FIELDS,
    PROTECTED_FIELDS,
    SCHEMA_VERSION,
    TERMINAL_EVENTS,
    AuditEventInvalid,
    AuditRecord,
    MAX_FUTURE_SKEW,
    EventType,
    continues_approved_target,
    is_future,
    valid_created_at,
    validate_chain_fields,
    validate_event,
)
from clw.common.timeutil import to_rfc3339_utc, utc_now

GENESIS = "0" * 64
DOMAIN_PREFIX = b"clw-audit-v1\n"

INTEGRITY_ISSUES = frozenset({
    "hash_mismatch", "link_mismatch", "seq_gap", "seq_duplicate", "chain_id_mismatch",
    "first_not_genesis", "invalid_event_shape", "invalid_record", "unsupported_schema_version",
    "invalid_created_at", "created_at_not_monotonic", "created_at_in_future", "invalid_recovery",
})
TRANSITION_ISSUES = frozenset({
    "run_not_requested", "run_already_requested", "run_already_started", "run_not_started",
    "run_started_mismatch", "event_after_run_end", "credential_profile_mismatch",
    "credential_not_acquired", "request_without_allowed_decision", "decision_already_used",
    "request_does_not_match_decision", "attempt_out_of_order", "response_without_request",
    "duplicate_response", "completed_with_outstanding_requests",
    "redaction_without_completed_run", "redaction_digest_mismatch", "result_already_redacted",
    "request_target_not_approved",
    "analysis_without_submission", "approval_without_analysis", "approved_by_submitter",
    "approval_already_recorded", "script_run_without_approval",
})


@dataclass(frozen=True)
class ChainError:
    seq: int
    issue: str
    detail: str = ""


@dataclass(frozen=True)
class ChainReport:
    valid: bool
    chain_id: str
    total: int
    head_seq: int | None
    head_hash: str | None
    errors: tuple[ChainError, ...]
    intents_without_outcome: tuple[int, ...]
    # Integrity errors acknowledged by a later valid CHAIN_RECOVERY record. They
    # are still errors: an acknowledged chain is never reported valid.
    acknowledged: tuple[ChainError, ...] = ()
    # Every CHAIN_RECOVERY record in the chain, valid or not (SD-016).
    recoveries: tuple["RecoveryInfo", ...] = ()
    # Integrity state (SD-016):
    #   clean       no integrity findings
    #   unrecovered unacknowledged integrity findings; appends are refused
    #   invalid_recovery  an unacknowledged invalid CHAIN_RECOVERY; appends refused
    #   recovered   every integrity finding is acknowledged by a valid recovery;
    #               appends resume, the history stays reported and valid stays False
    integrity_state: Literal["clean", "unrecovered", "invalid_recovery", "recovered"] = "clean"
    # Findings that depend on the verifier's clock rather than on stored
    # records: a record ahead of that clock that nothing later can vouch for
    # (the newest record, or any record with no trusted baseline before it,
    # such as at the start of a chain). They can disappear as time passes.
    # While any exist, other findings and recovery validity can change too;
    # once none remain, findings are stable for later verification (same
    # records, same rules, verifier clock not moving backwards). See SD-020.
    provisional: tuple[ChainError, ...] = ()

    @property
    def complete(self) -> bool:
        """Valid AND every recorded Graph attempt has a recorded response."""
        return self.valid and not self.intents_without_outcome

    def findings(self) -> list[list[object]]:
        return [[e.seq, e.issue] for e in self.errors]


@dataclass(frozen=True)
class RecoveryInfo:
    seq: int
    operator: object
    reason: object
    acknowledged: tuple[tuple[int, str], ...]
    valid: bool


def compute_record_hash(fields: Mapping[str, object]) -> str:
    keys = set(fields)
    if keys != set(PROTECTED_FIELDS):
        raise ValueError(
            f"hash input must be exactly the protected fields; "
            f"missing={sorted(set(PROTECTED_FIELDS) - keys)} extra={sorted(keys - set(PROTECTED_FIELDS))}"
        )
    return hashlib.sha256(DOMAIN_PREFIX + canonical_json(dict(fields))).hexdigest()


def result_sha256(result: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(dict(result))).hexdigest()


def next_record(
    head: "AuditRecord | Anchor | None",
    *,
    chain_id: str,
    event: Mapping[str, object],
    created_at: datetime,
) -> AuditRecord:
    """Build the record that follows ``head``. Raises AuditEventInvalid.

    created_at should come from the authoritative clock (the database server's,
    see AuditWriter). If the head's timestamp is valid and later than
    created_at by no more than MAX_FUTURE_SKEW (ordinary clock skew), the new
    record takes the head's timestamp so the chain stays non-decreasing. An
    invalid or far-future head timestamp is never copied: the record keeps
    its own clock's value, and the head is left to be flagged and recovered.
    """
    unknown = set(event) - set(EVENT_FIELDS)
    if unknown:
        raise AuditEventInvalid(f"unknown event fields {sorted(unknown)}")
    values: dict[str, object] = {name: event.get(name) for name in EVENT_FIELDS}
    if values["details"] is None:
        values["details"] = {}
    problems = validate_event(values, chain_id=chain_id)
    if problems:
        raise AuditEventInvalid("; ".join(problems))
    try:
        stamp = to_rfc3339_utc(created_at)
        head_created = getattr(head, "created_at", None)
        if (
            head is not None
            and valid_created_at(head_created)
            and stamp < head_created
            and not is_future(head_created, created_at)
        ):
            stamp = head_created
        values.update(
            schema_version=SCHEMA_VERSION,
            chain_id=chain_id,
            seq=1 if head is None else head.seq + 1,
            created_at=stamp,
            previous_hash=GENESIS if head is None else head.record_hash,
        )
        record_hash = compute_record_hash(values)
    except (CanonicalizationError, ValueError) as exc:
        raise AuditEventInvalid(str(exc)) from exc
    return AuditRecord(**values, record_hash=record_hash)  # type: ignore[arg-type]


# --------------------------------------------------------------- integrity


@dataclass(frozen=True)
class Anchor:
    """A previously verified record the next record must link to."""

    seq: int
    record_hash: str
    created_at: str


def record_local_findings(record: AuditRecord, chain_id: str, *, now: datetime | None = None) -> list[ChainError]:
    """Checks that need only the record itself (shape, hash, chain fields)."""
    seq = record.seq if _is_int(record.seq) else -1
    out = [ChainError(seq, issue, detail) for issue, detail in validate_chain_fields(record.stored(), now=now)]
    try:
        derived = compute_record_hash(record.protected())
        if not (isinstance(record.record_hash, str) and hmac.compare_digest(derived, record.record_hash)):
            out.append(ChainError(seq, "hash_mismatch"))
    except (CanonicalizationError, ValueError, TypeError) as exc:
        out.append(ChainError(seq, "hash_mismatch", f"unhashable: {exc}"))
    if record.chain_id != chain_id:
        out.append(ChainError(seq, "chain_id_mismatch"))
    version = record.schema_version if _is_int(record.schema_version) else SCHEMA_VERSION
    problems = validate_event({name: getattr(record, name) for name in EVENT_FIELDS}, chain_id=chain_id,
                              schema_version=version)
    if problems:
        out.append(ChainError(seq, "invalid_event_shape", "; ".join(problems)))
    return out


def integrity_findings(
    records: Sequence[AuditRecord],
    *,
    chain_id: str,
    anchor: Anchor | None = None,
    now: datetime | None = None,
) -> list[ChainError]:
    """Record-local, link, timestamp and recovery checks over ``records``.

    With ``anchor``, records are a segment that must continue from it. ``now``
    (default: this host's clock) is used only for records that no later
    record can vouch for; see _timestamp_findings. Never raises on malformed
    input; problems become findings.
    """
    now = now or utc_now()
    findings: list[ChainError] = []
    expected_seq = 1 if anchor is None else anchor.seq + 1
    previous_hash = GENESIS if anchor is None else anchor.record_hash
    stamps: list[tuple[int, str, bool]] = []
    seen: set[object] = set()
    for record in records:
        try:
            local = record_local_findings(record, chain_id)
            findings += local
            seq = record.seq
            iseq = seq if _is_int(seq) else -1
            if seq in seen:
                findings.append(ChainError(iseq, "seq_duplicate"))
            elif seq != expected_seq:
                findings.append(ChainError(iseq, "seq_gap", f"expected {expected_seq}"))
            if anchor is None and seq == 1:
                if record.previous_hash != GENESIS:
                    findings.append(ChainError(seq, "first_not_genesis"))
            elif record.previous_hash != previous_hash:
                findings.append(ChainError(iseq, "link_mismatch"))
            if valid_created_at(record.created_at):
                stamps.append((iseq, record.created_at, record.event_type == EventType.CHAIN_RECOVERY))
            seen.add(seq)
            if _is_int(seq):
                expected_seq = max(expected_seq, seq + 1)
            previous_hash = record.record_hash
        except Exception as exc:  # malformed input must become a finding, never a crash
            findings.append(ChainError(-1, "invalid_record", f"{type(exc).__name__}: {exc}"[:200]))
    try:
        findings += _timestamp_findings(stamps, None if anchor is None else anchor.created_at, now)
    except Exception as exc:
        findings.append(ChainError(-1, "invalid_record", f"{type(exc).__name__}: {exc}"[:200]))
    findings += _recovery_findings(records, findings)
    return findings


PROVISIONAL = "provisional: "


def _timestamp_findings(
    stamps: Sequence[tuple[int, str, bool]], last_trusted: str | None, now: datetime
) -> list[ChainError]:
    """Timestamp ordering over the records with well-formed created_at, in
    order (gate 1 findings H3, N2, M-2). Entries are (seq, created_at,
    is_recovery).

    For each record, with L the last *trusted* timestamp before it:

    1. created_at < L: created_at_not_monotonic (the record went backwards).
    2. Chain evidence of a timestamp ahead of real time: created_at more than
       MAX_FUTURE_SKEW ahead of a later record's timestamp t, where
       - if L exists: t >= L. A later record below L is itself flagged by
         rule 1 and is not evidence; otherwise one backdated record would
         make every honest record before it look "ahead".
       - if no L exists (start of the chain, or everything before is
         flagged): the later record must be a CHAIN_RECOVERY. Without a
         trusted baseline, "these records are ahead" and "that later record
         is backdated" look the same; a recovery is written after a full
         verification (at database time, or at a head timestamp at most 5
         minutes ahead), so it settles the question, and any other later
         record is treated as the one out of order.
       Result: created_at_in_future. It depends only on stored records, so
       the passage of time cannot remove it.
    3. Otherwise, if no record could become such evidence (L exists and no
       later record has t >= L, normally because this is the newest record;
       or no L exists, which at the start of a chain applies to every record
       until one is trusted), created_at more than MAX_FUTURE_SKEW ahead of
       ``now`` gives created_at_in_future marked *provisional*: it depends on
       the verifier's clock. Later evidence under rule 2 makes it permanent
       (with no L, only a later CHAIN_RECOVERY counts); if none is written
       before the clock catches up, the chain holds no evidence it was ever
       ahead. Because a provisional record's trust decides L for the records
       after it, their findings can change with the clock too while any
       provisional finding exists.
    4. Otherwise the record is trusted and its timestamp becomes L.

    Flagged records never become L, so they cannot contaminate later records.
    """
    if not stamps:
        return []
    order = sorted({t for _, t, _ in stamps})
    rank = {t: i for i, t in enumerate(order)}
    later = _Counts(len(order))  # timestamps of the records after the current one
    for _, t, _ in stamps:
        later.add(rank[t], 1)
    recovery_min_after: list[str | None] = [None] * len(stamps)
    running: str | None = None
    for idx in range(len(stamps) - 1, -1, -1):
        recovery_min_after[idx] = running
        _, t, is_recovery = stamps[idx]
        if is_recovery and (running is None or t < running):
            running = t
    limit_now = to_rfc3339_utc(now + MAX_FUTURE_SKEW)
    found: list[ChainError] = []
    for idx, (seq, t, _) in enumerate(stamps):
        later.add(rank[t], -1)
        if last_trusted is not None and t < last_trusted:
            found.append(ChainError(seq, "created_at_not_monotonic", f"before {last_trusted}"))
            continue
        bound = _minus_skew(t)  # evidence is strictly below this
        if last_trusted is not None:
            lo = bisect_left(order, last_trusted)
            evidence = later.range(lo, bisect_left(order, bound)) > 0
            can_be_vouched = later.range(lo, len(order)) > 0
        else:
            recovery = recovery_min_after[idx]
            evidence = recovery is not None and recovery < bound
            can_be_vouched = False
        if evidence:
            found.append(ChainError(seq, "created_at_in_future", "more than 5 minutes ahead of a later record"))
        elif not can_be_vouched and t > limit_now:
            found.append(ChainError(seq, "created_at_in_future", PROVISIONAL + "ahead of the verifier's clock"))
        else:
            last_trusted = t
    return found


def _minus_skew(created_at: str) -> str:
    parsed = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    if parsed - datetime.min.replace(tzinfo=timezone.utc) < MAX_FUTURE_SKEW:
        return ""  # nothing can be more than the skew below year 1
    return to_rfc3339_utc(parsed - MAX_FUTURE_SKEW)


class _Counts:
    """Fenwick tree of counts per timestamp rank (O(log n) update and range sum)."""

    def __init__(self, n: int) -> None:
        self._tree = [0] * (n + 1)

    def add(self, i: int, delta: int) -> None:
        i += 1
        while i < len(self._tree):
            self._tree[i] += delta
            i += i & -i

    def _prefix(self, i: int) -> int:  # sum over ranks [0, i)
        total = 0
        while i > 0:
            total += self._tree[i]
            i -= i & -i
        return total

    def range(self, lo: int, hi: int) -> int:  # sum over ranks [lo, hi)
        return self._prefix(hi) - self._prefix(lo)


def _acknowledged_items(record: AuditRecord) -> set[tuple[object, object]]:
    items = record.details.get("acknowledged", []) if isinstance(record.details, dict) else []
    return {(a.get("seq"), a.get("issue")) for a in items if isinstance(a, dict)} if isinstance(items, list) else set()


def _recovery_findings(records: Sequence[AuditRecord], base: Sequence[ChainError]) -> list[ChainError]:
    """A CHAIN_RECOVERY must name its real predecessor and acknowledge only
    findings that existed before it (N4). Recoveries are processed in order,
    so a later recovery may acknowledge an earlier invalid one."""
    found: list[ChainError] = []
    for record in records:
        try:
            if record.event_type != EventType.CHAIN_RECOVERY or not _is_int(record.seq):
                continue
            details = record.details if isinstance(record.details, dict) else {}
            prior = {(f.seq, f.issue) for f in (*base, *found) if 1 <= f.seq < record.seq}
            acknowledged = _acknowledged_items(record)
            problems = []
            if details.get("observed_head_seq") != record.seq - 1:
                problems.append("observed_head_seq is not the predecessor")
            if details.get("observed_head_hash") != record.previous_hash:
                problems.append("observed_head_hash is not the predecessor's stored hash")
            if not acknowledged:
                problems.append("acknowledges nothing")
            elif not acknowledged <= prior:
                problems.append(f"acknowledges findings that did not exist before it: {sorted(map(str, acknowledged - prior))[:5]}")
            if problems:
                found.append(ChainError(record.seq, "invalid_recovery", "; ".join(problems)))
        except Exception as exc:
            found.append(ChainError(-1, "invalid_record", f"{type(exc).__name__}: {exc}"[:200]))
    return found


def acknowledged_by_recovery(records: Sequence[AuditRecord], findings: Sequence[ChainError]) -> set[tuple[int, str]]:
    """(seq, issue) pairs acknowledged by a CHAIN_RECOVERY record that has no
    integrity finding of its own (findings must come from integrity_findings,
    which already enforces that acknowledgements precede the recovery)."""
    dirty = {f.seq for f in findings}
    acked: set[tuple[int, str]] = set()
    for record in records:
        try:
            if record.event_type != EventType.CHAIN_RECOVERY or record.seq in dirty:
                continue
            acked |= {(s, i) for s, i in _acknowledged_items(record) if _is_int(s) and isinstance(i, str)}
        except Exception:
            continue
    return acked


def blocking_findings(records: Sequence[AuditRecord], findings: Sequence[ChainError]) -> list[ChainError]:
    acked = acknowledged_by_recovery(records, findings)
    return [f for f in findings if (f.seq, f.issue) not in acked]


def recovery_record(
    records: Sequence[AuditRecord],
    blocking: Sequence[ChainError],
    *,
    chain_id: str,
    operator: str,
    reason: str,
    created_at: datetime,
    now: datetime | None = None,
) -> AuditRecord:
    """Build the CHAIN_RECOVERY record that follows ``records`` and
    acknowledges ``blocking`` (SD-016). Raises AuditEventInvalid.

    The recovery is written at database time (or at a head timestamp at
    most 5 minutes ahead), so it can itself be the evidence that earlier
    records are ahead (for example several records
    written while the clock ran fast; see _timestamp_findings). Those
    findings concern records before it and exist as soon as it is appended,
    so they are acknowledged as well. Findings on earlier records do not
    depend on the acknowledgement list, so one extra pass reaches the fixed
    point. Whether the result restores appends is for the caller to check.
    """
    head = records[-1]

    def build(acks: set[tuple[int, str]]) -> AuditRecord:
        return next_record(head, chain_id=chain_id, created_at=created_at, event={
            "tenant_id": chain_id,
            "event_type": EventType.CHAIN_RECOVERY,
            "status": "recorded",
            "reason": reason,
            "actor_oid": operator,
            "details": {
                "acknowledged": [{"seq": s, "issue": i} for s, i in sorted(acks) if s >= 1],
                "observed_head_seq": head.seq,
                "observed_head_hash": head.record_hash,
            },
        })

    acknowledged = {(f.seq, f.issue) for f in blocking}
    record = build(acknowledged)
    after = [*records, record]
    exposed = {(f.seq, f.issue) for f in blocking_findings(after, integrity_findings(after, chain_id=chain_id, now=now))
               if 1 <= f.seq < record.seq}
    if not exposed <= acknowledged:
        record = build(acknowledged | exposed)
    return record


def recovery_summary(records: Sequence[AuditRecord], findings: Sequence[ChainError]) -> tuple[RecoveryInfo, ...]:
    dirty = {f.seq for f in findings}
    out = []
    for record in records:
        if record.event_type == EventType.CHAIN_RECOVERY and _is_int(record.seq):
            acknowledged = tuple(sorted((s, i) for s, i in _acknowledged_items(record) if _is_int(s) and isinstance(i, str)))
            out.append(RecoveryInfo(record.seq, record.actor_oid, record.reason, acknowledged, record.seq not in dirty))
    return tuple(out)


# -------------------------------------------------------------- transitions


@dataclass
class _Run:
    state: str  # requested | started | ended
    requested: AuditRecord
    started: AuditRecord | None = None
    credential: str | None = None  # acquired | rejected
    latest_decision: dict[object, AuditRecord] = field(default_factory=dict)
    used_decisions: set[int] = field(default_factory=set)
    last_attempt: int = 0
    outstanding: dict[int, AuditRecord] = field(default_factory=dict)
    responded: set[int] = field(default_factory=set)
    completed: AuditRecord | None = None
    redacted: bool = False


_SCRIPT_EVENTS = (EventType.SCRIPT_SUBMITTED, EventType.SCRIPT_ANALYZED, EventType.MANIFEST_APPROVED)


@dataclass
class _Scripts:
    """Script records of one chain (SD-040): the submitter of each script, the
    scripts analysed, and the script digest of each approval by id."""

    submitter: dict[object, object] = field(default_factory=dict)
    analyzed: set[object] = field(default_factory=set)
    approvals: dict[object, object] = field(default_factory=dict)


def _script_step(record: AuditRecord, scripts: _Scripts, bad) -> None:
    details = record.details if isinstance(record.details, dict) else {}
    sha = details.get("script_sha256")
    et = record.event_type
    if et == EventType.SCRIPT_SUBMITTED:
        scripts.submitter.setdefault(sha, record.actor_oid)
    elif et == EventType.SCRIPT_ANALYZED:
        if sha not in scripts.submitter:
            bad(record, "analysis_without_submission")
        elif record.status == "analyzed":
            scripts.analyzed.add(sha)
    else:  # MANIFEST_APPROVED
        approval = details.get("approval_id")
        if sha not in scripts.analyzed:
            bad(record, "approval_without_analysis")
        elif record.actor_oid == scripts.submitter.get(sha):
            bad(record, "approved_by_submitter")
        elif approval in scripts.approvals:
            bad(record, "approval_already_recorded")
        else:
            scripts.approvals[approval] = sha


def _script_run_approved(record: AuditRecord, scripts: _Scripts) -> bool:
    """A script run's RUN_STARTED cites an earlier approval of that very script."""
    details = record.details if isinstance(record.details, dict) else {}
    approved = scripts.approvals.get(details.get("approval_id"))
    return approved is not None and approved == details.get("script_sha256")


def _transition_findings(records: Sequence[AuditRecord]) -> tuple[list[ChainError], tuple[int, ...]]:
    findings: list[ChainError] = []
    runs: dict[object, _Run] = {}
    by_seq: dict[object, AuditRecord] = {}
    scripts = _Scripts()

    def bad(record: AuditRecord, issue: str, detail: str = "") -> None:
        findings.append(ChainError(record.seq if _is_int(record.seq) else -1, issue, detail))

    for record in records:
        try:
            if record.event_type in _SCRIPT_EVENTS:
                _script_step(record, scripts, bad)
            else:
                is_script_start = (record.event_type == EventType.RUN_STARTED and isinstance(record.details, dict)
                                   and "script_sha256" in record.details)
                if is_script_start and not _script_run_approved(record, scripts):
                    bad(record, "script_run_without_approval")
                _step(record, runs, by_seq, bad)
        except Exception as exc:  # malformed input must become a finding, never a crash
            findings.append(ChainError(-1, "invalid_record", f"{type(exc).__name__}: {exc}"[:200]))
        if _is_int(record.seq):  # only well-formed records can be cited by later ones
            by_seq.setdefault(record.seq, record)

    intents = sorted(r.seq for run in runs.values() for r in run.outstanding.values() if _is_int(r.seq))
    return findings, tuple(intents)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _step(record: AuditRecord, runs: dict, by_seq: dict, bad) -> None:  # noqa: C901 - one state machine
    et = record.event_type
    if et == EventType.CHAIN_RECOVERY:
        return  # not part of any run; validated by integrity_findings
    if et == EventType.RESULT_REDACTED:
        # Not part of a run either; it must name an earlier completed run, the
        # digest that run's completion recorded, and be the run's only redaction.
        details = record.details if isinstance(record.details, dict) else {}
        target = runs.get(details.get("redacted_run_id"))
        if target is None or target.completed is None:
            bad(record, "redaction_without_completed_run")
        elif target.redacted:
            bad(record, "result_already_redacted")
        elif details.get("result_sha256") != target.completed.details.get("result_sha256"):
            bad(record, "redaction_digest_mismatch")
        else:
            target.redacted = True
        return

    run = runs.get(record.run_id)
    if et == EventType.RUN_REQUESTED:
        if run is not None:
            bad(record, "run_already_requested")
        else:
            runs[record.run_id] = _Run(state="requested", requested=record)
        return
    if run is None:
        bad(record, "run_not_requested")
        return
    if run.state == "ended":
        bad(record, "event_after_run_end")
        return

    if et == EventType.RUN_STARTED:
        if run.state != "requested":
            bad(record, "run_already_started")
            return
        if (record.task_id, record.task_manifest_sha256) != (run.requested.task_id, run.requested.task_manifest_sha256):
            bad(record, "run_started_mismatch")
        run.state, run.started = "started", record
        return
    if et in (EventType.RUN_FAILED, EventType.RUN_TIMED_OUT):
        run.state = "ended"  # may follow a partial failure; open intents stay reported
        return
    if run.state != "started":
        bad(record, "run_not_started")
        return

    started = run.started
    profile = (started.profile_id, started.profile_version, started.auth_mode)
    if et in (EventType.CREDENTIAL_ACQUIRED, EventType.CREDENTIAL_REJECTED):
        if (record.profile_id, record.profile_version, record.auth_mode) != profile:
            bad(record, "credential_profile_mismatch")
        run.credential = "acquired" if et == EventType.CREDENTIAL_ACQUIRED else "rejected"
    elif et == EventType.OP_DECISION:
        run.latest_decision[record.operation] = record
    elif et == EventType.GRAPH_REQUEST:
        if run.credential != "acquired":
            bad(record, "credential_not_acquired")
        decision = by_seq.get(record.decision_seq)
        latest = run.latest_decision.get(record.operation)
        if not (
            decision is not None
            and decision.event_type == EventType.OP_DECISION
            and decision.status == "allowed"
            and decision.run_id == record.run_id
            and decision.operation == record.operation
            and isinstance(decision.seq, int) and decision.seq < record.seq
            and latest is decision  # no later decision (e.g. a denial) for this run+operation
        ):
            bad(record, "request_without_allowed_decision")
        elif record.decision_seq in run.used_decisions:
            bad(record, "decision_already_used")
        elif (record.http_method, record.path_template) != (decision.http_method, decision.path_template):
            bad(record, "request_does_not_match_decision")
        elif not continues_approved_target(
                record.request_target, decision.details.get("request_target") if isinstance(decision.details, dict)
                else None):
            # RR-5 (SD-039): the exact target, query included, must be the one the
            # decision approved (or its $skiptoken continuation).
            bad(record, "request_target_not_approved")
        if isinstance(record.decision_seq, int):
            run.used_decisions.add(record.decision_seq)
        if record.attempt != run.last_attempt + 1:
            bad(record, "attempt_out_of_order", f"expected {run.last_attempt + 1}")
        if isinstance(record.attempt, int) and record.attempt not in run.outstanding and record.attempt not in run.responded:
            run.outstanding[record.attempt] = record
        if isinstance(record.attempt, int):
            run.last_attempt = max(run.last_attempt, record.attempt)
    elif et == EventType.GRAPH_RESPONSE:
        request = run.outstanding.get(record.attempt)
        if request is None:
            bad(record, "duplicate_response" if record.attempt in run.responded else "response_without_request")
        elif request.operation != record.operation:
            bad(record, "response_without_request", "operation differs from the request")
        else:
            del run.outstanding[record.attempt]
            run.responded.add(record.attempt)
    elif et == EventType.RUN_COMPLETED:
        if run.outstanding:
            bad(record, "completed_with_outstanding_requests", f"attempts {sorted(run.outstanding)}")
        run.state, run.completed = "ended", record


# ------------------------------------------------------------------ report


def verify_records(records: Sequence[AuditRecord], *, chain_id: str, now: datetime | None = None) -> ChainReport:
    """Verify integrity, links and run transitions of one chain, in the order given.

    ``now`` (default: this host's clock) matters only for records no later
    record vouches for; findings that depend on it are listed in
    ``provisional``. A verifier with a badly wrong clock can report false
    provisional findings."""
    records = list(records)
    integrity = integrity_findings(records, chain_id=chain_id, now=now)
    transitions, intents = _transition_findings(records)
    errors = tuple(integrity + transitions)
    acked = acknowledged_by_recovery(records, integrity)
    unacked = [e for e in integrity if (e.seq, e.issue) not in acked]
    if not integrity:
        state = "clean"
    elif any(e.issue == "invalid_recovery" for e in unacked):
        state = "invalid_recovery"
    elif unacked:
        state = "unrecovered"
    else:
        state = "recovered"
    head = records[-1] if records else None
    return ChainReport(
        valid=not errors,
        chain_id=chain_id,
        total=len(records),
        head_seq=head.seq if head else None,
        head_hash=head.record_hash if head else None,
        errors=errors,
        intents_without_outcome=intents,
        acknowledged=tuple(e for e in integrity if (e.seq, e.issue) in acked),
        recoveries=recovery_summary(records, integrity),
        integrity_state=state,
        provisional=tuple(e for e in integrity if e.detail.startswith(PROVISIONAL)),
    )


def verify_run_result(
    record: AuditRecord, stored_result: object, *, redaction: AuditRecord | None = None
) -> Literal["ok", "redacted", "result_mismatch", "not_a_completion_record"]:
    """SD-014: the stored run result must re-hash to the completion record's digest.

    SD-037: a result removed by the redaction procedure is "redacted" when it
    is gone (None) and ``redaction`` is a RESULT_REDACTED naming this run and
    this digest. A redaction record never vouches for a result still present.
    The records' own integrity is established by verify_records.
    """
    if record.event_type != EventType.RUN_COMPLETED:
        return "not_a_completion_record"
    expected = record.details.get("result_sha256") if isinstance(record.details, dict) else None
    if stored_result is None and redaction is not None:
        details = redaction.details if isinstance(redaction.details, dict) else {}
        named = (redaction.event_type == EventType.RESULT_REDACTED and redaction.chain_id == record.chain_id
                 and details.get("redacted_run_id") == record.run_id)
        if named and isinstance(expected, str) and details.get("result_sha256") == expected:
            return "redacted"
        return "result_mismatch"
    if not isinstance(stored_result, Mapping) or not isinstance(expected, str):
        return "result_mismatch"
    try:
        actual = result_sha256(stored_result)
    except (CanonicalizationError, TypeError, ValueError):
        return "result_mismatch"
    return "ok" if hmac.compare_digest(expected, actual) else "result_mismatch"
