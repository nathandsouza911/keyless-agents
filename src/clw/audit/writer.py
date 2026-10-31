"""Fail-closed audit writer (SD-006, SD-007, SD-016; review findings H2, N2, N3).

Each append runs in its own session and transaction under a per-chain
advisory lock, so a caller rolling back its own work cannot erase audit
evidence, and the record is durable (committed) before append() returns.

Clock: the PostgreSQL server clock (clock_timestamp(), read inside the
append transaction) is authoritative for created_at and for the 5-minute
future bound; the database trigger enforces the same bound against the same
clock. This process's own clock is used only to detect drift, which is
logged as an alert (audit_clock_drift) and does not affect records.

Before extending a chain the writer verifies it. If it holds a cached
position for the chain (the last record it verified, still within the
clock window) and the records added since then, by any process, produce no
findings at all, it extends them directly (the fast path). Otherwise it
verifies the whole chain in the same transaction, and that full
verification alone decides: any unacknowledged integrity finding makes the
writer refuse with AuditChainCompromised and log a CRITICAL alert. A
fast-path append agrees with full verification under the conditions in
SD-026; that rests on reasoning and tests, not a proof. Appends stay
refused until an operator completes the recovery procedure
(append_recovery, docs/runbooks/audit-chain-recovery.md). The writer also
runs the record-local checks on every record it builds before inserting it.

Every failure path raises AuditUnavailable or a subclass. Exceptions that
are not Exception subclasses (asyncio.CancelledError, KeyboardInterrupt)
propagate unwrapped; the transaction is rolled back and the caller still
fails closed because append() did not return a record.

Commit-acknowledgement ambiguity: if the connection drops after COMMIT is
sent but before it is acknowledged, append() raises although the row may
exist. Callers fail closed, so the worst case is an extra record.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable, Mapping
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.audit.chain import (
    PROVISIONAL,
    Anchor,
    blocking_findings,
    integrity_findings,
    next_record,
    record_local_findings,
    recovery_record,
)
from clw.audit.events import (
    MAX_FUTURE_SKEW,
    TERMINAL_EVENTS,
    AuditChainCompromised,
    AuditEventInvalid,
    AuditRecord,
    AuditRunStateRefused,
    AuditUnavailable,
    EventType,
    is_future,
    valid_created_at,
)
from clw.audit.verifier import load_chain
from clw.common.timeutil import to_rfc3339_utc, utc_now
from clw.db.models.audit_event import AuditEventRow

alert_log = logging.getLogger("clw.audit.alert")

RUNBOOK = "docs/runbooks/audit-chain-recovery.md"
MAX_ANCHORS = 1024
# Bounds on how long an audit write may wait (gate 1 finding L-3). A write
# that hits either fails with AuditUnavailable, so the caller fails closed.
LOCK_TIMEOUT_MS = 5_000
STATEMENT_TIMEOUT_MS = 30_000


def _provisional(findings) -> bool:
    return any(f.detail.startswith(PROVISIONAL) for f in findings)


def _wait_target(records, now: datetime) -> tuple[int, str] | None:
    """(seq, created_at) of the latest-stamped record ahead of the database
    clock, or None. Once the clock has passed it, no record is ahead: no
    finding is provisional and a recovery is stamped with the clock's own
    time, not copied from a head that is ahead (targeted review R2).

    The seq named is the first record carrying that latest timestamp, which
    need not be the last provisional seq: honest records after a head that is
    ahead copy its timestamp, and the first is where it came from (final
    review I-2). Callers pass the stored records only, never a recovery being
    built, so the seq named always exists."""
    limit = to_rfc3339_utc(now)
    ahead = [(r.created_at, r.seq) for r in records
             if valid_created_at(r.created_at) and isinstance(r.seq, int) and r.created_at > limit]
    if not ahead:
        return None
    latest = max(created_at for created_at, _ in ahead)
    return min(seq for created_at, seq in ahead if created_at == latest), latest


class AuditRecoveryRefused(Exception):
    """Recovery was not attempted: the request does not match the chain's
    observed state, or the recovery would not restore appends."""


class AuditRecoveryIncomplete(Exception):
    """A recovery record was committed, but the chain still fails integrity
    verification afterwards. Appends remain refused; investigate manually."""


class AuditWriter:
    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        clock: Callable[[], datetime] = utc_now,
        on_compromised: Callable[[AuditChainCompromised], None] | None = None,
        max_anchors: int = MAX_ANCHORS,
        lock_timeout_ms: int = LOCK_TIMEOUT_MS,
        statement_timeout_ms: int = STATEMENT_TIMEOUT_MS,
    ) -> None:
        self._sessionmaker = sessionmaker
        self._clock = clock  # drift monitoring only; records use the database clock
        self._on_compromised = on_compromised
        self._anchors: OrderedDict[str, Anchor] = OrderedDict()
        self._max_anchors = max_anchors
        if not all(type(v) is int and v > 0 for v in (lock_timeout_ms, statement_timeout_ms)):
            raise ValueError("audit timeouts must be positive integers (milliseconds)")
        self._timeouts = (lock_timeout_ms, statement_timeout_ms)

    async def append(self, *, chain_id: str, event: Mapping[str, object]) -> AuditRecord:
        try:
            async with self._sessionmaker() as session:
                async with session.begin():
                    await self._bound(session)
                    await self._lock(session, chain_id)
                    now = await self._db_now(session)
                    head, cacheable = await self._verified_head(session, chain_id, now)
                    record = next_record(head, chain_id=chain_id, event=event, created_at=now)
                    self._self_check(record, chain_id, now)
                    await self._check_run_state(session, chain_id, record)
                    session.add(AuditEventRow.from_record(record))
            if cacheable:
                self._remember(chain_id, Anchor(record.seq, record.record_hash, record.created_at))
            else:
                self._anchors.pop(chain_id, None)
            return record
        except AuditChainCompromised as exc:
            self._alert(exc)
            raise
        except AuditUnavailable:
            raise
        except Exception as exc:
            raise AuditUnavailable(f"audit append failed for chain {chain_id}") from exc

    async def append_recovery(
        self, *, chain_id: str, operator: str, reason: str, expected_head_hash: str
    ) -> AuditRecord:
        """Record an operator's acknowledgement of the chain's current
        integrity findings so normal appends can resume.

        Refused (AuditRecoveryRefused, nothing written) unless: the chain has
        unacknowledged findings, the operator names the head they inspected,
        and appending this exact recovery record would leave no blocking
        findings. After commit the chain is re-read and verified; if it is
        still blocked, AuditRecoveryIncomplete is raised. The chain remains
        reported as invalid permanently.
        """
        try:
            async with self._sessionmaker() as session:
                async with session.begin():
                    await self._bound(session)
                    await self._lock(session, chain_id)
                    now = await self._db_now(session)
                    records = await load_chain(session, chain_id=chain_id)
                    blocking = blocking_findings(records, integrity_findings(records, chain_id=chain_id, now=now))
                    if not records or not blocking:
                        raise AuditRecoveryRefused("chain has no unacknowledged integrity findings")
                    head = records[-1]
                    if head.record_hash != expected_head_hash:
                        raise AuditRecoveryRefused(
                            f"chain head is {head.record_hash} at seq {head.seq}, not the expected hash; re-inspect"
                        )
                    record = recovery_record(records, blocking, chain_id=chain_id, operator=operator,
                                             reason=reason, created_at=now, now=now)
                    acknowledged = sorted((a["seq"], a["issue"]) for a in record.details["acknowledged"])
                    after = [*records, record]
                    after_findings = integrity_findings(after, chain_id=chain_id, now=now)
                    remaining = blocking_findings(after, after_findings)
                    wait = _wait_target(records, now)
                    if remaining:
                        # Targeted review R2: a head slightly ahead of the clock
                        # is copied into the recovery, which can then itself be
                        # out of order. Waiting for the clock fixes that, so say
                        # so before sending the operator to manual investigation.
                        hint = (f"; if the database clock is correct, retry once it has passed the created_at "
                                f"{wait[1]} of seq {wait[0]} before investigating further" if wait else "")
                        raise AuditRecoveryRefused(
                            "this recovery would not restore appends; remaining findings "
                            f"{[(f.seq, f.issue) for f in remaining][:10]}{hint}; otherwise manual investigation "
                            "required"
                        )
                    # Gate 1 L-B (fifth review): a provisional finding depends on
                    # the clock. Acknowledging it would let the recovery look
                    # valid now and turn invalid once the clock passes the record,
                    # so the recovery waits until the chain itself is the evidence.
                    provisional = sorted({f.seq for f in after_findings if f.detail.startswith(PROVISIONAL)})
                    if provisional:
                        target = wait or (provisional[-1], "unknown")
                        raise AuditRecoveryRefused(
                            f"recovery would leave provisional (clock-dependent) findings at seqs {provisional[:10]}; "
                            f"retry once the database clock has passed the created_at {target[1]} of seq "
                            f"{target[0]}, or investigate the clock"
                        )
                    session.add(AuditEventRow.from_record(record))
        except (AuditRecoveryRefused, AuditUnavailable):
            raise
        except Exception as exc:
            raise AuditUnavailable(f"audit recovery failed for chain {chain_id}") from exc

        self._anchors.pop(chain_id, None)
        try:
            async with self._sessionmaker() as session:
                async with session.begin():
                    await self._bound(session)
                    stored = await load_chain(session, chain_id=chain_id)
                    now = await self._db_now(session)
        except Exception as exc:
            raise AuditRecoveryIncomplete(
                f"recovery record seq {record.seq} committed but the chain could not be re-verified") from exc
        stored_findings = integrity_findings(stored, chain_id=chain_id, now=now)
        still = blocking_findings(stored, stored_findings) + [
            f for f in stored_findings if f.detail.startswith(PROVISIONAL)]
        if still:
            alert_log.critical("audit_chain_recovery_incomplete chain_id=%s seq=%s remaining=%s",
                               chain_id, record.seq, [(f.seq, f.issue) for f in still][:20])
            raise AuditRecoveryIncomplete(
                f"recovery record seq {record.seq} committed but the chain is still blocked: "
                f"{[(f.seq, f.issue) for f in still][:10]}")
        alert_log.critical(
            "audit_chain_recovery_recorded chain_id=%s seq=%s operator=%s acknowledged=%s verified=true",
            chain_id, record.seq, operator, acknowledged,
        )
        return record

    # ----------------------------------------------------------- internals

    async def _bound(self, session: AsyncSession) -> None:
        # SET LOCAL lasts until the end of this transaction only. The values
        # are integers validated in __init__, never caller text.
        lock_ms, statement_ms = self._timeouts
        await session.execute(text(f"SET LOCAL lock_timeout = {lock_ms}"))
        await session.execute(text(f"SET LOCAL statement_timeout = {statement_ms}"))

    @staticmethod
    async def _lock(session: AsyncSession, chain_id: str) -> None:
        # Serialise appends per chain across processes. 64-bit key; a
        # collision only serialises two unrelated chains.
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"clw-audit:{chain_id}"},
        )

    async def _db_now(self, session: AsyncSession) -> datetime:
        now = await session.scalar(text("SELECT clock_timestamp()"))
        local = self._clock()
        if abs(local - now) > MAX_FUTURE_SKEW:
            alert_log.warning(
                "audit_clock_drift local=%s database=%s action=using_database_clock", local.isoformat(), now.isoformat()
            )
        return now

    async def _verified_head(
        self, session: AsyncSession, chain_id: str, now: datetime
    ) -> tuple[AuditRecord | Anchor | None, bool]:
        """Return (head to extend, whether the new record may be cached).

        The cached position is only a fast path, taken when the records after
        it produce no findings at all. Everything else is decided by full
        verification of the whole chain in this transaction, so a refusal is
        always full verification's refusal (gate 1 L-A). An append through the
        fast path agrees with full verification under the conditions in
        SD-026 (cached position within the clock window and cached with no
        provisional finding; no rewrite of records before it, RR-2); that
        rests on the reasoning there and on the tests, not on a proof.
        Refusal is fail closed: any error while verifying propagates and
        nothing is written.
        """
        anchor = self._anchors.get(chain_id)
        if anchor is not None and not self._anchor_trustworthy(anchor, now):
            # Gate 1 finding F-1 (fourth review): the cached record was judged
            # against the clock when it was written. If the database clock has
            # since stepped back, it is ahead of now, and only a full
            # verification applies the timestamp rules to it and to the
            # records before it. Anything not provably fine is re-verified.
            alert_log.warning("audit_anchor_untrusted chain_id=%s seq=%s created_at=%s action=full_verification",
                              chain_id, anchor.seq, anchor.created_at)
            self._anchors.pop(chain_id, None)
            anchor = None
        if anchor is not None:
            records = await load_chain(session, chain_id=chain_id, after_seq=anchor.seq)
            findings = integrity_findings(records, chain_id=chain_id, anchor=anchor, now=now)
            if not findings:
                return (records[-1] if records else anchor), True
            # Any finding at all, even one acknowledged inside the segment,
            # sends the decision to the whole chain. The incremental view can
            # disagree with it both ways: it can flag records the whole chain
            # explains (a valid recovery by another process, gate 1 L-A), and
            # a recovery in the segment can acknowledge a finding that exists
            # only in the incremental view (targeted review R1).
            self._anchors.pop(chain_id, None)
        records = await load_chain(session, chain_id=chain_id)
        findings = integrity_findings(records, chain_id=chain_id, now=now)
        blocking = blocking_findings(records, findings)
        if blocking:
            raise AuditChainCompromised(chain_id, [(f.seq, f.issue) for f in blocking])
        # Gate 1 L-B: while any finding is provisional (only possible here if
        # it is acknowledged, e.g. by a recovery written by older code or by
        # another INSERT-capable writer), the chain's verdict can change with
        # the clock. Do not cache: every append re-verifies in full until the
        # chain itself settles it.
        return (records[-1] if records else None), not _provisional(findings)

    @staticmethod
    def _anchor_trustworthy(anchor: Anchor, now: datetime) -> bool:
        """A cached position may be used only while its timestamp is well
        formed and not more than MAX_FUTURE_SKEW ahead of the database clock.
        It is still only a fast path: _verified_head falls back to full
        verification whenever the fast path does not clear the chain, and
        caches only when no finding is provisional (SD-024, SD-026)."""
        try:
            return valid_created_at(anchor.created_at) and not is_future(anchor.created_at, now)
        except Exception:  # anything unexpected: not trustworthy, verify in full
            return False

    @staticmethod
    def _self_check(record: AuditRecord, chain_id: str, now: datetime) -> None:
        problems = record_local_findings(record, chain_id, now=now)
        if problems:
            raise AuditEventInvalid(f"refusing to write a record that fails its own checks: "
                                    f"{[(p.issue, p.detail) for p in problems]}")

    @staticmethod
    async def _check_run_state(session: AsyncSession, chain_id: str, record: AuditRecord) -> None:
        """SD-034: refuse a run record after the run's terminal record, a
        second RUN_STARTED, and a completion while a request of the run is
        unanswered. Read under the chain's advisory lock in the append
        transaction, so the decision and the insert are atomic with respect to
        every other append to the chain; a late broker record cannot land after
        a terminal one. (Under an isolation level above READ COMMITTED the read
        could miss a concurrent append; the append then fails on the chain's
        (chain_id, seq) key instead, so it still fails closed.)"""
        if record.run_id is None or record.event_type in (EventType.RUN_REQUESTED, EventType.CHAIN_RECOVERY):
            return
        rows = (await session.execute(
            text("SELECT event_type, attempt FROM audit_events WHERE chain_id = :chain_id AND run_id = :run_id "
                 "AND event_type IN ('RUN_STARTED', 'RUN_COMPLETED', 'RUN_FAILED', 'RUN_TIMED_OUT', "
                 "'GRAPH_REQUEST', 'GRAPH_RESPONSE')"),
            {"chain_id": chain_id, "run_id": record.run_id},
        )).all()
        if any(kind in TERMINAL_EVENTS for kind, _ in rows):
            raise AuditRunStateRefused(record.run_id, "run_ended")
        if record.event_type == EventType.RUN_STARTED and any(kind == EventType.RUN_STARTED for kind, _ in rows):
            # A start already recorded whose run row never started (a lost
            # commit, RR-4): the run must not start again (SD-034).
            raise AuditRunStateRefused(record.run_id, "run_already_started")
        if record.event_type == EventType.RUN_COMPLETED:
            requested = {attempt for kind, attempt in rows if kind == EventType.GRAPH_REQUEST}
            answered = {attempt for kind, attempt in rows if kind == EventType.GRAPH_RESPONSE}
            if requested - answered:
                raise AuditRunStateRefused(record.run_id, "outstanding_requests")

    def _remember(self, chain_id: str, anchor: Anchor) -> None:
        self._anchors[chain_id] = anchor
        self._anchors.move_to_end(chain_id)
        while len(self._anchors) > self._max_anchors:
            self._anchors.popitem(last=False)  # evicted chains are re-verified in full next time

    def _alert(self, exc: AuditChainCompromised) -> None:
        alert_log.critical(
            "audit_chain_integrity_failure chain_id=%s findings=%s action=appends_refused runbook=%s",
            exc.chain_id, exc.findings[:20], RUNBOOK,
        )
        if self._on_compromised is not None:
            try:
                self._on_compromised(exc)
            except Exception:  # an alert hook failing must not mask the refusal
                alert_log.exception("audit_alert_hook_failed chain_id=%s", exc.chain_id)
