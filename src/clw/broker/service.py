"""Broker service: one controlled path from a task's named operation to Graph
(Task 12, SD-007, SD-014, SD-018, SD-032).

    run token -> run (database) -> tenant, manifest, profile (catalog)
    policy.evaluate(op, params)         -> OP_DECISION   (committed)
    credentials.token_for(run tenant)   -> CREDENTIAL_ACQUIRED | CREDENTIAL_REJECTED
    transport.execute(the approved BuiltRequest), per attempt:
        attempt 1: cites that OP_DECISION
        attempt n > 1 (retry or page): policy.evaluate again -> a new OP_DECISION
        GRAPH_REQUEST (committed) -> HTTP -> GRAPH_RESPONSE (committed)
    data returned only after every GRAPH_RESPONSE is committed

Binding (SD-018). The request the transport executes is the very object
policy.evaluate returned; nothing here builds or changes a request. The
OP_DECISION records the approved request target (normalized query
included) in details.request_target, and every attempt the transport
announces must be that target, or that target plus the broker's own
$skiptoken continuation, with the same method, before anything is recorded
or sent. Each attempt consumes exactly one allowed decision (SD-014): a
retry or a further page is re-authorized by the policy, and the policy's
request must still equal the approved one. Credentials are acquired for
the run's tenant and profile after the decision and never consulted by it;
the token's permissions are recorded, not used to authorize.

Outcomes:
  denied by policy, or the request body/run refused   OP_DECISION denied; 403;
                                                      the run continues
  credential rejected, or Graph execution failed      the run ends FAILED with
                                                      the reason, then RUN_FAILED;
                                                      502; no data
  any audit write fails                               the run is halted (no more
                                                      operations); 503; no data
Nothing derived from a Graph response is returned unless its GRAPH_RESPONSE
was committed. A GRAPH_REQUEST means "authorized and possibly sent" (RR-4):
a database transaction cannot undo a request that reached Graph, and a
request may reach Graph although its response is never recorded; the
verifier lists such intents (intents_without_outcome). Exactly-once
execution is not claimed.

Operations of one run are serialized in this process, so attempt numbers
(1, 2, 3 ... per run, as the chain requires) continue from the run's last
recorded GRAPH_REQUEST. Phase 1 runs one broker process; two processes
serving one run could interleave attempt numbers, which the verifier
reports (attempt_out_of_order) rather than accepts.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
import uuid
import weakref
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from clw.audit.events import AuditRecord, AuditUnavailable, EventType
from clw.broker import operations, proposals
from clw.broker.capability import RunContext, RunRefused, RunRef, parse_authorization, resolve_run
from clw.broker.facade.runs import parse_bearer
from clw.broker.credentials import CredentialProvider, CredentialRejected, ValidatedToken
from clw.broker.manifest import TaskManifest
from clw.broker.pagination import SKIPTOKEN, request_target
from clw.broker.policy import AllowlistPolicyEngine, PolicyEngine, evaluate
from clw.broker.transport import GraphAttempt, GraphError, Transport
from clw.common.timeutil import to_rfc3339_utc, utc_now
from clw.db.models.audit_event import AuditEventRow
from clw.db.models.proposal import ChangeProposal
from clw.db.models.run import Run

alert_log = logging.getLogger("clw.broker.alert")

MAX_BODY_BYTES = 64 * 1024
INVALID_OPERATION = "(invalid)"
_OPERATION_LABEL = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_BODY_FIELDS = frozenset({"op", "params"})


@dataclass(frozen=True, slots=True)
class OpResult:
    status_code: int
    body: dict


@dataclass(frozen=True, slots=True)
class ParsedBody:
    label: str  # what OP_DECISION records as the operation
    op: str | None
    params: dict | None
    reason: str | None  # None when the body is a well-formed {op, params}


class _BindingMismatch(Exception):
    """The transport announced an attempt that is not the approved request."""


class _Reauthorization(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def operation_label(op: object) -> str:
    return op if isinstance(op, str) and _OPERATION_LABEL.match(op) else INVALID_OPERATION


def parse_body(raw: bytes | None) -> ParsedBody:
    """Strict: a JSON object with exactly `op` (a string) and `params` (an
    object). Unknown fields (path, url, method, headers, tenant_id ...) are
    `unknown_field`; anything else malformed is `invalid_request`."""
    if raw is None or len(raw) > MAX_BODY_BYTES:
        return ParsedBody(INVALID_OPERATION, None, None, "invalid_request")

    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(pairs)

    def no_constants(name):
        raise ValueError("non-finite number")

    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates, parse_constant=no_constants)
    except (ValueError, RecursionError):
        return ParsedBody(INVALID_OPERATION, None, None, "invalid_request")
    if not isinstance(body, dict):
        return ParsedBody(INVALID_OPERATION, None, None, "invalid_request")
    label = operation_label(body.get("op"))
    if set(body) - _BODY_FIELDS:
        return ParsedBody(label, None, None, "unknown_field")
    op, params = body.get("op"), body.get("params")
    if type(op) is not str or type(params) is not dict:
        return ParsedBody(label, None, None, "invalid_request")
    return ParsedBody(label, op, params, None)


def response_fields(attempt: GraphAttempt) -> dict[str, object]:
    """GRAPH_RESPONSE fields for one attempt the transport reports as sent.

    succeeded          200 with a usable page (item_count set)
    failed/no_response no HTTP status (timeout, network error, cut at the deadline)
    failed/unusable_response  a 2xx that gave no usable page (malformed, too
                       large, compressed, or not 200); the chain forbids a 2xx
                       status on a failed response, so it goes in details
    failed/http_<code> any other status
    """
    status = attempt.http_status
    fields: dict[str, object] = {"graph_request_id": attempt.graph_request_id, "duration_ms": attempt.duration_ms}
    if status == 200 and attempt.item_count is not None:
        return fields | {"status": "succeeded", "http_status": 200, "item_count": attempt.item_count}
    if status is None:
        return fields | {"status": "failed", "reason": "no_response"}
    if 200 <= status <= 299:
        return fields | {"status": "failed", "reason": "unusable_response", "details": {"received_http_status": status}}
    return fields | {"status": "failed", "reason": f"http_{status}", "http_status": status}


def continues(target: object, approved: str) -> bool:
    """The approved target itself, or it plus the broker's $skiptoken continuation."""
    if not isinstance(target, str):
        return False
    return target == approved or target.startswith(f"{approved}{'&' if '?' in approved else '?'}{SKIPTOKEN}=")


class BrokerService:
    def __init__(
        self,
        *,
        sessionmaker: async_sessionmaker[AsyncSession],
        writer,
        transport: Transport,
        credentials: CredentialProvider,
        catalog: Mapping[str, TaskManifest],
        engine: PolicyEngine | None = None,
        clock: Callable[[], datetime] = utc_now,
        script_manifests=None,
        agent_catalog: Mapping[str, TaskManifest] | None = None,
    ) -> None:
        self._sessionmaker = sessionmaker
        self._writer = writer  # clw.audit.writer.AuditWriter
        self._transport = transport
        self._credentials = credentials
        self._catalog = catalog
        self._engine = AllowlistPolicyEngine() if engine is None else engine
        self._clock = clock
        self._locks: weakref.WeakValueDictionary[str, object] = weakref.WeakValueDictionary()
        # Runs halted by this process. Also written to runs.status when the
        # database allows; this set covers the case where it does not.
        self._halted: set[str] = set()
        # The Graph facade for script runs (SD-041): only when the deployment says
        # where a run's approved script manifest comes from. Without it every facade
        # request is refused.
        # Agent sessions (SD-049): the agent-profile catalog. Without it every
        # agent request is refused.
        self._agent_catalog = agent_catalog
        self._facade = None
        if script_manifests is not None:
            from clw.broker.facade.handler import FacadeHandler

            self._facade = FacadeHandler(self, manifests=script_manifests)

    async def handle_facade(self, authorization: object, method: object, raw_target: object,
                            headers: dict[str, str], body_length: int):
        """A Graph-shaped request from a script run (POST /v1/facade, from the facade proxy)."""
        from clw.broker.facade.handler import graph_error

        if self._facade is None:
            return graph_error(403, "Authorization_RequestDenied", "facade_disabled")
        return await self._facade.handle(authorization, method, raw_target, headers, body_length)

    # ------------------------------------------------------------ entry points

    async def handle_request(self, authorization: object, body: bytes | None) -> OpResult:
        """POST /v1/ops: the Authorization header value and the raw body."""
        return await self._serve(parse_authorization(authorization), body, catalog=self._catalog, kind="task")

    async def handle_agent_request(self, authorization: object, body: bytes | None) -> OpResult:
        """POST /v1/agent/ops (SD-049): an agent session's named operation, from the MCP gateway.
        `Authorization: Bearer <session capability>`; the same path as a task's, against the
        session's agent profile."""
        if self._agent_catalog is None:
            return _denied("agent_sessions_disabled")
        return await self._serve(parse_bearer(authorization), body, catalog=self._agent_catalog,
                                 kind="agent_session")

    async def describe_agent_session(self, authorization: object) -> OpResult:
        """POST /v1/agent/session (SD-048): what the gateway checks when an agent connects.
        200 with the session's id, expiry, profile and operations, or the same refusal (and,
        for a known session, the same audit) as an operation would get."""
        if self._agent_catalog is None:
            return _denied("agent_sessions_disabled")
        ctx = await self._resolve(parse_bearer(authorization), catalog=self._agent_catalog, kind="agent_session")
        if not isinstance(ctx, RunContext):
            return ctx if isinstance(ctx, OpResult) else await self._refused(ctx, None)
        return OpResult(200, {"status": "ok", "session": {
            "id": ctx.run_id, "expires_at": to_rfc3339_utc(ctx.deadline_at), "profile": ctx.manifest.id,
            "profile_name": ctx.manifest.name, "operations": list(ctx.manifest.allowed)}})

    async def handle_agent_proposal(self, authorization: object, body: bytes | None) -> OpResult:
        """POST /v1/agent/propose (SD-054): an agent asks for a change. Nothing is ever executed:
        the write is refused (OP_DECISION denied, write_not_executable, naming the proposal and the
        canonical request's hash), the target is looked up by the broker itself for a display
        snapshot, and the proposal is filed for a person to review."""
        if self._agent_catalog is None:
            return _denied("agent_sessions_disabled")
        ctx = await self._resolve(parse_bearer(authorization), catalog=self._agent_catalog, kind="agent_session")
        if isinstance(ctx, RunRefused):
            return await self._refused(ctx, None)
        if isinstance(ctx, OpResult):
            return ctx
        parsed = proposals.parse(body)
        if parsed is None:
            return await self._locked(ctx, lambda: self._deny(ctx, proposals.OPERATION, "invalid_proposal"))
        if proposals.ACTION not in ctx.manifest.proposals:  # the profile decides whether proposals exist at all
            return await self._locked(ctx, lambda: self._deny(ctx, proposals.OPERATION, "proposal_not_in_profile"))
        return await self._locked(ctx, lambda: self._propose(ctx, parsed))

    async def _propose(self, ctx: RunContext, asked: proposals.Asked) -> OpResult:
        async with self._sessionmaker() as session:
            filed = await session.scalar(select(func.count()).select_from(ChangeProposal).where(
                ChangeProposal.session_id == uuid.UUID(ctx.run_id)))
        if filed >= proposals.MAX_PER_SESSION:
            return await self._deny(ctx, proposals.OPERATION, "proposal_limit")
        proposal_id = uuid.uuid4()
        request, digest = proposals.canonical_request(asked.user_id)
        # Write-ahead: the refusal and the binding are in the chain before anything else happens.
        await self._decision(ctx, proposals.OPERATION, "denied",
                             {"proposal_id": str(proposal_id), "request_sha256": digest},
                             reason="write_not_executable")
        # The broker's own lookup, for this target only: policy-checked and audited like any operation,
        # under the session's profile narrowed to the internal lookup (no manifest can list it).
        # The profile's own prohibitions still apply: a profile can forbid the lookup itself.
        narrowed = dataclasses.replace(ctx, manifest=dataclasses.replace(
            ctx.manifest, allowed=(proposals.LOOKUP,), prohibited=ctx.manifest.prohibited))
        looked = await self._operation(narrowed, proposals.LOOKUP, {"user_id": asked.user_id},
                                       tolerate=frozenset({"not_found"}), internal=True)
        if looked.status_code not in (200, 404):
            return looked  # the session has ended or halted; nothing more is filed
        snapshot = proposals.snapshot(looked.body.get("data") if looked.status_code == 200 else None)
        looked_up_at = self._clock()
        try:
            async with self._sessionmaker() as session:
                async with session.begin():
                    session.add(ChangeProposal(
                        id=proposal_id, tenant_id=ctx.tenant_id, session_id=uuid.UUID(ctx.run_id),
                        action=proposals.ACTION, operation=proposals.OPERATION, target_id=asked.user_id,
                        request=request, request_sha256=digest, agent_reason=asked.reason,
                        lookup_status=snapshot.status, target_display_name=snapshot.display_name,
                        target_upn=snapshot.upn, target_account_enabled=snapshot.account_enabled,
                        looked_up_at=looked_up_at))
        except Exception:  # noqa: BLE001 - the chain names the proposal; the row could not be stored
            alert_log.error("broker_proposal_not_stored run_id=%s", ctx.run_id)
            return _error(503, "proposal_not_stored")
        return OpResult(200, proposals.answer(proposal_id, asked, digest, snapshot, looked_up_at))

    async def _resolve(self, token: str | None, *, catalog, kind) -> RunContext | RunRefused | OpResult:
        try:
            async with self._sessionmaker() as session:
                return await resolve_run(session, token, catalog=catalog, now=self._clock(), kind=kind)
        except RunRefused as refused:
            return refused
        except Exception:  # noqa: BLE001 - the run cannot be resolved, so nothing can be authorized
            alert_log.error("broker_run_resolution_failed")
            return _error(503, "broker_unavailable")

    async def _serve(self, token: str | None, body: bytes | None, *, catalog, kind) -> OpResult:
        ctx = await self._resolve(token, catalog=catalog, kind=kind)
        if isinstance(ctx, RunRefused):
            return await self._refused(ctx, body)
        if isinstance(ctx, OpResult):
            return ctx
        parsed = parse_body(body)
        if parsed.reason is not None:
            return await self._locked(ctx, lambda: self._deny(ctx, parsed.label, parsed.reason))
        return await self.handle(ctx, parsed.op, parsed.params)

    async def handle(self, ctx: RunContext, op: object, params: object) -> OpResult:
        if type(ctx) is not RunContext:
            raise ValueError("ctx must be a RunContext from resolve_run")
        return await self._locked(ctx, lambda: self._operation(ctx, op, params))

    # --------------------------------------------------------------- the path

    async def _operation(self, ctx: RunContext, op: object, params: object, *,
                         tolerate: frozenset[str] = frozenset(), internal: bool = False) -> OpResult:
        """The named-operation path. A Graph error whose category is in `tolerate` is
        answered 404 without ending the run (the proposal lookup's not_found, SD-054);
        any other ends it FAILED, as always."""
        label = operation_label(op)
        spec = operations.REGISTRY.get(label)
        if spec is not None and spec.internal_only and not internal:  # the broker's own, whatever a manifest says
            return await self._deny(ctx, label, "not_in_manifest")
        decision, request = evaluate(self._engine, ctx.manifest, op, params)  # type: ignore[arg-type]
        if not decision.allowed:
            return await self._deny(ctx, label, decision.reason)
        approved = request_target(request)
        first = await self._decision(ctx, label, "allowed", {"request_target": approved}, request=request)

        token = await self._acquire(ctx)
        if not isinstance(token, ValidatedToken):
            return token

        attempts = _AttemptAudit(self, ctx, label, op, params, request, approved, first.seq,
                                 await self._last_attempt(ctx))
        try:
            items = await self._transport.execute(
                request, token, deadline=ctx.deadline_at,
                before_attempt=attempts.before, after_attempt=attempts.after,
            )
        except _Reauthorization as denied:
            return _denied(denied.reason)
        except _BindingMismatch:
            return await self._fail(ctx, "request_binding_mismatch", {})
        except GraphError as exc:
            if exc.category in tolerate:  # recorded by the attempt's GRAPH_RESPONSE; the run goes on
                return OpResult(404, {"status": "not_found", "reason": exc.category})
            details = {k: v for k, v in (("http_status", exc.http_status), ("graph_error_code", exc.graph_error_code),
                                         ("graph_request_id", exc.graph_request_id)) if v is not None}
            return await self._fail(ctx, exc.category, details)
        # Only the properties the operation declares leave the broker (SD-053), whatever Graph returned.
        return OpResult(200, {"status": "ok", "data": operations.filter_items(operations.get(label), items)})

    async def _acquire(self, ctx: RunContext) -> ValidatedToken | OpResult:
        token: object = None
        try:
            token = await self._credentials.token_for(tenant_id=ctx.tenant_id, profile=ctx.profile)
            reason = None if type(token) is ValidatedToken else "acquisition_failed"
        except CredentialRejected as rejected:
            reason = rejected.reason
        except Exception:  # noqa: BLE001 - any other failure means no token; detail dropped
            reason = "acquisition_failed"
        profile = {"profile_id": ctx.profile.id, "profile_version": ctx.profile.version, "auth_mode": ctx.profile.mode}
        if reason is not None:
            await self._append(ctx, {"event_type": EventType.CREDENTIAL_REJECTED, "status": "rejected",
                                     "reason": reason, **profile})
            return await self._fail(ctx, reason, {}, client_reason="credential_rejected")
        await self._append(ctx, {"event_type": EventType.CREDENTIAL_ACQUIRED, "status": "accepted", **profile,
                                 "details": {"permissions": sorted(token.permissions)}})  # type: ignore[union-attr]
        return token  # type: ignore[return-value]

    async def _deny(self, run: RunRef | RunContext, label: str, reason: str) -> OpResult:
        await self._decision(run, label, "denied", {}, reason=reason)
        return _denied(reason)

    async def _decision(
        self, run: RunRef | RunContext, label: str, status: str, details: dict, *,
        reason: str | None = None, request: operations.BuiltRequest | None = None,
    ) -> AuditRecord:
        """An allowed decision names the method and template of the approved
        request itself; a denial of a registered operation names the
        registry's, as evidence of what was refused."""
        shape = request if status == "allowed" else operations.REGISTRY.get(label)
        return await self._append(run, {
            "event_type": EventType.OP_DECISION, "status": status, "operation": label,
            "reason": "allowed" if status == "allowed" else reason,
            "http_method": shape.method if shape else None, "path_template": shape.path_template if shape else None,
            "details": details,
        })

    async def _refused(self, refused: RunRefused, body: bytes | None) -> OpResult:
        run = refused.run
        if run is None:  # unknown, revoked, halted or ended: nothing may be added to its chain
            alert_log.warning("broker_run_refused reason=%s", refused.reason)  # never the token
            return _denied(refused.reason, 401 if refused.reason == "run_token_invalid" else 403)
        label = parse_body(body).label

        async def record() -> OpResult:
            result = await self._deny(run, label, refused.reason)
            if refused.reason == "manifest_changed":
                await self._fail(run, "manifest_changed", {}, client_reason="manifest_changed")
            return result

        return await self._locked(run, record)

    # ------------------------------------------------------------- run state

    async def _locked(self, run: RunRef | RunContext, action) -> OpResult:
        lock = self._locks.get(run.run_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[run.run_id] = lock
        async with lock:  # type: ignore[attr-defined]
            if run.run_id in self._halted:
                return _denied("run_halted")
            # The run was resolved before the lock was taken; an operation
            # holding it may have ended or halted the run since. Nothing may
            # be recorded for a run that is no longer running.
            try:
                status = await self._status(run)
            except Exception:  # noqa: BLE001
                alert_log.error("broker_run_status_unreadable run_id=%s", run.run_id)
                return _error(503, "broker_unavailable")
            if status != "running":
                return _denied("run_halted" if status == "halted" else "run_not_running")
            try:
                return await action()
            except AuditUnavailable:
                await self._halt(run, "audit_unavailable")
                return _error(503, "audit_unavailable")
            except Exception:  # noqa: BLE001 - unknown state: stop the run, release nothing
                await self._halt(run, "broker_error")
                return _error(503, "broker_unavailable")
            except BaseException:
                # Cancelled mid-operation: a request may be outstanding. Stop
                # the run here; the database write is left to the reconciler.
                self._halted.add(run.run_id)
                raise

    async def _fail(
        self, run: RunRef | RunContext, reason: str, details: dict, *, client_reason: str | None = None
    ) -> OpResult:
        """End the run FAILED: first the run row (status, outcome, token
        revoked), so no further operation is accepted even if the audit
        write fails; then RUN_FAILED. If the row was no longer running
        (ended or halted elsewhere), no RUN_FAILED is written."""
        if await self._set_status(run, "failed", reason, revoke=True):
            await self._append(run, {"event_type": EventType.RUN_FAILED, "status": "failed", "reason": reason,
                                     "details": details})
        return OpResult(502, {"status": "failed", "reason": client_reason or reason})

    async def _halt(self, run: RunRef | RunContext, reason: str) -> None:
        self._halted.add(run.run_id)
        alert_log.critical("broker_run_halted run_id=%s reason=%s", run.run_id, reason)
        try:
            await self._set_status(run, "halted", reason, revoke=False)
        except Exception:  # noqa: BLE001 - the in-memory halt still applies in this process
            alert_log.critical("broker_run_halt_not_persisted run_id=%s", run.run_id)

    async def _set_status(self, run: RunRef | RunContext, status: str, outcome: str, *, revoke: bool) -> bool:
        values: dict[str, object] = {"status": status, "outcome": outcome, "updated_at": func.now()}
        if revoke:
            values |= {"run_token_sha256": None, "ended_at": func.now()}
        async with self._sessionmaker() as session:
            async with session.begin():
                result = await session.execute(
                    update(Run)
                    .where(Run.id == uuid.UUID(run.run_id), Run.tenant_id == run.tenant_id, Run.status == "running")
                    .values(**values)
                )
        return result.rowcount == 1

    async def _status(self, run: RunRef | RunContext) -> str | None:
        async with self._sessionmaker() as session:
            return await session.scalar(
                select(Run.status).where(Run.id == uuid.UUID(run.run_id), Run.tenant_id == run.tenant_id))

    async def _last_attempt(self, ctx: RunContext) -> int:
        try:
            async with self._sessionmaker() as session:
                last = await session.scalar(
                    select(func.max(AuditEventRow.attempt)).where(
                        AuditEventRow.chain_id == ctx.tenant_id,
                        AuditEventRow.run_id == ctx.run_id,
                        AuditEventRow.event_type == EventType.GRAPH_REQUEST,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            raise AuditUnavailable("attempt history not readable") from exc
        return last or 0

    async def _append(self, run: RunRef | RunContext, event: dict) -> AuditRecord:
        try:
            return await self._writer.append(
                chain_id=run.tenant_id, event={"tenant_id": run.tenant_id, "run_id": run.run_id, **event})
        except AuditUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AuditUnavailable("audit append failed") from exc


class _AttemptAudit:
    """The transport's before/after hooks for one operation."""

    def __init__(self, service: BrokerService, ctx: RunContext, label: str, op: object, params: object,
                 request: operations.BuiltRequest, approved: str, first_decision_seq: int, base: int) -> None:
        self._service, self._ctx, self._label = service, ctx, label
        self._op, self._params, self._request, self._approved = op, params, request, approved
        self._first_decision_seq = first_decision_seq
        self._base = base
        self._last = 0  # the transport's attempt number last announced
        self._open = False

    async def before(self, attempt: GraphAttempt) -> None:
        if (
            type(attempt) is not GraphAttempt
            or self._open
            or attempt.attempt != self._last + 1
            or attempt.method != self._request.method
            or not continues(attempt.request_target, self._approved)
        ):
            raise _BindingMismatch
        number = self._base + attempt.attempt
        if attempt.attempt == 1:
            decision_seq = self._first_decision_seq
        else:
            decision, rebuilt = evaluate(self._service._engine, self._ctx.manifest, self._op, self._params)  # type: ignore[arg-type]
            if not decision.allowed or rebuilt != self._request:
                reason = decision.reason if not decision.allowed else "request_changed"
                await self._service._decision(self._ctx, self._label, "denied", {"for_attempt": number}, reason=reason)
                raise _Reauthorization(reason)
            record = await self._service._decision(
                self._ctx, self._label, "allowed", {"request_target": self._approved, "for_attempt": number},
                request=rebuilt)
            decision_seq = record.seq
        await self._service._append(self._ctx, {
            "event_type": EventType.GRAPH_REQUEST, "status": "attempted", "operation": self._label,
            "decision_seq": decision_seq, "http_method": self._request.method,
            "path_template": self._request.path_template, "request_target": attempt.request_target,
            "attempt": number,
        })
        self._last, self._open = attempt.attempt, True

    async def after(self, attempt: GraphAttempt) -> None:
        if type(attempt) is not GraphAttempt or not self._open or attempt.attempt != self._last:
            raise _BindingMismatch
        await self._service._append(self._ctx, {
            "event_type": EventType.GRAPH_RESPONSE, "operation": self._label,
            "attempt": self._base + attempt.attempt, **response_fields(attempt),
        })
        self._open = False


def _denied(reason: str, status_code: int = 403) -> OpResult:
    return OpResult(status_code, {"status": "denied", "reason": reason})


def _error(status_code: int, reason: str) -> OpResult:
    return OpResult(status_code, {"status": "error", "reason": reason})
