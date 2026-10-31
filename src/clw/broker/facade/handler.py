"""The facade's request path inside the broker (SD-041).

    Bearer capability -> script run (database) -> approved script manifest
    canonicalize(raw request)                -> refused: OP_DECISION denied, 403
    continuation ($skiptoken=clw_<handle>)   -> the stored continuation, and the
                                                ORIGINAL approved request
                                                re-authorized against the manifest
    or a first request                       -> evaluate against the manifest
    OP_DECISION allowed (committed)          details.request_target = the approved
                                                canonical target (RR-5, SD-039), its
                                                $filter/$search values keyed-hashed
                                                (SD-042)
    credentials (exact-set check)            -> CREDENTIAL_ACQUIRED | REJECTED
    per attempt: GRAPH_REQUEST (committed) -> Graph -> GRAPH_RESPONSE (committed)
    a page with a nextLink                   -> validated, held under a new handle
    the body, nextLink rewritten             -> back to the script

It runs under the broker's per-run lock and uses the broker's own audit,
credential, fail and halt paths, so the named-operation path and this one
cannot diverge on fail-closed behaviour: an audit failure halts the run
(503), a credential or Graph execution failure ends it FAILED (502), and
nothing from a response is returned unless its GRAPH_RESPONSE was committed.

What the script receives: Graph's own response (200 with its body, or a final
Graph error with its body) or, for anything Cloud Locksmith refuses, a
Graph-shaped error `{"error": {"code": ..., "message": "Cloud Locksmith: ...",
"innerError": {"clw-reason": ...}}}`. A denied request is recorded with its
method, its path (bounded) and the reason, never its query text.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from clw.audit.events import AuditUnavailable, EventType, continues_approved_target
from clw.broker.capability import RunRefused
from clw.broker.credentials import ValidatedToken
from clw.broker.facade.canonical import FacadeRequest, Refused, canonicalize
from clw.broker.facade.hashing import ValueKey, ValueKeys, audit_target
from clw.broker.facade.pages import Continuation, PageHandles, next_target, rewrite_next_link
from clw.broker.facade.policy import FacadeDecision, evaluate
from clw.broker.facade.runs import ManifestLookup, ScriptRunContext, parse_bearer, resolve_script_run
from clw.broker.transport import GraphAttempt, GraphError

if TYPE_CHECKING:  # pragma: no cover
    from clw.broker.service import BrokerService, OpResult

alert_log = logging.getLogger("clw.broker.alert")

FACADE_OPERATION = "facade"
MAX_RECORDED_PATH = 256


@dataclass(frozen=True, slots=True)
class FacadeReply:
    status_code: int
    body: bytes = field(repr=False)
    graph_request_id: str | None = None


def graph_error(status: int, code: str, reason: str) -> FacadeReply:
    body = {"error": {"code": code, "message": f"Cloud Locksmith: {reason}", "innerError": {"clw-reason": reason}}}
    return FacadeReply(status, json.dumps(body, separators=(",", ":")).encode())


def denied(reason: str, parameter: str | None = None) -> FacadeReply:
    if parameter is None:
        return graph_error(403, "Authorization_RequestDenied", reason)
    body = {"error": {"code": "Authorization_RequestDenied",
                      "message": f"Cloud Locksmith: {reason}: {parameter}",
                      "innerError": {"clw-reason": reason, "clw-parameter": parameter}}}
    return FacadeReply(403, json.dumps(body, separators=(",", ":")).encode())


def _from_op_result(result: OpResult) -> FacadeReply:
    """The broker's own refusal (halted, not running, audit or credential failure) as a Graph error."""
    reason = str(result.body.get("reason", "broker_error"))
    if result.status_code in (401, 403):
        return graph_error(result.status_code, "Authorization_RequestDenied", reason)
    return graph_error(result.status_code, "serviceNotAvailable" if result.status_code == 503 else "generalException",
                       reason)


def _recorded_path(raw_target: object) -> str:
    path = raw_target.partition("?")[0] if isinstance(raw_target, str) else ""
    shown = "".join(c if 0x21 <= ord(c) <= 0x7e else "?" for c in path)
    return shown[:MAX_RECORDED_PATH] or "(none)"


class _BindingMismatch(Exception):
    pass


class _Reauthorization(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class FacadeHandler:
    def __init__(self, service: BrokerService, *, manifests: ManifestLookup, pages: PageHandles | None = None) -> None:
        self._service = service
        self._manifests = manifests
        self._pages = pages or PageHandles()
        self._keys = ValueKeys()

    async def handle(self, authorization: object, method: object, raw_target: object, headers: dict[str, str],
                     body_length: int) -> FacadeReply:
        svc = self._service
        token = parse_bearer(authorization)
        try:
            async with svc._sessionmaker() as session:
                ctx = await resolve_script_run(session, token, manifests=self._manifests, now=svc._clock())
        except RunRefused as refused:
            if refused.run is None:
                return graph_error(401 if refused.reason == "run_token_invalid" else 403,
                                   "InvalidAuthenticationToken" if refused.reason == "run_token_invalid"
                                   else "Authorization_RequestDenied", refused.reason)
            run = refused.run

            async def record() -> FacadeReply:
                await self._deny(run, refused.reason, method, raw_target)
                return denied(refused.reason)
            return await self._guarded(run, record)
        except Exception:  # noqa: BLE001 - the run cannot be resolved, so nothing can be authorized
            alert_log.error("facade_run_resolution_failed")
            return graph_error(503, "serviceNotAvailable", "broker_unavailable")
        return await self._guarded(ctx, lambda: self._request(ctx, method, raw_target, headers, body_length))

    async def _guarded(self, run, action) -> FacadeReply:
        result = await self._service._locked(run, action)
        return result if isinstance(result, FacadeReply) else _from_op_result(result)

    async def _deny(self, run, reason: str, method: object, raw_target: object, parameter: str | None = None) -> None:
        shown = method if isinstance(method, str) and method.isascii() and method.isalpha() else "(invalid)"
        details = {"method": shown[:16], "path": _recorded_path(raw_target)}
        if parameter is not None:
            details["parameter"] = parameter  # its name only, never its value (D1)
        await self._service._append(run, {
            "event_type": EventType.OP_DECISION, "status": "denied", "operation": FACADE_OPERATION, "reason": reason,
            "details": details,
        })

    async def _request(self, ctx: ScriptRunContext, method, raw_target, headers, body_length) -> FacadeReply:
        svc = self._service
        request = canonicalize(method, raw_target, headers, body_length)
        if isinstance(request, Refused):
            await self._deny(ctx, request.reason, method, raw_target, request.parameter)
            return denied(request.reason, request.parameter)

        continuation = None
        handle = request.option("$skiptoken")
        if handle is not None:
            if {name for name, _ in request.options} != {"$skiptoken"}:
                await self._deny(ctx, "continuation_tampered", method, raw_target)
                return denied("continuation_tampered")
            continuation = self._pages.take(handle, run_id=ctx.run_id, now=svc._clock())
            if continuation is None or request.target(without=frozenset({"$skiptoken"})) != \
                    continuation.approved_target.partition("?")[0]:
                await self._deny(ctx, "continuation_invalid", method, raw_target)
                return denied("continuation_invalid")
            original = canonicalize("GET", continuation.approved_target, dict(continuation.headers), 0)
            decision = evaluate(ctx.manifest, original) if isinstance(original, FacadeRequest) else None
            if decision is None or not decision.allowed or decision.target != continuation.approved_target:
                reason = decision.reason if decision is not None and not decision.allowed else "request_changed"
                await self._deny(ctx, reason, method, raw_target)
                return denied(reason)
            upstream, forwarded = continuation.upstream_target, continuation.headers
        else:
            decision = evaluate(ctx.manifest, request)
            if not decision.allowed:
                await self._deny(ctx, decision.reason, method, raw_target)
                return denied(decision.reason)
            original = request
            upstream, forwarded = decision.target, request.headers

        label = f"{FACADE_OPERATION}.{decision.entry.id}"
        try:
            key = await self._keys.get(svc._sessionmaker, ctx.tenant_id)
        except Exception as exc:  # noqa: BLE001 - without the key nothing can be recorded safely: fail closed
            raise AuditUnavailable("audit value key unavailable") from exc
        first = await self._decision(ctx, label, decision, key, continuation=continuation is not None)
        token = await svc._acquire(ctx)
        if not isinstance(token, ValidatedToken):
            return _from_op_result(token)

        attempts = _FacadeAttempts(self, ctx, label, decision, original, first.seq, await svc._last_attempt(ctx), key)
        try:
            page = await svc._transport.fetch_target(
                upstream, template=decision.path_template, headers=forwarded, token=token, deadline=ctx.deadline_at,
                before_attempt=attempts.before, after_attempt=attempts.after)
        except _Reauthorization as refused:
            return denied(refused.reason)
        except _BindingMismatch:
            return _from_op_result(await svc._fail(ctx, "request_binding_mismatch", {}))
        except GraphError as exc:
            details = {k: v for k, v in (("http_status", exc.http_status), ("graph_request_id", exc.graph_request_id))
                       if v is not None}
            return _from_op_result(await svc._fail(ctx, exc.category, details))

        body = page.body
        if page.http_status == 200 and page.next_link is not None:
            following = next_target(page.next_link, approved_target=decision.target, template=decision.path_template)
            new_handle = None if following is None else self._pages.issue(Continuation(
                run_id=ctx.run_id, approved_target=decision.target, upstream_target=following,
                template=decision.path_template, entry_id=decision.entry.id, headers=forwarded,
                expires_at=ctx.deadline_at))
            if new_handle is None:
                reason = "invalid_next_link" if following is None else "page_cap"
                return _from_op_result(await svc._fail(ctx, reason, {}))
            body = rewrite_next_link(body, approved_target=decision.target, handle=new_handle)
        return FacadeReply(page.http_status, body, page.graph_request_id)

    async def _decision(self, ctx, label: str, decision: FacadeDecision, key: ValueKey, *, continuation=False,
                        for_attempt: int | None = None):
        details: dict[str, object] = {"request_target": audit_target(decision.target, key), "entry": decision.entry.id}
        if continuation:
            details["continuation"] = True
        if for_attempt is not None:
            details["for_attempt"] = for_attempt
        return await self._service._append(ctx, {
            "event_type": EventType.OP_DECISION, "status": "allowed", "operation": label, "reason": "allowed",
            "http_method": "GET", "path_template": decision.path_template, "details": details,
        })


class _FacadeAttempts:
    """The transport's before/after hooks for one facade request: attempt 1 cites
    the request's decision; a retry is re-authorized and gets its own (SD-014)."""

    def __init__(self, handler: FacadeHandler, ctx, label, decision: FacadeDecision, original: FacadeRequest,
                 first_seq: int, base: int, key: ValueKey) -> None:
        self._h, self._ctx, self._label, self._decision, self._original = handler, ctx, label, decision, original
        self._first_seq, self._base, self._key = first_seq, base, key
        self._last, self._open = 0, False

    async def before(self, attempt: GraphAttempt) -> None:
        if (type(attempt) is not GraphAttempt or self._open or attempt.attempt != self._last + 1
                or attempt.method != "GET" or not continues_approved_target(attempt.request_target,
                                                                            self._decision.target)):
            raise _BindingMismatch
        number = self._base + attempt.attempt
        if attempt.attempt == 1:
            decision_seq = self._first_seq
        else:
            again = evaluate(self._ctx.manifest, self._original)
            if not again.allowed or again.target != self._decision.target:
                reason = again.reason if not again.allowed else "request_changed"
                await self._h._service._append(self._ctx, {
                    "event_type": EventType.OP_DECISION, "status": "denied", "operation": self._label,
                    "reason": reason, "details": {"for_attempt": number}})
                raise _Reauthorization(reason)
            decision_seq = (await self._h._decision(self._ctx, self._label, again, self._key, for_attempt=number)).seq
        await self._h._service._append(self._ctx, {
            "event_type": EventType.GRAPH_REQUEST, "status": "attempted", "operation": self._label,
            "decision_seq": decision_seq, "http_method": "GET", "path_template": self._decision.path_template,
            "request_target": audit_target(attempt.request_target, self._key), "attempt": number,
        })
        self._last, self._open = attempt.attempt, True

    async def after(self, attempt: GraphAttempt) -> None:
        from clw.broker.service import response_fields

        if type(attempt) is not GraphAttempt or not self._open or attempt.attempt != self._last:
            raise _BindingMismatch
        await self._h._service._append(self._ctx, {
            "event_type": EventType.GRAPH_RESPONSE, "operation": self._label,
            "attempt": self._base + attempt.attempt, **response_fields(attempt),
        })
        self._open = False
