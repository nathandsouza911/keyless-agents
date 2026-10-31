"""Server-rendered pages for agent sessions and change proposals (v0.1; SD-049, SD-054; SD-045's rules).

    GET  /ui/sessions                  start a session (choose a profile and a lifetime); the tenant's sessions
    POST /ui/sessions                  start one: the capability is shown once, on the page that answers
    GET  /ui/sessions/{id}             the session: its audit trail from the chain, its proposals; revoke
    POST /ui/sessions/{id}/revoke      revoke it (its starter or a security lead)
    GET  /ui/proposals                 the tenant's change proposals (filed, never executed in v0.1)

Each action calls the JSON route's own function, so every check is the
API's. Proposals are shown effect first: the Graph change derived from the
stored canonical request (operation, object type, count, object ID). Then,
clearly labelled and escaped, the broker's lookup of the target (tenant data,
which may be written to mislead) and the agent's reason (agent text). The
agent's words never head anything. The page also re-checks the binding: the
stored request must hash to the stored digest, and the session's audit chain
must name the same proposal with the same digest.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select

from clw.api.routes import agent_sessions as session_routes
from clw.api.routes import runs as runs_routes
from clw.api.runtime import get_agent_catalog, get_sessionmaker, get_writer
from clw.api.deps import current_session
from clw.api.ui.pages import _error, _form, _post_guard, _principal, _render, _see_other
from clw.audit.canonical import canonical_json
from clw.audit.events import EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.broker import proposals
from clw.common.timeutil import to_rfc3339_utc
from clw.db.models.proposal import ChangeProposal
from clw.db.models.run import Run

router = APIRouter(prefix="/ui")

TTL_CHOICES = (15, 60, 240, 480)
DEFAULT_MCP_URL = "http://127.0.0.1:8090/mcp"  # the gateway as compose publishes it
NOT_FOUND_WARNING = ("No user with this ID was found when the proposal was filed. It may not exist, or it may be "
                     "another kind of object (a group or an app). Check the ID before acting on this proposal.")


def _session_view(row: Run) -> dict:
    return {"id": str(row.id), "profile": row.task_id, "status": row.status, "outcome": row.outcome,
            "started_at": to_rfc3339_utc(row.started_at) if row.started_at else None,
            "expires_at": to_rfc3339_utc(row.deadline_at) if row.deadline_at else None,
            "ended_at": to_rfc3339_utc(row.ended_at) if row.ended_at else None, "actor_oid": row.actor_oid}


def _bindings(records) -> dict[str, tuple[str, str]]:
    """proposal id -> (the session it was refused in, the request hash the chain recorded)."""
    found: dict[str, tuple[str, str]] = {}
    for r in records:
        details = r.details if isinstance(r.details, dict) else {}
        if r.event_type == EventType.OP_DECISION and r.operation == "users.update" and "proposal_id" in details:
            found[str(details["proposal_id"])] = (str(r.run_id), str(details.get("request_sha256")))
    return found


def visible(text: str | None) -> str | None:
    """Tenant data and agent text with every invisible or direction-changing character shown as [U+XXXX]
    (review F6): a right-to-left override or a zero-width space must not disguise a name."""
    if text is None:
        return None
    return "".join(f"[U+{ord(c):04X}]" if unicodedata.category(c) in ("Cc", "Cf", "Co", "Cs", "Zl", "Zp")
                   and c not in "\t" else c for c in text)


def _proposal_view(p: ChangeProposal, chain: dict[str, tuple[str, str]]) -> dict:
    recomputed = hashlib.sha256(canonical_json(p.request)).hexdigest()
    session, in_chain = chain.get(str(p.id), (None, None))
    expected = proposals.canonical_request(p.target_id)[0]  # the request the shown object ID implies
    binding_ok = (recomputed == p.request_sha256 == in_chain and p.request == expected
                  and session == str(p.session_id))
    return {
        "id": str(p.id), "session_id": str(p.session_id), "created_at": to_rfc3339_utc(p.created_at),
        "method": p.request.get("method"), "path": p.request.get("path"),
        "change": json.dumps(p.request.get("body"), sort_keys=True), "target_id": p.target_id,
        "found": p.lookup_status == "found", "warning": NOT_FOUND_WARNING,
        "display_name": visible(p.target_display_name), "upn": visible(p.target_upn),
        "account_enabled": p.target_account_enabled, "looked_up_at": to_rfc3339_utc(p.looked_up_at),
        "reason": visible(p.agent_reason), "request_sha256": p.request_sha256,
        "binding_ok": binding_ok,
        "binding_detail": ("the request is for the object ID shown, hashes to the stored digest, and the session's "
                           "audit chain records the same" if binding_ok else
                           "the audit chain does not record this proposal" if in_chain is None else
                           "the request does not match the object ID shown" if p.request != expected else
                           "the stored request, its digest and the audit chain disagree"),
    }


async def _proposals(sessionmaker, tid: str, session_id: uuid.UUID | None = None) -> list[dict]:
    async with sessionmaker() as session:
        query = select(ChangeProposal).where(ChangeProposal.tenant_id == tid)
        if session_id is not None:
            query = query.where(ChangeProposal.session_id == session_id)
        rows = (await session.execute(query.order_by(ChangeProposal.created_at.desc()).limit(100))).scalars().all()
        records = await load_chain(session, chain_id=tid) if rows else []
    hashes = _bindings(records)
    return [_proposal_view(p, hashes) for p in rows]


@router.get("/sessions", name="ui_sessions")
async def sessions_page(request: Request, sessionmaker=Depends(get_sessionmaker),
                        agent_catalog=Depends(get_agent_catalog)) -> HTMLResponse:
    principal = await _principal(request)
    if principal is None:
        return _render("signin.html")
    async with sessionmaker() as session:
        rows = (await session.execute(
            select(Run).where(Run.tenant_id == principal.tid, Run.kind == "agent_session")
            .order_by(Run.created_at.desc()).limit(50))).scalars().all()
    profiles = [{"id": m.id, "name": m.name, "purpose": m.purpose, "operations": list(m.allowed)}
                for m in sorted(agent_catalog.values(), key=lambda m: m.id) if principal.role in m.start_roles]
    return _render("sessions.html", principal=principal, profiles=profiles, ttls=TTL_CHOICES,
                   sessions=[_session_view(r) for r in rows])


@router.post("/sessions", name="ui_sessions_start")
async def start(request: Request, sessionmaker=Depends(get_sessionmaker), writer=Depends(get_writer),
                agent_catalog=Depends(get_agent_catalog)):
    principal, refused = await _post_guard(request, ("analyst", "security_lead"))
    if refused:
        return refused
    form = await _form(request)
    if form is None or set(form) != {"profile", "ttl_minutes"} or not form["ttl_minutes"].isdigit():
        return _error(422, "invalid_request", principal)
    try:
        body = session_routes.StartBody(profile=form["profile"], ttl_minutes=int(form["ttl_minutes"]))
        reply = await session_routes.start_session(body, principal=principal, agent_catalog=agent_catalog,
                                                   sessionmaker=sessionmaker, writer=writer,
                                                   claims=await current_session(request))
    except HTTPException as exc:
        if exc.detail == "fresh_sign_in_required":
            return _render("reauth.html", status=401, principal=principal,
                           sign_in=("/ui/demo-signin" if request.app.state.demo_mode else "/auth/microsoft/start"),
                           minutes=session_routes.FRESH_SIGN_IN_SECONDS // 60)
        return _error(exc.status_code, exc.detail, principal)
    except ValueError:
        return _error(422, "invalid_request", principal)
    started = json.loads(reply.body)
    return _render("session_started.html", principal=principal, started=started,
                   mcp_url=getattr(request.app.state, "mcp_public_url", DEFAULT_MCP_URL))


@router.get("/sessions/{session_id}", name="ui_session")
async def session_page(session_id: str, request: Request, sessionmaker=Depends(get_sessionmaker)) -> HTMLResponse:
    principal = await _principal(request)
    if principal is None:
        return _render("signin.html")
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        return _error(404, "session_not_found", principal)
    async with sessionmaker() as session:
        row = (await session.execute(select(Run).where(
            Run.id == sid, Run.tenant_id == principal.tid, Run.kind == "agent_session"))).scalar_one_or_none()
    if row is None:
        return _error(404, "session_not_found", principal)
    audit = await runs_routes.get_run_audit(str(sid), principal=principal, sessionmaker=sessionmaker)
    return _render("session.html", principal=principal, session=_session_view(row), audit=audit,
                   proposals=await _proposals(sessionmaker, principal.tid, sid),
                   can_revoke=row.status == "running" and (row.actor_oid == principal.oid
                                                           or principal.role == "security_lead"))


@router.post("/sessions/{session_id}/revoke", name="ui_session_revoke")
async def revoke(session_id: str, request: Request, sessionmaker=Depends(get_sessionmaker),
                 writer=Depends(get_writer)):
    principal, refused = await _post_guard(request, ("analyst", "security_lead"))
    if refused:
        return refused
    try:
        await session_routes.revoke_session(session_id, principal=principal, sessionmaker=sessionmaker, writer=writer)
    except HTTPException as exc:
        return _error(exc.status_code, exc.detail, principal)
    return _see_other(f"/ui/sessions/{uuid.UUID(session_id)}")


@router.get("/proposals", name="ui_proposals")
async def proposals_page(request: Request, sessionmaker=Depends(get_sessionmaker)) -> HTMLResponse:
    principal = await _principal(request)
    if principal is None:
        return _render("signin.html")
    async with sessionmaker() as session:
        report = await verify_chain(session, chain_id=principal.tid)
        total = await session.scalar(select(func.count()).select_from(ChangeProposal).where(
            ChangeProposal.tenant_id == principal.tid))
    return _render("proposals.html", principal=principal, proposals=await _proposals(sessionmaker, principal.tid),
                   chain_valid=report.valid, total=total)
