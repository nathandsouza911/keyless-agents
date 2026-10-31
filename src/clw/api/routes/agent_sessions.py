"""Agent sessions (v0.1; SD-048, SD-049): a person starts and ends an AI agent's session.

    POST   /v1/agent-sessions        {"profile": "<agent profile id>", "ttl_minutes": 1-480 (default 60)}
    201 {"id", "profile", "expires_at", "capability"}   the capability is shown here once
    DELETE /v1/agent-sessions/{id}   the session's own starter, or a security lead of the tenant
    200 {"id", "status": "revoked", "audited": true | false}

Both need the browser session cookie: a verified human sign-in (SD-029). The
tenant and the actor come from that session only, never the request; the
profile is chosen explicitly from the agent-profile catalog, never defaulted.

Starting is write-ahead audited: the row (through clw_start_agent_session,
SD-049), RUN_REQUESTED and RUN_STARTED are written in one transaction, and the
capability is returned only after it commits. If either record cannot be
written, the row is rolled back and no capability exists. The capability is
256 random bits; only its SHA-256 is stored, and it is never logged.

Revoking ends the row through clw_end_agent_session (agent sessions of this
tenant only) and records RUN_COMPLETED / revoked. If a Graph request of the
session is still unanswered, the chain refuses a completion, so it ends
RUN_FAILED / revoked_during_request instead. If no record can be written at
all, the token is still revoked (the row alone, as the runner's lifecycle
does) and the response says `"audited": false`; an operator alert is logged.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from collections.abc import Mapping

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from clw.api.deps import Principal, current_principal, current_session
from clw.api.runtime import get_agent_catalog, get_sessionmaker, get_writer
from clw.audit.chain import result_sha256
from clw.audit.events import AuditRunStateRefused, AuditUnavailable, EventType
from clw.auth.session_jwt import SessionClaims
from clw.broker.capability import issue_run_token
from clw.broker.manifest import TaskManifest
from clw.common.timeutil import to_rfc3339_utc
from clw.db.models.run import Run

router = APIRouter(prefix="/v1/agent-sessions", tags=["agent-sessions"])
alert_log = logging.getLogger("clw.api.alert")

# Starting a session needs a workbench sign-in this recent (SD-055, review F1): every Microsoft sign-in is
# interactive (prompt=login), so an agent driving a browser on an 8-hour cookie cannot mint sessions.
FRESH_SIGN_IN_SECONDS = 10 * 60
DEFAULT_TTL_MINUTES = 60
MAX_TTL_MINUTES = 8 * 60
REVOKED_RESULT = {"session": "revoked"}  # what clw_end_agent_session stores
_NO_STORE = {"Cache-Control": "no-store"}


class StartBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    profile: str = Field(min_length=1, max_length=64)
    ttl_minutes: int = Field(default=DEFAULT_TTL_MINUTES, ge=1, le=MAX_TTL_MINUTES)


async def json_from_this_origin(request: Request) -> None:
    """A cookie-authenticated, state-changing JSON route: refuse another origin, and (for POST) anything
    but application/json, which a cross-site form or a no-preflight fetch cannot send (review F4)."""
    origin = request.headers.get("origin")
    if origin is not None and origin != f"{request.url.scheme}://{request.url.netloc}":
        raise HTTPException(status_code=403, detail="cross_origin_refused")
    if request.method == "POST" and \
            request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise HTTPException(status_code=415, detail="json_required")


@router.post("", name="agent_sessions_start", status_code=201, dependencies=[Depends(json_from_this_origin)])
async def start_session(
    body: StartBody,
    principal: Principal = Depends(current_principal),
    agent_catalog: Mapping[str, TaskManifest] = Depends(get_agent_catalog),
    sessionmaker=Depends(get_sessionmaker),
    writer=Depends(get_writer),
    claims: SessionClaims = Depends(current_session),
) -> JSONResponse:
    if not 0 <= int(time.time()) - claims.issued_at <= FRESH_SIGN_IN_SECONDS:
        raise HTTPException(status_code=401, detail="fresh_sign_in_required")
    manifest = agent_catalog.get(body.profile)
    if manifest is None:
        raise HTTPException(status_code=404, detail="profile_not_found")
    if principal.role not in manifest.start_roles:  # SD-055: the profile names who may start it
        raise HTTPException(status_code=403, detail="role_not_allowed")
    session_id, issued = uuid.uuid4(), issue_run_token()
    ttl_seconds = body.ttl_minutes * 60
    rid = str(session_id)
    try:
        async with sessionmaker() as session:
            async with session.begin():
                deadline = await session.scalar(
                    text("SELECT clw_start_agent_session(:id, :tid, :task, :msha, :pid, :pver, :psha, :mode, "
                         ":uid, :oid, :token, :ttl)"),
                    {"id": session_id, "tid": principal.tid, "task": manifest.id, "msha": manifest.sha256,
                     "pid": manifest.profile.id, "pver": manifest.profile.version, "psha": manifest.profile.sha256,
                     "mode": manifest.mode, "uid": principal.user_id, "oid": principal.oid,
                     "token": issued.sha256, "ttl": ttl_seconds})
                await writer.append(chain_id=principal.tid, event={
                    "tenant_id": principal.tid, "event_type": EventType.RUN_REQUESTED, "status": "requested",
                    "run_id": rid, "task_id": manifest.id, "task_manifest_sha256": manifest.sha256,
                    "actor_oid": principal.oid, "actor_tid": principal.tid})
                await writer.append(chain_id=principal.tid, event={
                    "tenant_id": principal.tid, "event_type": EventType.RUN_STARTED, "status": "started",
                    "run_id": rid, "task_id": manifest.id, "task_manifest_sha256": manifest.sha256,
                    "profile_id": manifest.profile.id, "profile_version": manifest.profile.version,
                    "auth_mode": manifest.mode, "details": {
                        "kind": "agent_session", "ttl_seconds": ttl_seconds,
                        "signed_in_at": to_rfc3339_utc(datetime.fromtimestamp(claims.issued_at, timezone.utc))}})
    except AuditUnavailable:
        # Nothing committed: the row rolled back, and the capability is discarded unseen.
        raise HTTPException(status_code=503, detail="audit_unavailable") from None
    except DBAPIError:
        # The actor is no longer a member of the tenant, or the tenant is gone.
        raise HTTPException(status_code=403, detail="access_denied") from None
    return JSONResponse({"id": rid, "profile": manifest.id, "expires_at": to_rfc3339_utc(deadline),
                         "capability": issued.token}, status_code=201, headers=_NO_STORE)


def _session_uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status_code=404, detail="session_not_found") from None


async def _end(sessionmaker, writer, session_id: uuid.UUID, tid: str, status: str, outcome: str, *,
               record: bool) -> bool:
    """End the row and (if `record`) write its terminal record, in one transaction."""
    async with sessionmaker() as session:
        async with session.begin():
            ended = await session.scalar(text("SELECT clw_end_agent_session(:id, :tid, :status, :outcome)"),
                                         {"id": session_id, "tid": tid, "status": status, "outcome": outcome})
            if ended and record:
                event = {"tenant_id": tid, "run_id": str(session_id), "status": status}
                if status == "completed":
                    event |= {"event_type": EventType.RUN_COMPLETED, "outcome": outcome,
                              "details": {"result_sha256": result_sha256(REVOKED_RESULT)}}
                else:
                    event |= {"event_type": EventType.RUN_FAILED, "reason": outcome}
                await writer.append(chain_id=tid, event=event)
    return bool(ended)


async def end_sessions_started_by(sessionmaker, writer, tid: str, oid: str) -> int:
    """Signing out ends the person's own running agent sessions (review F2, SD-055): revoked and recorded,
    or revoked row-only if the record cannot be written. The number ended."""
    async with sessionmaker() as session:
        ids = (await session.execute(select(Run.id).where(
            Run.tenant_id == tid, Run.actor_oid == oid, Run.kind == "agent_session", Run.status == "running"))).scalars()
        ids = list(ids)
    ended = 0
    for sid in ids:
        try:
            try:
                done = await _end(sessionmaker, writer, sid, tid, "completed", "revoked", record=True)
            except AuditRunStateRefused as exc:
                if exc.reason != "outstanding_requests":
                    raise
                done = await _end(sessionmaker, writer, sid, tid, "failed", "revoked_during_request", record=True)
        except AuditUnavailable:
            alert_log.critical("api_session_end_not_recorded run_id=%s", sid)
            done = await _end(sessionmaker, writer, sid, tid, "completed", "revoked", record=False)
        ended += bool(done)
    return ended


@router.delete("/{session_id}", name="agent_sessions_revoke", dependencies=[Depends(json_from_this_origin)])
async def revoke_session(
    session_id: str,
    principal: Principal = Depends(current_principal),
    sessionmaker=Depends(get_sessionmaker),
    writer=Depends(get_writer),
) -> JSONResponse:
    sid = _session_uuid(session_id)
    async with sessionmaker() as session:
        row = (await session.execute(select(Run.actor_oid, Run.status).where(
            Run.id == sid, Run.tenant_id == principal.tid, Run.kind == "agent_session"))).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="session_not_found")
    if row.actor_oid != principal.oid and principal.role != "security_lead":
        raise HTTPException(status_code=403, detail="not_your_session")
    if row.status != "running":
        raise HTTPException(status_code=409, detail="session_not_running")
    audited = True
    try:
        try:
            ended = await _end(sessionmaker, writer, sid, principal.tid, "completed", "revoked", record=True)
        except AuditRunStateRefused as exc:
            if exc.reason != "outstanding_requests":
                raise
            ended = await _end(sessionmaker, writer, sid, principal.tid, "failed", "revoked_during_request",
                               record=True)
    except AuditUnavailable:
        # Revoke the token regardless; the chain lacks the terminal record (an operator alert).
        alert_log.critical("api_session_end_not_recorded run_id=%s", sid)
        audited = False
        ended = await _end(sessionmaker, writer, sid, principal.tid, "completed", "revoked", record=False)
    if not ended:
        raise HTTPException(status_code=409, detail="session_not_running")
    return JSONResponse({"id": str(sid), "status": "revoked", "audited": audited}, headers=_NO_STORE)
