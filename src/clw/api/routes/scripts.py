"""Bring-your-own scripts: submission, analysis view, approval (Part B, M4; SD-043).

    POST /scripts                       submit a script's text (analyst, security lead)
    GET  /scripts/{sha256}              the script, its analysis (summary, risk flags,
                                        proposed manifest) and its approvals
    POST /scripts/{sha256}/approvals    approve one manifest for it (security lead only;
                                        never the script's submitter)

Everything is the caller's tenant's (from the session), never a tenant in the
request. A script is identified by the SHA-256 of its UTF-8 text: editing it
makes a new script, with no analysis and no approval. Submitting the same
text again returns the stored script.

Write-ahead, as for runs (SD-034): the rows and the audit record commit
together, and an audit failure rolls the rows back (503).
SCRIPT_SUBMITTED, MANIFEST_APPROVED (and, from the runner, SCRIPT_ANALYZED)
are the tenant chain's evidence (SD-040). The approval rules are enforced
three times: here (clear errors), by the database's insert guard on
script_approvals whatever the caller, and checked again by the chain verifier.
"""

from __future__ import annotations

import hashlib
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError

from clw.api.deps import Principal, require_role
from clw.api.runtime import get_sessionmaker, get_writer
from clw.audit.events import AuditUnavailable, EventType
from clw.broker.facade.rules import ManifestRefused, load_script_manifest
from clw.common.timeutil import to_rfc3339_utc
from clw.db.models.script import Script, ScriptAnalysis, ScriptApproval

router = APIRouter(prefix="/scripts")

MAX_SCRIPT_BYTES = 256 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class SubmitBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    text: str = Field(min_length=1)


class ApproveBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    manifest: dict


def _sha(value: str) -> str:
    if not _SHA.match(value):
        raise HTTPException(status_code=404, detail="script_not_found")
    return value


def _dt(value):
    return to_rfc3339_utc(value) if value is not None else None


async def _script(session, tenant_id: str, sha256: str) -> Script | None:
    return (await session.execute(select(Script).where(Script.tenant_id == tenant_id, Script.sha256 == sha256))
            ).scalar_one_or_none()


@router.post("", name="scripts_submit", status_code=201)
async def submit(body: SubmitBody, principal: Principal = Depends(require_role("analyst", "security_lead")),
                 sessionmaker=Depends(get_sessionmaker), writer=Depends(get_writer)) -> dict:
    raw = body.text.encode("utf-8")
    if len(raw) > MAX_SCRIPT_BYTES:
        raise HTTPException(status_code=413, detail="script_too_large")
    sha256 = hashlib.sha256(raw).hexdigest()
    async with sessionmaker() as session:
        existing = await _script(session, principal.tid, sha256)
    if existing is not None:
        return {"sha256": sha256, "created": False}
    script_id, analysis_id = uuid.uuid4(), uuid.uuid4()
    try:
        async with sessionmaker() as session:
            async with session.begin():
                await session.execute(insert(Script).values(
                    id=script_id, tenant_id=principal.tid, sha256=sha256, text=body.text,
                    submitted_by=principal.user_id))
                await session.execute(insert(ScriptAnalysis).values(
                    id=analysis_id, script_id=script_id, tenant_id=principal.tid, status="queued"))
                await writer.append(chain_id=principal.tid, event={
                    "tenant_id": principal.tid, "event_type": EventType.SCRIPT_SUBMITTED, "status": "submitted",
                    "actor_oid": principal.oid, "details": {"script_sha256": sha256, "script_bytes": len(raw)}})
    except IntegrityError:
        raise HTTPException(status_code=409, detail="script_exists") from None  # a concurrent identical submission
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail="audit_unavailable") from None
    return {"sha256": sha256, "created": True}


@router.get("/{sha256}", name="scripts_get")
async def get_script(sha256: str, principal: Principal = Depends(require_role("analyst", "security_lead")),
                     sessionmaker=Depends(get_sessionmaker)) -> dict:
    sha256 = _sha(sha256)
    async with sessionmaker() as session:
        script = await _script(session, principal.tid, sha256)
        if script is None:
            raise HTTPException(status_code=404, detail="script_not_found")
        analysis = (await session.execute(select(ScriptAnalysis).where(ScriptAnalysis.script_id == script.id)
                                          .order_by(ScriptAnalysis.created_at.desc()))).scalars().first()
        approvals = (await session.execute(select(ScriptApproval).where(ScriptApproval.script_id == script.id)
                                           .order_by(ScriptApproval.created_at))).scalars().all()
    return {
        "sha256": script.sha256, "text": script.text, "created_at": _dt(script.created_at),
        "submitted_by_you": script.submitted_by == principal.user_id,
        "analysis": None if analysis is None else {
            "status": analysis.status, "analyser_version": analysis.analyser_version, "reason": analysis.reason,
            "summary": analysis.summary, "proposed_manifest": analysis.proposed_manifest,
            "risks": (analysis.analysis or {}).get("risks", []), "ended_at": _dt(analysis.ended_at)},
        "approvals": [{"id": str(a.id), "manifest_sha256": a.manifest_sha256, "manifest": a.manifest,
                       "created_at": _dt(a.created_at)} for a in approvals],
    }


@router.post("/{sha256}/approvals", name="scripts_approve", status_code=201)
async def approve(sha256: str, body: ApproveBody, principal: Principal = Depends(require_role("security_lead")),
                  sessionmaker=Depends(get_sessionmaker), writer=Depends(get_writer)) -> dict:
    sha256 = _sha(sha256)
    try:
        manifest = load_script_manifest(body.manifest)
    except ManifestRefused as exc:
        raise HTTPException(status_code=422, detail=f"manifest_refused: {exc}") from None
    async with sessionmaker() as session:
        script = await _script(session, principal.tid, sha256)
        if script is None:
            raise HTTPException(status_code=404, detail="script_not_found")
        analyzed = (await session.execute(select(ScriptAnalysis.id).where(
            ScriptAnalysis.script_id == script.id, ScriptAnalysis.status == "analyzed"))).first()
    if script.submitted_by == principal.user_id:
        raise HTTPException(status_code=403, detail="cannot_approve_own_script")
    if analyzed is None:
        raise HTTPException(status_code=409, detail="analysis_not_complete")
    approval_id = uuid.uuid4()
    try:
        async with sessionmaker() as session:
            async with session.begin():
                await session.execute(insert(ScriptApproval).values(
                    id=approval_id, tenant_id=principal.tid, script_id=script.id, script_sha256=sha256,
                    manifest=manifest.document, manifest_sha256=manifest.sha256, approved_by=principal.user_id))
                await writer.append(chain_id=principal.tid, event={
                    "tenant_id": principal.tid, "event_type": EventType.MANIFEST_APPROVED, "status": "approved",
                    "actor_oid": principal.oid, "details": {"script_sha256": sha256, "manifest_sha256": manifest.sha256,
                                                            "approval_id": str(approval_id)}})
    except IntegrityError:
        raise HTTPException(status_code=403, detail="approval_refused") from None  # the database's guard refused it
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail="audit_unavailable") from None
    return {"approval_id": str(approval_id), "manifest_sha256": manifest.sha256}
