"""Run creation and tenant-scoped run views (Task 16).

    POST /runs              start a run of a catalog task for the caller's tenant
    GET  /runs/{run_id}     the run's status and result, the caller's tenant only
    GET  /runs/{run_id}/audit  the run's audit events and the chain's validity

The tenant and the actor come only from the verified session (`current_principal`),
never from the request body or query. The body is a strict `{task_id, params}`:
a `tenant_id`, `actor`, `status`, `image`, `url`, `path` or any other field is
rejected (422) before anything is created. The run is bound to the task's
manifest and profile from the catalog; the caller cannot choose the image,
command, credential, container settings, manifest digest or profile.

Creating a run is write-ahead and fail-closed, like the runner's start
(SD-034): the `runs` row is inserted (its composite foreign key enforces that
the actor is a member of the run's tenant), then `RUN_REQUESTED` is written to
the tenant's audit chain, and only if both succeed does the transaction
commit. A membership/tenant foreign-key violation is a 403 with nothing
written; an audit failure rolls the row back (503). The runner validates the
manifest and params again when it claims the run.

A run view never includes the run-token hash, the deadline, or any internal
error detail. Fetching another tenant's run (or an unknown id) is a 404, with
no distinction between the two, so run ids are not an existence oracle across
tenants.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError

from clw.api.deps import Principal, current_principal
from clw.api.runtime import ParamsInvalid, get_catalog, get_sessionmaker, get_writer, normalized_params
from clw.audit.events import AuditUnavailable, EventType
from clw.audit.verifier import load_chain, verify_chain
from clw.broker.facade.rules import ManifestRefused, load_script_manifest
from clw.broker.manifest import DEFAULT_PROFILES_DIR, TaskManifest
from clw.broker.profiles import load_profile_by_id
from clw.common.timeutil import to_rfc3339_utc
from clw.db.models.run import Run
from clw.db.models.script import Script, ScriptApproval

SCRIPT_TASK_ID = "script"  # runs.task_id of every script run; its manifest digest is the approval's

router = APIRouter(prefix="/runs")

# Fields of an audit record returned to the caller. The run-token hash is not
# a record field; previous_hash/record_hash are chain internals left out of
# the event view (the chain's validity is reported separately).
_AUDIT_FIELDS = (
    "seq", "event_type", "status", "reason", "outcome", "operation", "decision_seq",
    "http_method", "path_template", "request_target", "http_status", "graph_request_id",
    "attempt", "item_count", "duration_ms", "created_at",
)


class CreateRunBody(BaseModel):
    """Exactly one of: a built-in task (`task_id`, `params`), or an approved script
    (`script_sha256`, optionally the `approval_id` to run under; default the latest)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    task_id: str | None = None
    params: dict[str, int] = Field(default_factory=dict)
    script_sha256: str | None = None
    approval_id: str | None = None

    @model_validator(mode="after")
    def _one_kind(self):
        if (self.task_id is None) == (self.script_sha256 is None):
            raise ValueError("exactly one of task_id and script_sha256")
        if self.script_sha256 is not None and self.params:
            raise ValueError("a script run takes no params")
        if self.task_id is not None and self.approval_id is not None:
            raise ValueError("approval_id is for script runs")
        return self


def _redacts(record, run_id: str) -> bool:
    """A RESULT_REDACTED naming this run (it carries no run_id of its own)."""
    details = record.details if isinstance(record.details, dict) else {}
    return record.event_type == EventType.RESULT_REDACTED and details.get("redacted_run_id") == run_id


def _dt(value) -> str | None:
    return to_rfc3339_utc(value) if value is not None else None


def serialize_run(run: Run) -> dict:
    """The safe, tenant-owned view of a run. No run-token hash, no deadline,
    no internal error detail. A redacted result (SD-037) is null, with
    result_redacted set."""
    return {
        "id": str(run.id),
        "task_id": run.task_id,
        "status": run.status,
        "params": dict(run.params),
        "outcome": run.outcome,
        "result": run.result,
        "result_redacted": run.result_redacted_at is not None,
        "kind": run.kind,
        "created_at": _dt(run.created_at),
        "started_at": _dt(run.started_at),
        "ended_at": _dt(run.ended_at),
    }


async def _load_run(sessionmaker, run_id: uuid.UUID, tenant_id: str) -> Run | None:
    async with sessionmaker() as session:
        return (await session.execute(
            select(Run).where(Run.id == run_id, Run.tenant_id == tenant_id))).scalar_one_or_none()


def _run_uuid(run_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(run_id)
    except (ValueError, AttributeError):
        # Not a UUID: it can match no run, so it is a 404 like any other miss
        # (and never an error that echoes the input).
        raise HTTPException(status_code=404, detail="run_not_found") from None


@router.post("", name="runs_create", status_code=201)
async def create_run(
    body: CreateRunBody,
    principal: Principal = Depends(current_principal),
    catalog: Mapping[str, TaskManifest] = Depends(get_catalog),
    sessionmaker=Depends(get_sessionmaker),
    writer=Depends(get_writer),
) -> dict:
    if body.script_sha256 is not None:
        return await _create_script_run(body, principal, sessionmaker, writer)
    manifest = catalog.get(body.task_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="task_not_found")
    try:
        params = normalized_params(manifest, body.params)
    except ParamsInvalid:
        raise HTTPException(status_code=422, detail="params_invalid") from None

    run_id = uuid.uuid4()
    # A Core INSERT that names only the columns the API may set: the queued
    # identity, never a run token, deadline, result, outcome or timestamps. The
    # application database role is granted INSERT on exactly these columns, so
    # the API cannot plant a run that is already running or pre-authorized; the
    # others take their database defaults (NULL, or now() for the timestamps).
    new_run = insert(Run).values(
        id=run_id,
        tenant_id=principal.tid,
        task_id=manifest.id,
        task_manifest_sha256=manifest.sha256,
        profile_id=manifest.profile.id,
        profile_version=manifest.profile.version,
        profile_sha256=manifest.profile.sha256,
        auth_mode=manifest.mode,
        actor_user_id=principal.user_id,
        actor_oid=principal.oid,
        actor_tid=principal.tid,
        params=params,
        status="queued",
    )
    try:
        async with sessionmaker() as session:
            async with session.begin():
                await session.execute(new_run)  # the actor-membership foreign key is enforced here
                await writer.append(chain_id=principal.tid, event={
                    "tenant_id": principal.tid, "event_type": EventType.RUN_REQUESTED, "status": "requested",
                    "run_id": str(run_id), "task_id": manifest.id, "task_manifest_sha256": manifest.sha256,
                    "actor_oid": principal.oid, "actor_tid": principal.tid})
    except IntegrityError:
        # The actor is no longer a member of the tenant (or the tenant is gone):
        # nothing was written to the chain (the flush failed first).
        raise HTTPException(status_code=403, detail="access_denied") from None
    except AuditUnavailable:
        # The request could not be recorded; the row was rolled back.
        raise HTTPException(status_code=503, detail="audit_unavailable") from None

    created = await _load_run(sessionmaker, run_id, principal.tid)
    if created is None:  # pragma: no cover - the commit above succeeded
        raise HTTPException(status_code=503, detail="run_unavailable")
    return serialize_run(created)


async def _create_script_run(body: CreateRunBody, principal: Principal, sessionmaker, writer) -> dict:
    """A queued script run, bound to an approval of exactly this script (SD-043).
    Launching it needs the PowerShell sandbox (M5); until then it stays queued."""
    async with sessionmaker() as session:
        script = (await session.execute(select(Script).where(
            Script.tenant_id == principal.tid, Script.sha256 == body.script_sha256))).scalar_one_or_none()
        query = select(ScriptApproval).where(ScriptApproval.tenant_id == principal.tid,
                                             ScriptApproval.script_id == (script.id if script else None))
        if body.approval_id is not None:
            query = query.where(ScriptApproval.id == _run_uuid_or_none(body.approval_id))
        approval = (await session.execute(query.order_by(ScriptApproval.created_at.desc()))).scalars().first()
    if script is None:
        raise HTTPException(status_code=404, detail="script_not_found")
    if approval is None:
        raise HTTPException(status_code=403, detail="script_not_approved")
    try:
        manifest = load_script_manifest(approval.manifest)
        profile = load_profile_by_id(manifest.profile, profiles_dir=DEFAULT_PROFILES_DIR)
    except (ManifestRefused, Exception):  # noqa: BLE001 - an approval that no longer loads runs nothing
        raise HTTPException(status_code=409, detail="approval_unusable") from None
    if manifest.sha256 != approval.manifest_sha256:
        raise HTTPException(status_code=409, detail="approval_unusable")
    run_id = uuid.uuid4()
    new_run = insert(Run).values(
        id=run_id, tenant_id=principal.tid, task_id=SCRIPT_TASK_ID, task_manifest_sha256=manifest.sha256,
        profile_id=profile.id, profile_version=profile.version, profile_sha256=profile.sha256, auth_mode="app_only",
        actor_user_id=principal.user_id, actor_oid=principal.oid, actor_tid=principal.tid, params={},
        status="queued", kind="script", script_id=script.id, approval_id=approval.id)
    try:
        async with sessionmaker() as session:
            async with session.begin():
                await session.execute(new_run)
                await writer.append(chain_id=principal.tid, event={
                    "tenant_id": principal.tid, "event_type": EventType.RUN_REQUESTED, "status": "requested",
                    "run_id": str(run_id), "task_id": SCRIPT_TASK_ID, "task_manifest_sha256": manifest.sha256,
                    "actor_oid": principal.oid, "actor_tid": principal.tid})
    except IntegrityError:
        raise HTTPException(status_code=403, detail="access_denied") from None
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail="audit_unavailable") from None
    created = await _load_run(sessionmaker, run_id, principal.tid)
    return serialize_run(created)


def _run_uuid_or_none(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return None


@router.get("/{run_id}", name="runs_get")
async def get_run(
    run_id: str,
    principal: Principal = Depends(current_principal),
    sessionmaker=Depends(get_sessionmaker),
) -> dict:
    run = await _load_run(sessionmaker, _run_uuid(run_id), principal.tid)
    if run is None:
        raise HTTPException(status_code=404, detail="run_not_found")
    return serialize_run(run)


@router.get("/{run_id}/audit", name="runs_audit")
async def get_run_audit(
    run_id: str,
    principal: Principal = Depends(current_principal),
    sessionmaker=Depends(get_sessionmaker),
) -> dict:
    rid = _run_uuid(run_id)
    run = await _load_run(sessionmaker, rid, principal.tid)
    if run is None:
        raise HTTPException(status_code=404, detail="run_not_found")
    async with sessionmaker() as session:
        records = await load_chain(session, chain_id=principal.tid)
        report = await verify_chain(session, chain_id=principal.tid)
    events = [{field: getattr(r, field) for field in _AUDIT_FIELDS}
              for r in records if r.run_id == str(rid) or _redacts(r, str(rid))]
    return {
        "run_id": str(rid),
        "events": events,
        "chain": {"valid": report.valid, "head_seq": report.head_seq},
    }
