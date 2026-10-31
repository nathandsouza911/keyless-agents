"""Task catalog and manifest view (Task 16).

    GET /tasks            a summary per registered task
    GET /tasks/{task_id}  the full manifest view

Both require a session (the tenant is never read from the request). The
manifest view shows, for every allowed and prohibited operation, the method
and path template the broker would use (from the operation registry), so a
security lead can see exactly what the task may and may not do. It never
exposes a credential, a profile's environment-variable names, or any URL a
caller could pass back.

`manifest_view` is a pure function of the manifest (tested without a
database). The route adds `audit.chain_valid`, the verification result of the
caller's own tenant audit chain, so the view also answers "is my audit trail
intact". That is the caller's chain only.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Depends, HTTPException

from clw.api.deps import Principal, current_principal
from clw.api.runtime import get_catalog, get_sessionmaker
from clw.audit.verifier import verify_chain
from clw.broker import operations
from clw.broker.manifest import TaskManifest

router = APIRouter(prefix="/tasks")


def _operation_views(names: tuple[str, ...]) -> list[dict]:
    views = []
    for name in names:
        spec = operations.get(name)
        views.append({"op": name, "method": spec.method, "path_template": spec.path_template})
    return views


def task_summary(manifest: TaskManifest) -> dict:
    return {
        "id": manifest.id,
        "name": manifest.name,
        "purpose": manifest.purpose,
        "mode": manifest.mode,
        "approval_required": manifest.approval_required,
        "timeout_seconds": manifest.timeout_seconds,
    }


def manifest_view(manifest: TaskManifest) -> dict:
    """The manifest as the API returns it, without the per-tenant audit status."""
    profile = manifest.profile
    return {
        "id": manifest.id,
        "name": manifest.name,
        "purpose": manifest.purpose,
        "permission_profile": {
            "id": profile.id,
            "version": profile.version,
            "expected_permissions": sorted(profile.expected_permissions),
        },
        "mode": manifest.mode,
        "allowed": _operation_views(manifest.allowed),
        "prohibited": _operation_views(manifest.prohibited),
        "approval_required": manifest.approval_required,
        "timeout_seconds": manifest.timeout_seconds,
        "audit": {"enabled": True},
    }


@router.get("", name="tasks_list")
async def list_tasks(
    _principal: Principal = Depends(current_principal),
    catalog: Mapping[str, TaskManifest] = Depends(get_catalog),
) -> dict:
    return {"tasks": [task_summary(catalog[task_id]) for task_id in sorted(catalog)]}


@router.get("/{task_id}", name="tasks_get")
async def get_task(
    task_id: str,
    principal: Principal = Depends(current_principal),
    catalog: Mapping[str, TaskManifest] = Depends(get_catalog),
    sessionmaker=Depends(get_sessionmaker),
) -> dict:
    manifest = catalog.get(task_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="task_not_found")
    view = manifest_view(manifest)
    async with sessionmaker() as session:
        report = await verify_chain(session, chain_id=principal.tid)
    view["audit"]["chain_valid"] = report.valid
    return view
