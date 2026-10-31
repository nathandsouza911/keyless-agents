"""A script run's approved manifest, from its approval (SD-043).

The facade's manifest lookup in production: only a `script` run, only its own
approval (by the run row's approval_id, in the run's tenant), and only if the
stored manifest still loads and its digest is the one approved and the one the
run was created with (runs.task_manifest_sha256). Anything else is None, and
the facade refuses the run (not_a_script_run).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from clw.broker.facade.rules import ManifestRefused, ScriptManifest, load_script_manifest
from clw.db.models.run import Run
from clw.db.models.script import ScriptApproval


async def approved_manifest(session: AsyncSession, row: Run) -> ScriptManifest | None:
    if row.kind != "script" or row.approval_id is None:
        return None
    approval = (await session.execute(select(ScriptApproval).where(
        ScriptApproval.id == row.approval_id, ScriptApproval.tenant_id == row.tenant_id,
        ScriptApproval.script_id == row.script_id))).scalar_one_or_none()
    if approval is None:
        return None
    try:
        manifest = load_script_manifest(approval.manifest)
    except ManifestRefused:
        return None
    if not (manifest.sha256 == approval.manifest_sha256 == row.task_manifest_sha256):
        return None
    return manifest
