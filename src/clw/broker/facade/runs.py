"""Script runs as the facade sees them (SD-041).

The task container holds one credential, its run capability (CLW_RUN_TOKEN).
Graph clients send it as `Authorization: Bearer <capability>` (the preloaded
Connect-MgGraph passes it to the SDK). `parse_bearer` reads exactly that.

`resolve_script_run` resolves the capability the way `capability.resolve_run`
does for built-in tasks (by its SHA-256, the run row only; never the
request), with the same refusals, and gives the run's approved script
manifest and the profile it names. Where the manifest comes from is
injected: the approval bound to the run (M4) in production, a fixed mapping
in tests. A run without one is `not_a_script_run`.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from clw.broker.capability import RunRef, RunRefused, run_token_sha256
from clw.broker.facade.rules import ScriptManifest
from clw.broker.manifest import DEFAULT_PROFILES_DIR
from clw.broker.profiles import PermissionProfile, load_profile_by_id
from clw.db.models.run import Run

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")

ManifestLookup = Callable[[AsyncSession, Run], Awaitable[ScriptManifest | None]]


@dataclass(frozen=True, slots=True)
class ScriptRunContext:
    run_id: str
    tenant_id: str
    deadline_at: datetime
    manifest: ScriptManifest
    profile: PermissionProfile


def parse_bearer(header: object) -> str | None:
    """The capability from exactly `Bearer <capability>` (scheme case-insensitive), or None."""
    if not isinstance(header, str):
        return None
    scheme, sep, token = header.partition(" ")
    if scheme.lower() != "bearer" or not sep or not _TOKEN.match(token):
        return None
    return token


async def resolve_script_run(
    session: AsyncSession, token: str | None, *, manifests: ManifestLookup, now: datetime,
    profiles_dir: Path = DEFAULT_PROFILES_DIR,
) -> ScriptRunContext:
    if not (isinstance(token, str) and _TOKEN.match(token)):
        raise RunRefused("run_token_invalid")
    row = (await session.execute(select(Run).where(Run.run_token_sha256 == run_token_sha256(token)))).scalar_one_or_none()
    if row is None:
        raise RunRefused("run_token_invalid")
    if row.status == "halted":
        raise RunRefused("run_halted")
    if row.status != "running":
        raise RunRefused("run_not_running")
    run = RunRef(run_id=str(row.id), tenant_id=row.tenant_id)
    if not now < row.deadline_at:
        raise RunRefused("deadline_exceeded", run=run)
    manifest = await manifests(session, row)
    if not isinstance(manifest, ScriptManifest):
        raise RunRefused("not_a_script_run", run=run)
    try:
        profile = load_profile_by_id(manifest.profile, profiles_dir=profiles_dir)
    except Exception:  # noqa: BLE001 - an approval naming no loadable profile authorizes nothing
        raise RunRefused("manifest_changed", run=run) from None
    return ScriptRunContext(run_id=run.run_id, tenant_id=run.tenant_id, deadline_at=row.deadline_at,
                            manifest=manifest, profile=profile)
