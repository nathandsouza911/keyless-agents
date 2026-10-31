"""Run tokens and run resolution (Task 12, SD-032; threat model T9, T17, T22).

A run token is 256 random bits (URL-safe base64, 43 characters), handed to
the task container once and stored only as its SHA-256 (runs.run_token_sha256).
The task presents it as `Authorization: RunToken <token>`.

resolve_run turns a token into a RunContext using the database only: the
token selects exactly one run, and the tenant, task, manifest and profile
all come from that run's row and the broker's own manifest catalog, never
from the request (T9). It refuses, in this order:
  run_token_invalid  malformed, unknown, or revoked (the hash is cleared
                     when a run ends);
  run_halted         the broker halted the run after an audit failure;
  run_not_running    any other status (queued, completed, failed, timed_out);
  deadline_exceeded  now >= deadline_at (T17);
  not_a_task_run / not_an_agent_session
                     the run is not of the kind the caller serves: a task
                     route never accepts an agent session's capability, and
                     the agent route (SD-049) never accepts a task's token;
  manifest_changed   the catalog's manifest for the run's task is not the one
                     the run was started with: manifest digest, profile id,
                     version or digest, or mode differ. For an agent session
                     the catalog is the agent-profile catalog, so this is
                     "the profile changed since the session started".
Only the last two concern a run that is still `running`, so only they carry
the run's id and tenant for the caller to audit; recording anything for a
run that has ended would contradict the chain's run state machine.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, get_args

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from clw.broker.manifest import TaskManifest
from clw.broker.profiles import PermissionProfile
from clw.db.models.run import Run
from clw.db.models.tenant import Tenant
from clw.db.models.workbench_user import WorkbenchUser

AUTH_SCHEME = "RunToken"
RUN_TOKEN_BYTES = 32
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")

RefusalReason = Literal["run_token_invalid", "run_halted", "run_not_running", "deadline_exceeded", "manifest_changed",
                        "not_a_script_run", "not_a_task_run", "not_an_agent_session", "tenant_disabled",
                        "actor_not_allowed"]
RunKind = Literal["task", "agent_session"]
_REASONS = frozenset(get_args(RefusalReason))


@dataclass(frozen=True, slots=True)
class IssuedRunToken:
    token: str = field(repr=False)  # given to the task container once; never stored or logged
    sha256: str


@dataclass(frozen=True, slots=True)
class RunRef:
    run_id: str
    tenant_id: str


@dataclass(frozen=True, slots=True)
class RunContext:
    """Everything the broker uses for one run, from the database and the catalog."""

    run_id: str
    tenant_id: str
    task_id: str
    manifest: TaskManifest
    deadline_at: datetime

    @property
    def profile(self) -> PermissionProfile:
        return self.manifest.profile


class RunRefused(Exception):
    """The token does not resolve to a usable run. The message is the reason only."""

    def __init__(self, reason: RefusalReason, *, run: RunRef | None = None) -> None:
        if reason not in _REASONS:
            raise ValueError("unknown run refusal reason")
        super().__init__(reason)
        self.reason = reason
        self.run = run


def issue_run_token() -> IssuedRunToken:
    token = secrets.token_urlsafe(RUN_TOKEN_BYTES)
    return IssuedRunToken(token=token, sha256=run_token_sha256(token))


def run_token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def parse_authorization(header: object) -> str | None:
    """The token from exactly `RunToken <token>`, or None."""
    if not isinstance(header, str):
        return None
    scheme, sep, token = header.partition(" ")
    if scheme != AUTH_SCHEME or not sep or not _TOKEN.match(token):
        return None
    return token


def _bound_to_run(manifest: TaskManifest | None, row: Run) -> bool:
    return (
        isinstance(manifest, TaskManifest)
        and manifest.id == row.task_id
        and manifest.sha256 == row.task_manifest_sha256
        and manifest.mode == row.auth_mode
        and manifest.profile.id == row.profile_id
        and manifest.profile.version == row.profile_version
        and manifest.profile.sha256 == row.profile_sha256
    )


async def resolve_run(
    session: AsyncSession, token: str | None, *, catalog: Mapping[str, TaskManifest], now: datetime,
    kind: RunKind = "task",
) -> RunContext:
    if not (isinstance(token, str) and _TOKEN.match(token)):
        raise RunRefused("run_token_invalid")
    digest = run_token_sha256(token)
    # Looked up by digest: an index lookup on the SHA-256 of a 256-bit secret
    # reveals nothing usable about the token through timing, so no separate
    # constant-time comparison follows (it could only re-compare equal values).
    row = (await session.execute(select(Run).where(Run.run_token_sha256 == digest))).scalar_one_or_none()
    if row is None:
        raise RunRefused("run_token_invalid")
    if row.status == "halted":
        raise RunRefused("run_halted")
    if row.status != "running":
        raise RunRefused("run_not_running")
    run = RunRef(run_id=str(row.id), tenant_id=row.tenant_id)
    if not now < row.deadline_at:  # a running run always has one (ck_runs_running_has_token)
        raise RunRefused("deadline_exceeded", run=run)
    if row.kind != kind:  # a script run reaches Graph only through the facade (SD-043)
        raise RunRefused("not_a_task_run" if kind == "task" else "not_an_agent_session", run=run)
    manifest = catalog.get(row.task_id)
    if not _bound_to_run(manifest, row):
        raise RunRefused("manifest_changed", run=run)
    if kind == "agent_session":
        # SD-055 (review F2): on every use, the tenant must still be active, and its starter still a member
        # whose current role may start this profile. Disabling a tenant or demoting a person takes effect at once.
        standing = (await session.execute(
            select(Tenant.status, WorkbenchUser.role)
            .join(WorkbenchUser, (WorkbenchUser.tenant_id == Tenant.id) & (WorkbenchUser.oid == row.actor_oid),
                  isouter=True)
            .where(Tenant.id == row.tenant_id))).one_or_none()
        if standing is None or standing.status != "active":
            raise RunRefused("tenant_disabled", run=run)
        if standing.role is None or standing.role not in manifest.start_roles:  # type: ignore[union-attr]
            raise RunRefused("actor_not_allowed", run=run)
    return RunContext(run_id=run.run_id, tenant_id=run.tenant_id, task_id=row.task_id,
                      manifest=manifest, deadline_at=row.deadline_at)  # type: ignore[arg-type]
