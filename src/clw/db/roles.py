"""Least-privileged database roles, one per component (SD-038).

The single definition of what each component may do in the database. The
deployment applies it with `clw db-provision-roles`; the pg test fixtures
apply the same statements to their test roles, so tests and deployments
cannot drift apart.

Every component may read and append audit records, never change or delete
them (the audit triggers refuse that for every role, owner included):

  api     sign-in (tenants and memberships: read; oidc_logins: create,
          claim), and runs: read, create queued runs naming only their
          identity (never a token, deadline, result or outcome); scripts
          and approvals: read and create; analyses: read, queue (SD-043)
  broker  runs: read; end or halt a run (status, outcome, token revoked);
          audit_value_keys: read and create (SD-042); scripts and
          approvals: read (SD-043)
  runner  runs: read; start (token, deadline, started_at) and end runs
          (status, outcome, result); scripts: read; analyses: read and
          record the analyser's output (SD-043); approvals: read, to
          check what a script run is bound to (SD-044)

No role may set runs.result_redacted_at: redaction is the owner's (SD-037).
No role owns a table, creates objects or holds any database-wide privilege
beyond CONNECT.
"""

from __future__ import annotations

import re
from typing import Literal

Component = Literal["api", "broker", "runner"]
COMPONENTS: tuple[Component, ...] = ("api", "broker", "runner")

_IDENT = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")

_RUN_INSERT_COLUMNS = ("id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version, profile_sha256, "
                       "auth_mode, actor_user_id, actor_oid, actor_tid, params, status, kind, script_id, approval_id")

_GRANTS: dict[Component, tuple[str, ...]] = {
    "api": (
        "GRANT SELECT ON tenants, workbench_users TO {role}",
        "GRANT SELECT, INSERT ON oidc_logins TO {role}",
        "GRANT UPDATE (used_at) ON oidc_logins TO {role}",
        "GRANT SELECT ON runs TO {role}",
        f"GRANT INSERT ({_RUN_INSERT_COLUMNS}) ON runs TO {{role}}",
        # SD-043: submit scripts (queuing their analysis) and record approvals; never change either.
        "GRANT SELECT, INSERT ON scripts TO {role}",
        "GRANT SELECT ON script_analyses TO {role}",
        "GRANT INSERT (id, script_id, tenant_id, status) ON script_analyses TO {role}",
        "GRANT SELECT, INSERT ON script_approvals TO {role}",
        # SD-049: start and end agent sessions only through these functions (agent-session rows only);
        # no INSERT of a token or deadline and no UPDATE on runs.
        "GRANT EXECUTE ON FUNCTION clw_start_agent_session(uuid, text, text, text, text, integer, text, text, uuid, "
        "text, text, integer) TO {role}",
        "GRANT EXECUTE ON FUNCTION clw_end_agent_session(uuid, text, text, text) TO {role}",
        # SD-054: read change proposals for display; never write one.
        "GRANT SELECT ON change_proposals TO {role}",
    ),
    "broker": (
        # SD-042: read and create a tenant's audit value key; never change or delete one.
        "GRANT SELECT, INSERT ON audit_value_keys TO {role}",
        "GRANT SELECT ON runs TO {role}",
        "GRANT UPDATE (status, outcome, run_token_sha256, ended_at, updated_at) ON runs TO {role}",
        # SD-043: a script run's approved manifest (and, from M5, its script text).
        "GRANT SELECT ON scripts, script_approvals TO {role}",
        # SD-054: file an agent's change proposal; never change or delete one.
        "GRANT SELECT, INSERT ON change_proposals TO {role}",
    ),
    "runner": (
        "GRANT SELECT ON runs TO {role}",
        "GRANT UPDATE (status, outcome, result, run_token_sha256, deadline_at, started_at, ended_at, updated_at) "
        "ON runs TO {role}",
        # SD-043: run the offline analyser and record its output, once.
        "GRANT SELECT ON scripts TO {role}",
        "GRANT SELECT ON script_analyses TO {role}",
        "GRANT UPDATE (status, analyser_version, analysis, analysis_sha256, proposed_manifest, summary, reason, "
        "ended_at) ON script_analyses TO {role}",
        # SD-044: a script run starts only if its approval still binds it to its script.
        "GRANT SELECT ON script_approvals TO {role}",
    ),
}


def identifier(name: str) -> str:
    """A role or database name safe to place in SQL unquoted (lowercase, no quoting needed)."""
    if not (isinstance(name, str) and _IDENT.match(name)):
        raise ValueError("role and database names must be lowercase letters, digits and '_' (max 63)")
    return name


def grant_statements(component: Component, *, role: str, database: str) -> list[str]:
    """The GRANTs that give `role` exactly `component`'s privileges in `database`."""
    if component not in _GRANTS:
        raise ValueError(f"unknown component {component!r}")
    role, database = identifier(role), identifier(database)
    return [
        f'GRANT CONNECT ON DATABASE "{database}" TO {role}',
        f"GRANT USAGE ON SCHEMA public TO {role}",
        f"GRANT SELECT, INSERT ON audit_events TO {role}",
        *(statement.format(role=role) for statement in _GRANTS[component]),
    ]
