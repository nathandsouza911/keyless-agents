"""clw_start_agent_session refuses a disabled tenant (security review F2, 2026-10-31; SD-055)

Revision ID: 20261107_session_tenant_active
Revises: 20261106_proposal_binding
Create Date: 2026-10-31

The api checked the tenant only at sign-in, so a person with a still-valid browser session could start an
agent session in a tenant that had since been disabled. The function now refuses that itself. Both bodies
are written out in full here: a migration is a fixed snapshot.
"""

from alembic import op

revision = "20261107_session_tenant_active"
down_revision = "20261106_proposal_binding"
branch_labels = None
depends_on = None

# No backslashes in the bodies (SD-019). The function as 20261104 created it, then with the tenant guard.
_WITHOUT_GUARD = "\nCREATE OR REPLACE FUNCTION public.clw_start_agent_session(\n    p_id uuid, p_tenant_id text, p_task_id text, p_task_manifest_sha256 text, p_profile_id text,\n    p_profile_version integer, p_profile_sha256 text, p_auth_mode text, p_actor_user_id uuid,\n    p_actor_oid text, p_run_token_sha256 text, p_ttl_seconds integer) RETURNS timestamptz\nLANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pg_catalog, pg_temp\nAS $$\nDECLARE\n    v_deadline timestamptz;\nBEGIN\n    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 60 OR p_ttl_seconds > 28800 THEN\n        RAISE EXCEPTION 'agent session: the ttl must be 60 to 28800 seconds'\n            USING ERRCODE = 'check_violation';\n    END IF;\n    IF p_run_token_sha256 IS NULL THEN\n        RAISE EXCEPTION 'agent session: a token hash is required' USING ERRCODE = 'check_violation';\n    END IF;\n    v_deadline := now() + make_interval(secs => p_ttl_seconds);\n    INSERT INTO public.runs (id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version,\n                             profile_sha256, auth_mode, actor_user_id, actor_oid, actor_tid, params, status,\n                             run_token_sha256, deadline_at, started_at, kind)\n    VALUES (p_id, p_tenant_id, p_task_id, p_task_manifest_sha256, p_profile_id, p_profile_version,\n            p_profile_sha256, p_auth_mode, p_actor_user_id, p_actor_oid, p_tenant_id, '{}'::jsonb, 'running',\n            p_run_token_sha256, v_deadline, now(), 'agent_session');\n    RETURN v_deadline;\nEND;\n$$\n"

_GUARD = "    IF NOT EXISTS (SELECT 1 FROM public.tenants t WHERE t.id = p_tenant_id AND t.status = 'active') THEN\n        RAISE EXCEPTION 'agent session: the tenant is not active' USING ERRCODE = 'check_violation';\n    END IF;\n"
_ANCHOR = '    v_deadline := now() + make_interval(secs => p_ttl_seconds);'
_WITH_GUARD = _WITHOUT_GUARD.replace(_ANCHOR, _GUARD + _ANCHOR)
assert _WITH_GUARD != _WITHOUT_GUARD


def upgrade() -> None:
    op.execute(_WITH_GUARD)


def downgrade() -> None:
    op.execute(_WITHOUT_GUARD)
