"""agent sessions as runs (v0.1, SD-049)

Revision ID: 20261104_agent_sessions
Revises: 20261103_scripts
Create Date: 2026-10-30

An agent session (an AI agent's MCP session under a profile, SD-048) is a run
of kind 'agent_session'. Only two SECURITY DEFINER functions create or end
one, and each touches agent-session rows only, so the api is granted EXECUTE
on them and no INSERT of a token or deadline and no UPDATE on runs at all:

- clw_start_agent_session(...) inserts the row already running, with the
  capability's SHA-256, deadline_at = now() + ttl (60 s to 8 h), started_at =
  now() and kind 'agent_session'. Nothing else can be inserted through it.
- clw_end_agent_session(run_id, tenant_id, status, outcome) ends a running
  agent session of that tenant and revokes its token. It accepts only
  ('completed', 'revoked'), storing the fixed result {"session": "revoked"},
  or ('failed', 'revoked_during_request'). For any other row (another
  tenant's, a task or script run, a session that has already ended) it
  changes nothing and returns false.

ck_runs_kind_binding gains the third kind: an agent session names no script
and no approval. Expiry needs nothing new: the reconciler ends a running run
past its deadline, and the broker refuses its token from the deadline on.
"""

from alembic import op

revision = "20261104_agent_sessions"
down_revision = "20261103_scripts"
branch_labels = None
depends_on = None

MAX_TTL_SECONDS = 8 * 3600
MIN_TTL_SECONDS = 60

# No backslashes in the bodies: a plpgsql body is parsed in the calling
# session, where standard_conforming_strings may be off (SD-019).
_START_FN = f"""
CREATE FUNCTION public.clw_start_agent_session(
    p_id uuid, p_tenant_id text, p_task_id text, p_task_manifest_sha256 text, p_profile_id text,
    p_profile_version integer, p_profile_sha256 text, p_auth_mode text, p_actor_user_id uuid,
    p_actor_oid text, p_run_token_sha256 text, p_ttl_seconds integer) RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_deadline timestamptz;
BEGIN
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < {MIN_TTL_SECONDS} OR p_ttl_seconds > {MAX_TTL_SECONDS} THEN
        RAISE EXCEPTION 'agent session: the ttl must be {MIN_TTL_SECONDS} to {MAX_TTL_SECONDS} seconds'
            USING ERRCODE = 'check_violation';
    END IF;
    IF p_run_token_sha256 IS NULL THEN
        RAISE EXCEPTION 'agent session: a token hash is required' USING ERRCODE = 'check_violation';
    END IF;
    v_deadline := now() + make_interval(secs => p_ttl_seconds);
    INSERT INTO public.runs (id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version,
                             profile_sha256, auth_mode, actor_user_id, actor_oid, actor_tid, params, status,
                             run_token_sha256, deadline_at, started_at, kind)
    VALUES (p_id, p_tenant_id, p_task_id, p_task_manifest_sha256, p_profile_id, p_profile_version,
            p_profile_sha256, p_auth_mode, p_actor_user_id, p_actor_oid, p_tenant_id, '{{}}'::jsonb, 'running',
            p_run_token_sha256, v_deadline, now(), 'agent_session');
    RETURN v_deadline;
END;
$$
"""

_END_FN = """
CREATE FUNCTION public.clw_end_agent_session(
    p_run_id uuid, p_tenant_id text, p_status text, p_outcome text) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- COALESCE: with a NULL argument the test is NULL, and IF NULL would not refuse.
    IF NOT COALESCE((p_status = 'completed' AND p_outcome = 'revoked')
                    OR (p_status = 'failed' AND p_outcome = 'revoked_during_request'), false) THEN
        RAISE EXCEPTION 'agent session: % / % is not a way to end a session', p_status, p_outcome
            USING ERRCODE = 'check_violation';
    END IF;
    UPDATE public.runs
       SET status = p_status, outcome = p_outcome, run_token_sha256 = NULL, ended_at = now(), updated_at = now(),
           result = CASE WHEN p_status = 'completed' THEN '{"session": "revoked"}'::jsonb ELSE NULL END
     WHERE id = p_run_id AND tenant_id = p_tenant_id AND kind = 'agent_session' AND status = 'running';
    RETURN FOUND;
END;
$$
"""

_KINDS_OLD = ("(kind = 'task' AND script_id IS NULL AND approval_id IS NULL) "
              "OR (kind = 'script' AND script_id IS NOT NULL AND approval_id IS NOT NULL)")
_KINDS_NEW = _KINDS_OLD + " OR (kind = 'agent_session' AND script_id IS NULL AND approval_id IS NULL)"


def upgrade() -> None:
    op.drop_constraint("ck_runs_kind_binding", "runs", type_="check")
    op.create_check_constraint("ck_runs_kind_binding", "runs", _KINDS_NEW)
    op.execute(_START_FN)
    op.execute(_END_FN)
    for fn in ("clw_start_agent_session(uuid, text, text, text, text, integer, text, text, uuid, text, text, "
               "integer)", "clw_end_agent_session(uuid, text, text, text)"):
        op.execute(f"REVOKE ALL ON FUNCTION public.{fn} FROM PUBLIC")


def downgrade() -> None:
    op.execute("DROP FUNCTION public.clw_end_agent_session(uuid, text, text, text)")
    op.execute("DROP FUNCTION public.clw_start_agent_session(uuid, text, text, text, text, integer, text, text, "
               "uuid, text, text, integer)")
    op.drop_constraint("ck_runs_kind_binding", "runs", type_="check")
    op.create_check_constraint("ck_runs_kind_binding", "runs", _KINDS_OLD)
