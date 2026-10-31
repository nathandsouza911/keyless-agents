"""runs (Task 12, SD-032)

Revision ID: 20261021_runs
Revises: 20261020_tenants_users
Create Date: 2026-10-17

The plan names this revision 20261013_runs; the date prefix follows the
existing chain instead, so the file order matches the upgrade order.

Database-side guarantees (tests/db/test_runs_table.py):
- the actor belongs to the run's tenant (actor_tid = tenant_id, and
  (tenant_id, actor_oid) is a workbench_users member of that tenant);
- digests and the run-token hash are 64 lowercase hex;
- a running run has a token hash and a deadline; a completed, failed or
  timed-out run has no token hash (the token is revoked);
- BEFORE UPDATE trigger runs_guard_update: the run's identity (tenant,
  task, manifest digest, profile id/version/digest, mode, actor, params,
  created_at) never changes; a terminal status is final; only the
  transitions queued -> running|failed, running -> halted|completed|failed|
  timed_out and halted -> failed|timed_out are allowed; the deadline is set
  only when leaving queued; a token hash can be set only when leaving
  queued and later only cleared.

No grants are made here: database roles are created with the deployment.
The broker needs SELECT on runs and UPDATE of (status, outcome,
run_token_sha256, ended_at, updated_at) only.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "20261021_runs"
down_revision = "20261020_tenants_users"
branch_labels = None
depends_on = None

_HEX64 = "^[0-9a-f]{64}$"
_STATUSES = ("queued", "running", "halted", "completed", "failed", "timed_out")

# No backslashes in the body: a plpgsql body is parsed in the calling
# session, where standard_conforming_strings may be off (SD-019).
_GUARD_FN = r"""
CREATE FUNCTION public.clw_runs_guard_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.task_id IS DISTINCT FROM OLD.task_id
       OR NEW.task_manifest_sha256 IS DISTINCT FROM OLD.task_manifest_sha256
       OR NEW.profile_id IS DISTINCT FROM OLD.profile_id
       OR NEW.profile_version IS DISTINCT FROM OLD.profile_version
       OR NEW.profile_sha256 IS DISTINCT FROM OLD.profile_sha256
       OR NEW.auth_mode IS DISTINCT FROM OLD.auth_mode
       OR NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id
       OR NEW.actor_oid IS DISTINCT FROM OLD.actor_oid
       OR NEW.actor_tid IS DISTINCT FROM OLD.actor_tid
       OR NEW.params IS DISTINCT FROM OLD.params
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'runs: the identity of a run cannot change'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status IN ('completed', 'failed', 'timed_out') THEN
        RAISE EXCEPTION 'runs: a % run cannot change', OLD.status
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
           (OLD.status = 'queued' AND NEW.status IN ('running', 'failed'))
        OR (OLD.status = 'running' AND NEW.status IN ('halted', 'completed', 'failed', 'timed_out'))
        OR (OLD.status = 'halted' AND NEW.status IN ('failed', 'timed_out'))) THEN
        RAISE EXCEPTION 'runs: transition % -> % is not allowed', OLD.status, NEW.status
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status <> 'queued' AND NEW.deadline_at IS DISTINCT FROM OLD.deadline_at THEN
        RAISE EXCEPTION 'runs: the deadline of a started run cannot change'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status <> 'queued' AND NEW.run_token_sha256 IS NOT NULL
       AND NEW.run_token_sha256 IS DISTINCT FROM OLD.run_token_sha256 THEN
        RAISE EXCEPTION 'runs: the token of a started run can only be revoked'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("task_id", sa.Text, nullable=False),
        sa.Column("task_manifest_sha256", sa.String(64), nullable=False),
        sa.Column("profile_id", sa.Text, nullable=False),
        sa.Column("profile_version", sa.Integer, nullable=False),
        sa.Column("profile_sha256", sa.String(64), nullable=False),
        sa.Column("auth_mode", sa.Text, nullable=False),
        sa.Column("actor_user_id", UUID(as_uuid=True), sa.ForeignKey("workbench_users.id"), nullable=False),
        sa.Column("actor_oid", sa.String(36), nullable=False),
        sa.Column("actor_tid", sa.String(36), nullable=False),
        sa.Column("params", JSONB, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("run_token_sha256", sa.String(64), nullable=True),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", JSONB, nullable=True),
        sa.Column("outcome", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("run_token_sha256", name="uq_runs_run_token_sha256"),
        sa.ForeignKeyConstraint(["tenant_id", "actor_oid"], ["workbench_users.tenant_id", "workbench_users.oid"],
                                name="fk_runs_actor_member"),
        sa.CheckConstraint("status IN (" + ", ".join(f"'{s}'" for s in _STATUSES) + ")", name="ck_runs_status"),
        sa.CheckConstraint("auth_mode IN ('app_only', 'delegated')", name="ck_runs_auth_mode"),
        sa.CheckConstraint("actor_tid = tenant_id", name="ck_runs_actor_tenant"),
        sa.CheckConstraint(f"task_manifest_sha256 ~ '{_HEX64}'", name="ck_runs_manifest_hex"),
        sa.CheckConstraint(f"profile_sha256 ~ '{_HEX64}'", name="ck_runs_profile_hex"),
        sa.CheckConstraint(f"run_token_sha256 IS NULL OR run_token_sha256 ~ '{_HEX64}'", name="ck_runs_token_hex"),
        sa.CheckConstraint("profile_version >= 1", name="ck_runs_profile_version"),
        sa.CheckConstraint("jsonb_typeof(params) = 'object'", name="ck_runs_params_object"),
        sa.CheckConstraint("status <> 'running' OR (run_token_sha256 IS NOT NULL AND deadline_at IS NOT NULL)",
                           name="ck_runs_running_has_token"),
        sa.CheckConstraint("status NOT IN ('completed', 'failed', 'timed_out') OR run_token_sha256 IS NULL",
                           name="ck_runs_ended_token_revoked"),
    )
    op.create_index("ix_runs_tenant_id", "runs", ["tenant_id"])
    op.execute(_GUARD_FN)
    op.execute("REVOKE ALL ON FUNCTION public.clw_runs_guard_update() FROM PUBLIC")
    op.execute("""CREATE TRIGGER runs_guard_update BEFORE UPDATE ON public.runs
                  FOR EACH ROW EXECUTE FUNCTION public.clw_runs_guard_update()""")


def downgrade() -> None:
    op.execute("DROP TRIGGER runs_guard_update ON public.runs")
    op.execute("DROP FUNCTION public.clw_runs_guard_update()")
    op.drop_index("ix_runs_tenant_id", table_name="runs")
    op.drop_table("runs")
