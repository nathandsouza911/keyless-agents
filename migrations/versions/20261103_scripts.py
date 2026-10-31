"""Scripts, their analyses and approvals; script runs (Part B, M4; SD-043)

Revision ID: 20261103_scripts
Revises: 20261102_audit_value_keys
Create Date: 2026-10-25

- scripts: a submitted script's text (at most 256 KiB), its SHA-256 and its
  submitter, per tenant. Never changed once stored (scripts_guard_update);
  approvals and runs bind to the digest, so an edited script is a new script.
- script_analyses: the offline analyser's output for a script: queued, then
  analyzed or failed. The analysis, the proposed manifest and the summary are
  written once, by the runner.
- script_approvals: a security lead's approval of one manifest for one script.
  script_approvals_guard_insert refuses, whatever the caller: an approver who
  is not a security_lead of the script's tenant, the script's own submitter, a
  digest that is not the script's, a script without a successful analysis, and
  any manifest entry whose method is not GET. Approvals are never changed.
- runs: kind ('task' | 'script'); a script run names its script and the
  approval it runs under (ck_runs_kind_binding); those columns never change
  once set (runs_guard_script_identity).
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "20261103_scripts"
down_revision = "20261102_audit_value_keys"
branch_labels = None
depends_on = None

_HEX64 = "^[0-9a-f]{64}$"

_IMMUTABLE_FN = r"""
CREATE FUNCTION public.clw_refuse_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION '%: rows cannot change', TG_TABLE_NAME USING ERRCODE = 'check_violation';
END;
$$
"""

_ANALYSIS_FN = r"""
CREATE FUNCTION public.clw_script_analyses_guard_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.script_id IS DISTINCT FROM OLD.script_id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'script_analyses: the identity of an analysis cannot change' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status IN ('analyzed', 'failed') THEN
        RAISE EXCEPTION 'script_analyses: a finished analysis cannot change' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT ((OLD.status = 'queued' AND NEW.status IN ('running', 'failed'))
            OR (OLD.status = 'running' AND NEW.status IN ('analyzed', 'failed'))) THEN
        RAISE EXCEPTION 'script_analyses: transition % -> % is not allowed', OLD.status, NEW.status
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""

_APPROVAL_FN = r"""
CREATE FUNCTION public.clw_script_approvals_guard_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    s public.scripts%ROWTYPE;
    approver_role text;
BEGIN
    SELECT * INTO s FROM public.scripts WHERE id = NEW.script_id;
    IF NOT FOUND OR s.tenant_id <> NEW.tenant_id OR s.sha256 <> NEW.script_sha256 THEN
        RAISE EXCEPTION 'script_approvals: not this tenant''s script, or not its digest' USING ERRCODE = 'check_violation';
    END IF;
    SELECT role INTO approver_role FROM public.workbench_users WHERE id = NEW.approved_by AND tenant_id = NEW.tenant_id;
    IF approver_role IS DISTINCT FROM 'security_lead' THEN
        RAISE EXCEPTION 'script_approvals: only a security lead of the tenant can approve' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.approved_by = s.submitted_by THEN
        RAISE EXCEPTION 'script_approvals: a script cannot be approved by its submitter' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.script_analyses a WHERE a.script_id = s.id AND a.status = 'analyzed') THEN
        RAISE EXCEPTION 'script_approvals: the script has no completed analysis' USING ERRCODE = 'check_violation';
    END IF;
    IF jsonb_typeof(NEW.manifest -> 'entries') IS DISTINCT FROM 'array'
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.manifest -> 'entries') e
                  WHERE (e ->> 'method') IS DISTINCT FROM 'GET') THEN
        RAISE EXCEPTION 'script_approvals: only GET entries can be approved' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""

_RUN_SCRIPT_FN = r"""
CREATE FUNCTION public.clw_runs_guard_script_identity() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.script_id IS DISTINCT FROM OLD.script_id
       OR NEW.approval_id IS DISTINCT FROM OLD.approval_id THEN
        RAISE EXCEPTION 'runs: the script identity of a run cannot change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""


def upgrade() -> None:
    op.create_table(
        "scripts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("text", sa.Text, nullable=False),
        sa.Column("submitted_by", UUID(as_uuid=True), sa.ForeignKey("workbench_users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "sha256", name="uq_scripts_tenant_sha256"),
        sa.CheckConstraint(f"sha256 ~ '{_HEX64}'", name="ck_scripts_sha256_hex"),
        sa.CheckConstraint("octet_length(text) BETWEEN 1 AND 262144", name="ck_scripts_text_size"),
    )
    op.create_table(
        "script_analyses",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("script_id", UUID(as_uuid=True), sa.ForeignKey("scripts.id"), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("analyser_version", sa.Text, nullable=True),
        sa.Column("analysis", JSONB, nullable=True),
        sa.Column("analysis_sha256", sa.String(64), nullable=True),
        sa.Column("proposed_manifest", JSONB, nullable=True),
        sa.Column("summary", JSONB, nullable=True),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('queued', 'running', 'analyzed', 'failed')", name="ck_script_analyses_status"),
        sa.CheckConstraint(f"analysis_sha256 IS NULL OR analysis_sha256 ~ '{_HEX64}'", name="ck_script_analyses_hex"),
        sa.CheckConstraint("status <> 'analyzed' OR (analysis IS NOT NULL AND analysis_sha256 IS NOT NULL "
                           "AND proposed_manifest IS NOT NULL AND summary IS NOT NULL)",
                           name="ck_script_analyses_analyzed_complete"),
        sa.CheckConstraint("status <> 'failed' OR reason IS NOT NULL", name="ck_script_analyses_failed_reason"),
    )
    op.create_index("ix_script_analyses_status", "script_analyses", ["status"])
    op.create_table(
        "script_approvals",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("script_id", UUID(as_uuid=True), sa.ForeignKey("scripts.id"), nullable=False),
        sa.Column("script_sha256", sa.String(64), nullable=False),
        sa.Column("manifest", JSONB, nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("approved_by", UUID(as_uuid=True), sa.ForeignKey("workbench_users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"manifest_sha256 ~ '{_HEX64}'", name="ck_script_approvals_manifest_hex"),
        sa.CheckConstraint(f"script_sha256 ~ '{_HEX64}'", name="ck_script_approvals_script_hex"),
    )
    op.add_column("runs", sa.Column("kind", sa.Text, nullable=False, server_default="task"))
    op.add_column("runs", sa.Column("script_id", UUID(as_uuid=True), sa.ForeignKey("scripts.id"), nullable=True))
    op.add_column("runs", sa.Column("approval_id", UUID(as_uuid=True), sa.ForeignKey("script_approvals.id"),
                                    nullable=True))
    op.create_check_constraint(
        "ck_runs_kind_binding", "runs",
        "(kind = 'task' AND script_id IS NULL AND approval_id IS NULL) "
        "OR (kind = 'script' AND script_id IS NOT NULL AND approval_id IS NOT NULL)")

    op.execute(_IMMUTABLE_FN)
    op.execute(_ANALYSIS_FN)
    op.execute(_APPROVAL_FN)
    op.execute(_RUN_SCRIPT_FN)
    for fn in ("clw_refuse_update()", "clw_script_analyses_guard_update()", "clw_script_approvals_guard_insert()",
               "clw_runs_guard_script_identity()"):
        op.execute(f"REVOKE ALL ON FUNCTION public.{fn} FROM PUBLIC")
    op.execute("CREATE TRIGGER scripts_guard_update BEFORE UPDATE ON public.scripts "
               "FOR EACH ROW EXECUTE FUNCTION public.clw_refuse_update()")
    op.execute("CREATE TRIGGER script_approvals_guard_update BEFORE UPDATE ON public.script_approvals "
               "FOR EACH ROW EXECUTE FUNCTION public.clw_refuse_update()")
    op.execute("CREATE TRIGGER script_approvals_guard_insert BEFORE INSERT ON public.script_approvals "
               "FOR EACH ROW EXECUTE FUNCTION public.clw_script_approvals_guard_insert()")
    op.execute("CREATE TRIGGER script_analyses_guard_update BEFORE UPDATE ON public.script_analyses "
               "FOR EACH ROW EXECUTE FUNCTION public.clw_script_analyses_guard_update()")
    op.execute("CREATE TRIGGER runs_guard_script_identity BEFORE UPDATE ON public.runs "
               "FOR EACH ROW EXECUTE FUNCTION public.clw_runs_guard_script_identity()")


def downgrade() -> None:
    op.execute("DROP TRIGGER runs_guard_script_identity ON public.runs")
    op.drop_constraint("ck_runs_kind_binding", "runs", type_="check")
    op.drop_column("runs", "approval_id")
    op.drop_column("runs", "script_id")
    op.drop_column("runs", "kind")
    op.drop_table("script_approvals")
    op.drop_table("script_analyses")
    op.drop_table("scripts")
    for fn in ("clw_runs_guard_script_identity()", "clw_script_approvals_guard_insert()",
               "clw_script_analyses_guard_update()", "clw_refuse_update()"):
        op.execute(f"DROP FUNCTION public.{fn}")
