"""Audited redaction of a stored run result (SD-037)

Revision ID: 20261025_result_redaction
Revises: 20261021_runs
Create Date: 2026-10-25

A completed run's result can hold personal data (the dormant accounts it
lists). This revision allows exactly one change to an ended run: clearing
`result` while setting the new `result_redacted_at`, once. Everything else
about an ended run stays final (runs_guard_update), and the change is only
made by the operator procedure (clw audit-redact-result), which first appends
a RESULT_REDACTED record carrying the removed result's SHA-256 to the
tenant's audit chain. The chain itself is not altered: RUN_COMPLETED keeps
its result_sha256, and the verifier reports the run as redacted rather than
as a result mismatch.

- runs.result_redacted_at: NULL, or set only together with result = NULL on
  a completed run (ck_runs_redaction).
- clw_runs_guard_update: as in 20261021_runs, except that an ended run may
  take the redaction change above and nothing else.
- audit_events: RESULT_REDACTED is a known event type.

No grants are made here: the application roles get no UPDATE on
result_redacted_at, so neither the api nor the runner nor the broker can
redact. The operator runs the command with the deployment's owner role.
"""

import sqlalchemy as sa
from alembic import op

revision = "20261025_result_redaction"
down_revision = "20261021_runs"
branch_labels = None
depends_on = None

_EVENT_TYPES_BEFORE = (
    "RUN_REQUESTED", "RUN_STARTED", "OP_DECISION", "CREDENTIAL_ACQUIRED", "CREDENTIAL_REJECTED",
    "GRAPH_REQUEST", "GRAPH_RESPONSE", "RUN_COMPLETED", "RUN_FAILED", "RUN_TIMED_OUT", "CHAIN_RECOVERY",
)
_EVENT_TYPES = (*_EVENT_TYPES_BEFORE, "RESULT_REDACTED")


def _known(types: tuple[str, ...]) -> str:
    return "event_type IN (" + ", ".join(f"'{t}'" for t in types) + ")"


# The 20261021_runs body with one change: the terminal-status check lets
# through exactly the redaction of a completed run's result. No backslashes
# in the body (SD-019).
_GUARD_BODY = r"""
CREATE OR REPLACE FUNCTION public.clw_runs_guard_update() RETURNS trigger
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
        IF NOT (OLD.status = 'completed'
                AND OLD.result IS NOT NULL AND NEW.result IS NULL
                AND OLD.result_redacted_at IS NULL AND NEW.result_redacted_at IS NOT NULL
                AND NEW.status IS NOT DISTINCT FROM OLD.status
                AND NEW.outcome IS NOT DISTINCT FROM OLD.outcome
                AND NEW.run_token_sha256 IS NOT DISTINCT FROM OLD.run_token_sha256
                AND NEW.deadline_at IS NOT DISTINCT FROM OLD.deadline_at
                AND NEW.started_at IS NOT DISTINCT FROM OLD.started_at
                AND NEW.ended_at IS NOT DISTINCT FROM OLD.ended_at) THEN
            RAISE EXCEPTION 'runs: a % run cannot change', OLD.status
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.result_redacted_at IS NOT NULL THEN
        RAISE EXCEPTION 'runs: only a completed run can be redacted'
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

# 20261021_runs, verbatim, for downgrade.
_GUARD_BEFORE = r"""
CREATE OR REPLACE FUNCTION public.clw_runs_guard_update() RETURNS trigger
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

_REFUSE_IF_REDACTED = r"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.runs WHERE result_redacted_at IS NOT NULL)
       OR EXISTS (SELECT 1 FROM public.audit_events WHERE event_type = 'RESULT_REDACTED') THEN
        RAISE EXCEPTION 'redactions exist; refusing to downgrade 20261025_result_redaction';
    END IF;
END
$$
"""


def upgrade() -> None:
    op.add_column("runs", sa.Column("result_redacted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        "ck_runs_redaction", "runs",
        "result_redacted_at IS NULL OR (status = 'completed' AND result IS NULL)")
    op.execute(_GUARD_BODY)
    op.drop_constraint("ck_audit_events_event_type_known", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_event_type_known", "audit_events", _known(_EVENT_TYPES))


def downgrade() -> None:
    op.execute(_REFUSE_IF_REDACTED)
    op.drop_constraint("ck_audit_events_event_type_known", "audit_events", type_="check")
    op.create_check_constraint("ck_audit_events_event_type_known", "audit_events", _known(_EVENT_TYPES_BEFORE))
    op.execute(_GUARD_BEFORE)
    op.drop_constraint("ck_runs_redaction", "runs", type_="check")
    op.drop_column("runs", "result_redacted_at")
