"""Mutation check for the audit subsystem: each mutation must make the tests fail.

Run:  uv run python scripts/audit_mutation_check.py [name-substring ...]
Needs the compose Postgres for the pg-marked mutations (tests/db recreates
the test database and re-applies migrations on every run).

Each mutation is classified:
  KILLED    pytest exited 1 with test *failures* only, none of which is an
            infrastructure or collection problem, and (where EXPECT names
            tests for the mutation) those expected tests failed.
  SURVIVED  the tests passed with the mutation applied.
  BROKEN    anything else: target text not found exactly once, collection
            or setup errors (pytest "error"), exit codes other than 0/1,
            failures caused by infrastructure (database unreachable,
            import or syntax errors), or the expected tests did not fail.
            A BROKEN mutation proves nothing and fails the run.

Before any mutation, the union of the selected test paths is run unmutated
and must pass (--strict-baseline runs each set separately); otherwise the
run stops (exit 2) because no result would be meaningful.

Speed (no change to what counts as KILLED): each mutation first runs the
test file that killed it last time (scripts/audit_mutation_hints.json,
refreshed with --update-hints). If that file does not produce an
attributable failure, the mutation's full test set runs, so SURVIVED is
only reported after the full set passed with the mutation applied. If the
failing test already matches the EXPECT expression, the separate EXPECT
rerun is skipped. --no-hints runs every mutation's full test set
(see docs/testing.md, open item I-4).
Restores every file byte-for-byte, even on failure. Exit code 0 only if
every selected mutation is KILLED.
"""

import json
import os
import pathlib
import re
import subprocess
import sys
import time

UNIT = ["tests/unit/audit"]
CLI_UNIT = ["tests/unit/test_cli.py"]
DB = ["tests/db"]
ALL = ["tests/unit/audit", "tests/unit/test_cli.py", "tests/db"]

CHAIN = "src/clw/audit/chain.py"
EVENTS = "src/clw/audit/events.py"
CANON = "src/clw/audit/canonical.py"
WRITER = "src/clw/audit/writer.py"
WA = "src/clw/audit/write_ahead.py"
CKPT = "src/clw/audit/checkpoint.py"
CLI = "src/clw/cli.py"
M1 = "migrations/versions/20261014_audit_events.py"
M2 = "migrations/versions/20261015_audit_hardening.py"
M3 = "migrations/versions/20261016_audit_time_size.py"
M4 = "migrations/versions/20261017_audit_ts_session_free.py"
M5 = "migrations/versions/20261018_audit_text_limits.py"
M6 = "migrations/versions/20261019_audit_ts_no_escapes.py"
VERIFIER = "src/clw/audit/verifier.py"
REDACT = "src/clw/audit/redaction.py"
M7 = "migrations/versions/20261025_result_redaction.py"
REDACT_DB = ["tests/db/test_result_redaction.py"]
F_CANON = "src/clw/broker/facade/canonical.py"
F_POLICY = "src/clw/broker/facade/policy.py"
F_PAGES = "src/clw/broker/facade/pages.py"
F_HANDLER = "src/clw/broker/facade/handler.py"
F_UNIT = ["tests/security/test_facade_canonical.py", "tests/security/test_facade_policy.py",
          "tests/security/test_facade_pages.py", "tests/security/test_facade_transport.py"]
F_DB = ["tests/db/test_facade_service.py"]
F_HASH = "src/clw/broker/facade/hashing.py"
S_DEPS = "src/clw/api/deps.py"
S_ROUTES = "src/clw/api/routes/scripts.py"
S_RUNS = "src/clw/api/routes/runs.py"
S_MIG = "migrations/versions/20261103_scripts.py"
S_CAP = "src/clw/broker/capability.py"
S_SESSION_MIG = "migrations/versions/20261104_agent_sessions.py"
S_SESSIONS = "src/clw/api/routes/agent_sessions.py"
SESSION_TABLE_DB = ["tests/db/test_agent_sessions_table.py"]
SESSION_API_DB = ["tests/db/test_agent_sessions_api.py"]
S_GATEWAY = "src/clw/mcp_gateway/app.py"
GATEWAY_UNIT = ["tests/unit/test_mcp_gateway_auth.py"]
AGENT_READS_TESTS = ["tests/security/test_agent_reads.py", "tests/db/test_broker_agent_ops.py"]
PROPOSAL_TESTS = ["tests/db/test_broker_proposals.py"]
S_PROPOSAL_TPL = "src/clw/api/ui/templates/_proposal.html"
AGENT_UI_DB = ["tests/db/test_agent_ui_pages.py"]
DEMO_TESTS = ["tests/unit/test_demo_mode.py", "tests/db/test_demo_signin.py"]
S_APPROVALS = "src/clw/broker/facade/approvals.py"
S_LAUNCHER = "src/clw/runner/launcher.py"
S_ANALYSER = "src/clw/runner/analyser.py"
S_DB = ["tests/db/test_scripts.py"]
S_RESULT = "src/clw/runner/result.py"
R_DB = ["tests/db/test_script_runs.py"]
S_SPEC = "src/clw/runner/sandbox_spec.py"
SPEC_UNIT = ["tests/unit/runner/test_sandbox_spec.py", "tests/unit/test_script_sandbox.py"]
S_UI = "src/clw/api/ui/pages.py"
UI_DB = ["tests/db/test_ui_pages.py"]
F_HASH_TESTS = ["tests/security/test_facade_hashing.py", "tests/db/test_facade_service.py"]
TRANSPORT = "src/clw/broker/transport.py"
TIMEUTIL = "src/clw/common/timeutil.py"
# The schema guard is test infrastructure, but a weak guard lets a test leave
# the shared database weakened and every later test pass against it.
FINGERPRINT = "tests/db/schema_fingerprint.py"
DB_CONFTEST = "tests/db/conftest.py"
GUARD = ["tests/db/test_schema_guard.py", "tests/db/test_schema_guard_wiring.py"]

MUTATIONS = [
    # --- hashing / canonical form (SD-005)
    ("legacy defect: status/reason not hashed", CHAIN, UNIT,
     "return hashlib.sha256(DOMAIN_PREFIX + canonical_json(dict(fields))).hexdigest()",
     "return hashlib.sha256(DOMAIN_PREFIX + canonical_json({k: v for k, v in fields.items() if k not in ('status','reason')})).hexdigest()"),
    ("canonical keys unsorted", CANON, UNIT, "sort_keys=True", "sort_keys=False"),
    ("floats accepted", CANON, UNIT,
     "    if value is None or isinstance(value, bool):\n        return",
     "    if value is None or isinstance(value, (bool, float)):\n        return"),
    ("no depth limit (L1)", CANON, UNIT, "    if depth > MAX_DEPTH:\n", "    if False:\n"),
    # --- chain integrity
    ("no link check", CHAIN, UNIT, "            elif record.previous_hash != previous_hash:", "            elif False:"),
    ("no seq check", CHAIN, UNIT, "            elif seq != expected_seq:", "            elif False:"),
    ("record hash not compared", CHAIN, UNIT,
     "        if not (isinstance(record.record_hash, str) and hmac.compare_digest(derived, record.record_hash)):",
     "        if False:"),
    ("event shape not enforced on write", CHAIN, UNIT,
     "    if problems:\n        raise AuditEventInvalid", "    if False:\n        raise AuditEventInvalid"),
    ("malformed record crashes integrity checks (L1)", CHAIN, UNIT,
     '        except Exception as exc:  # malformed input must become a finding, never a crash\n'
     '            findings.append(ChainError(-1, "invalid_record", f"{type(exc).__name__}: {exc}"[:200]))\n'
     '    try:\n        findings += _timestamp_findings(',
     '        except ZeroDivisionError as exc:\n'
     '            findings.append(ChainError(-1, "invalid_record", f"{type(exc).__name__}: {exc}"[:200]))\n'
     '    try:\n        findings += _timestamp_findings('),
    # The try/except around _timestamp_findings is defensive: it only receives
    # validated timestamps (year 1 handled), so removing it is an equivalent
    # mutant and is not listed.
    ("malformed record crashes transition checks (L1)", CHAIN, UNIT,
     "            _step(record, runs, by_seq, bad)\n        except Exception as exc:",
     "            _step(record, runs, by_seq, bad)\n        except ZeroDivisionError as exc:"),
    ("malformed seq indexed for citation (L1)", CHAIN, UNIT,
     "        if _is_int(record.seq):  # only well-formed records can be cited by later ones\n"
     "            by_seq.setdefault(record.seq, record)",
     "        by_seq.setdefault(record.seq, record)"),
    # --- H3 verifier checks
    ("schema version not checked (H3)", EVENTS, UNIT,
     "    if not (_type_ok(\"schema_version\", version) and version in SUPPORTED_SCHEMA_VERSIONS):",
     "    if False:"),
    ("created_at format not checked (H3)", EVENTS, UNIT,
     "    if not valid_created_at(created_at):\n        problems.append", "    if False:\n        problems.append"),
    ("created_at monotonicity not checked (H3)", CHAIN, UNIT,
     "        if last_trusted is not None and t < last_trusted:",
     "        if False:"),
    # --- M1 approval binding
    ("stale approval accepted (M1)", CHAIN, UNIT, "            and latest is decision", "            and True"),
    ("denied decision accepted as approval (M1)", CHAIN, UNIT,
     '            and decision.status == "allowed"', "            and True"),
    ("one approval, many attempts (M1)", CHAIN, UNIT,
     "        elif record.decision_seq in run.used_decisions:", "        elif False:"),
    ("request not bound to approved method/template (M1)", CHAIN, UNIT,
     "        elif (record.http_method, record.path_template) != (decision.http_method, decision.path_template):",
     "        elif False:"),
    ("any request target accepted (M1)", EVENTS, UNIT,
     "    if not (isinstance(target, str) and valid_path_template(template)):\n        return False",
     "    return True"),
    ("allowed decision need not name method (M1)", EVENTS, UNIT,
     '        if status == "allowed" and (values["http_method"] is None or values["path_template"] is None):',
     "        if False:"),
    # --- L5 state machine
    ("work before run started accepted (L5)", CHAIN, UNIT,
     '    if run.state != "started":\n        bad(record, "run_not_started")',
     '    if False:\n        bad(record, "run_not_started")'),
    ("request without credential accepted (L5)", CHAIN, UNIT,
     '        if run.credential != "acquired":', "        if False:"),
    ("completion with open requests accepted (L5)", CHAIN, UNIT, "        if run.outstanding:", "        if False:"),
    ("events after run end accepted (L5)", CHAIN, UNIT,
     '    if run.state == "ended":\n        bad(record, "event_after_run_end")',
     '    if False:\n        bad(record, "event_after_run_end")'),
    ("intents hidden", CHAIN, UNIT,
     "    intents = sorted(r.seq for run in runs.values() for r in run.outstanding.values() if _is_int(r.seq))",
     "    intents = []"),
    ("result binding ignored", CHAIN, UNIT,
     '    return "ok" if hmac.compare_digest(expected, actual) else "result_mismatch"', '    return "ok"'),
    # --- writer / H2
    ("writer fails open", WRITER, ALL,
     'raise AuditUnavailable(f"audit append failed for chain {chain_id}") from exc', "return None"),
    ("writer without advisory lock", WRITER, DB,
     '            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),', '            text("SELECT :key"),'),
    ("writer extends a compromised chain (H2)", WRITER, DB,
     "        blocking = blocking_findings(records, findings)\n        if blocking:",
     "        blocking = []\n        if blocking:"),
    ("recovery ignores inspected head (H2)", WRITER, DB,
     "                    if head.record_hash != expected_head_hash:", "                    if False:"),
    ("recovery from a dirty record accepted (H2)", CHAIN, ALL,
     "            if record.event_type != EventType.CHAIN_RECOVERY or record.seq in dirty:",
     "            if record.event_type != EventType.CHAIN_RECOVERY:"),
    ("request sent despite missing intent", WA, ALL,
     'raise AuditUnavailable("intent not recorded; request not sent") from exc', "pass"),
    ("data released despite missing outcome", WA, ALL,
     '        del result  # withhold: nothing derived from the response leaves this function\n'
     '        raise AuditUnavailable("response not recorded; data withheld") from exc',
     "        return result"),
    # --- database (H1 / H2 / H3)
    ("DB trigger lets UPDATE/DELETE through", M2, DB,
     "    RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP",
     "    RETURN COALESCE(NEW, OLD);\n    RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP"),
    ("DB accepts inserts that do not extend the head", M4, DB,
     "    ELSIF NEW.seq <> head_seq + 1 OR NEW.previous_hash <> head_hash THEN", "    ELSIF false THEN"),
    ("H1: trigger reads unqualified table", M4, DB,
     "      FROM public.audit_events AS e", "      FROM audit_events AS e"),
    ("H1: TEMP not revoked from PUBLIC", M2, DB,
     "           EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());",
     "           NULL;"),
    ("H1: search_path not pinned", M4, DB,
     "CREATE OR REPLACE FUNCTION public.clw_audit_events_check_append() RETURNS trigger\n"
     "LANGUAGE plpgsql\nSET search_path = pg_catalog, pg_temp\n",
     "CREATE OR REPLACE FUNCTION public.clw_audit_events_check_append() RETURNS trigger\nLANGUAGE plpgsql\n"),
    ("DB accepts backdated insert (H3)", M4, DB,
     '       AND (NEW.created_at COLLATE "C") < (head_created COLLATE "C") THEN', "       AND false THEN"),
    ("DB hash format unconstrained (H2)", M2, DB,
     """    ("ck_audit_events_record_hash_hex", "record_hash ~ '^[0-9a-f]{64}$'"),\n""", ""),
    # The H2 depth constraint of 20261015 is dropped by 20261016 and folded
    # into ck_audit_events_details_bounds, so the live check is mutated there
    # (removing the 20261015 one only breaks the later migration: BROKEN).
    ("DB details depth unconstrained (H2)", M3, DB,
     '    "WHEN public.clw_jsonb_depth(details) > 15 THEN false "', '    "WHEN false THEN false "'),
    # Without the cheap length pre-check first, huge details run the costly recursive checks (N8).
    ("DB huge details skip the cheap length pre-check (N8)", M3, ["tests/db/test_audit_time_size.py"],
     '    "CASE WHEN octet_length(details::text) > 131072 THEN false "', '    "CASE WHEN false THEN false "'),
    # --- checkpoints (SD-006, M2, H2)
    ("checkpoint signature not checked", CKPT, UNIT,
     "        public_key.verify(signature, canonical_json(payload))", "        pass"),
    ("checkpoint ignores truncation", CKPT, UNIT,
     '    if len(covered) != checkpoint["record_count"]:\n        return "truncated"',
     '    if not covered:\n        return "truncated"'),
    ("checkpoint compares head hash only (M2)", CKPT, UNIT,
     '    if not hmac.compare_digest(chain_fingerprint(covered), checkpoint["chain_fingerprint"]):',
     '    if covered[-1].record.record_hash != checkpoint["head_record_hash"]:'),
    ("INVALID checkpoint accepted as ok (H2)", CKPT, UNIT,
     '    if checkpoint["status"] != "VALID":\n        return "checkpoint_marks_chain_invalid"',
     '    if False:\n        return "checkpoint_marks_chain_invalid"'),
    ("checkpoint signs an invalid chain silently", CKPT, UNIT,
     "    if not report.valid and not allow_invalid:", "    if False:"),
    # --- CLI (reviewer survivors M24 and M41, L2, L4)
    ("CLI verify ignores chain validity (M2/M24)", CLI, DB,
     '    return OK if (report.valid and result == "ok") else FAILED', '    return OK if result == "ok" else FAILED'),
    ("checkpoint file overwritten (L3/M41)", CLI, DB,
     "    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, \"O_BINARY\", 0)",
     "    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, \"O_BINARY\", 0)"),
    ("key load errors not mapped to config (L2)", CLI, CLI_UNIT,
     "    except (OSError, ValueError, TypeError) as exc:\n        raise _ConfigError",
     "    except KeyError as exc:\n        raise _ConfigError"),
    ("private key not restricted (L4)", CLI, CLI_UNIT,
     "        if private and os.name == \"nt\":\n            _restrict_to_owner_windows(path)",
     "        if False:\n            _restrict_to_owner_windows(path)"),
    ("private key not restricted on POSIX (L4)", CLI, CLI_UNIT,
     "    fd = os.open(path, flags, 0o600 if private else 0o644)",
     "    fd = os.open(path, flags, 0o644)"),
    # --- third-round findings (N1-N9, Requirements A and B)
    ("N2: DB accepts impossible calendar dates", M3, DB,
     """    op.create_check_constraint("ck_audit_events_created_at_valid", "audit_events",
                               "public.clw_valid_created_at(created_at)")""", "    pass"),
    ("N2: DB date validator accepts anything", M6, DB,
     "    IF (t COLLATE \"C\") !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$' THEN\n        RETURN false;",
     "    IF false THEN\n        RETURN false;"),
    ("N3: DB accepts far-future created_at", M4, DB,
     '    IF (NEW.created_at COLLATE "C") > (limit_ts COLLATE "C") THEN', "    IF false THEN"),
    ("N2: DB applies ordering against a corrupt head", M4, DB,
     '       AND public.clw_valid_created_at(head_created)\n       AND (head_created COLLATE "C") <= (limit_ts COLLATE "C")\n',
     ""),
    # --- fourth-round findings (M-1 session settings)
    ("M-1: validator parses in the session TimeZone again", M6, DB,
     "    PERFORM pg_catalog.make_date(substr(t, 1, 4)::integer, substr(t, 6, 2)::integer, substr(t, 9, 2)::integer);\n"
     "    RETURN true;",
     "    RETURN pg_catalog.to_char(pg_catalog.to_timestamp(substr(t, 1, 26), 'YYYY-MM-DD\"T\"HH24:MI:SS.US')\n"
     "                              AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') = substr(t, 1, 26)\n"
     "           AND substr(t, 1, 4) <> '0000';"),
    ("M-1: validator ignores hour/minute/second ranges", M6, DB,
     "    IF substr(t, 12, 2)::integer > 23 OR substr(t, 15, 2)::integer > 59 OR substr(t, 18, 2)::integer > 59 THEN",
     "    IF false THEN"),
    ("M-1: validator ignores impossible calendar dates", M6, DB,
     "    PERFORM pg_catalog.make_date(substr(t, 1, 4)::integer, substr(t, 6, 2)::integer, substr(t, 9, 2)::integer);",
     "    NULL;"),
    ("M-1: existing rows not re-validated on upgrade", M4, DB, "    op.execute(_REVALIDATE)", "    pass"),
    # --- fifth-round findings (F-3 escapes in function bodies)
    ("F-3: validator pattern uses a backslash escape again", M6, DB,
     "[0-9]{2}:[0-9]{2}[.][0-9]{6}Z$", "[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z$"),
    # --- fifth-round findings (F-4 checkpoint range cross-check)
    ("F-4: signed range and head not cross-checked", CKPT, UNIT,
     '    if (checkpoint["seq_from"], checkpoint["seq_to"], checkpoint["head_record_hash"]) != _range_of(covered):',
     "    if False:"),
    ("F-4: only seq_from cross-checked", CKPT, UNIT,
     '    if (checkpoint["seq_from"], checkpoint["seq_to"], checkpoint["head_record_hash"]) != _range_of(covered):',
     '    if checkpoint["seq_from"] != _range_of(covered)[0]:'),
    ("F-4: head not cross-checked", CKPT, UNIT,
     '    if (checkpoint["seq_from"], checkpoint["seq_to"], checkpoint["head_record_hash"]) != _range_of(covered):',
     '    if (checkpoint["seq_from"], checkpoint["seq_to"]) != _range_of(covered)[:2]:'),
    # --- fifth-round findings (F-5 recovery evidence; reviewer mutants R1, R5, R9)
    ("F-5: latest instead of earliest later recovery is the evidence (R1)", CHAIN, UNIT,
     "        if is_recovery and (running is None or t < running):",
     "        if is_recovery and (running is None or t > running):"),
    ("F-5: records below the baseline can vouch (R5)", CHAIN, UNIT,
     "            can_be_vouched = later.range(lo, len(order)) > 0",
     "            can_be_vouched = later.range(0, len(order)) > 0"),
    ("L-3: timeouts set for the session, not the transaction (R9)", WRITER, DB,
     'text(f"SET LOCAL lock_timeout = {lock_ms}")', 'text(f"SET lock_timeout = {lock_ms}")'),
    # Equivalent mutants from the fourth review, deliberately not listed:
    # - R6 recovery_record may acknowledge its own or later seqs: a recovery
    #   with a finding at its own seq is dirty and acknowledges nothing, and
    #   append_recovery refuses one that leaves blocking findings.
    # - R7 recovery_record's exposure judged with the host clock instead of
    #   the database clock: findings on earlier records after the recovery is
    #   appended are evidence-based or provisional; append_recovery re-checks
    #   the result with the database clock before insert and re-verifies after
    #   commit, so a wrong clock there can only cause a refusal (fail closed).
    # - R8 anchor kept after a compromise: the next attempt re-reads the same
    #   records after the anchor and refuses again; append_recovery drops it.
    # - the try/except around _timestamp_findings (see above).
    # --- sixth-round findings (L-C platform-independent timestamps)
    ("L-C: timestamps formatted with the platform strftime again", TIMEUTIL, ["tests/unit/test_timeutil.py", "tests/unit/audit"],
     '    return (f"{u.year:04d}-{u.month:02d}-{u.day:02d}T{u.hour:02d}:{u.minute:02d}:{u.second:02d}"\n'
     '            f".{u.microsecond:06d}Z")',
     '    return u.strftime("%Y-%m-%dT%H:%M:%S.%fZ")'),
    # --- sixth-round findings (L-A, L-B; reviewer gaps S1, S5, S7, S8, S11, S15, S17)
    ("L-A: stale cache refuses without full verification", WRITER, DB,
     "            # Any finding at all, even one acknowledged inside the segment,\n",
     "            raise AuditChainCompromised(chain_id, [(f.seq, f.issue) for f in blocking_findings(records, findings)])\n"
     "            # Any finding at all, even one acknowledged inside the segment,\n"),
    ("L-B: recovery may leave provisional findings", WRITER, DB,
     "                    if provisional:\n                        target",
     "                    if False:\n                        target"),
    ("L-B: cached while an acknowledged provisional finding exists", WRITER, DB,
     "        return (records[-1] if records else None), not _provisional(findings)",
     "        return (records[-1] if records else None), True"),
    # Equivalent: the post-commit re-verification's provisional clause. The
    # pre-insert check refuses any recovery that would leave a provisional
    # finding, so a provisional finding after commit is new, unacknowledged
    # and therefore already blocking (test_recovery_is_incomplete_if_the_
    # clock_steps_back_before_re_verification shows the step-back case).
    ("S1: cached-position window doubled (10 min)", WRITER, ALL,
     "            return valid_created_at(anchor.created_at) and not is_future(anchor.created_at, now)",
     "            return valid_created_at(anchor.created_at) and not is_future(anchor.created_at, now + MAX_FUTURE_SKEW)"),
    ("S7: incremental check uses the host clock", WRITER, DB,
     "            findings = integrity_findings(records, chain_id=chain_id, anchor=anchor, now=now)",
     "            findings = integrity_findings(records, chain_id=chain_id, anchor=anchor)"),
    ("S7: full check uses the host clock", WRITER, DB,
     "        records = await load_chain(session, chain_id=chain_id)\n"
     "        findings = integrity_findings(records, chain_id=chain_id, now=now)",
     "        records = await load_chain(session, chain_id=chain_id)\n"
     "        findings = integrity_findings(records, chain_id=chain_id)"),
    ("S8: incremental check ignores the cached record's timestamp", CHAIN, ["tests/unit/audit", "tests/db"],
     "        findings += _timestamp_findings(stamps, None if anchor is None else anchor.created_at, now)",
     "        findings += _timestamp_findings(stamps, None, now)"),
    ("S5: single-record range treated as unusable", CKPT, ["tests/unit/audit", "tests/db"],
     "    if seq_from is None or seq_to is None or seq_from > seq_to:",
     "    if seq_from is None or seq_to is None or seq_from >= seq_to:"),
    ("S11: no-baseline evidence boundary inclusive", CHAIN, UNIT,
     "            evidence = recovery is not None and recovery < bound",
     "            evidence = recovery is not None and recovery <= bound"),
    ("S15: loader does not order by seq", VERIFIER, DB,
     "        .order_by(AuditEventRow.seq)\n", "\n"),
    ("S17: VALID checkpoint accepted with findings", CKPT, UNIT,
     '    return (status == "INVALID") == bool(findings)',
     '    return status == "VALID" or bool(findings)'),
    # --- seventh-round findings (targeted review R1, R2)
    ("R1: fast path accepts findings acknowledged inside the segment", WRITER, DB,
     "            if not findings:\n                return (records[-1] if records else anchor), True",
     "            if not blocking_findings(records, findings) and not _provisional(findings):\n"
     "                return (records[-1] if records else anchor), True"),
    ("R2: retry target is the earliest record ahead, not the latest", WRITER, DB,
     "    latest = max(created_at for created_at, _ in ahead)", "    latest = min(created_at for created_at, _ in ahead)"),
    ("R2: refusals give no retry target", WRITER, DB,
     "                    wait = _wait_target(records, now)", "                    wait = None"),
    # --- final review I-2 (which seq the retry message names). Computing the
    # target over the records plus the recovery being built (reviewer's
    # mutation G) is now equivalent: a tie names the first record with that
    # timestamp, and the recovery has the highest seq.
    ("I-2: tie names the last copy, not the first record", WRITER, ALL,
     "    return min(seq for created_at, seq in ahead if created_at == latest), latest",
     "    return max(seq for created_at, seq in ahead if created_at == latest), latest"),
    ("I-2: provisional message names the last provisional seq", WRITER, ALL,
     '                        target = wait or (provisional[-1], "unknown")',
     '                        target = (provisional[-1], wait[1]) if wait else (provisional[-1], "unknown")'),
    ("I-2: malformed timestamps can be the retry target", WRITER, ALL,
     "             if valid_created_at(r.created_at) and isinstance(r.seq, int) and r.created_at > limit]",
     "             if isinstance(r.created_at, str) and isinstance(r.seq, int) and r.created_at > limit]"),
    # --- final review L-1 / I-1 (schema guard and its wiring)
    ("L-1: guard ignores constraint definitions", FINGERPRINT, GUARD,
     "SELECT conname, pg_get_constraintdef(oid, true), convalidated", "SELECT conname, '', convalidated"),
    ("L-1: guard ignores function bodies", FINGERPRINT, GUARD, "md5(p.prosrc)", "md5('')"),
    ("L-1: guard ignores trigger enabled state", FINGERPRINT, GUARD,
     "pg_get_triggerdef(oid, true), tgenabled::text", "pg_get_triggerdef(oid, true), 'O'"),
    ("L-1: guard compares row names only", FINGERPRINT, GUARD,
     "        before, after = set(reference.get(name, ())), set(current.get(name, ()))",
     "        before, after = {r[:1] for r in reference.get(name, ())}, {r[:1] for r in current.get(name, ())}"),
    ("L-1: guard ignores database privileges", FINGERPRINT, GUARD,
     "coalesce(datacl::text, '<default>')", "''"),
    ("L-1: guard ignores schema privileges", FINGERPRINT, GUARD,
     "coalesce(nspacl::text, '<default>')", "''"),
    ("L-1: guard ignores rules", FINGERPRINT, GUARD,
     "FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class", "FROM pg_rewrite r JOIN pg_class c ON false"),
    ("L-1: guard ignores indexes", FINGERPRINT, GUARD,
     "FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid", "FROM pg_index i JOIN pg_class c ON false"),
    ("L-1: guard ignores column defaults", FINGERPRINT, GUARD,
     "coalesce(pg_get_expr(d.adbin, d.adrelid), '')", "''"),
    ("L-1: guard ignores STRICT", FINGERPRINT, GUARD, "p.prosecdef, p.proisstrict,", "p.prosecdef, true,"),
    ("L-1: guard ignores function privileges", FINGERPRINT, GUARD,
     "p.proowner::regrole::text, coalesce(p.proacl::text, '<default>')", "p.proowner::regrole::text, ''"),
    ("L-1: guard sees clw_ functions only", FINGERPRINT, GUARD,
     "FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace",
     "FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'clw!_%' ESCAPE '!'"),
    ("L-1: guard ignores role-level settings", FINGERPRINT, GUARD,
     "         WHERE s.setdatabase = 0\n            OR", "         WHERE false\n            OR"),
    ("L-1: guard ignores role attributes", FINGERPRINT, GUARD,
     "r.rolreplication, r.rolbypassrls,", "r.rolreplication, false,"),
    ("I-1: guard compares the current schema with itself", DB_CONFTEST, GUARD,
     "    differences = schema_differences(reference, current)",
     "    differences = schema_differences(current, current)"),
    ("I-1: guard never runs", DB_CONFTEST, GUARD,
     '    if request.node.get_closest_marker("pg") is None or "pg_dsn" not in request.fixturenames:',
     "    if True:"),
    ("I-1: guard result ignored", DB_CONFTEST, GUARD,
     '    assert differences == [], "test left the audit schema changed: "',
     '    assert True, "test left the audit schema changed: "'),
    # The validator moved to 20261019; its predecessor in 20261017 is replaced
    # on upgrade, so mutating it there is equivalent. The 20261019 re-validation
    # cannot fire: no storable row passes the old function but fails the new
    # one (the format CHECK already rejects them), so removing it is equivalent.
    # COLLATE "C" in the trigger is defence in depth: for strings that pass the
    # format check, en_US and C order identically, so removing it is an
    # equivalent mutant and is deliberately not listed.
    ("N2: next_record copies any later head timestamp", CHAIN, UNIT,
     "            and valid_created_at(head_created)\n            and stamp < head_created\n            and not is_future(head_created, created_at)",
     "            and stamp < str(head_created)"),
    ("N2: ordering reference taken from a flagged timestamp", CHAIN, UNIT,
     '            found.append(ChainError(seq, "created_at_in_future", "more than 5 minutes ahead of a later record"))',
     '            found.append(ChainError(seq, "created_at_in_future", "more than 5 minutes ahead of a later record")); last_trusted = t'),
    ("N3: verifier ignores a future newest record", CHAIN, UNIT,
     "        elif not can_be_vouched and t > limit_now:", "        elif False:"),
    ("N3: writer self-check ignores future timestamps", EVENTS, ALL,
     "    elif now is not None and is_future(created_at, now):", "    elif False:"),
    # --- fourth-round findings (M-2 durable timestamp anomalies)
    ("M-2: no chain evidence (wall clock decides)", CHAIN, UNIT,
     "        if evidence:\n", "        if False:\n"),
    ("M-2: later records below the baseline count as evidence", CHAIN, UNIT,
     "            lo = bisect_left(order, last_trusted)\n", "            lo = 0\n"),
    ("M-2: any later record is evidence without a baseline", CHAIN, UNIT,
     "        if is_recovery and (running is None or t < running):", "        if running is None or t < running:"),
    ("M-2: verifier clock applied to vouched-for records", CHAIN, UNIT,
     "        elif not can_be_vouched and t > limit_now:", "        elif t > limit_now:"),
    ("M-2: recovery does not acknowledge what it exposes", CHAIN, UNIT,
     "    if not exposed <= acknowledged:", "    if False:"),
    ("M-2: invalid recovery state hidden", CHAIN, UNIT,
     '    elif any(e.issue == "invalid_recovery" for e in unacked):', "    elif False:"),
    ("M-2: recovered chain reported clean", CHAIN, UNIT,
     '        state = "recovered"', '        state = "clean"'),
    ("M-2: provisional findings not reported", CHAIN, UNIT,
     "        provisional=tuple(e for e in integrity if e.detail.startswith(PROVISIONAL)),", "        provisional=(),"),
    # --- fourth-round findings (L-1 text limits)
    ("L-1: writer has no text limit", EVENTS, UNIT,
     "        elif text_too_long(name, value):", "        elif False:"),
    ("L-1: chain_id length unchecked", EVENTS, UNIT,
     ' or text_too_long("chain_id", values.get("chain_id")):', ":"),
    ("L-1: request_target given the general limit", EVENTS, UNIT,
     '    return MAX_REQUEST_TARGET_BYTES if name == "request_target" else MAX_TEXT_BYTES',
     "    return MAX_TEXT_BYTES"),
    ("L-1: writer counts characters, not UTF-8 bytes", EVENTS, UNIT,
     '    return len(value.encode("utf-8", "surrogatepass")) > text_limit(name)',
     "    return len(value) > text_limit(name)"),
    ("L-1: database has no text limit", M5, DB,
     '    op.create_check_constraint("ck_audit_events_text_bounds", "audit_events", TEXT_BOUNDS)', "    pass"),
    ("L-1: database counts characters, not bytes", M5, DB,
     """    [f"octet_length(coalesce({c}, '')) <= 1024" for c in TEXT_COLUMNS]""",
     """    [f"char_length(coalesce({c}, '')) <= 1024" for c in TEXT_COLUMNS]"""),
    ("L-1: database request_target unbounded", M5, DB,
     """    + ["octet_length(coalesce(request_target, '')) <= 4096"]""", """    + ["true"]"""),
    ("L-1: migration does not check existing rows first", M5, DB,
     "    op.execute(_PRECHECK)", "    pass"),
    # --- fourth-round findings (L-2, L-3, checkpoint tenant)
    ("L-2: checkpoint key_id format not checked", CKPT, ALL,
     '    if not HEX64_RE.fullmatch(cp["key_id"]):', "    if False:"),
    ("checkpoint tenant_id not compared (review 3 info)", CKPT, UNIT,
     '    if checkpoint["chain_id"] != chain_id or checkpoint["tenant_id"] != chain_id:',
     '    if checkpoint["chain_id"] != chain_id:'),
    ("L-3: no lock timeout", WRITER, DB,
     '        await session.execute(text(f"SET LOCAL lock_timeout = {lock_ms}"))', "        pass"),
    ("L-3: no statement timeout", WRITER, DB,
     '        await session.execute(text(f"SET LOCAL statement_timeout = {statement_ms}"))', "        pass"),
    ("L-3: timeout values not validated", WRITER, DB,
     "        if not all(type(v) is int and v > 0 for v in (lock_timeout_ms, statement_timeout_ms)):",
     "        if False:"),
    # --- fifth-round findings (F-1 cached writer position)
    ("F-1: cached position never re-checked against the clock", WRITER, DB,
     "        if anchor is not None and not self._anchor_trustworthy(anchor, now):", "        if False:"),
    ("F-1: any cached position trusted", WRITER, DB,
     "            return valid_created_at(anchor.created_at) and not is_future(anchor.created_at, now)",
     "            return True"),
    ("F-1: malformed cached timestamp trusted", WRITER, DB,
     "            return valid_created_at(anchor.created_at) and not is_future(anchor.created_at, now)",
     "            return not is_future(anchor.created_at, now)"),
    ("N3: writer uses its local clock for records", WRITER, DB,
     "                    record = next_record(head, chain_id=chain_id, event=event, created_at=now)",
     "                    record = next_record(head, chain_id=chain_id, event=event, created_at=self._clock())"),
    ("N3: no clock-drift alert", WRITER, DB,
     "        if abs(local - now) > MAX_FUTURE_SKEW:", "        if False:"),
    ("writer skips self-check before insert", WRITER, DB,
     "        if problems:\n            raise AuditEventInvalid(f\"refusing", "        if False:\n            raise AuditEventInvalid(f\"refusing"),
    ("N4: recovery predecessor not checked", CHAIN, UNIT,
     '            if details.get("observed_head_seq") != record.seq - 1:', "            if False:"),
    ("N4: recovery head hash not checked", CHAIN, UNIT,
     '            if details.get("observed_head_hash") != record.previous_hash:', "            if False:"),
    ("N4: recovery may acknowledge non-existent findings", CHAIN, UNIT,
     "            elif not acknowledged <= prior:", "            elif False:"),
    ("N4: recovery may acknowledge later findings", CHAIN, UNIT,
     "            prior = {(f.seq, f.issue) for f in (*base, *found) if 1 <= f.seq < record.seq}",
     "            prior = {(f.seq, f.issue) for f in (*base, *found)}"),
    ("N4: recoveries hidden from the report", CHAIN, UNIT,
     "        recoveries=recovery_summary(records, integrity),", "        recoveries=(),"),
    ("Req B: recovery written even if it would not restore appends", WRITER, DB,
     "                    if remaining:\n                        # Targeted review R2",
     "                    if False:\n                        # Targeted review R2"),
    ("Req B: recovery not re-verified after commit", WRITER, DB,
     "        if still:\n            alert_log.critical(\"audit_chain_recovery_incomplete",
     "        if False:\n            alert_log.critical(\"audit_chain_recovery_incomplete"),
    ("N5: timestamp digits accept non-ASCII", EVENTS, UNIT,
     'CREATED_AT_RE = re.compile(r"[0-9]{4}-', 'CREATED_AT_RE = re.compile(r"\\d{4}-'),
    ("N5: hex pattern allows trailing newline", EVENTS, UNIT,
     '        and bool(HEX64_RE.fullmatch(details["observed_head_hash"]))',
     '        and bool(re.match(r"^[0-9a-f]{64}$", details["observed_head_hash"]))'),
    ("N6: placeholders may be reserved segments", EVENTS, UNIT,
     "        if lowered in _RESERVED_SEGMENT_VALUES or lowered.startswith(_RESERVED_SEGMENT_PREFIXES):",
     "        if False:"),
    ("N6: template may start with a placeholder", EVENTS, UNIT,
     '_TEMPLATE_RE = re.compile(rf"/{_LITERAL}(/(?:{_LITERAL}|{_PLACEHOLDER}))*")',
     '_TEMPLATE_RE = re.compile(rf"(/(?:{_LITERAL}|{_PLACEHOLDER}))+")'),
    ("N8: writer has no details size limit", EVENTS, UNIT,
     "if size > MAX_DETAILS_BYTES else []", "if False else []"),
    ("N8: database has no details size limit", M3, DB,
     '    "ELSE public.clw_jsonb_compact_size(details) <= 65536 END"', '    "ELSE true END"'),
    ("N8: no cheap pre-check before recursive work", M3, DB,
     '    "CASE WHEN octet_length(details::text) > 131072 THEN false "', '    "CASE WHEN false THEN false "'),
    ("N9: anchor cache unbounded", WRITER, DB,
     "        while len(self._anchors) > self._max_anchors:", "        while False:"),
    ("N9: chain id not validated", CLI, DB,
     "    if not _CHAIN_ID_RE.fullmatch(value):", "    if False:"),
    ("N7: deep checkpoint file crashes CLI", CLI, DB,
     "    except (OSError, ValueError, RecursionError) as exc:  # N7: deeply nested files too",
     "    except (OSError, ValueError) as exc:"),
    ("N1: fingerprint uses re-serialized details", CKPT, UNIT,
     '        value = stored.details_text if name == "details" else getattr(stored.record, name)',
     '        value = repr(stored.record.details) if name == "details" else getattr(stored.record, name)'),
    ("N1: fingerprint not length-prefixed", CKPT, UNIT,
     '        return b"S" + str(len(raw)).encode() + b":" + raw', '        return b"S" + raw'),
    ("Req A: UNAVAILABLE checkpoint accepted as ok", CKPT, UNIT,
     '    if checkpoint["status"] == "UNAVAILABLE":\n        return "checkpoint_unavailable"',
     '    if False:\n        return "checkpoint_unavailable"'),
    ("Req A: VALID checkpoint may start mid-chain", CKPT, UNIT,
     '    if status == "VALID" and not (cp["seq_from"] == 1 and', '    if status == "VALID" and not (True and'),
    ("loader re-parses details for fingerprints", VERIFIER, DB,
     "            row[\"details\"],\n        )", "            json.dumps(_parse_details(row[\"details\"])),\n        )"),
    # --- result redaction (SD-037)
    ("redaction record shape not enforced", EVENTS, UNIT,
     "        problems += _redaction_problems(details)", "        problems += []"),
    ("redaction of a run that never completed accepted", CHAIN, UNIT,
     "        if target is None or target.completed is None:", "        if target is None:"),
    ("second redaction of a run accepted", CHAIN, UNIT, "        elif target.redacted:", "        elif False:"),
    ("redaction digest not compared with the completion", CHAIN, UNIT,
     '        elif details.get("result_sha256") != target.completed.details.get("result_sha256"):',
     "        elif False:"),
    ("redaction counted without its digest", CHAIN, UNIT,
     '        if named and isinstance(expected, str) and details.get("result_sha256") == expected:',
     "        if named:"),
    ("redaction vouches for a result still present", CHAIN, UNIT,
     "    if stored_result is None and redaction is not None:", "    if redaction is not None:"),
    ("tampered result redacted (evidence destroyed)", REDACT, REDACT_DB,
     '            if verify_run_result(completion, row.result) != "ok":', "            if False:"),
    ("redaction allowed on a run that is not completed", REDACT, REDACT_DB,
     '            if row.status != "completed" or row.result is None:', "            if row.result is None:"),
    ("ended run may change its outcome with a redaction", M7, REDACT_DB,
     "                AND NEW.outcome IS NOT DISTINCT FROM OLD.outcome\n", ""),
    ("redaction marker without a removed result", M7, REDACT_DB,
     "\"result_redacted_at IS NULL OR (status = 'completed' AND result IS NULL)\"", "\"true\""),
    # --- RR-5: request target bound to its decision (SD-039)
    ("RR-5: request target not compared with the decision", CHAIN, UNIT,
     "        elif not continues_approved_target(", "        elif False and not continues_approved_target("),
    ("RR-5: continuation may carry other parameters", EVENTS, UNIT,
     '    return bool(token) and "&" not in token and "#" not in token', "    return bool(token)"),
    ("RR-5: any target starting with the approved one accepted", EVENTS, UNIT,
     "    prefix = f\"{approved}{'&' if '?' in approved else '?'}{SKIPTOKEN}=\"", "    prefix = approved"),
    ("RR-5: a decision without an approved target approves anything", EVENTS, UNIT,
     "    if not (isinstance(target, str) and isinstance(approved, str) and approved):\n        return False",
     "    if not (isinstance(target, str) and isinstance(approved, str) and approved):\n        return True"),
    # --- audit schema v3 (SD-040)
    ("v3: script records accepted under v2", EVENTS, UNIT,
     "    if rule is None or (event_type in V3_ONLY_EVENTS and schema_version < 3):", "    if rule is None:"),
    ("v3: /beta accepted under v2", EVENTS, UNIT,
     'TARGET_VERSIONS = {2: ("/v1.0",), 3: ("/v1.0", "/beta")}', 'TARGET_VERSIONS = {2: ("/v1.0", "/beta"), 3: ("/v1.0", "/beta")}'),
    ("v3: stored records checked under the current version", CHAIN, UNIT,
     "    version = record.schema_version if _is_int(record.schema_version) else SCHEMA_VERSION",
     "    version = SCHEMA_VERSION"),
    ("v3: script record shapes not checked", EVENTS, UNIT,
     "        problems += _script_problems(event_type, status, values, details)  # type: ignore[arg-type]",
     "        problems += []"),
    ("v3: analysis without submission accepted", CHAIN, UNIT,
     "        if sha not in scripts.submitter:\n            bad(record, \"analysis_without_submission\")",
     "        if False:\n            bad(record, \"analysis_without_submission\")"),
    ("v3: approval without analysis accepted", CHAIN, UNIT,
     "        if sha not in scripts.analyzed:", "        if False:"),
    ("v3: submitter may approve", CHAIN, UNIT,
     "        elif record.actor_oid == scripts.submitter.get(sha):", "        elif False:"),
    ("v3: duplicate approval id accepted", CHAIN, UNIT, "        elif approval in scripts.approvals:", "        elif False:"),
    ("v3: script run approved by an approval of another script", CHAIN, UNIT,
     '    return approved is not None and approved == details.get("script_sha256")', "    return approved is not None"),
    ("v3: script run start not checked", CHAIN, UNIT,
     "                if is_script_start and not _script_run_approved(record, scripts):",
     "                if False:"),
    # --- Graph facade (SD-041)
    ("facade: non-GET accepted", F_CANON, F_UNIT,
     '    if method != "GET":\n        return Refused("method_not_allowed")', '    if False:\n        return Refused("method_not_allowed")'),
    ("facade: GET body accepted", F_CANON, F_UNIT,
     '    if body_length:\n        return Refused("body_not_allowed")', '    if False:\n        return Refused("body_not_allowed")'),
    ("facade: encoded separators accepted", F_CANON, F_UNIT,
     '    if not path.startswith("/") or _ENCODED_SEPARATOR.search(path) or "\\\\" in path:',
     '    if not path.startswith("/") or "\\\\" in path:'),
    ("facade: dot and empty segments accepted", F_CANON, F_UNIT,
     '    if any(p in ("", ".", "..") for p in parts):', '    if False:'),
    ("facade: double encoding accepted", F_CANON, F_UNIT,
     '    if "%" in decoded or _CONTROL_OR_SPACE.search(decoded) or not decoded.isascii():',
     '    if _CONTROL_OR_SPACE.search(decoded) or not decoded.isascii():'),
    ("facade: $batch accepted", F_CANON, F_UNIT, '    if any("$batch" in s for s in rest):', '    if False:'),
    ("facade: unknown OData option silently dropped", F_CANON, F_UNIT,
     '            return Refused("unknown_query_option", sanitize_name(name))', '            continue'),
    ("facade: unknown parameter silently dropped (D1)", F_CANON, F_UNIT,
     '            return Refused("unknown_query_parameter", sanitize_name(name))', '            continue'),
    ("facade: a refused parameter is recorded with its value", F_HANDLER, F_DB,
     '            details["parameter"] = parameter  # its name only, never its value (D1)',
     '            details["parameter"] = str(raw_target)'),
    ("facade: $select outside the allowlist", F_POLICY, F_UNIT,
     '    elif not select or not set(select.split(",")) <= entry.select:', '    elif False:'),
    ("facade: $filter property not checked", F_POLICY, F_UNIT,
     "            if names is None or not names <= entry.filter_properties:", "            if False:"),
    ("facade: $top unbounded", F_POLICY, F_UNIT,
     '        if not _TOP.match(options["$top"]) or int(options["$top"]) > entry.top:',
     '        if not _TOP.match(options["$top"]):'),
    ("facade: placeholder takes any value", F_POLICY, F_UNIT,
     "            if not _GUID.match(got):\n                return False", "            if False:\n                return False"),
    ("facade: nextLink may change the approved options", F_PAGES, F_UNIT,
     "    if any(values[name] != value for name, value in expected):", "    if False:"),
    ("facade: a handle works for another run", F_PAGES, F_UNIT,
     "            if continuation is None or continuation.run_id != run_id:", "            if continuation is None:"),
    ("facade: a handle can be reused", F_PAGES, F_UNIT,
     "            del self._handles[handle]\n        return continuation", "            pass\n        return continuation"),
    ("facade: continuation not re-authorized", F_HANDLER, F_DB,
     "            if decision is None or not decision.allowed or decision.target != continuation.approved_target:",
     "            if decision is None:"),
    ("facade: continuation may carry other options", F_HANDLER, F_DB,
     '            if {name for name, _ in request.options} != {"$skiptoken"}:', "            if False:"),
    ("facade: a denied request's query is recorded", F_HANDLER, F_DB,
     '        details = {"method": shown[:16], "path": _recorded_path(raw_target)}',
     '        details = {"method": shown[:16], "path": str(raw_target)}'),
    ("facade: transport forwards any header", TRANSPORT, F_UNIT,
     "            or not all(item in FACADE_HEADERS for item in headers)\n", ""),
    # --- keyed hashing of free-text values (SD-042)
    ("hashing: free-text values not hashed", F_HASH, F_HASH_TESTS,
     "        parts.append(f\"{name}={value_digest(key, option, unquote(raw))}\" if eq and option in HASHED_OPTIONS else part)",
     "        parts.append(part)"),
    ("hashing: only $filter hashed, $search left raw", F_HASH, F_HASH_TESTS,
     'HASHED_OPTIONS = frozenset({"$filter", "$search"})', 'HASHED_OPTIONS = frozenset({"$filter"})'),
    ("hashing: the request is recorded unhashed", F_HANDLER, F_HASH_TESTS,
     '            "request_target": audit_target(attempt.request_target, self._key), "attempt": number,',
     '            "request_target": attempt.request_target, "attempt": number,'),
    ("hashing: a missing key does not stop the request", F_HANDLER, F_HASH_TESTS,
     '            raise AuditUnavailable("audit value key unavailable") from exc',
     '            key = ValueKey("00000000", b"0" * 32)'),
    # --- bring-your-own scripts: intake, approval, runs (SD-043)
    ("scripts: role not checked", S_DEPS, S_DB,
     "        if principal.role not in allowed:", "        if False:"),
    ("scripts: API lets a lead approve their own script", S_ROUTES, S_DB,
     "    if script.submitted_by == principal.user_id:", "    if False:"),
    ("scripts: API approves before the analysis", S_ROUTES, S_DB,
     "    if analyzed is None:\n        raise HTTPException(status_code=409", "    if False:\n        raise HTTPException(status_code=409"),
    ("scripts: database lets the submitter approve", S_MIG, S_DB,
     "    IF NEW.approved_by = s.submitted_by THEN", "    IF false THEN"),
    ("scripts: database lets an analyst approve", S_MIG, S_DB,
     "    IF approver_role IS DISTINCT FROM 'security_lead' THEN", "    IF false THEN"),
    ("scripts: database approves a write entry", S_MIG, S_DB,
     "                  WHERE (e ->> 'method') IS DISTINCT FROM 'GET') THEN", "                  WHERE false) THEN"),
    ("scripts: database approves another digest", S_MIG, S_DB,
     "    IF NOT FOUND OR s.tenant_id <> NEW.tenant_id OR s.sha256 <> NEW.script_sha256 THEN",
     "    IF NOT FOUND OR s.tenant_id <> NEW.tenant_id THEN"),
    ("scripts: a script can be edited", S_MIG, S_DB,
     '    op.execute("CREATE TRIGGER scripts_guard_update BEFORE UPDATE ON public.scripts "\n'
     '               "FOR EACH ROW EXECUTE FUNCTION public.clw_refuse_update()")\n', ""),
    ("scripts: a script runs without an approval", S_RUNS, S_DB,
     '    if approval is None:\n        raise HTTPException(status_code=403, detail="script_not_approved")',
     '    if False:\n        raise HTTPException(status_code=403, detail="script_not_approved")'),
    ("scripts: the named-operation path serves script runs", S_CAP, S_DB,
     '    if row.kind != kind:  # a script run reaches Graph only through the facade (SD-043)',
     "    if False:"),
    ("scripts: a tampered approval is served", S_APPROVALS, S_DB,
     "    if not (manifest.sha256 == approval.manifest_sha256 == row.task_manifest_sha256):", "    if False:"),
    ("scripts: a runner without the script sandbox launches script runs", S_LAUNCHER, S_DB,
     '                        queued = queued.where(Run.kind == "task")',
     '                        queued = queued'),
    ("scripts: the analyser gets a network", S_ANALYSER, S_DB,
     '        "network_mode": "none",', '        "network_mode": "bridge",'),
    ("scripts: an unrecorded analysis stays approvable", S_ANALYSER, S_DB,
     '            await self._transition(analysis_id, {"status": "failed", "reason": "audit_unavailable"}, None)',
     "            pass"),
    # --- script runs in the PowerShell sandbox (SD-044)
    ("script runs: an edited script still launches", S_LAUNCHER, R_DB,
     '            == hashlib.sha256(script.text.encode("utf-8")).hexdigest()\n', ""),
    ("script runs: a tampered approval still launches", S_LAUNCHER, R_DB,
     "        return load_script_manifest(approval.manifest).sha256 == row.task_manifest_sha256",
     "        return True"),
    ("script runs: RUN_STARTED does not name the bootstrap", S_LAUNCHER, R_DB,
     '                                "bootstrap_sha256": self._bootstrap}',
     '                                "bootstrap_sha256": "0" * 64}'),
    ("script runs: the script is not what goes in on stdin", S_LAUNCHER, R_DB,
     '                              script=script.text.encode("utf-8"), script_sha256=script.sha256)',
     '                              script=b"", script_sha256=script.sha256)'),
    ("script runs: a bootstrap refusal is just a task error", S_LAUNCHER, R_DB,
     "            if refusal is not None:\n                return await self._end(run, \"failed\", refusal)",
     "            if False:\n                return await self._end(run, \"failed\", refusal)"),
    ("script runs: output past 1 MiB is not cut off", S_LAUNCHER, R_DB,
     '        limit = MAX_SCRIPT_OUTPUT_BYTES if claimed.kind == "script" else MAX_RESULT_BYTES',
     "        limit = MAX_RESULT_BYTES"),
    ("script runs: an unfinished bootstrap still gives a result", S_RESULT, R_DB,
     '    if m is None:\n        raise ResultRejected("result_missing")',
     '    if m is None:\n        m = re.match(rb"(0)", b"0")'),
    ("script runs: an unknown bootstrap reason is believed", S_RESULT, R_DB,
     "    return reason if reason in BOOTSTRAP_REASONS else None", "    return reason"),
    # --- gVisor follow-up (SD-044): the peer by address, RLIMIT_NPROC
    ("sandbox: a run starts with no peer to reach", S_LAUNCHER, R_DB + ["tests/db/test_runner.py"],
     "            if peer is None:", "            if False:"),
    ("sandbox: the peer's name is left to Docker's DNS", S_SPEC, SPEC_UNIT + R_DB,
     '        "network": TASK_NETWORK,\n        "extra_hosts": _hosts(config.broker_url, peer),\n',
     '        "network": TASK_NETWORK,\n'),
    ("sandbox: any string is accepted as the peer", S_SPEC, SPEC_UNIT,
     "        address = ipaddress.ip_address(peer)", "        address = peer"),
    ("sandbox: no RLIMIT_NPROC (gVisor ignores the PID limit)", S_SPEC, SPEC_UNIT,
     'NPROC_ULIMIT = {"Name": "nproc", "Soft": 64, "Hard": 64}', 'NPROC_ULIMIT = {"Name": "nofile", "Soft": 64, "Hard": 64}'),
    # --- the demo pages (SD-045)
    ("ui: a cross-site form post is accepted", S_UI, UI_DB,
     '    return request.headers.get("origin") == f"{request.url.scheme}://{request.url.netloc}"',
     "    return True"),
    ("ui: rendered values are not escaped", S_UI, UI_DB,
     "autoescape=True,", "autoescape=False,"),
    ("ui: a page post ignores the role", S_UI, UI_DB,
     "    if principal.role not in roles:", "    if False:"),
    ("api: production starts without Redis", "src/clw/api/main.py", ["tests/unit/test_api_startup.py"],
     "        lifespan=_lifespan,\n", ""),
    ("ui: pages may run scripts", S_UI, UI_DB,
     "\"default-src 'none'; style-src", "\"default-src *; style-src"),
    # --- the agent tools' reads (SD-053)
    ("reads: the broker returns unfiltered items", "src/clw/broker/service.py", AGENT_READS_TESTS,
     '{"status": "ok", "data": operations.filter_items(operations.get(label), items)}',
     '{"status": "ok", "data": items}'),
    ("reads: expanded principals are not filtered", "src/clw/broker/operations.py", AGENT_READS_TESTS,
     "                out[key] = _keep(out[key], properties)", "                pass"),
    ("reads: the principal allowlist includes mail", "src/clw/broker/operations.py", AGENT_READS_TESTS,
     'PRINCIPAL_PROPERTIES = frozenset({"id", "displayName", "userPrincipalName", "@odata.type"})',
     'PRINCIPAL_PROPERTIES = frozenset({"id", "displayName", "userPrincipalName", "@odata.type", "mail"})'),
    ("reads: stage 2 ignores the fixed query", "src/clw/broker/policy.py", AGENT_READS_TESTS,
     "        if query[-fixed:] != rule.fixed_query:\n            return None\n", ""),
    ("reads: the transport sends any query parameter", "src/clw/broker/transport.py", AGENT_READS_TESTS,
     "not all(item[0] in caller or item in spec.fixed_query for item in request.query)", "False"),
    ("lookup: the transport sends a lookup without its fixed select", "src/clw/broker/transport.py",
     ["tests/security/test_identity_lookup.py"],
     "or not all(item in request.query for item in spec.fixed_query)", "or False"),
    ("lookup: a manifest may list the internal lookup", "src/clw/broker/manifest.py",
     ["tests/security/test_identity_lookup.py"],
     "        if spec.internal_only:  # the broker's own", "        if False:  # the broker's own"),
    ("lookup: a collection is accepted as the single object", "src/clw/broker/transport.py",
     ["tests/security/test_identity_lookup.py"],
     '        if "value" in body or "@odata.nextLink" in body:\n            return None\n', ""),
    # --- change proposals (SD-054)
    ("proposals: the refusal is not recorded before the lookup", "src/clw/broker/service.py", PROPOSAL_TESTS,
     '                             reason="write_not_executable")', '                             reason="write_not_executable") if False else None'),
    ("proposals: a missing user ends the session", "src/clw/broker/service.py", PROPOSAL_TESTS,
     'tolerate=frozenset({"not_found"}), internal=True)', "internal=True)"),
    ("proposals: a non-user object is taken as found", "src/clw/broker/proposals.py", PROPOSAL_TESTS,
     '    if kind is not None and kind != "#microsoft.graph.user":', "    if False:"),
    ("proposals: the hash binds the display name", "src/clw/broker/proposals.py", PROPOSAL_TESTS,
     '    request = {"method": "PATCH", "path": f"/v1.0/users/{user_id}", "body": {"accountEnabled": False}}',
     '    request = {"method": "PATCH", "path": f"/v1.0/users/{user_id}", "body": {"accountEnabled": True}}'),
    ("proposals: any action is accepted", "src/clw/broker/proposals.py", PROPOSAL_TESTS,
     ' or body.get("action") != ACTION:', ":"),
    ("inbox: the tenant display name is rendered as markup", S_PROPOSAL_TPL, AGENT_UI_DB,
     "<td><code><bdi>{{ p.display_name }}</bdi></code></td>", "<td><code><bdi>{{ p.display_name|safe }}</bdi></code></td>"),
    ("inbox: the tenant display name heads the proposal", S_PROPOSAL_TPL, AGENT_UI_DB,
     '    <span class="state">Filed, not executed</span></p>',
     '    {{ p.display_name }} <span class="state">Filed, not executed</span></p>'),
    ("inbox: the agent's reason is rendered as markup", S_PROPOSAL_TPL, AGENT_UI_DB,
     "<pre><bdi>{{ p.reason }}</bdi></pre>", "<pre><bdi>{{ p.reason|safe }}</bdi></pre>"),
    ("inbox: the binding is not re-checked", "src/clw/api/ui/agent_pages.py", AGENT_UI_DB,
     "    binding_ok = (recomputed == p.request_sha256 == in_chain and p.request == expected",
     "    binding_ok = True or (recomputed == p.request_sha256 == in_chain and p.request == expected"),
    ("inbox: the shown object ID need not be the request's", "src/clw/api/ui/agent_pages.py", AGENT_UI_DB,
     "    binding_ok = (recomputed == p.request_sha256 == in_chain and p.request == expected",
     "    binding_ok = (recomputed == p.request_sha256 == in_chain"),
    ("inbox: invisible characters are shown as they are", "src/clw/api/ui/agent_pages.py", AGENT_UI_DB,
     '        "display_name": visible(p.target_display_name), "upn": visible(p.target_upn),',
     '        "display_name": p.target_display_name, "upn": p.target_upn,'),
    ("proposals: a profile without proposals files them", "src/clw/broker/service.py", PROPOSAL_TESTS,
     "        if proposals.ACTION not in ctx.manifest.proposals:", "        if False:"),
    ("proposals: no per-session limit", "src/clw/broker/service.py", PROPOSAL_TESTS,
     "        if filed >= proposals.MAX_PER_SESSION:", "        if False:"),
    ("proposals: the broker runs an internal operation for an agent", "src/clw/broker/service.py", PROPOSAL_TESTS,
     "        if spec is not None and spec.internal_only and not internal:", "        if False:"),
    ("sessions: the JSON start accepts another origin", "src/clw/api/routes/agent_sessions.py", SESSION_API_DB,
     '    if origin is not None and origin != f"{request.url.scheme}://{request.url.netloc}":', "    if False:"),
    # --- who starts a session, and what keeps it alive (SD-055)
    ("sessions: a stale sign-in starts a session", "src/clw/api/routes/agent_sessions.py", SESSION_API_DB,
     "    if not 0 <= int(time.time()) - claims.issued_at <= FRESH_SIGN_IN_SECONDS:", "    if False:"),
    ("sessions: any role starts any profile", "src/clw/api/routes/agent_sessions.py", SESSION_API_DB,
     "    if principal.role not in manifest.start_roles:", "    if False:"),
    ("sessions: a disabled tenant's session still works", "src/clw/broker/capability.py", SESSION_API_DB,
     '        if standing is None or standing.status != "active":', "        if False:"),
    ("sessions: a demoted starter's session still works", "src/clw/broker/capability.py", SESSION_API_DB,
     "        if standing.role is None or standing.role not in manifest.start_roles:", "        if False:"),
    ("sessions: signing out leaves agent sessions running", "src/clw/api/ui/pages.py", AGENT_UI_DB,
     "    await end_sessions_started_by(request.app.state.sessionmaker, request.app.state.writer, session.tid, session.oid)",
     "    pass"),
    ("sign-in: silent single sign-on is accepted", "src/clw/auth/signin.py", ["tests/security/test_signin.py"],
     '        "prompt": "login",\n', ""),
    ("inbox: a cross-site form starts a session", "src/clw/api/ui/agent_pages.py", AGENT_UI_DB,
     '    principal, refused = await _post_guard(request, ("analyst", "security_lead"))\n    if refused:\n'
     '        return refused\n    form = await _form(request)',
     '    principal = await _principal(request)\n    form = await _form(request)'),
    # --- demo mode (SD-051)
    ("demo: the api runs demo mode in production", "src/clw/demo/__init__.py", DEMO_TESTS,
     '    if settings.is_production:\n        raise DemoModeRefused("demo mode is refused when ENVIRONMENT=production")\n',
     ""),
    ("demo: the api runs demo mode beside real sign-in settings", "src/clw/demo/__init__.py", DEMO_TESTS,
     "    if configured:\n        raise DemoModeRefused", "    if False:\n        raise DemoModeRefused"),
    ("demo: the demo broker runs with real profile credentials", "src/clw/demo/__init__.py", DEMO_TESTS,
     '    if real:\n        raise DemoModeRefused', '    if False:\n        raise DemoModeRefused'),
    ("demo: a normal broker serves the demo tenant", "src/clw/broker/credentials.py", DEMO_TESTS,
     "        if (tenant_id == DEMO_TENANT_ID) is not self._demo:", "        if self._demo and tenant_id != DEMO_TENANT_ID:"),
    ("demo: the demo broker serves any tenant", "src/clw/broker/credentials.py", DEMO_TESTS,
     "        if (tenant_id == DEMO_TENANT_ID) is not self._demo:", "        if not self._demo and tenant_id == DEMO_TENANT_ID:"),
    ("demo: the demo sign-in exists outside demo mode", "src/clw/api/main.py", DEMO_TESTS,
     "    if demo_mode:  # the fictional tenant's sign-in", "    if True:  # the fictional tenant's sign-in"),
    ("demo: the banner is missing", "src/clw/api/ui/pages.py", DEMO_TESTS,
     '    _TEMPLATES.globals["demo_mode"] = bool(on)', '    _TEMPLATES.globals["demo_mode"] = False'),
    ("demo: the demo sign-in accepts a cross-site form", "src/clw/api/ui/demo_signin.py", DEMO_TESTS,
     "    if not _same_origin(request):\n        return _error(403", "    if False:\n        return _error(403"),
    ("proposals: the lookup may target any user the agent names elsewhere", "src/clw/broker/service.py",
     PROPOSAL_TESTS, '        looked = await self._operation(narrowed, proposals.LOOKUP, {"user_id": asked.user_id},',
     '        looked = await self._operation(narrowed, proposals.LOOKUP, {"user_id": "0" * 8 + "-0000-0000-0000-" + "0" * 12},'),
    ("reads: the registry accepts any fixed parameter", "src/clw/broker/operations.py", AGENT_READS_TESTS,
     "        any(name not in _FIXED_QUERY_NAMES or not re.fullmatch", "        any(False and not re.fullmatch"),
    # --- the MCP gateway (SD-048, SD-052)
    ("gateway: a capability the broker refuses is accepted", S_GATEWAY, GATEWAY_UNIT,
     "        if session is None:\n            return None\n        try:\n            expires",
     "        if session is None:\n            session = {\"expires_at\": \"2999-01-01T00:00:00Z\", \"id\": \"x\"}\n"
     "        try:\n            expires"),
    ("gateway: the broker's answer is remembered", S_GATEWAY, GATEWAY_UNIT,
     "        session = await self._broker.describe(token)\n",
     "        session = self.__dict__.setdefault(token, await self._broker.describe(token))\n"),
    ("gateway: any Host header is served", S_GATEWAY, GATEWAY_UNIT,
     "TransportSecuritySettings(enable_dns_rebinding_protection=True,",
     "TransportSecuritySettings(enable_dns_rebinding_protection=False,"),
    # --- agent sessions (SD-049)
    ("sessions: the end function ends any kind of run", S_SESSION_MIG, SESSION_TABLE_DB,
     "     WHERE id = p_run_id AND tenant_id = p_tenant_id AND kind = 'agent_session' AND status = 'running';",
     "     WHERE id = p_run_id AND tenant_id = p_tenant_id AND status = 'running';"),
    ("sessions: the end function ignores the tenant", S_SESSION_MIG, SESSION_TABLE_DB,
     "     WHERE id = p_run_id AND tenant_id = p_tenant_id AND kind = 'agent_session' AND status = 'running';",
     "     WHERE id = p_run_id AND kind = 'agent_session' AND status = 'running';"),
    ("sessions: the api may update runs", "src/clw/db/roles.py", SESSION_TABLE_DB,
     '        "GRANT EXECUTE ON FUNCTION clw_end_agent_session(uuid, text, text, text) TO {role}",\n',
     '        "GRANT EXECUTE ON FUNCTION clw_end_agent_session(uuid, text, text, text) TO {role}",\n'
     '        "GRANT UPDATE (status, outcome, run_token_sha256, ended_at, updated_at) ON runs TO {role}",\n'),
    # The function's live body is 20261107's (it replaced 20261104's), so the bound is mutated there.
    ("sessions: the ttl has no upper bound", "migrations/versions/20261107_session_tenant_active.py",
     SESSION_TABLE_DB, "OR p_ttl_seconds > 28800 THEN", "THEN"),
    ("sessions: a disabled tenant can start a session", "migrations/versions/20261107_session_tenant_active.py",
     SESSION_TABLE_DB, "_WITH_GUARD = _WITHOUT_GUARD.replace(_ANCHOR, _GUARD + _ANCHOR)",
     "_WITH_GUARD = _WITHOUT_GUARD.replace(_ANCHOR, _ANCHOR + ' ')"),
    ("sessions: a session token works as a task token", S_CAP, SESSION_API_DB,
     '        raise RunRefused("not_a_task_run" if kind == "task" else "not_an_agent_session", run=run)',
     "        pass"),
    ("sessions: any member may revoke another's session", S_SESSIONS, SESSION_API_DB,
     '    if row.actor_oid != principal.oid and principal.role != "security_lead":', "    if False:"),
    ("sessions: the capability is issued before the audit commits", S_SESSIONS, SESSION_API_DB,
     "    except AuditUnavailable:\n        # Nothing committed: the row rolled back, and the capability is discarded unseen.\n"
     "        raise HTTPException(status_code=503, detail=\"audit_unavailable\") from None",
     "    except AuditUnavailable:\n        # Nothing committed: the row rolled back, and the capability is discarded unseen.\n"
     "        return JSONResponse({\"id\": rid, \"capability\": issued.token}, status_code=201)"),
    ("sessions: a revoked session keeps its token when the audit fails", S_SESSIONS, SESSION_API_DB,
     '        ended = await _end(sessionmaker, writer, sid, principal.tid, "completed", "revoked", record=False)',
     "        ended = True"),
]


# Mutations whose kill must come from specific tests (pytest -k expressions).
# Older entries are classified by failure type only; see the module docstring.
EXPECT = {
    "M-1: validator parses in the session TimeZone again": "test_audit_session_settings",
    "M-1: validator ignores hour/minute/second ranges": "validator_ignores_session or impossible_timestamps",
    "M-1: validator ignores impossible calendar dates": "aborts_over_invalid_rows or impossible_timestamps",
    "M-1: existing rows not re-validated on upgrade": "aborts_over_invalid_rows",
    "M-2: no chain evidence (wall clock decides)": "test_timestamp_durability",
    "M-2: later records below the baseline count as evidence": "backdated_record_in_the_middle",
    "M-2: any later record is evidence without a baseline": "not_blamed or backdated",
    "M-2: verifier clock applied to vouched-for records": "several_records_ahead",
    "M-2: recovery does not acknowledge what it exposes": "several_records_ahead or survives_the_passage_of_time",
    "M-2: invalid recovery state hidden": "test_states_clean_unrecovered",
    "M-2: recovered chain reported clean": "test_timestamp_durability",
    "M-2: provisional findings not reported": "test_timestamp_durability",
    "L-1: writer has no text limit": "test_text_limits",
    "L-1: chain_id length unchecked": "over_limit_chain_id",
    "L-1: request_target given the general limit": "request_target",
    "L-1: writer counts characters, not UTF-8 bytes": "utf8_bytes_not_characters",
    "L-1: database has no text limit": "test_audit_text_limits",
    "L-1: database counts characters, not bytes": "utf8_bytes or never_truncates",
    "L-1: database request_target unbounded": "database_enforces_the_request_target_limit",
    "L-1: migration does not check existing rows first": "never_truncates",
    "L-2: checkpoint key_id format not checked": "key_id or malformed_checkpoints",
    "checkpoint tenant_id not compared (review 3 info)": "another_tenant",
    "L-3: no lock timeout": "test_audit_timeouts",
    "L-3: no statement timeout": "slow_statement or defaults_are_applied",
    "L-3: timeout values not validated": "timeouts_must_be_positive",
    "F-1: cached position never re-checked against the clock": "test_audit_anchor",
    "F-1: any cached position trusted": "test_audit_anchor",
    "F-1: malformed cached timestamp trusted": "untrustworthy_cached_position",
    "F-3: validator pattern uses a backslash escape again": "every_setting or backslash",
    "F-4: signed range and head not cross-checked": "inconsistent",
    "F-4: only seq_from cross-checked": "inconsistent_range_or_head",
    "F-4: head not cross-checked": "inconsistent_range_or_head",
    "F-5: latest instead of earliest later recovery is the evidence (R1)": "earliest_later_recovery",
    "F-5: records below the baseline can vouch (R5)": "cannot_vouch",
    "L-3: timeouts set for the session, not the transaction (R9)": "do_not_leak",
    "L-C: timestamps formatted with the platform strftime again": "no_strftime or four_digit or year_1000",
    "L-A: stale cache refuses without full verification": "stale_cached_writer",
    "L-B: recovery may leave provisional findings": "leave_a_provisional",
    "L-B: cached while an acknowledged provisional finding exists": "never_caches",
    "S1: cached-position window doubled (10 min)": "trust_boundary",
    "S7: incremental check uses the host clock": "database_clock_behind_the_host",
    "S7: full check uses the host clock": "database_clock_behind_the_host",
    "S8: incremental check ignores the cached record's timestamp": "backdated_record_after_the_cached",
    "S5: single-record range treated as unusable": "single_record",
    "S11: no-baseline evidence boundary inclusive": "evidence_boundary",
    "S15: loader does not order by seq": "physical_order",
    "S17: VALID checkpoint accepted with findings": "carrying_findings",
    "R1: fast path accepts findings acknowledged inside the segment": "forged_recoveries_cannot",
    "R2: retry target is the earliest record ahead, not the latest": "latest_stamped",
    "R2: refusals give no retry target": "retry_guidance or latest_stamped or leave_a_provisional",
    "I-2: tie names the last copy, not the first record": "first_record_with_that_timestamp or copying_the_head",
    "I-2: provisional message names the last provisional seq": "first_provisional_record",
    "I-2: malformed timestamps can be the retry target": "malformed_timestamps_and_seqs",
    "L-1: guard ignores constraint definitions": "changed_constraint_definition",
    "L-1: guard ignores function bodies": "function_body_replaced",
    "L-1: guard ignores trigger enabled state": "trigger_disabled or production_shape",
    "L-1: guard compares row names only": "changed_constraint_definition",
    "L-1: guard ignores database privileges": "on_the_database",
    "L-1: guard ignores schema privileges": "schema_public_granted",
    "L-1: guard ignores rules": "rule_added or production_shape",
    "L-1: guard ignores indexes": "index_dropped or production_shape",
    "L-1: guard ignores column defaults": "column_default",
    "L-1: guard ignores STRICT": "non_STRICT",
    "L-1: guard ignores function privileges": "EXECUTE",
    "L-1: guard sees clw_ functions only": "not_clw",
    "L-1: guard ignores role-level settings": "role_level_setting or production_shape",
    "L-1: guard ignores role attributes": "BYPASSRLS",
    "I-1: guard compares the current schema with itself": "test_schema_guard_wiring",
    "I-1: guard never runs": "test_schema_guard_wiring",
    "I-1: guard result ignored": "test_schema_guard_wiring",
}

INFRASTRUCTURE = re.compile(
    r"ConnectionRefusedError|CannotConnectNow|InvalidPasswordError|InvalidAuthorizationSpecification|"
    r"TooManyConnections|Connect call failed|could not connect|ConnectionResetError|ConnectionDoesNotExist|"
    r"socket\.gaierror|OSError: \[Errno|ModuleNotFoundError|ImportError|SyntaxError|IndentationError|"
    r"fixture '[^']*' not found|INTERNALERROR"
)


def _pytest(tests: list[str], *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["uv", "run", "--no-sync", "pytest", *tests, "-q", "-rfE", "--tb=line", "-p", "no:cacheprovider", *extra],
        capture_output=True, text=True,
    )


def classify(r: subprocess.CompletedProcess) -> tuple[str, str]:
    lines = r.stdout.strip().splitlines() or ["<no output>"]
    summary = lines[-1]
    if r.returncode == 0:
        return "SURVIVED", summary
    if r.returncode != 1:
        return "BROKEN", f"pytest exit {r.returncode} (collection, usage or internal error) | {summary}"
    if re.search(r"\berrors?\b", summary):
        first = next((line for line in lines if line.startswith("ERROR ")), "")
        return "BROKEN", f"errors outside test bodies (setup/collection) | {summary} | {first[:200]}"
    failures = [l for l in lines if l.startswith("FAILED ")]
    if not failures:
        return "BROKEN", f"exit 1 without a reported test failure | {summary}"
    infra = [l for l in failures if INFRASTRUCTURE.search(l)]
    if infra:
        return "BROKEN", f"infrastructure failure: {infra[0][:200]}"
    return "KILLED", f"{failures[0][:400]} | {summary}"


def baseline(test_sets: list[list[str]], strict: bool) -> bool:
    """Unmutated code must pass. By default the union of all selected test
    paths runs once (every set is a subset of it); --strict-baseline runs
    each set separately, as earlier versions did."""
    if not strict:
        union = sorted({path for tests in test_sets for path in tests})
        test_sets = [union]
    for tests in test_sets:
        status, detail = classify(_pytest(tests))
        if status != "SURVIVED":
            print(f"BASELINE FAILED for {tests}: {detail}")
            return False
        print(f"baseline ok  {' '.join(tests)} | {detail}")
    return True


HINTS_FILE = pathlib.Path(__file__).with_name("audit_mutation_hints.json")


def _load_hints() -> dict[str, str]:
    try:
        return json.loads(HINTS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _failing_file(detail: str) -> str | None:
    m = re.match(r"FAILED (\S+?)::", detail)
    return m.group(1) if m else None


def _matches_expect(detail: str, expression: str) -> bool:
    m = re.match(r"FAILED (\S+)", detail)
    node = m.group(1) if m else ""
    return any(token.strip() and token.strip() in node for token in re.split(r"\s+or\s+", expression))


def run_mutation(name: str, tests: list[str], hints: dict[str, str]) -> tuple[str, str]:
    """Hinted file first (the file that killed this mutation last time); a
    KILLED verdict needs an attributable failure there. Anything else falls
    back to the mutation's full test set, so a survivor is only ever declared
    after the full set has passed with the mutation applied."""
    hint = hints.get(name)
    status, detail = ("", "")
    # The hint must be inside the mutation's own test set: equal to a listed
    # file, or under a listed directory (path separator required, so
    # "tests/db" does not admit "tests/dbx/...").
    if hint and pathlib.Path(hint).exists() and any(
            hint == t or hint.startswith(t.rstrip("/") + "/") for t in tests):
        status, detail = classify(_pytest([hint], "-x"))
        if status != "KILLED":
            status = ""  # not decided by the hint: run the full set
    if not status:
        status, detail = classify(_pytest(tests, "-x"))
    if status == "KILLED" and name in EXPECT and not _matches_expect(detail, EXPECT[name]):
        expected, why = classify(_pytest(tests, "-k", EXPECT[name]))
        if expected != "KILLED":
            status, detail = "BROKEN", f"expected tests ({EXPECT[name]}) did not fail: {expected} {why}"
    return status, detail


# Mutations of code that runs on one platform only: their tests are skipped
# elsewhere, so elsewhere they cannot be killed and are not run.
PLATFORM_ONLY = {
    "private key not restricted (L4)": "nt",
    "private key not restricted on POSIX (L4)": "posix",
}


def main(argv: list[str]) -> int:
    strict = "--strict-baseline" in argv
    update_hints = "--update-hints" in argv
    no_hints = "--no-hints" in argv
    selected = [a for a in argv if not a.startswith("--")]
    todo = [m for m in MUTATIONS if (not selected or any(s in m[0] for s in selected))
            and PLATFORM_ONLY.get(m[0], os.name) == os.name]
    unknown = [n for n in (*EXPECT, *PLATFORM_ONLY) if n not in {m[0] for m in MUTATIONS}]
    if unknown:
        print(f"EXPECT names unknown mutations: {unknown}")
        return 2
    sets = []
    for m in todo:
        if m[2] not in sets:
            sets.append(m[2])
    started = time.monotonic()
    if not baseline(sets, strict):
        return 2
    hints = {} if no_hints else _load_hints()
    new_hints = dict(hints)
    counts = {"KILLED": 0, "SURVIVED": 0, "BROKEN": 0}
    for name, path, tests, old, new in todo:
        p = pathlib.Path(path)
        original = p.read_bytes()
        text = original.decode("utf-8")
        t0 = time.monotonic()
        if text.count(old) != 1:
            status, detail = "BROKEN", f"mutation target found {text.count(old)} times"
        else:
            p.write_bytes(text.replace(old, new).encode("utf-8"))
            try:
                status, detail = run_mutation(name, tests, hints)
            finally:
                p.write_bytes(original)
        if status == "KILLED" and _failing_file(detail):
            new_hints[name] = _failing_file(detail)
        counts[status] += 1
        print(f"{status:<9}{name} | {time.monotonic() - t0:5.1f}s | {detail}")
    print(f"\n{counts['KILLED']}/{len(todo)} killed, {counts['SURVIVED']} survived, {counts['BROKEN']} broken"
          f" in {time.monotonic() - started:.0f}s")
    if update_hints:
        HINTS_FILE.write_bytes((json.dumps(dict(sorted(new_hints.items())), indent=1) + "\n").encode("utf-8"))
        print(f"hints written: {HINTS_FILE}")
    return 0 if counts["KILLED"] == len(todo) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
