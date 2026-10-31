# Testing the audit subsystem

Everything here runs one thing at a time. The PostgreSQL tests share one test database (`clw_test`, recreated at the start of each run), and the mutation check edits source files while it runs, so never run two of these at once and never edit code while the mutation check is running.

Prerequisite for anything that touches PostgreSQL: `docker compose up -d` (Postgres on 127.0.0.1:5433). On this Windows machine Docker Desktop does not always come back after a restart; if every pg test errors with a connection failure, start Docker Desktop and `docker compose up -d` again. That is an environment failure, not a test result.

## Groups

`uv run python scripts/run_tests.py <group>`

| Group | What it runs | Time | Peak memory (pytest process) |
|---|---|---|---|
| `quick` | all unit and security tests (`tests/unit`, `tests/security`), no database | ~50 s on Windows (each refused-connection test for Redis-down behaviour waits ~2 s there) | ~180 MiB |
| `focused` | writer, recovery, timestamp, checkpoint, text-limit and schema-guard tests, unit and PostgreSQL (1056 tests) | ~50 s | ~170 MiB |
| `db` | all PostgreSQL tests, admin sessions | ~1 min | ~230 MiB |
| `db-app` | all PostgreSQL tests, every writer session as the least-privileged app role | ~1 min | ~230 MiB |
| `redis` | session revocation and rate-limit tests against the compose Redis (`TEST_REDIS_URL`, database 15) | ~5 s | small |
| `full` | `quick`, then `db`, then `db-app`, then `redis` | ~2 min 15 s | ~240 MiB |

Docker's VM (`vmmemWSL`) adds about 0.7 GB while Postgres is up, whatever runs.

Mutation testing: `uv run python scripts/audit_mutation_check.py [name-substring ...]`. With no names it runs every mutation. Names select a subset, for example `"L-A" "L-B" "R1:" "R2:"`.

## What to run when

| Situation | Required |
|---|---|
| Ordinary change outside the audit subsystem's security logic (docs, comments, test refactors) | `quick` |
| Change to audit code (`src/clw/audit`, `src/clw/cli.py`, `src/clw/common/timeutil.py`, models, migrations) | `focused` while working; `full` before committing |
| Security-sensitive change (writer, recovery, timestamps, checkpoints, triggers, constraints, migrations) | `full`, plus the mutation check for the affected mutations by name, plus `tests/unit/test_mutation_check.py` (it fails if a mutation target no longer exists) |
| Before a gate decision or an independent review | `full`; the complete mutation check (all mutations, `--update-hints`); the attack replays from previous reviews; the unit suite in the Linux container (below). The reviewer runs its own copy of these; do not run them at the same time as the reviewer. |

`full` is the only path that runs the PostgreSQL tests under the least-privileged application role, and it is required before any gate decision.

## What makes the mutation check faster without making it weaker

- The baseline runs the union of the selected test paths once instead of each test set separately (`--strict-baseline` restores the old behaviour).
- Each mutation first runs the test file that killed it last time (`scripts/audit_mutation_hints.json`, refreshed with `--update-hints`). A mutation counts as KILLED only for an attributable test failure there, exactly as before. If that file does not kill it, the mutation's full test set runs, so a survivor is only ever reported after the full set passed with the mutation applied. Errors, collection failures and infrastructure failures are still BROKEN and still fail the run.
- If the failing test already matches the mutation's expected tests, the separate expected-test rerun is skipped.
- A hint is used only if it is inside the mutation's own test set: the same file, or under a listed directory with a path separator (`tests/db` does not admit `tests/dbx/...`; final review I-4).

### Open testing-process item (tracked, not resolved): hint files have no baseline of their own

Final review I-4. The baseline runs the union of the test paths together. A hinted run executes one test file on its own. A test that fails only when its file runs alone (for example, one that depends on state another file sets up) would be counted KILLED for every mutation hinted to that file, without the mutation having caused it.

- **Evidence that it is not happening today:** in the final review, the reviewer ran each of the 22 hint files alone, unmutated, and all passed.
- **What is missing:** the mutation check does not repeat that check itself, so a future test that fails only when run alone would not be noticed.
- **Planned fix:** before using hints, run each distinct hint file alone, unmutated, and ignore any hint whose file fails (those mutations fall back to their full test set). Until then, before a gate decision, run the complete mutation check without hints (`--no-hints`) if a hint file has changed or been added since the last full run.

## Linux run

Production runs on Linux; the development machine is Windows. Timestamp formatting once differed between them (SD-025), so before a gate decision also run the unit suite in a glibc container:

```bash
# From the repository root (Git Bash on Windows: $(pwd -W) gives Docker a Windows path).
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W 2>/dev/null || pwd):/src:ro" python:3.11-slim sh -c '
  mkdir /w && cd /src && tar --exclude=.venv --exclude=__pycache__ --exclude=.git -cf - . | tar -xf - -C /w
  cd /w && pip install -q uv && uv sync --frozen -q && uv run pytest tests/unit -q -p no:cacheprovider'
```

## Measurements

Recorded on the development laptop (16 GB RAM, Windows 11, Docker Desktop with WSL2).

| Run | Before | After |
|---|---|---|
| `quick` (unit) | 23 s, 183 MiB | unchanged |
| `db` | 65 s, 229 MiB (+0.7 GB Docker VM) | unchanged |
| `focused` | (did not exist) | 45 s, 167 MiB |
| `full` (unit + db + db-app) | ~2.5 min if run by hand | 131 s, 242 MiB |
| full mutation check | ~40 min (130 mutations; six separate baselines; every PostgreSQL mutation re-ran the whole PostgreSQL suite) | 7 min 19 s, 282 MiB peak (133 mutations, all KILLED, 0 broken) |

Peak memory is the resident memory of the test processes; it excludes Docker's VM (~0.7 GB while Postgres runs) and everything else open on the machine. Long, memory-heavy sessions earlier came from the 40-minute mutation runs and from independent reviews running suites and mutation checks of their own, not from the suites.

## Intermittent database-test failures: investigation (2026-10-31)

**What we saw (Windows dev box, Docker Desktop):** three different one-off failures in full `-m pg` runs while other work loaded the machine:
1. `test_chain_is_loaded_in_seq_order_whatever_the_physical_order` asserted the rows' exact reverse heap order, but Postgres may place a row in earlier free space. **A real test bug, fixed** (`9b4c48c`): it now asserts only "out of seq order".
2. `test_recovery_insert_failure_leaves_chain_blocked` errored in set-up with `OSError: [WinError 121] The semaphore timeout period has expired`, raised inside asyncpg's connect to `127.0.0.1:5433` (Docker Desktop's port forward). It passed alone, and on every rerun.
3. `test_huge_details_rejected_quickly_by_database` (found by the stress loop below).

**Reproduction on Linux:** `scripts/pg_stress.sh 4 3`. Four copies of the pg suite run in parallel, in Linux containers (`python:3.11-slim`), each against its own Postgres 15 container on a private network, three rounds each: 12 full runs sharing CPU, memory and the Docker daemon.
- **Before the fix:** 10/12 runs green. 2 failed, both on (3) in round 1, when all four copies started at once: 6.5 s against a 5 s wall-clock bound. The bound timed the client building and sending a 12 MB payload, not just the database's work.
- **The fix:** the test now bounds the database's own execution with `statement_timeout = 3s`. The slow path it guards against (about 66 s of database CPU for 26 MB, reviewer N8) is cancelled and still fails the test. A new mutant, which removes the cheap length pre-check, is killed.
- **After the fix:** 12/12 runs green (4 copies × 3 rounds, 939 tests each, about 10 minutes, 2026-10-31).
- **(2) never appeared on Linux:** 0 connection errors in all 12 runs, and none in CI. WinError 121 is a Windows TCP timeout on the host-to-Docker-Desktop port forward. **We treat it as environmental:** the code path is a plain asyncpg connect, and nothing in the code under test is involved. On a Windows box, rerun the failed file. CI runs on Linux.
