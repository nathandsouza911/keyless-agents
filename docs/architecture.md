# Architecture

Status: **v0.1 beta, built.** Companion docs: [threat-model.md](threat-model.md), [assumptions-to-verify.md](assumptions-to-verify.md), [security-decisions.md](security-decisions.md).

## 0. v0.1: AI agents over MCP

v0.1's feature is the agent path. Sections 1–6 below describe the core it is built on (named operations, the broker, write-ahead audit, runs and the database roles), first built for a single analyst task, and still accurate.

```
AI agent (MCP client) --Bearer: session capability--> MCP gateway --named operations--> broker --> Microsoft Graph
person (browser) --sign in, start/revoke sessions, see proposals and the audit trail--> web app (api)
api, broker --> Postgres (sessions as runs, change proposals, the audit chain)
```

| Component | Holds | Does | Decisions |
|---|---|---|---|
| **MCP gateway** (`src/clw/mcp_gateway/`) | nothing: no Microsoft credential, no database access, no route to Graph | Serves the four tools over streamable HTTP. Asks the broker to vouch for the session capability on every request. Turns each tool call into named operations | SD-048, SD-052 |
| **Broker** (`src/clw/broker/`) | the profile apps' certificates | `POST /v1/agent/session`, `/v1/agent/ops` and `/v1/agent/propose`. Resolves the session, then applies the two-stage policy, the exact-permission token check, response filtering and write-ahead audit. Files proposals and never executes writes | SD-049, SD-053, SD-054, SD-055 |
| **Web app** (`src/clw/api/`) | the browser-session secret | Signs people in. Starts and revokes agent sessions through two `SECURITY DEFINER` functions. Shows sessions, their audit trails and proposals | SD-049, SD-051, SD-055 |
| **Postgres** | sessions (runs of kind `agent_session`), change proposals, the hash-chained audit | Database guards: no role but the api's functions starts or ends a session; proposals are immutable and bound to their request | SD-038, SD-049, SD-054 |

Agent profiles live in `agent_profiles/`. Each names its operations, the proposals it allows, and which roles may start it. The quick start (`quickstart/`, SD-051) runs this stack against a fake Graph serving a fictional tenant.

## 1. What Phase 1 delivers

One read-only task, **Dormant Account Investigation**, runs end to end through a controlled execution path:

1. An analyst signs in (Entra ID OIDC) and picks the task.
2. The API shows the task manifest.
3. The analyst starts a run. The run is bound server-side to the analyst's verified tenant.
4. The runner starts an isolated task container. That container holds no credentials and can reach only the broker.
5. Task code calls **named operations** through the task SDK. The broker authorizes each one, builds the Graph request itself, and handles auth, pagination, retries and throttling.
6. An authorized operation succeeds. An unauthorized operation is denied.
7. Every decision and every Graph HTTP attempt is written to a tamper-evident audit chain before the next step proceeds.

Frontend work is deferred. Phase 1 ends at a documented backend API contract (section 5) and an end-to-end test that drives it.

## 2. Components and trust boundaries

```
                      Internet / analyst browser
                               │  HTTPS
                     ┌─────────▼─────────┐
                     │        api        │  public. Analyst sign-in, task catalog,
                     │  (no Graph creds) │  run creation, run/audit views
                     └─────────┬─────────┘
                               │ Postgres (runs, audit)      net: backend
   ┌──────────────┐    ┌───────▼────────┐    ┌──────────────────────────┐
   │    runner    │───▶│   postgres     │◀───│          broker          │
   │ docker socket│    │   redis        │    │ ONLY holder of Graph     │
   │ no Graph cred│    └────────────────┘    │ credentials; policy;     │
   └──────┬───────┘                          │ request builder; audit   │
          │ starts                           └───┬──────────────┬───────┘
          ▼                                      │ net: tasknet │ net: egress
   ┌──────────────────┐   POST /v1/ops (run token)│ (internal)   │
   │  task container  │──────────────────────────┘              ▼
   │ no creds, no     │                               login.microsoftonline.com
   │ egress, limits   │                               graph.microsoft.com
   └──────────────────┘
```

| Component | Holds | Can reach | Must never hold or reach |
|---|---|---|---|
| `api` | Session signing key, sign-in app config, DB credentials | Postgres, Redis, Entra login endpoint (sign-in only) | Graph profile credentials; Docker socket |
| `broker` | Profile certificates (private keys), DB credentials (audit) | Postgres, Entra token endpoint, Graph | Docker socket; anything on `tasknet` other than inbound task calls |
| `runner` | Docker socket, DB credentials | Postgres, Docker daemon | Graph credentials; outbound Internet |
| task container | One per-run capability token (env) | `broker` on `tasknet` only | Any credential; any other host |

Three independent enforcement layers (brief, principle 2):

- **Layer 1, token scope (Microsoft).** Each permission profile is a separate app registration consented only to its narrow permission set. The broker additionally checks the token claims against the profile's expected permission set and refuses the token on any mismatch (SD-004).
- **Layer 2, operation policy (broker).** Only named operations exist. Deny by default (SD-002, SD-003).
- **Layer 3, isolation (runner + Docker).** The task cannot see credentials and cannot reach anything except the broker (SD-008).

## 3. Repository structure

```
cloud-locksmith-analyst-workbench/
├── README.md
├── pyproject.toml                # one Python project; packages under src/
├── docker-compose.yml            # postgres, redis, api, broker, runner; networks backend/tasknet/egress
├── docker/
│   ├── api.Dockerfile
│   ├── broker.Dockerfile
│   ├── runner.Dockerfile
│   └── task.Dockerfile           # sandbox image: task_sdk + tasks only
├── migrations/                   # Alembic (revision IDs ≤ 32 chars)
├── profiles/                     # permission profile definitions (NO secrets)
│   └── directory-read-auditlog-read.yaml
├── tasks/                        # built-in tasks (trusted code), copied into task image
│   └── dormant_account_investigation/
│       ├── manifest.yaml
│       ├── classify.py
│       └── task.py
├── task_sdk/                     # separate package; imports nothing from src/clw
│   └── clw_task_sdk/
│       ├── __init__.py
│       ├── client.py             # GraphSecurityClient: named operations → broker
│       └── result.py             # emit_result: the one CLW_RESULT line
├── src/clw/
│   ├── common/                   # config.py (pydantic-settings), timeutil.py
│   ├── db/                       # base.py, session.py, models/
│   ├── audit/                    # canonical.py, chain.py, writer.py, verifier.py, checkpoint.py, events.py
│   ├── crypto/                   # fernet.py
│   ├── auth/                     # oidc.py, session_jwt.py, denylist.py, redis.py, signin.py
│   ├── api/                      # main.py, deps.py, routes/, middleware/rate_limit.py
│   ├── broker/                   # app.py, capability.py, manifest.py, profiles.py, operations.py,
│   │                             # policy.py, credentials.py, transport.py, pagination.py, service.py
│   └── runner/                   # launcher.py, sandbox_spec.py, result.py, lifecycle.py,
│                                 # reconciler.py, backend.py, catalog.py, __main__.py
├── tests/
│   ├── unit/                     # no network, no Docker; mocked Graph (respx)
│   ├── security/                 # brief's Phase 1 security table; boundary and tamper tests
│   ├── db/                       # needs Postgres (marker: pg): triggers, locks, concurrency
│   ├── sandbox/                  # needs Docker (marker: sandbox): egress, creds, timeout
│   └── integration/              # needs dev tenant (marker: tenant); never production data
└── docs/
```

**Why `task_sdk` is a separate package.** The task image is built from `task_sdk/` and `tasks/` only. The broker code, the profile files and the credentials are not in the image, so a task cannot import them. A unit test parses every module under `task_sdk/` and `tasks/` and fails if any of them imports `clw`, `msal`, `httpx` (other than the SDK client), `socket`, `subprocess`, or `os.environ` access beyond `CLW_RUN_TOKEN` and `CLW_BROKER_URL`. This is a hygiene check on trusted code, **not** a security boundary (SD-008).

## 4. Dependency map

### 4.1 Internal module dependencies (allowed directions only)

```
common  ◀── db ◀── audit ◀── broker
   ▲         ▲        ▲        ▲
   │         │        └─── runner
   │         └──────────── api ──▶ auth ──▶ crypto
   └──────────────────────────────────────────┘
task_sdk ──▶ (stdlib + httpx only)        tasks ──▶ task_sdk only
```

Rules (enforced by a test that inspects imports):

- `broker` must not import `api` or `runner`. `api` must not import `broker.credentials` or `broker.transport`.
- `task_sdk` and `tasks` must not import anything under `clw`.
- Only `broker.credentials` imports `msal`. Only `broker.transport` constructs Graph URLs.

### 4.2 Legacy → workbench mapping

Source: an earlier, private prototype, imported selectively from one tagged commit. The full disposition of each file is recorded in the private development repository.

| Legacy file | Workbench module | Disposition |
|---|---|---|
| `app/utils/datetime.py` | `clw/common/timeutil.py` | Import as-is |
| `app/db/base.py`, `app/db/session.py` | `clw/db/` | Import, async engine only |
| `app/config.py` (pattern only) | `clw/common/config.py` | Rewrite: only the settings the workbench needs |
| `app/services/audit/audit_logger.py`, `audit_chain_verifier.py`, `critical_events.py`, `app/db/models/audit_log.py`, trigger SQL from migrations `d8e9f0a1b2c3` and `c7d8e9f0a1b2` | `clw/audit/*`, `clw/db/models/audit_event.py`, one fresh migration | Import and redesign (SD-005, SD-006) |
| `app/services/crypto.py` | `clw/crypto/fernet.py` | Import and fix |
| `app/services/oidc_verifier.py` | `clw/auth/oidc.py` | Import and fix |
| `app/services/auth/jwt_service.py`, `token_denylist.py`, `app/core/redis_client.py` | `clw/auth/session_jwt.py`, `denylist.py`, `redis.py` | Import and fix |
| `app/db/models/oauth_state_nonce.py`, state handling in `app/api/routes/auth_microsoft.py` (pattern only) | `clw/auth/signin.py` | Rewrite without SMB/MSP branching |
| `app/middleware/rate_limit.py` | `clw/api/middleware/rate_limit.py` | Import as-is (route-name matching retained) |
| `app/services/graph_client.py` retry, error classification, `_token_permissions`, `_token_mode`, `is_non_premium_signin_activity_error` | `clw/broker/transport.py`, `credentials.py` | Reference only; rewritten |
| `app/services/graph_app_token.py`, `app/services/token_manager.py`, all other Graph helpers | none | **Not imported** (standing broad credentials) |

### 4.3 Third-party dependencies

| Package | Used by | Purpose |
|---|---|---|
| fastapi, uvicorn | api, broker | HTTP services |
| pydantic v2, pydantic-settings | all | Strict schemas (`extra="forbid"`), config |
| SQLAlchemy 2 (async), asyncpg, alembic | db, audit | Postgres 15 |
| redis | auth | Session revocation list |
| PyJWT[crypto], cryptography | auth, crypto | ID token and session JWT, Fernet |
| msal | broker.credentials | Certificate-based client-credentials token acquisition |
| httpx | broker.transport, task_sdk | HTTP client |
| PyYAML (`safe_load` only) | broker.manifest | Manifest and profile parsing |
| docker (SDK) | runner | Container launch |
| pytest, pytest-asyncio, respx | tests | Testing, mocked Graph |

The first install is about 100 MB of downloads, plus Docker images (postgres:15, redis:7-alpine, python:3.11-slim), so do it on Wi-Fi.

## 5. Backend API contract (Phase 1)

The public API is served by `api`. Every route except sign-in requires a session. **The tenant is always taken from the server-side session, never from the request.**

| Method | Path | Purpose | Notes |
|---|---|---|---|
| GET | `/auth/microsoft/start` | Begin OIDC sign-in | Issues single-use `state` and `nonce` |
| GET | `/auth/microsoft/callback` | Complete sign-in | Verifies state, nonce, iss, aud, tid, oid; checks workbench membership |
| POST | `/auth/logout` | Revoke session | Adds session `jti` to the revocation list |
| GET | `/tasks` | Task catalog | Summary per manifest |
| GET | `/tasks/{task_id}` | Manifest view | Purpose, profile + version, mode, allowed and prohibited operations (name + method + path), approval requirement, timeout, audit status |
| POST | `/runs` | Start run | Body: `{task_id, params}` (strict schema). Tenant and actor come from the session. |
| GET | `/runs/{run_id}` | Run status and results | 404 if the run belongs to another tenant |
| GET | `/runs/{run_id}/audit` | Audit events for the run, plus chain verification result | Tenant-scoped |
| GET | `/audit/verify` | Verify the tenant's whole audit chain | Tenant-scoped |

The internal broker API is served by `broker`, on `tasknet` only:

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/v1/ops` | `{"op": "<name>", "params": {...}}`, header `Authorization: RunToken <token>` | `200 {"status":"ok","data":...}` or `403 {"status":"denied","reason":"<code>"}` |

The broker schema has `extra="forbid"`. A body that contains `path`, `url`, `method`, `headers` or any other unknown field is rejected and audited as `DENIED / unknown_field`. No endpoint accepts a URL or a path.

## 6. Run lifecycle

```
api: POST /runs ── audit RUN_REQUESTED ──▶ runs.status = queued
runner: claim queued run (SELECT … FOR UPDATE SKIP LOCKED)
        mint run token (256-bit random; store SHA-256 hash + expiry = now + timeout)
        audit RUN_STARTED ──▶ start container (hardened spec, token in env)
task:   SDK → broker /v1/ops (named op)
broker: token→run→tenant→manifest→profile
        policy decision ── audit OP_DECISION (committed before any network I/O)
        if allowed: acquire+validate token ── audit GRAPH_REQUEST (intent)
                    send ── audit GRAPH_RESPONSE ── (per page / per retry)
                    return data
runner: on exit or deadline: kill container, collect bounded stdout result,
        revoke run token, audit RUN_COMPLETED | RUN_FAILED | RUN_TIMED_OUT
```

Only `app_only` mode is implemented in Phase 1. Manifests declaring `mode: delegated` are **rejected at load time** (fail closed) until the delegated path is built. The data model and audit schema already carry `auth_mode` so delegated runs need no schema change (SD-010).
