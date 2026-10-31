# Threat model

Status: **v0.1 beta.** Sections 1–7 cover the broker, audit and the frozen script sandbox; section 8 covers AI agents over MCP, the v0.1 feature. This document describes what the boundaries protect against and, as importantly, what they do not. Each mitigation is keyed to an entry in [security-decisions.md](security-decisions.md).

## 1. Assets

| Asset | Why it matters |
|---|---|
| Profile credentials (certificate private keys) | Grant app-only Graph access to a customer tenant |
| Graph access tokens (in broker memory) | Same as above, for about an hour |
| Customer directory data (users, sign-in times) | Personal data; tenant-confidential |
| Audit chain | The evidence a security lead hands to a reviewer |
| Run tokens | Let a task invoke its allowed operations for one run |
| Analyst sessions | Let a person start runs in a tenant |

## 2. Actors

| Actor | Assumed capability |
|---|---|
| External attacker | Calls public `api` endpoints; tampers with any request, header or body |
| Malicious or compromised analyst | Valid session in **their own** tenant; tries to reach other tenants or exceed task scope |
| Buggy or subverted task code | Arbitrary Python **inside the task container** (Phase 1 tasks are trusted built-ins, but we design as if this code were hostile) |
| Customer tenant admin | Can change consent on profile app registrations (for example, add permissions) |
| Workbench operator or DBA | Full access to Postgres, possibly to hosts |
| Microsoft endpoints | Trusted for token issuance; responses still validated (for example, `nextLink`) |

## 3. Trust boundaries

1. **Browser → `api`.** Nothing from the client is trusted. The tenant comes from the verified sign-in (`tid` + `oid`) only.
2. **Task container → `broker`.** The task is untrusted. The broker trusts only the run token, and everything the token resolves to comes from the database (run → tenant → manifest → profile).
3. **`broker` → Microsoft.** TLS to fixed hosts. The broker validates token claims and every server-supplied URL.
4. **Application → database.** The audit chain detects partial tampering. It does not stop a privileged DBA (section 6).

## 4. Threats and mitigations

### 4.1 Tenant isolation

| # | Threat | Mitigation | Test |
|---|---|---|---|
| T1 | Client supplies `tenant_id` to start a run elsewhere | `POST /runs` has no tenant field (strict schema); tenant from session only | `test_run_create_rejects_tenant_field`, `test_run_bound_to_session_tenant` |
| T2 | Analyst reads another tenant's run or audit by ID | Every query filters by session tenant; foreign IDs return 404 (no existence oracle) | `test_cross_tenant_run_returns_404`, `test_cross_tenant_audit_returns_404` |
| T3 | ID token with missing `tid` | Rejected (legacy accepted it) | `test_id_token_missing_tid_rejected` |
| T4 | ID token `tid` ≠ expected | Rejected | `test_id_token_tid_mismatch_rejected` |
| T5 | Replayed or forged ID token (nonce) | Nonce issued at `/start`, stored single-use, must equal the `nonce` claim | `test_id_token_nonce_missing_rejected`, `..._mismatch_rejected`, `..._replay_rejected` |
| T6 | Wrong issuer or audience | Rejected | `test_id_token_wrong_issuer_rejected`, `..._wrong_audience_rejected` |
| T7 | Signed-in user not a member of a workbench tenant | Callback denies; no session issued | `test_signin_unknown_membership_denied` |
| T8 | Graph token for the wrong tenant or app | Credential validator requires exact `tid` and app ID match; missing claim = mismatch | `test_graph_token_missing_tid_rejected`, `..._tid_mismatch_rejected`, `..._appid_mismatch_rejected` |
| T9 | Run token used against another tenant | Token resolves to exactly one run; the tenant is read from that run, never from the request | `test_run_token_cannot_select_tenant` |

### 4.2 Task scope (the broker boundary)

| # | Threat | Mitigation | Test |
|---|---|---|---|
| T10 | Task calls a write operation (`users.disable`) | Not in the manifest → deny; prohibited list checked; read-only profile token cannot write anyway | `test_readonly_task_disable_user_denied_and_audited` |
| T11 | Task calls an operation not in its manifest | Deny by default | `test_unlisted_operation_denied` |
| T12 | Task calls an unregistered operation name | Deny by default | `test_unknown_operation_denied` |
| T13 | Task smuggles a path or URL (`path`, `url`, `/beta`, `..`, `%2F`, `$batch`) | No API accepts a path; extra fields rejected; IDs validated as GUIDs before templating; final URL re-checked against the manifest's method + path pattern | `test_path_field_rejected`, `test_url_field_rejected`, `test_param_traversal_rejected`, `test_param_encoded_slash_rejected`, `test_built_request_must_match_manifest_pattern` |
| T14 | Parameter abuse (`$expand`, `$select` of unlisted properties, huge `$top`) | Per-operation parameter schema: `$select` from an allowlist, no `$expand`, bounded `$top` | `test_select_outside_allowlist_rejected`, `test_expand_rejected`, `test_top_out_of_bounds_rejected` |
| T15 | Malicious `@odata.nextLink` (other host, `/beta`, other path) | Broker follows pagination itself. `nextLink` must be https, host `graph.microsoft.com`, version `v1.0`, same path as the original request; page cap | `test_nextlink_foreign_host_denied`, `..._beta_denied`, `..._path_change_denied`, `test_page_cap_enforced` |
| T16 | Over-consented profile (admin added write permissions) | Token's permission set must **equal** the profile's expected set; superset → refuse token, run fails, audited | `test_graph_token_extra_role_rejected`, `test_graph_token_missing_role_rejected` |
| T17 | Run token reused after the run ends or the deadline passes | Token hash revoked on completion; expiry = start + timeout; broker checks the run status is `running` | `test_run_token_after_completion_denied`, `test_run_token_after_deadline_denied` |
| T18 | Throttling abuse or retry storms | Bounded retries on 429/503/504; `Retry-After` parsed (seconds or HTTP-date), capped; total wait bounded by run deadline | `test_retry_after_seconds`, `test_retry_after_http_date`, `test_retry_after_capped`, `test_retry_budget_bounded_by_deadline` |

### 4.3 Credential exposure

| # | Threat | Mitigation | Test |
|---|---|---|---|
| T19 | Task reads credentials from env, files or broker config | Not present in the task container (env holds only `CLW_RUN_TOKEN`, `CLW_BROKER_URL`); profile keys mounted only into `broker` | `test_task_env_has_no_secrets`, `test_task_cannot_read_profile_keys` (sandbox) |
| T20 | Task reads broker memory | Separate container, separate PID namespace | `test_task_cannot_see_broker_processes` (sandbox) |
| T21 | Tokens or secrets logged | Logging filter redacts `Authorization`, JWT-shaped strings and client assertions; audit stores no tokens | `test_logs_redact_bearer_tokens`, `test_audit_contains_no_tokens` |
| T22 | Run token leaks from the task | Worth only that run's allowed read operations until the deadline; stored as a hash only | design (documented limit) |

## 5. Fail-closed behaviour (SD-007)

### 5.1 Before a Graph request is sent: the request is not sent

| Failure | Result | Audit |
|---|---|---|
| Run token invalid, expired, or run not `running` | 401/403 to task | `OP_DECISION denied/run_token_invalid` (best effort; no run context if the token is unknown, so logged to stderr) |
| Manifest or profile fails to load or validate | Run fails to start | `RUN_FAILED manifest_invalid` |
| Unknown operation, unlisted operation, invalid params | 403 to task | `OP_DECISION denied/<reason>` |
| Policy engine raises any exception | 403 to task (exception never means allow) | `OP_DECISION denied/policy_error` |
| **`OP_DECISION` or `GRAPH_REQUEST` audit record cannot be committed** | **Request not sent**; 503 to task; run halted | stderr alert (the audit store is the failing component) |
| Token acquisition fails, or claims do not match the profile | Request not sent; run fails | `CREDENTIAL_REJECTED <reason>` |
| Run deadline already passed | Request not sent | `OP_DECISION denied/deadline_exceeded` |

Write-ahead rule: the `GRAPH_REQUEST` record (intent) is **committed** before the HTTP request leaves the broker. If the commit fails, nothing is sent. Because a commit can succeed while its acknowledgement is lost, an intent record means "authorized and possibly sent", never "definitely sent" (SD-007).

### 5.2 After a Graph request has succeeded

The read is already done, and that cannot be undone. The goal is that no data reaches the task without a matching audit record, and that the evidence gap stays visible.

| Failure | Result |
|---|---|
| `GRAPH_RESPONSE` audit record cannot be committed | Response data is **withheld** from the task (discarded from memory). The task gets 503. The run is halted: the broker refuses further operations for the run, and the runner marks it `FAILED / audit_unavailable` when the DB is reachable again. The committed `GRAPH_REQUEST` intent with no matching outcome stays in the chain, and the verifier reports it as `intent_without_outcome`. |
| Task crashes after receiving data | Runner records `RUN_FAILED task_error` with exit code; results already audited per request |
| Runner cannot record the final run outcome | Run stays `running` until the reconciler (run on runner start-up and every minute) marks runs past their deadline `RUN_TIMED_OUT / outcome_unrecorded`. If the terminal record cannot be written either, the row is still ended and the token revoked; the chain then shows the run without an end (SD-034) |

For future **write** operations (Phase 3, not built now) the same intent record lets a reconciler detect "intent without outcome" and put the operation in `OUTCOME_UNKNOWN` for human verification. It must never be retried automatically. This is why the write-ahead rule is in place from Phase 1.

## 6. Audit integrity: what the chain does and does not prove (SD-005, SD-006, SD-014–SD-018)

**What it provides (tamper evidence after writing).**

- Each record's hash covers a canonical serialization of every protected field plus the previous record's hash.
- Changing any covered field, deleting a record, inserting one, or reordering records is detected by the verifier, unless the attacker recomputes every later hash.
- The verifier also checks:
  - the record shape for each event type
  - the run state machine
  - approval binding: each attempt consumes exactly one allowed decision for the same method and path template, and its target is a relative `/v1.0` path matching that template
  - the schema version
  - timestamps: well-formed real dates; never earlier than the last trusted timestamp; not more than 5 minutes ahead of a later record (chain evidence, unaffected by when verification runs); and, for a record nothing later vouches for, not more than 5 minutes ahead of the verifier's clock (reported as `provisional`, SD-020)
  - recovery consistency: each recovery names its real predecessor and acknowledges only findings that existed before it
- Postgres enforces, against any role that is neither the table owner nor a superuser:
  - UPDATE, DELETE and TRUNCATE are rejected
  - inserts must extend the chain head
  - `created_at` must be a real calendar timestamp, no more than 5 minutes ahead of the database clock, and not earlier than the head's timestamp when that is trustworthy. These checks do not depend on session settings such as `TimeZone` (SD-019, gate 1 finding M-1)
  - text columns at most 1024 UTF-8 bytes, `request_target` at most 4096 (SD-021)
  - CHECK constraints on hash format, event type, schema version, and the shape, depth (15) and size (64 KiB compact UTF-8) of `details`

  The trigger functions use schema-qualified names and a pinned `search_path`, and TEMPORARY and `CREATE ON SCHEMA public` are revoked from `PUBLIC`, so temporary-table shadowing (gate 1 finding H1) is closed. The application role has only `SELECT, INSERT`, no role memberships, and no ownership. Tests run as that role.
- The **database server clock** is authoritative for `created_at` (SD-017). Writer hosts whose clocks drift by more than 5 minutes raise an `audit_clock_drift` alert.
- A writer that finds any unacknowledged integrity problem refuses to append and raises a critical alert. The tenant's runs stay stopped until an operator completes a recovery, which is verified after commit (SD-016, runbook `docs/runbooks/audit-chain-recovery.md`). A recovered chain is never reported valid again (`integrity_state` `recovered`), and every recovery record is listed by verification.

**What it does not provide.**

- **RR-1: Authenticity of events.** Any writer that can INSERT into `audit_events` can append fabricated records that are hash-consistent and follow every rule. That includes the api, broker or runner role, a compromised one of those components, or SQL injection through one of them. The verifier accepts such records (`test_forgery_with_plausible_timestamps_is_not_detectable`). The chain proves that records were not changed after they were linked. It does **not** prove that a recorded event happened, or that it happened as described. The same writer can also record a `CHAIN_RECOVERY` to unblock a chain it poisoned. Recovery records are always visible to verification, and the chain then never reports valid, but they are not proof of an authorized operator.
- **RR-2: Superuser or owner rewrite.** A DBA, superuser or table owner can disable the triggers, edit records, and recompute every hash from the edit point onward. The chain alone will verify. A hash chain stored in the database it protects cannot stop this.
- **RR-3: Tail truncation** after the newest checkpoint leaves a valid, shorter chain.
- **RR-4: Commit-acknowledgement ambiguity.** A `GRAPH_REQUEST` record means "authorized and possibly sent", not "definitely sent" (SD-007). Killing a task at its deadline does not cancel a broker request already sent; its late records are refused after the run's end (SD-034), so the intent stays listed without an outcome.
- **RR-5 (closed 2026-10-25, SD-039): query parameters are bound to approvals by the verifier.** The broker executes the very request the policy approved and records the approved target, query included, with each allowed decision (SD-018, SD-032). The chain verifier now requires every `GRAPH_REQUEST` to carry exactly that target, or that target plus one `$skiptoken` continuation and nothing else (`request_target_not_approved`). An allowed decision that records no target approves nothing. **What remains is RR-1:** a writer that can insert records can forge a decision and a matching request together, and the verifier accepts them; the chain proves the records agree, not that the events happened.
- **RR-6: Time is the database's.** A wrong database clock yields wrong but internally consistent timestamps. There is no independent or trusted time source in Phase 1. Timestamp anomalies are judged against later records where possible. A record ahead of the verifier's clock that nothing later can vouch for (the newest record, or at the start of a chain any record before the first trusted one) is only a *provisional* finding: if no evidence is written before the clock passes it, the chain holds no evidence it was ever ahead. While a chain has provisional findings, its other findings and the validity of its recoveries can also change as the clock moves, because a provisional record's trust status shifts the baseline for every later record. Once no provisional findings remain, verifying again later reports the same findings, as long as the records and the rules are unchanged and the verifier's clock does not move backwards. (SD-020, gate 1 finding F-2)

**Partial mitigation for RR-2 and RR-3 (checkpoints, format v3, implemented and tested).**

- A checkpoint signs, with an Ed25519 key held outside the database:
  - the tenant and chain
  - the sequence range and record count
  - the head hash
  - a fingerprint over per-record fingerprints of the **persisted** values (details verbatim as stored, so any storable value can be fingerprinted and none is reinterpreted)
  - a `VALID`/`INVALID`/`UNAVAILABLE` status
  - the findings
- Any rewrite, truncation or edit of a covered record is then detectable, including edits that leave stored hashes untouched and numeric rewrites a JSON parser would treat as equal.
- `INVALID` and `UNAVAILABLE` checkpoints record an incident's observed state but can never verify as ok.
- Records written after the newest checkpoint are still exposed.
- Phase 1 provides the commands but **no scheduler and no off-host storage**. The protection depends on an operator running `audit-checkpoint` regularly and copying the files somewhere the DBA cannot write. Until that exists, the system does not provide durable protection against database compromise.

**Not in Phase 1 (decided at gate 2, or later).**

- Per-component signing keys, so a record is attributable to the component that holds the key (SD-015, deferred to gate 2). Even then, a compromised component can still sign false records about its own actions.
- ~~Query-parameter binding in approvals~~: done, SD-039 (RR-5 closed).
- WORM storage and scheduling for checkpoints.
- RFC 3161 timestamping.
- Streaming audit records to an external append-only log the operator cannot rewrite.

Customer-facing wording must say **"tamper-evident"**, never "tamper-proof", "immutable" or "proof of what happened".

## 6a. The Graph facade for script runs (SD-041 to SD-045; Part B)

Script runs reach "Graph" only through the facade: inside their internal network, `graph.microsoft.com` is a credential-less proxy that forwards each request to the broker, which canonicalizes it and allows it only if the run's approved script manifest does. Every request is audited write-ahead and bound to its approval.

**What it protects against:**
- a write (any non-GET is refused and never sent);
- a request outside the approved manifest (path, version, `$select`, `$filter` properties, `$top`, `$expand` and the rest);
- path and encoding tricks;
- `$batch`;
- tampered or foreign nextLinks (paging stays broker-held);
- a script choosing its own identity (no route to Entra; its capability works only through the facade).

**Demo pages (SD-045).** They are a thin layer over the API's own route functions. Everything rendered is escaped, a script's output is shown only as text, the pages run no JavaScript (the CSP allows none), and a form post must carry the page's own `Origin`.

**Approvals (SD-043).** A script runs only under a security lead's approval of a GET-only manifest for its exact digest, never approved by its submitter. That is enforced by the API and by a database guard, and evidenced in the chain. The offline analysis explains a script; it never enforces.

**What it does not protect against:**
- misuse of what the manifest allows (the script receives that data);
- guessing a `$filter`/`$search` value from its audit record by anyone who holds the tenant's value key: the chain stores only a per-tenant keyed hash (SD-042), so a candidate value (a UPN, say) can be confirmed with the key until the key is deleted;
- a compromised broker;
- container escape. Third-party scripts need gVisor or a microVM first (section 7.3);
- a false failure reason from a script about its own run. A script can end its process with any output, so the `RUN_FAILED` reasons of script runs are reports from inside the sandbox (SD-044).

## 7. Task sandbox (SD-008)

### 7.1 Configuration

| Control | Setting |
|---|---|
| Network | Task attached **only** to Docker network `tasknet`, created with `internal: true` (no route off the host). `broker` is the only other member. No `egress` attachment. |
| DNS | Docker's embedded DNS resolves only container names on `tasknet`; external names do not resolve. Raw-IP connections have no route. |
| Credentials | Env contains only `CLW_RUN_TOKEN` and `CLW_BROKER_URL`. No volumes, no secrets mounts, no Docker socket. The image contains only `task_sdk/` and `tasks/`. |
| Filesystem | `read_only: true` root; `tmpfs /tmp` (16 MiB, `noexec`) |
| Privileges | Non-root UID, `cap_drop: [ALL]`, `security_opt: no-new-privileges`, default seccomp profile, no `privileged` |
| Limits | `mem_limit` 256 MiB, `nano_cpus` 0.5 CPU, `pids_limit` 64, stdout result capped at 5 MiB |
| Time | Runner kills the container at `timeout_seconds`. Broker independently rejects the run token after the same deadline (two enforcement points). |

### 7.2 What it protects against

- A task calling Graph directly: no credential to present, and no route to `graph.microsoft.com`.
- A task contacting any external host (data exfiltration over the network).
- A task reading broker credentials: they are in a different container and filesystem.
- A task spawning a subprocess (`curl`, PowerShell) to call Graph: same network and credential constraints apply.
- Runaway tasks: memory, CPU, PID and time limits.

### 7.3 What it does not protect against

- **Container escape** through kernel or runtime vulnerabilities. Containers share the host kernel. Every task, script and analyser container can run under gVisor (`CLW_TASK_RUNTIME=runsc`, SD-044). A first evaluation on a Kali Linux host (2026-10-26) found and fixed DNS, PID-limit and performance issues; its rerun passed every sandbox test under gVisor there; the pilot host is still to be tested (A-28). **gVisor or a microVM is required before anyone runs third-party scripts.**
- **A compromised Docker daemon or host**, or anyone holding the runner's Docker socket (equivalent to root on the host). The runner is a high-value component and must have no Graph credentials and no inbound exposure.
- **A compromised broker.** The broker holds credentials by design.
- **Misuse of allowed operations.** A task may legitimately read all user sign-in data its manifest allows and print it to stdout. The boundary limits *what can be touched*, not *what is done with permitted data*.
- **Timing or resource side channels** between containers on the same host.
- **Hostile task code in general.** Built-in tasks are reviewed. Script runs (Part B) execute code we did not write: the network, the facade and the hardening above confine them, but a kernel or runtime escape is not covered until they run under gVisor or a microVM (see container escape above).

### 7.4 Platform note

Development runs on Windows with Docker Desktop (WSL2). On 2026-10-14 (Docker 29.1.2) a manual probe from a container on an `internal: true` network found that external DNS failed (`SERVFAIL`), `1.1.1.1:443` was unreachable, and `graph.microsoft.com` did not resolve. A control container on the default bridge reached `1.1.1.1`. This is an observation, not a test.

The automated sandbox tests (plan Task 15, SD-008) are the source of truth. The escape probe runs inside a container built with the runner's real sandbox kwargs and attempts each escape; the tests assert the OS-level failure. They pass on both Docker Desktop (Windows/WSL2) and native Linux (Kali, Docker Engine) — `pytest -m sandbox` → 19 passed on 2026-10-20 (external egress blocked by attempt, raw socket and `setuid(0)` `EPERM`, `/` `EROFS`, PID limit capped, the over-running container killed at its deadline and its token revoked). The CI `sandbox` job on Linux (GitHub Actions) runs `pytest -m sandbox` as the ongoing gate; a failure blocks merging. Two properties are not proven by attempt: memory and CPU limits (config-verified only). `/tmp` `noexec` is confirmed by attempt on both platforms, but Docker mounts the tmpfs `noexec` by default, so our explicit flag is redundant defense-in-depth (SD-008 equivalent mutant).

## 8. AI agents over MCP (v0.1: built)

Status: **built for v0.1**, read-only tools and inert proposals (SD-047 to SD-055; tests named in each). Executing changes after a person approves them is roadmap D, and the rows that mention approval describe what D must meet.

**New actor:** an AI agent (Claude Code, Copilot, Cursor or a custom agent) acting for a signed-in person. Its instructions come from that person **and from any text it reads**, tenant data included. We assume it can be talked into anything.

**New asset:** the agent's **session capability**: 256 random bits, shown once and stored only as a hash, bound on the server side to one person, one tenant and one profile, with a TTL of 1 minute to 8 hours, and revocable.

| Threat | Mitigation (v0.1) | What it does not cover |
|---|---|---|
| **Prompt injection through tenant data** (a display name or description saying "disable all admins") | Tool outputs are labelled as data. The broker decides every call against the session profile, and nothing the model says changes the profile. Tools take no URL, tenant or profile. Fixtures in tests and the quick start (SD-053, SD-054). | The agent can still be misled *within* its profile: wrong conclusions, reading data it was allowed but not asked to read, or filing a proposal. |
| **Agent self-approval** ("approved" typed in chat or passed in a tool argument) | v0.1 has no approval step at all: proposals are never executed, and the agent is told so. For D: approval only in the web app, under a fresh sign-in, bound to the canonical request's hash, single-use and expiring. | A person who approves without reading (D). **Approval fatigue:** approvals turning into rubber stamps. D's approval-page requirements (roadmap D) reduce it; they can't remove it. |
| **Credential bypass via other tools** (the person's Azure CLI or Graph PowerShell login, a `.env`, a browser session on the same machine) | Out of reach by design: Cloud Locksmith limits only what goes **through** it. Run the agent where no other credentials exist (roadmap E), and every claim says so. | Everything an agent does outside Cloud Locksmith. |
| **Session capability theft or replay** | Accepted only as `Authorization: Bearer`, never from a URL. The gateway asks the broker on every request and caches nothing. The broker refuses it after its deadline, after revocation, after the profile changed, once the tenant is disabled, or once its starter may no longer use the profile (SD-048, SD-055). Never logged or audited. It is not an OAuth token: no authorization server exists (SD-048). | A copy used within its lifetime and profile: it is a bearer token. **In the quick start the capability is an environment variable in the agent's own shell**, so an agent with a shell tool can read it and use it outside the MCP client, still within the profile, and only where the gateway is reachable. A header helper that reads it from the OS keychain is better (SD-048). |
| **An agent driving the person's browser** (a computer-use or browser-extension agent on the same machine as a signed-in person) | Starting a session needs an interactive Microsoft sign-in (`prompt=login`) from the last 10 minutes (SD-055). An analyst can't start the broadest profile. | An agent acting within those 10 minutes, just after the person signed in, can start a session and read the capability off the page. |
| **An agent changing its own configuration** (editing its MCP config to point elsewhere, or raising its own profile) | The profile is chosen by the person at session start and stored server-side; no tool changes it. Editing the client config only disconnects the agent. | It may then use other credentials (see bypass above). |
| **An agent requesting or changing its own access.** Covers its profile, its session and the broker app's Graph permissions | **Profile:** server-side; a changed profile makes existing sessions refuse (`manifest_changed`). **Session:** issued only by a person in the web app (SD-055); no tool issues, extends or re-scopes one, and there is no refresh. **App permissions:** no tool touches app registrations, consent, role assignments or credentials. If the broker app's Graph application permissions are widened, the exact-set token check refuses the token (`permissions_extra`, SD-004). | A person who grants the agent more access when it asks. **Widening outside the token's `roles`:** the check sees only Graph application permissions. An Entra directory role assigned to the broker's service principal, Exchange RBAC for Applications, or Azure RBAC would add rights it can't see. Keep the service principal out of directory roles, and review it. |
| **Injection into the approval text** (tenant data or agent-written text shown to a person to mislead them) | The proposal list leads with the Graph effect from the stored canonical request. The target's name, UPN and state come from the **broker's own lookup**, never from the agent, and are shown escaped and labelled as tenant data with the object ID alongside. The agent's reason is boxed and labelled as the agent's. Invisible and direction-changing characters are shown as `[U+XXXX]`, inside `<bdi>` (SD-054). A display name written to look like an approval is a test fixture. | A plausible-looking but harmful change that a person accepts (D). |
| **Proposal flooding** (an injected agent files hundreds of proposals to bury real ones) | A profile must allow proposals. At most 20 per session, and each is audited. The list says how many exist when it shows the latest 100 (SD-054). | 20 per session, across many sessions. |
| **A compromised MCP gateway or MCP SDK** | The gateway holds no Microsoft credential, no database access and no route to Graph of its own (SD-052). The broker decides everything. | It sees every capability in transit (plain HTTP on the internal network) and could replay one during its lifetime, within its profile. It could also tell the agent things that aren't true, for example a fake "proposal filed". |
| **Over-broad generic tool** | None in v0.1. One, if built, follows SD-047: matched against the registry and never forwarded. | Misuse of what the profile allows. |
| **Exfiltration of allowed data by the agent** (the agent sends data it may read to a third party) | Not prevented by the broker. Profiles allow only what the task needs; response filtering trims each result. The sandbox recipe (E) would limit egress. The model provider sees every tool result. | An agent with internet access can send what it read. |
| **Audit growth** (agents add records quickly) | Every record is needed. | The session and proposal pages load and verify the whole tenant chain on each view, so the cost grows without bound. Paging and checkpoint-based verification are later work. |
