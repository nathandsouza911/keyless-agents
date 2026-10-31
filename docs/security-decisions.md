# Security Decisions

Each entry records a security-relevant decision, the threat it addresses (keyed to [threat-model.md](threat-model.md)), and its known limits. **Every imported component and every security fix adds an entry here in the same commit.**

Status values: `proposed` (design, awaiting approval), `accepted` (approved, not yet built), `implemented` (in code, with tests).

---

## SD-001: Separate codebase; legacy repository preserved

- **Status:** proposed
- **Decision:** The workbench is a new repository. Legacy code is imported selectively from one tagged commit of an earlier, private prototype. The prototype is not modified.
- **Threat addressed:** Legacy code built around one broad, standing Graph credential (`graph_app_token.py`, `token_manager.py`) leaking into the broker and silently widening its authority.
- **Limits:** Shared lineage means fixes found here (SD-005, SD-009, SD-011) also apply to the legacy product and must be reported there separately.

## SD-002: Named operations only; no task-supplied URLs

- **Status:** implemented (registry and request builder, `src/clw/broker/operations.py`, Task 7). Its callers are the policy (Task 9), the transport (Task 11) and the broker service (Task 12, SD-032), whose `POST /v1/ops` body is exactly `{op, params}`.
- **Decision:** Task code can invoke only registered operation names with schema-validated parameters. The broker alone builds the HTTP request (method, path, query) from a fixed template. No interface accepts a URL, path, method or header. Unknown operations are denied.
- **Threat addressed:** T11–T14: path traversal, encoding tricks, `/beta`, `$batch` and `$expand` smuggling. A whole class of bugs disappears because there is no raw-request surface to normalize.
- **Limits:** The broker's own templates become the trust anchor. A wrong template is a broker bug, which SD-003's second check is designed to catch.

- **Implementation (Task 7):**
  - **Registry:** four operations, read-only `MappingProxyType`, frozen specs. `users.list_with_sign_in_activity` (read, executable, `GET /users`, paginated) and three writes registered for display and prohibition only: `users.update` (`PATCH /users/{user_id}`), `users.delete` (`DELETE /users/{user_id}`), `directory_roles.add_member` (`POST /directoryRoles/{role_id}/members/$ref`). Write bodies are not modelled.
  - **Lookup:** `get(name)` is exact (no case folding or trimming); anything else, including a non-string, raises `UnknownOperation` (a `KeyError`).
  - **Building:** `build_request` accepts only the registered spec object itself (an equal copy or an edited spec is `UnknownOperation`), refuses every non-executable operation with `NotExecutable` before reading its parameters, and validates parameters with the operation's strict, `extra="forbid"` model. Path placeholders take only a GUID (`^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$`), checked by the model and again by the renderer, and are emitted lowercase.
  - **Post-check:** the built target (`/v1.0` + path + query) must pass the audit chain's own `target_matches_template` (Task 2b) and contain no `..`, `//`, `%` or `\`, so an approval's template always covers the request built for it.
  - **Import-time checks:** every template passes `valid_path_template`, has no `/beta`, `$batch` or `v1.0` (any case), and its placeholders are exactly fields of its model; models are strict and forbid extra fields; the only other model fields are `select` and `top`; reads are `GET`; writes are not executable; only reads paginate; a `select` field's choices equal the spec's allowlist. A bad entry stops the broker at import.
- **Tests:** `tests/security/test_operations.py` (213): registry contents and immutability; exact lookup; forged and copied specs refused; every write op `NotExecutable` with any parameters; `$select` outside the allowlist, wrong case, duplicates, empty, missing or not a list rejected; `$expand`, `$filter`, `$search`, `$orderby`, `$count`, `$skip`, `$skiptoken`, `nextLink`, `path`, `url`, `method`, `headers` and similar keys rejected; `$top` 0, 1000, a bool, a float or a string rejected; `../me`, `%2E%2E`, `a/b`, `me`, a UPN, `delta`, `microsoft.graph.user`, a trailing newline, a full-width digit and other non-GUIDs rejected by the model and by the renderer; every one of the 508 valid parameter sets (all 127 `$select` subsets × four `$top` choices) builds a path with no `..`, `//`, `%2F`, `%5C`, `/beta` or `$batch` that matches the audit template rule; the post-check refuses a renderer that returns `/users/../me` or another collection; each import-time check refuses its bad entry.
- **Mutation check (ad hoc):** 25 mutants; 24 killed. One **survived**: removing the builder's re-check that `$select` is within the spec's allowlist, because the params model's `Literal` choices already refuse anything else and the import-time check requires those choices to equal the allowlist. It is kept as an explicit layer; it is not counted as killed. A mutant removing `re.ASCII` from the renderer's GUID regex was equivalent (the character classes are explicit ASCII), so the flag was removed rather than counted.
- **Deviations from the plan:** none in the interface. Additions: `UnknownOperation` (a `KeyError`, as the plan's `get` contract requires) and `InvalidParams`; `select` is required (without `$select` Graph returns its default property set, not the allowlist); an explicit `top: null` is the same as omitting it.

## SD-003: Two-stage policy evaluation, deny by default

- **Status:** implemented (`src/clw/broker/policy.py`, Task 9)
- **Decision:**
  - **Stage 1** (`authorize_operation`) denies, in this order: `unknown_operation` (not a plain `str` naming a registered operation; `str` subclasses are refused), `prohibited`, `not_in_manifest`, `not_executable` (a write, or a read marked not executable), `invalid_params` (the registry's strict params model or `InvalidParams` refuses them). Otherwise it returns the request built by `operations.build_request`.
  - **Stage 2** (`authorize_request`) checks the **built** request against `RULES`: one rule per executable read, taken from the registry when the policy module is imported, so a registry entry replaced at runtime cannot widen it. The request passes only if, for an operation the manifest allows and does not prohibit, the method and declared template equal the rule's; the path fully matches the template compiled to a case-sensitive regex (literals escaped, each placeholder a lowercase GUID); and the query is exactly the normalized form the registry emits (permitted names only, each once, `$select` before `$top`; `$select` sorted and unique; `$top` with no sign or leading zero) with values the operation's params model accepts. Otherwise `request_pattern_mismatch`. Stage 2 therefore checks the query as well as method and path (SD-018).
  - **`evaluate`** is the only entry point for the broker. Any exception, or an engine result that is not a `Decision` (and, for stage 1, a `BuiltRequest` when allowed), is `policy_error`; exception detail is dropped, because messages can quote parameters. A denial never returns a request. After both stages allow, `evaluate` checks for itself that the request belongs to the named operation: the name is allowed and not prohibited, the request matches that operation's rule, and it equals what the registry builds from the same parameters. A replacement engine (for example OPA) can therefore deny more, but it cannot allow an operation the manifest does not, or substitute a different request.
  - **`Decision`** cannot be constructed inconsistently: `allowed` must be a `bool`, the reason one of the eight codes, and `allowed` true exactly when the reason is `allowed`.
  - **No reliance on configuration validation.** The manifest loader already refuses overlaps, writes in `allowed` and unregistered names (SD-030); the policy makes each check again at decision time, and refuses a `TaskManifest` whose name lists are not tuples of `str` (a `str` would make `in` match substrings).
  - A manifest whose `allowed` and `prohibited` overlap fails to load (SD-030); if one were constructed anyway, `prohibited` wins.
- **Threat addressed:** T10–T13, and template bugs in the broker itself.
- **Tests:** `tests/security/test_policy.py` (214): the plan's five cases; the reason order; every check holding for manifests that bypass the loader (overlap, writes and unregistered names in `allowed`, empty `allowed`, malformed name lists); a non-executable refused even when the builder no longer refuses it; lookalike and non-`str` names; request-shaping and unsafe params; all 381 valid parameter sets allowed and equal to the registry's request; stage 2 refusing changed methods, paths, templates and 31 non-normalized or unpermitted queries, lookalike request types, prohibited and write operations; rules fixed at import, literals escaped, GUID placeholders lowercase; `evaluate` turning exceptions and malformed engine results into `policy_error`, never returning a request with a denial, returning the very request stage 2 checked, and refusing a permissive engine that allows an op outside the manifest, an unknown op, an altered or lookalike request, swapped parameters, or a request with a template bug.
- **Mutation check (ad hoc):** 47 mutants of `policy.py`; 47 killed. The first run killed 37. Four survivors were test gaps (permissive-engine tests returned a request that also failed the rebuild check, hiding the membership and rule checks; no test reached the import-time unknown-field check, literal escaping, or the stage 1 executable check independently of the builder) and were closed with tests; two redundant clauses in the query check (duplicate and unknown names, both already refused by the order comparison) were removed rather than counted.
- **Deviations from the plan:** `users.update` in the dormant manifest is denied as `prohibited`, not `not_in_manifest`: the plan's example contradicts its own stated order, and the explicit order was followed (both deny; Task 12's `test_readonly_task_disable_user_denied_and_audited` should expect `prohibited`). Stage 2 also checks the query, and `evaluate` adds the belongs-to-the-named-operation check; neither is in the plan's interface.
- **Limits:**
  - Policy covers *which* operations run and the exact request shape, not *how much* data a permitted operation returns.
  - The policy decides; it records nothing. The broker service records each decision and executes the very `BuiltRequest` the policy returned (Task 12, SD-032); see SD-018 for what the audit chain itself does and does not check.
  - Pagination requests (`nextLink`) are not authorized here; Task 11 validates them against the original `BuiltRequest`.
  - The policy trusts the code it runs in: a change to `policy.py` or the registry source changes the rules.

## SD-004: Credential validation is separate from task authorization

- **Status:** implemented (`src/clw/broker/credentials.py`, Task 10)
- **Decision:** The credential provider checks that a profile's token is the right token:
  - `tid` = tenant
  - app ID = profile client ID
  - audience = Graph
  - app-only token type
  - permission set **exactly equal** to the profile's expected set

  It knows nothing about tasks. Task authorization (SD-003) is evaluated independently for every operation and never consults token claims. Neither check substitutes for the other, and script analysis (Phase 4) is never an enforcement input.
- **Implementation:**
  - `validate_token_claims` refuses, in order: `tid_missing`/`tid_mismatch` (exact string match with the run's tenant), `appid_missing`/`appid_mismatch` (`appid` or `azp`; every one present must equal the client id), `aud_mismatch` (exact match), `not_app_token` (`scp` present; `idtyp` present and not `app`; or neither `idtyp` nor `roles`), `permissions_extra` (any role outside the expected set, or a non-string role), `permissions_missing`. Extra is checked before missing, so an over-consented token (T16) is reported as such even when a role is also missing. Empty expected values and delegated profiles are refused as caller errors (`ValueError`).
  - `MsalCertificateProvider.token_for(tenant_id, profile)`: the tenant must be a lowercase GUID (it is also the authority path, `login.microsoftonline.com/{tid}`). One `ConfidentialClientApplication` per (tenant, profile id, version, sha256), with MSAL's default in-memory cache only, so an edited profile gets a fresh app. The client id, certificate key path and thumbprint are read from the environment variables the profile names, only when an app is first built; the client id must be a GUID, the thumbprint 40 hex characters, and the key file at most 64 KiB containing a private key. The scope is `{resource}/.default`. MSAL runs in a worker thread, off the event loop. Every token, cached or not, is decoded (claims only) and validated before it is returned; `exp` must be an integer at least 60 s in the future.
  - Configuration, file, MSAL and decoding failures are all `acquisition_failed`. Rejections carry only the reason code and are raised outside `except` blocks, so MSAL's response, a file's contents or a token are never attached as context. `ValidatedToken.access_token` is excluded from `repr`.
  - **The Graph resource is a constructor argument, not a constant in this module.** The Task 0 boundary test lets only `clw.broker.transport` (Task 11) name the Graph host; the broker will pass transport's origin (Task 12), so the audience a token is checked against is the origin requests go to. It must be an `https://` origin with no path.
- **Threat addressed:** T8 (wrong tenant or app), T16 (over-consented profile). Prevents "the token allows it, so the task may do it".
- **Tests:** `tests/security/test_credentials.py` (123; carries the `# A-06/A-08` marker): the plan's ten cases; exact-match variants for `tid`, `appid`/`azp` and `aud`; `idtyp` and `scp` combinations; extra, case-variant and non-string roles; MSAL error dicts, exceptions, missing or malformed tokens (including `bytes`), and missing, past, near-expiry or non-integer `exp` as `acquisition_failed`; missing or malformed environment and key files refused before any MSAL app is built; tenant arguments that are not lowercase GUIDs (`common`, traversal) refused; one app per tenant and profile, with every token validated again; only the profile's environment variables read; MSAL called off the event loop; no token, key or thumbprint in any rendering of an error or the provider. Separation: `credentials` imports nothing from `policy`, `manifest` or `operations`; `policy` imports nothing from `credentials`, `msal` or `jwt`, and `evaluate` takes no token; a valid token (even one carrying a write role a profile expected) leaves the policy's denials unchanged, and a policy allow does not make a bad token valid.
- **Mutation check (ad hoc):** 49 mutants of `credentials.py`; 48 run in the final pass, 48 killed. The first pass killed 46: two survivors were test gaps (a `bytes` token, which PyJWT would decode; a float `exp` in the future), now tested; one (an explicit empty key path check) was equivalent, because opening the path already fails, and the check was removed rather than counted.
- **Deviations from the plan:** `validate_token_claims` and `MsalCertificateProvider` take the Graph resource (`audience` / `resource`) as an argument, for the boundary reason above. The provider also takes `environ`, `app_factory` and `clock` for testing; production uses `os.environ`, MSAL and `utc_now`.
- **Limits:**
  - Graph access tokens are not meant to be signature-validated by clients (assumption A-07). Claims are trusted because the token came straight from the Entra token endpoint over TLS.
  - Claim names are verified against Microsoft Learn (A-06, A-08; 2026-10-20): app-only tokens carry `roles` (not `scp`) and `idtyp == app`, and the app id is `appid` (v1) or `azp` (v2); the validator accepts either. The `aud` **value** Graph emits (origin vs resource GUID) is still unverified: if Graph issues `aud` as a GUID, every token is refused (fail closed) until revised. MSAL certificate client credentials (A-10) are supported, but the `{private_key, thumbprint}` (SHA-1) form is now deprecated in favour of PFX/SN+I (SHA-256), a later design decision. No real token has been validated.
  - An over-consented profile is detected only through a newly issued token (A-09).
  - Recording `CREDENTIAL_ACQUIRED`/`CREDENTIAL_REJECTED` and failing the run on a rejection are done by the broker service (Task 12, SD-032); the token is used only by the transport (Task 11). MSAL's own logging is not configured here.

## SD-005: Audit records are canonicalized and every security field is hashed

- **Status:** implemented (`src/clw/audit/{canonical,chain,events}.py`). Record schema version 2 since the gate 1 fixes.
- **Decision:**
  - Each audit record hash is `SHA-256("clw-audit-v1\n" || canonical_json(record_without_hash))`.
  - `canonical_json`:
    - keys sorted by Unicode code point. This is the workbench's own scheme, **not RFC 8785/JCS**, which sorts by UTF-16 code units; the two differ only for keys mixing U+E000–U+FFFF with supplementary-plane characters.
    - separators `,` and `:`
    - UTF-8
    - only str, int, bool, null, list and object allowed (floats rejected; durations stored as integer ms)
    - timestamps as RFC 3339 UTC strings with microseconds and `Z`. The **value** comes from the database server clock (`clock_timestamp()`, read by the writer inside the append transaction, SD-017); the writer formats it and hashes the string, which is stored as text exactly as hashed. (Corrected in the fourth round: this line previously said "generated by the application, not the database", which stopped being true when SD-017 made the database clock authoritative.)
  - The hash covers every column except `record_hash`:
    - `schema_version`, `chain_id`, `seq`, `tenant_id`, `event_type`, `status`, `reason`, `outcome`
    - `run_id`, `task_id`, `task_manifest_sha256`, `profile_id`, `profile_version`, `auth_mode`
    - `actor_oid`, `actor_tid`
    - `operation`, `decision_seq` (added during implementation: the seq of the allowing `OP_DECISION`), `http_method`, `path_template`, `request_target`, `http_status`, `graph_request_id`, `attempt`, `item_count`, `duration_ms`
    - `details`, `created_at`, `previous_hash`
- **Threat addressed:** Legacy gap: `status` and `reason` were not hashed, so a privileged edit turning "blocked" into "allowed" was undetectable by the verifier. Also removes serialization ambiguity.
- **Canonicalization details:** integers limited to ±(2^53−1); strings must be valid UTF-8 without NUL; no Unicode normalization; tuples and sets are rejected (lists only); nesting is limited to 16 levels (so `details` can be at most 15 levels deep, enforced by the database too).
- **`details` size limit:** 64 KiB, defined as the **UTF-8 byte length of the compact JSON serialization**.
  - That is the canonical form; key order does not change the length.
  - The writer enforces it before hashing and insert, and the verifier flags stored records over it.
  - The database enforces the same quantity independently (`clw_jsonb_compact_size`, whose equality with the Python definition is tested), after a cheap stored-text length pre-check.
  - The canonical form is not used for checkpoint fingerprints (SD-006).
- **Text field limits:** every text field is at most 1024 UTF-8 bytes, `request_target` at most 4096. Enforced by the writer, reported by the verifier (`invalid_event_shape`; `invalid_record` for `chain_id`), and enforced independently by the database with `octet_length()` (SD-021).
- **Pattern matching:** every validation pattern uses `fullmatch` and ASCII `[0-9]`, so trailing newlines and non-ASCII digits are rejected (gate 1 finding N5).
- **Event shape:** every event type has required, optional and forbidden fields (`events.RULES`). The writer refuses malformed events (`AuditEventInvalid`, a subclass of `AuditUnavailable`, so callers fail closed), and the verifier reports `invalid_event_shape`.
- **Tests:**
  - every protected field × every record of a realistic run is tampered individually (`tests/unit/audit/test_chain_tamper.py`, 224 cases), plus the same with the record's own hash recomputed, which must break the next link
  - deletion, insertion, reordering, duplicate seq, splicing from another chain, and genesis tests
  - malformed-record matrix: verification never raises (`tests/unit/audit/test_malformed.py`)
  - `scripts/audit_mutation_check.py` lists the deliberate weakenings that must make the test suite fail. Its own output gives the current count. A mutation counts as killed only when pytest reports test failures that are not infrastructure, import or collection problems, and, for the fourth-round mutations, only when the named expected tests fail. Everything else is reported `BROKEN` and fails the run. An unmutated baseline must pass first (classification tested in `tests/unit/test_mutation_check.py`). Equivalent mutants are documented in the script rather than listed.
- **Limits:** see SD-006.

## SD-006: Tamper evidence, not tamper prevention; signed external checkpoints

- **Status:** implemented (`src/clw/audit/writer.py`, migrations `20261014_audit_events`, `20261015_audit_hardening` and `20261016_audit_time_size`, `src/clw/audit/checkpoint.py`, `python -m clw.cli audit-checkpoint` / `audit-verify-checkpoint` / `audit-verify` / `audit-recover` / `audit-keygen`)
- **As built (database):**
  - UPDATE, DELETE and TRUNCATE are rejected unconditionally.
  - A `BEFORE INSERT` trigger rejects any row that does not extend the chain head (`seq = head + 1`, `previous_hash = head.record_hash`, or seq 1 linked to genesis).
  - The same trigger rejects a `created_at` more than 5 minutes ahead of the database clock, and one earlier than the head's timestamp when that is trustworthy (well-formed and not more than 5 minutes ahead of the database clock) (SD-017). These checks read no session setting, so the app role cannot switch them off with `SET TIME ZONE` (SD-019, tested under six zones).
  - Text columns are bounded in UTF-8 bytes (SD-021).
  - CHECK constraints require:
    - lowercase-hex hashes
    - known event types
    - a real calendar timestamp in the fixed format
    - `schema_version = 2`
    - `details` an object, at most 15 levels deep and at most 64 KiB in compact serialization (SD-005), with a cheap length pre-check ordered before the recursive checks
  - The application role must have only `SELECT, INSERT` on `audit_events`, must not own the table, and must have no role memberships. Tests running as such a role show it cannot:
    - UPDATE, DELETE or TRUNCATE
    - disable or drop triggers, drop constraints, create rules, or set `session_replication_role`
    - replace trigger functions or create objects in `public`
    - bypass continuity via COPY or `ON CONFLICT`
    - shadow the table with a temporary table. Functions are schema-qualified with a pinned `search_path`, TEMPORARY is revoked from `PUBLIC`, and the attack is replayed with TEMP re-granted.

    The trigger still blocks changes if UPDATE/DELETE are over-granted.
  - Test hygiene (fifth review I-2): privileged test steps bypass triggers with `session_replication_role = replica` on their own session rather than `ALTER TABLE ... DISABLE TRIGGER`, and the one test that needs an impossible timestamp restores the validated constraint afterwards. An autouse fixture compares, after every pg test that uses the shared test database, a fingerprint of its security-relevant state against the one captured right after migration (`tests/db/schema_fingerprint.py`; targeted review I-c, previously counts only; final review L-1). It covers constraint, trigger, index, rule and policy definitions; constraint validation and trigger enabled state; every function in schema `public` (body, STRICT, volatility, security definer, settings, return type, owner, EXECUTE privileges); columns including defaults and column privileges; every relation in `public` with owner, privileges and row security; schema and database ownership and privileges; database- and role-level settings that reach the database; extensions, event triggers, default privileges, and the attributes and memberships of the `clw*` roles. It does not cover other databases, the server configuration file or `pg_catalog`. `tests/db/test_schema_guard.py` applies 24 weakening changes (including every case the final review found missed) to the shared test database inside a transaction that is always rolled back, and shows each is detected and that the schema is back to the reference afterwards. `tests/db/test_schema_guard_wiring.py` runs a separate pytest session against its own database and shows that the fixture itself fails a test that leaves a change behind, and the next test too (final review I-1). This is test infrastructure: it keeps a test from weakening the database that later tests run against; it says nothing about production databases.
  - Tests pin the residual risk: a superuser who disables the triggers and edits one record is caught by the verifier, while one who rewrites from that record to the head with recomputed hashes is **not** (`test_superuser_full_rewrite_is_not_detected_by_verifier_alone`).
- **As built (checkpoints, format v3; gate 1 findings M2 and N1):**
  - **Fingerprint per record:** SHA-256 over a length-prefixed encoding of every persisted column in fixed order, with `details` taken **verbatim as the text PostgreSQL returns**. No JSON parsing or re-serialization is involved.
    - This works for anything the database can store: floats, integers above 2^53, the maximum depth, malformed rows.
    - It cannot silently convert a value. A `1.5` → `1.50` rewrite, which a JSON parser would treat as equal, is detected (tested).
  - **Chain fingerprint:** SHA-256 over the ordered list of record fingerprints.
  - **What is signed (Ed25519):** `tenant_id`, `chain_id`, `seq_from`, `seq_to`, `record_count`, `head_record_hash`, `chain_fingerprint`, `status`, `findings`, `reason`, `issued_at` and `key_id`.
  - **Statuses:**
    - `VALID`: every check passed, the range starts at seq 1, and there are no findings.
    - `INVALID`: the findings are signed with the exact observed state (`--allow-invalid`).
    - `UNAVAILABLE`: the state could not be determined; a reason is given and there is no fingerprint (`--record-unavailable`).
  - **Cross-check (gate 1 finding F-4, fourth review):** after the fingerprint matches, the signed `seq_from`, `seq_to` and `head_record_hash` must equal those of the covered records; otherwise the result is `checkpoint_inconsistent`. This only matters for a checkpoint signed with the real key but with inconsistent fields (a signer bug or a key holder); unsigned tampering already fails the signature. `issued_at` cannot be derived from the records and is not cross-checked. Tested field by field.
  - **Only `VALID` can verify as `ok`.** `INVALID` and `UNAVAILABLE` are evidence of an observed state, never integrity attestations. Relabelling one breaks the signature (tested).
  - Fingerprinting is not validation: `verify_records` alone decides the status, and an invalid chain stays invalid however it is fingerprinted.
  - Checkpoint and key files are created with O_EXCL and never overwritten. Chain IDs are validated before being used in file names.
- **As built (broken chains, gate 1 findings H2 and N2):**
  - The writer verifies the chain before appending: in full on first use, then incrementally from a bounded cache of verified positions. A cached position is used only while its timestamp is well formed and not more than 5 minutes ahead of the database clock; otherwise the writer drops it and verifies in full (SD-024).
  - It self-checks every record it builds before inserting it.
  - It refuses all appends while an unacknowledged integrity finding exists, raising `AuditChainCompromised` with a CRITICAL alert.
  - Appends resume only after a verified recovery (SD-016).
- **Operational requirement (not enforced by code):** checkpoints protect only if the signing key and the checkpoint files are outside the database operator's control, and checkpoints are taken regularly. Scheduling and off-host storage are **not built in Phase 1**, so the current system does not yet provide durable protection against database compromise.
- **Decision:**
  - Records are written with a **single INSERT** (hash computed before insert), so the trigger can block all UPDATE and DELETE.
  - `(chain_id, seq)` is unique, and inserts take a per-chain advisory lock.
  - Signed checkpoints are exported with an Ed25519 key held outside the database.
- **Threat addressed:** Partial tampering, forks, a full chain rewrite before the last checkpoint, and edits invisible to JSON-level comparison.
- **Limits:**
  - A DBA can still rewrite the chain after the last checkpoint, and truncate the tail since then (RR-2, RR-3).
  - Documented in threat-model §6.
  - Customer-facing wording is "tamper-evident", never "tamper-proof".

## SD-007: Fail closed before the request; withhold data after an audit failure

- **Status:** implemented (audit primitives: `AuditWriter`, `write_ahead.audited_attempt`, Task 2b; wired into the broker through the transport's write-ahead hooks, Tasks 11–12, SD-031, SD-032). "Prohibited or unaudited requests never reach Graph" is shown at the broker's egress with mocked Graph (`tests/db/test_broker_ops.py`, `tests/db/test_broker_fail_closed.py`); the receiving-end proof with a fake Graph container is Task 17.
- **As built:**
  - Every append commits in its own transaction before returning. Every `Exception` raises `AuditUnavailable` or a subclass (`AuditEventInvalid`, `AuditChainCompromised`).
  - Non-`Exception` errors (`asyncio.CancelledError`, `KeyboardInterrupt`) propagate unwrapped. They still fail closed: the transaction rolls back, nothing is returned, `send` is never called without a committed intent, and no data is released without a committed outcome (tested).
  - `audited_attempt` never calls `send` without a committed intent, and never returns data without a committed outcome.
  - Real-database tests cover an unreachable database before the request (nothing sent), a database lost after the response (data withheld, gap visible as `intents_without_outcome`), and inserts refused by privileges.
- **Known ambiguity:** if the connection drops after COMMIT but before the acknowledgement, the writer raises even though the row may exist. The caller fails closed, so the worst case is an intent record for a request that was never sent. A `GRAPH_REQUEST` record therefore means "authorized and possibly sent", not "definitely sent".
- **Decision:**
  - The `OP_DECISION` and `GRAPH_REQUEST` (intent) records must commit before any network I/O to Microsoft. Failure means no request.
  - If the `GRAPH_RESPONSE` record cannot commit, the response is withheld from the task and the run is halted.
  - The verifier reports intents without an outcome.
  - Full matrix in threat-model §5.
- **Threat addressed:** Actions without evidence; evidence gaps hidden by silent fail-open (legacy logger returned `None` on failure for non-critical events).
- **Limits:** A successful read cannot be undone. The guarantee is that no data reaches the task unaudited, and that the gap stays visible.

## SD-008: Task sandbox is a separate boundary

- **Status:** implemented and tested against a real Docker daemon (Task 15: `tests/sandbox/test_escape_attempts.py`, `tests/db/test_sandbox_timeout.py`, probe `tests/fixtures/tasks/escape_probe/`, image `docker/task-probe.Dockerfile`, CI `sandbox` job). Configuration was built in Task 14 (SD-034: `sandbox_spec.py`, `docker/task.Dockerfile`, `docker-compose.yml` networks). **Verified on native Linux (Kali, Docker Engine, 2026-10-20): `pytest -m sandbox` → 19 passed**, confirming the properties hold on real Linux and not only Docker Desktop. The CI `sandbox` job on Linux remains the ongoing gate.
- **Decision:** Hardened container on an `internal` Docker network shared only with the broker; no credentials; resource and time limits. The configuration is in threat-model §7.1.
- **Threat addressed:** T19, T20; brief's tests on direct Graph access, external hosts, subprocesses and timeouts.
- **Tests (how each property is proved).** A test-only probe (`escape_probe`) runs INSIDE a container built with the runner's real `sandbox_container_kwargs`, on the `internal` network, and actually attempts each escape; the tests assert the OS-level failure it reports, not configuration strings. The probe image carries `curl` on purpose, so the subprocess test is a real attempt.
  - **External egress blocked:** DNS for `graph.microsoft.com` fails, a TCP connect to it fails, a raw-IP connect (`1.1.1.1:443`) has no route, and `curl` to both fails — all by attempt (`test_task_cannot_reach_graph_directly`, `test_task_cannot_reach_raw_ip`, `test_subprocess_cannot_call_graph`).
  - **Broker reachable (positive control):** a stub on `tasknet`, resolvable as `broker`, is reached, so the block is egress-specific, not a dead network (`test_task_can_reach_the_broker_endpoint`).
  - **No secrets:** no secret-named env var is present, `/run/secrets` and the broker's profile-key and docker-socket paths do not exist (`test_task_env_has_no_secrets`, `test_task_cannot_read_profile_keys`). The runner injecting exactly the two keys is proved deterministically off-Docker in `tests/unit/runner/test_sandbox_spec.py`.
  - **No broker processes:** the container's PID namespace shows only the probe (`test_task_cannot_see_broker_processes`).
  - **Read-only root, bounded write:** writing to `/` fails `EROFS`; `/tmp` is writable but a script there cannot be executed (`test_rootfs_read_only`, `test_tmp_is_writable`, `test_tmp_is_noexec`).
  - **Non-root, capabilities dropped, no escalation:** the task runs as uid 10001; a raw socket (needs `CAP_NET_RAW`) and `setuid(0)` both fail `EPERM` (`test_task_runs_as_non_root`, `test_capabilities_are_dropped`, `test_privilege_escalation_is_blocked`).
  - **PID limit:** starting threads past `pids_limit` fails; the probe is capped below 64 by attempt (`test_pid_limit_is_enforced`).
  - **Memory and CPU limits:** verified from the container's enforced host config only; driving them to a deterministic OOM-kill or CPU-starvation failure is not reliable here, so enforcement of these two is **not** asserted by attempt (`test_memory_and_cpu_limits_are_set`).
  - **Params cannot shape the container:** proved deterministically in `tests/unit/runner/test_sandbox_spec.py` and `tests/db/test_runner.py` (a hostile params row fails `params_invalid` before any container starts). The sandbox tests additionally confirm the enforced settings are present on the real running container.
  - **Startup/termination/cleanup fail safe:** an unknown image raises and leaves no container (`test_startup_with_an_unknown_image_fails_and_leaks_nothing`); the timeout test (`test_over_running_container_is_killed_...`, Docker + Postgres) runs the real `DockerBackend` through the real launcher: the probe sleeps past its 10 s deadline, the container is killed near the deadline (not after the 60 s sleep), `RUN_TIMED_OUT` is audited on a valid chain, the container is removed, and the run token no longer resolves at the broker (`resolve_run` refuses it) — the two enforcement points of §7.1.
- **Mutation check (focused, ad hoc):** 10 mutants, each weakening one real `sandbox_spec` setting, run against `tests/sandbox/test_escape_attempts.py`; a mutant is killed only when the Docker tests fail. 9 killed (network→bridge, read-only off, user→root, caps kept, no-new-privileges off, PID limit raised, memory lowered, CPU raised, an extra env var). **1 equivalent, not counted as killed:** removing `noexec` from the `/tmp` mount changes nothing observable, because Docker mounts the tmpfs `noexec` by default — confirmed on **both** Docker Desktop (WSL2) and native Linux (Kali): with the flag stripped, `/tmp` exec still fails `EACCES` and `test_tmp_is_noexec` still passes. No behavioral test can distinguish our flag (only a config-string assertion could, which these tests deliberately avoid); the `/tmp` non-exec property itself is confirmed true, and our explicit flag is kept as redundant defense-in-depth. Net: 9 killed, 1 equivalent, 0 true survivors.
- **Limits:**
  - No protection against kernel or container escape, a compromised Docker host, or a compromised broker.
  - The import-hygiene test on `task_sdk` and `tasks` is not a security control.
  - **Where the tests ran:** against Docker Desktop (Windows/WSL2) and against native Linux (Kali, Docker Engine) — 19 passed on both. The CI `sandbox` job on Linux (threat-model §7.4) is the ongoing gate and also covers the job's own wiring.
  - **Not asserted by attempt:** memory and CPU enforcement (config-verified only). `/tmp` `noexec` is confirmed by attempt (exec fails) but our flag is redundant with Docker's default (the equivalent mutant above).
  - See threat-model §7.3.

## SD-009: ID token verification requires `tid`, nonce, issuer and audience

- **Status:** implemented for verification (`src/clw/auth/oidc.py`: `verify_id_token`, `fetch_microsoft_jwks`, `OIDCVerificationError`, `IdTokenClaims`). Issuing the nonce at `/start`, single-use storage and replay rejection are Task 6 (`signin.py`); until then T5 is covered for missing and mismatched nonces only.
- **Decision:**
  - A missing `tid` or a mismatched `tid` is a rejection.
  - An OIDC `nonce` is sent at `/start`, stored single-use with the state, and must equal the ID token's `nonce` claim.
  - Issuer and audience must match exactly.
  - **Caller contract:** `expected_tid` (a lowercase GUID; anything else is a `ValueError` before any network call), `expected_nonce` and `client_id` come from server-side state, never from the token being verified. The JWKS URL and the expected issuer are built from `expected_tid` only.
  - **Checks, in order:** token is an ASCII string of at most 16,384 characters; header parses, has no `crit`, `alg` is exactly `RS256`, `kid` is a non-empty string; the tenant JWKS is fetched (any failure is `jwks_unavailable`); exactly one key has that `kid` (no fallback to another key; none is `kid_unknown`, several is `jwks_invalid`), and it is an RSA public key of at least 2048 bits with `use` and `alg` compatible; RS256 signature; `exp`, `iat`, `iss`, `aud`, `sub` and `oid` present; `exp` and `nbf` with no leeway; `iss` equal to `https://login.microsoftonline.com/{expected_tid}/v2.0`; `aud` a single string equal to `client_id`; `tid` present and exactly equal; `nonce` present and equal (constant-time comparison); `oid` and `sub` non-empty strings, `preferred_username` a string if present.
  - **Errors:** each failure raises `OIDCVerificationError` with one fixed `reason` code (`REASONS`) and the message "ID token rejected: <reason>". No token, claim or key material is in the message, and nothing is logged; the caller records the reason. Unverified claims are never returned. No HTTP types are used.
  - **JWKS fetcher:** the default `fetch_microsoft_jwks` GETs `https://login.microsoftonline.com/{tid}/discovery/v2.0/keys` with a 10-second timeout and no redirects; any non-200 is an error. There is no cache, so every verification fetches (as in legacy).
- **Threat addressed:** T3–T6. Legacy accepted ID tokens without `tid` (`if id_token_tid and …`) and did not bind the OIDC `nonce` claim (its "nonce" was a state-replay token only). Legacy also logged the attacker-supplied `kid` and accepted a lower-case `alg` spelling in its own check.
- **Tests:** `tests/security/test_oidc_tenant_boundary.py` (threat-model names `test_id_token_missing_tid_rejected`, `..._tid_mismatch_rejected`, `..._nonce_missing_rejected`, `..._nonce_mismatch_rejected`, `..._wrong_issuer_rejected`, `..._wrong_audience_rejected`) with a locally generated RSA key and a fake fetcher: a valid token returns its claims; every plan reason has a test (`tid_missing`, `tid_mismatch`, `nonce_missing`, `nonce_mismatch`, `issuer_mismatch`, `audience_mismatch`, `expired`, `unsupported_alg` for `none`, HS256 key confusion, RS512, PS256 and misspellings, `kid_unknown`, `claim_missing`), and the added ones (`not_yet_valid`, `kid_missing`, `signature_invalid` for another key and a tampered payload, `malformed` including `crit` and an oversized valid token rejected before any fetch, `jwks_unavailable`, `jwks_invalid` for empty or malformed documents, duplicate `kid`, non-RSA, `use=enc`, other `alg`, a private JWK and 1024-bit keys, `claim_invalid`); the JWKS is fetched for `expected_tid`, not the token's tenant; invalid caller arguments fail before any fetch; errors carry no token material. `tests/unit/test_oidc_jwks.py` (respx): the exact URL, non-200, redirect not followed, non-JSON, network errors and a non-GUID tenant without a request. An ad-hoc mutation run (not part of `scripts/audit_mutation_check.py`) killed 23 of 24 mutants, including the legacy "tid only if present" rule, no nonce check, a prefix nonce match, a case-insensitive `alg`, falling back to the first key, an extra accepted issuer, a dropped `iat` or `oid` requirement, no tenant GUID check, no size cap, following redirects and dropping both audience guards. One mutant **survived**: dropping the explicit `kty` check. The tests still pass because `RSAAlgorithm.from_jwk` (PyJWT 2.15) rejects a non-RSA `kty` itself, so the explicit check is probably redundant with that PyJWT version; it is kept as defence in depth, and the mutant is not counted as killed. Commit A (`20001f9`) marks every test strict xfail, not only the `tid`-missing and nonce tests as the plan says: the verbatim legacy module cannot load here (it imports `app.config`) and has a different interface, so it gives no runnable baseline. The legacy working tree was not changed to recreate one.
- **Limits:**
  - Depends on the Microsoft JWKS endpoint being available. Failure to fetch keys means no sign-in (fail closed). There is no JWKS cache, so a Microsoft outage or rate limit blocks sign-in.
  - A key rotated out of the JWKS is rejected at once (`kid_unknown`); a newly published key is accepted on the next fetch.
  - No clock-skew leeway: a host clock behind Microsoft's rejects fresh tokens that carry `nbf` as `not_yet_valid` and accepts tokens for up to its offset past `exp`; a clock ahead treats tokens as expired early. Host time sync is therefore part of the boundary.
  - The Microsoft behaviour relied on (A-11, A-12, A-21, A-22) is unverified; a wrong assumption makes sign-in fail closed rather than accept more.
  - The verifier binds a token to a tenant, app and nonce; it does not decide whether that user may use the workbench (T7, Task 6).

## SD-010: Design for app-only and delegated; build app-only only

- **Status:** partly implemented: manifests and profiles carry `mode`, and a manifest whose mode is not `app_only` is refused at load (Task 8, SD-030). Runs carry `auth_mode`, which must equal the manifest's at every operation, and credential records carry it (Task 12, SD-032).
- **Decision:** Manifests, profiles, audit records and runs all carry `auth_mode`. Phase 1 rejects `delegated` manifests at load time. The delegated path will add an analyst-consented token whose effective rights are the intersection of the app's scopes and the analyst's roles.
- **Threat addressed:** A half-built delegated path silently falling back to app-only (a privilege increase).
- **Limits:** Until delegated mode exists, an analyst's own Entra roles do not further narrow what a task can read. Only the profile does.

## SD-011: Session tokens must carry a `jti`

- **Status:** implemented (`src/clw/auth/session_jwt.py`, `src/clw/auth/denylist.py`, `src/clw/auth/redis.py`; `Settings.SESSION_JWT_SECRET`, `Settings.REDIS_URL`). Logout, the session cookie and `current_principal` are wired in Task 6.
- **Decision:** A session JWT without a `jti` is rejected. Logout revokes by `jti`.
  - **Token:** HS256 only, with a dedicated `SESSION_JWT_SECRET` of at least 32 bytes (missing or short: `SessionConfigError` on issue and decode; nothing is issued or accepted). The algorithm is a constant, not a setting. The header must be exactly `alg` and `typ`. Claims are exactly `sub` (internal user ID, canonical UUID), `oid` and `tid` (lowercase GUIDs), `role` (`analyst` or `security_lead`), `jti` (canonical UUID, fresh per session), `iat` and `exp` (integers, not booleans or strings); all are required and any other claim is rejected. Lifetime is 8 hours (legacy: 24), and `exp - iat` may not exceed the current TTL, so shortening it also cuts sessions already issued. No leeway; a future `iat` is rejected. Tokens over 4,096 characters are rejected before their claims are read.
  - **Decode:** `decode_session` (async) verifies, then always checks the revocation list by `jti`; no path skips it. Each failure raises `SessionInvalid` with one fixed `reason` (`REASONS`) and no token material. The legacy unverified pre-decode (`verify_signature: False`), `create_token` (hardcoded `ADMIN`), `organization_id`, `tenant_ids`, `email` and `token_source` are gone.
  - **Revocation list:** Redis keys `clw:denylist:<jti>` with a TTL rounded **up** to the session's remaining lifetime (legacy truncated, so a session with under a second left was never revoked). A malformed `jti` counts as revoked. In production, if Redis cannot be read every session counts as revoked, and if a revocation cannot be written `revoke` raises `RevocationUnavailable` (nothing is kept in memory). Outside production a per-process memory fallback is used. Logs carry no `jti`.
  - **Redis client:** async (`redis.asyncio`), built on first use, never at import; no default host (without `REDIS_URL`, Redis is unavailable); `redis://` or `rediss://` only, checked without echoing the URL; 5-second connect and socket timeouts; one attempt, no retries. `verify_redis_available_in_production()` is the startup check; the processes that need it call it (Task 6 onward).
- **Deviation from the plan interface:** `revoke`, `is_revoked` and `decode_session` are `async`. A sync client would block the API event loop for up to the timeout on every request while Redis is slow.
- **Threat addressed:** Legacy skipped the revocation check when `jti` was absent (`if jti and is_revoked(jti)`), so a token minted without one could not be revoked.
- **Tests:** `tests/unit/test_session_jwt.py`: round trip and the exact claim set; a missing `jti` and each other missing claim give `claim_missing`; bad `jti`, role (`ADMIN`, wrong case), tenant, `oid` and `sub` formats, boolean, float and string times and a lifetime over the TTL give `claim_invalid`; MSP and other extra claims give `claim_unexpected`; a revoked `jti` gives `revoked`; production with Redis refused or unset makes every session `revoked`; HS384, HS512, RS256 and `none` give `unsupported_alg`; a wrong secret and a tampered payload give `signature_invalid`; extra header fields, garbage and an oversized signed token give `malformed`; expiry and a future `iat`; a missing or short secret; the legacy helpers do not exist; no unverified decode and no web-framework import. `tests/unit/test_denylist.py`: production fail-closed reads and writes with Redis refused (a real closed port) or unset, and no memory fallback in production; the memory fallback outside production; expiry, sub-second lifetimes and already-expired sessions; malformed `jti`s; no `jti` in logs. `tests/unit/test_redis_client.py`: no client built and no settings read at import (fresh interpreter), no default host, the scheme check without echo, timeouts and zero retries, the production startup check. `tests/redis/test_redis_store.py` (real Redis, marker `redis`): a revoked session is rejected in production, the key TTL is rounded up, revocations are read from Redis rather than memory, and the server's `maxmemory-policy` is `noeviction`.
- **Mutation check (ad hoc, not part of `scripts/audit_mutation_check.py`):** 20 mutants in these three modules; 17 were killed (skipping revocation, accepting extra claims, no header `alg` check, no header-key check, no role or tenant format check, no TTL cap, a short secret, issuing any role, a 24-hour TTL, no size cap, production reads failing open or using memory, production writes falling back, truncating the TTL, accepting malformed `jti`s, logging the `jti`, retries, no scheme check, a no-op startup check). Three **survived**: the legacy "check revocation only if `jti` is present" rule (the required-claims list already rejects a missing `jti`), accepting HS512 in the decode call (the header `alg` check rejects it first), and treating booleans as integers (a boolean `iat` already fails the lifetime cap). Each check is kept as a second layer; none is counted as killed.
- **Limits:**
  - In-memory revocation fallback is allowed only outside production; it is per process and does not see revocations already in Redis. Production fails closed if Redis is unavailable (behaviour retained from legacy), which makes Redis an availability dependency for every authenticated request.
  - Revocations last only while Redis keeps them: the server must run with `maxmemory-policy noeviction` and persistence suited to the deployment. A Redis restart without persistence un-revokes every session still within its lifetime.
  - TLS to Redis (`rediss://`) is not required by the code; it is a deployment choice.
  - A stolen session is valid until it expires or is revoked; 8 hours bounds that window.
  - With HS256, any process that can verify sessions can also mint them; only `api` should hold the secret.

## SD-012: Hosting model: SaaS broker holds customer-tenant credentials

- **Status:** proposed
- **Decision:** Phase 1 is designed as SaaS: the broker holds profile credentials for each customer tenant.
- **Threat addressed / risk accepted:**
  - A broker compromise exposes read access to every connected tenant within each profile's scope.
  - Mitigations: narrow profiles (SD-004), certificates rather than secrets, credentials only in the broker container, and per-tenant audit.
- **Alternative to evaluate:** a self-hosted broker and runner inside the customer's environment, with SaaS providing only the catalog and UI. The broker/API split in the architecture is drawn so this remains possible.
- **Limits:** This risk is inherent to the SaaS model and must be disclosed to customers.
- **Update (2026-10-28):** design-partner pilots use the alternative instead. Each pilot is a single-tenant deployment in the customer's own Azure subscription, with their app registrations and their Key Vault, and we hold no customer credentials or data. The SaaS model above stays proposed for any later hosted offering. The deployment package (launch kit, Track 4) gets its own entry.

## SD-014: Audit events separate decision, attempt, response and verified outcome

- **Status:** implemented at chain level (`events.RULES`, the run state machine in `chain.py`, `verify_run_result`). Producers: the broker service writes `OP_DECISION`, `CREDENTIAL_*`, `GRAPH_REQUEST`, `GRAPH_RESPONSE` and its own `RUN_FAILED` (Task 12, SD-032); `RUN_REQUESTED` is the API's (Task 16); `RUN_STARTED`, `RUN_COMPLETED` and `RUN_TIMED_OUT` are the runner's (Task 14).
- **Decision:** The audit taxonomy keeps four distinct kinds of evidence:
  1. **Authorization decision:** `OP_DECISION`, plus `CREDENTIAL_ACQUIRED` / `CREDENTIAL_REJECTED`. An *allowed* decision must name the `http_method` and `path_template` it authorizes (schema v2, gate 1 finding M1).
  2. **Attempted operation:** `GRAPH_REQUEST`. A write-ahead intent, one per HTTP attempt.
  3. **Graph response:** `GRAPH_RESPONSE`. Linked to its request by `(run_id, attempt)` and operation.
  4. **Verified outcome:** `RUN_COMPLETED` (carries `result_sha256`), `RUN_FAILED`, `RUN_TIMED_OUT`.

  `CHAIN_RECOVERY` is a fifth, non-run record (SD-016).

  Rules (each has a negative test in `tests/unit/audit/test_transitions.py`):
  - **Run order:** `RUN_REQUESTED`, then `RUN_STARTED` (same task and manifest), then work, then a terminal event. Nothing may precede `RUN_REQUESTED` or follow the terminal event.
  - **Credentials:** a credential record must use the started run's profile and version. A `GRAPH_REQUEST` requires that the latest credential record for the run is `CREDENTIAL_ACQUIRED`.
  - **Approval binding:** a `GRAPH_REQUEST` must cite the **latest** `OP_DECISION` for its run and operation, and that decision must be `allowed` (so a later denial voids an earlier approval). Method and template must match the decision. `request_target` must be a relative `/v1.0` path that fills the template (one segment of unreserved characters per placeholder; no `%`, `.` or `..` segments, scheme, host, or fragment).
  - **One approval, one attempt:** a decision can be consumed by a single `GRAPH_REQUEST`. Retries and further pages need a new approval, which gives an explicit authorization transition per attempt. Attempt numbers run 1, 2, 3, … per run.
  - **Responses** must answer an outstanding request. Duplicates are rejected.
  - **Completion** with an unanswered request is rejected. The run must end `RUN_FAILED` or `RUN_TIMED_OUT` instead, with the open intent listed in `intents_without_outcome`.
  - **Result binding:** the stored run result must re-hash to `result_sha256`.
- **Migration and recovery implications of schema v2:**
  - No columns were added. `http_method` and `path_template` already existed and are now required on allowed decisions, so the change is to record rules and the hash-covered `schema_version`.
  - v1 records cannot satisfy v2 rules, and re-hashing them would rewrite evidence. So no conversion is provided: migration `20261015_audit_hardening` refuses to run while any v1 rows exist, and the verifier reports v1 records as `unsupported_schema_version`.
  - No v1 data exists outside test databases (the workbench has never been deployed). If v1 data ever existed, the procedure would be to export and archive those chains with their checkpoints, then start new v2 chains. A v2 chain cannot continue a v1 chain.
- **Threat addressed:** A run reported "completed" whose stored result was altered; a request outside what was approved; reuse of stale or superseded approvals; work outside a properly started run.
- **Limits:**
  - "Verified" means the stored result matches what the task produced at completion time, not that the analysis is correct.
  - These rules constrain what the records say. They do not authenticate who wrote them (RR-1, SD-015).

## SD-015: Per-component record signing deferred to gate 2

- **Status:** accepted residual risk (decision at security review gate 2)
- **Context:** Gate 1 finding H3. The record hash is unkeyed, so any role with INSERT can append records that verify (threat-model §6, RR-1). A test pins this: `test_forgery_with_plausible_timestamps_is_not_detectable`.
- **Decision:** For now, document the limit and add the cheap checks that bind forgeries to the rules: schema version, timestamp format and ordering (in the verifier and in the database), and approval binding (SD-014). Per-component signing keys (broker, runner, api) are evaluated at gate 2, when the broker's credential and key handling exist.
- **What this means today:** the current design does **not** protect against a compromised broker, runner or api, or any unrestricted writer, fabricating audit evidence. Customer-facing material must not imply otherwise.
- **Limits of the deferred option:** per-component signatures make records attributable to a key and stop writers without a key (for example SQL injection through a component that holds no signing key). They still cannot stop a compromised component from signing false statements about its own actions.

## SD-016: Broken-chain recovery is explicit, recorded, verified and permanent

- **Status:** implemented (`AuditWriter.append_recovery`, `python -m clw.cli audit-recover`, `docs/runbooks/audit-chain-recovery.md`)
- **Decision:**
  - When a chain fails integrity verification, every writer refuses to append, so all runs for that tenant stop. A writer with a cached position takes its fast path only when the records after that position produce no findings at all; otherwise full verification decides, so every integrity refusal is full verification's refusal. When the fast path is taken, the append agrees with full verification under the conditions stated in SD-026; that is supported by reasoning and tests (including forged recoveries by the app role), not by a formal proof.
  - Appends resume only after an operator records a `CHAIN_RECOVERY` that passes **all** of these checks:
    - the chain has unacknowledged integrity findings
    - the head the operator inspected is still the head
    - the recovery record names its real predecessor (seq and stored hash)
    - it acknowledges only findings that existed before it
    - appending it would leave no blocking findings (checked in memory before insert; otherwise refused and nothing is written)
    - appending it would leave no provisional finding (gate 1 finding L-B; otherwise refused with "retry once the database clock has passed the created_at X of seq N" and nothing is written). A provisional finding depends on the clock, so acknowledging one would let a recovery look valid now and become invalid later.
    - after commit, the chain is re-read and re-verified. If it is still blocked, `AuditRecoveryIncomplete` is raised with a CRITICAL alert, and the CLI reports `RECOVERY INCOMPLETE`. **Inserting a recovery record is never reported as success by itself.**
  - The recovery record is written at database time, or at the head's timestamp when the head is at most 5 minutes ahead (kept so the chain stays in order). It never inherits an invalid or far-future predecessor timestamp (gate 1 finding N2). (Corrected in the sixth round: this said "takes its timestamp from the database clock", which is not true when the head is slightly ahead.) Timestamps are ordered against the last *trusted* timestamp only, so a flagged record never becomes the reference for later ones (SD-020, tested, including verification two hours and a day later).
  - The recovery also acknowledges the findings its own record exposes on earlier records: when it is more than 5 minutes below them, it is the evidence that records written while the clock ran fast are ahead (SD-020). It acknowledges nothing at or after its own seq.
  - The failing records stay. The chain reports invalid permanently, with the findings under `acknowledged`, and later checkpoints of it are `INVALID`. Every recovery record, valid or not, is listed by `audit-verify`.
  - The verifier distinguishes an invalid historical record (an error, possibly acknowledged) from a valid recovery transition (`recoveries[].valid`) and from an invalid recovery (`invalid_recovery`, which acknowledges nothing).
  - `integrity_state` (in `audit-verify` output) is one of `clean`, `unrecovered`, `invalid_recovery` or `recovered`. `recovered` means every integrity finding is acknowledged by a valid recovery: appends resume, but `valid` stays false and the findings stay listed.
- **When recovery succeeds (tested):**
  - poisoned rows from the app role (bogus hash, bogus status, float or big-integer `details`)
  - superuser-planted impossible or far-future timestamps, including timestamps only an hour ahead that the clock later passes (gate 1 finding M-2)
  - several consecutive records ahead, as a database clock that ran fast and was corrected produces
  - recovery of an earlier invalid recovery
- **When it does not, by design (runbook, "manual intervention"):**
  - findings that cannot be tied to a sequence number
  - a recovery whose database time is earlier than a record still trusted (one less than 5 minutes ahead of the corrected clock): the recovery record would itself be out of order, so the writer refuses it; it succeeds once the clock has passed that record (tested). A clock stepped back before every record recovers, with every record acknowledged as ahead (tested).
  - a chain changing concurrently under an active attacker
- **Threat addressed:** Gate 1 findings H2, N2, N4 and M-2. A poisoned record silently extended; a poisoned chain disabling checkpoints; a corrupt timestamp making recovery impossible; recovery records that claim more than the chain supports.
- **Limits:**
  - Any INSERT-capable writer can also write a `CHAIN_RECOVERY` (RR-1). Recovery records are evidence to review, not proof of operator authority.
  - A poisoning attack remains a denial-of-service lever against one tenant's runs. That is the deliberate fail-closed trade-off.

## SD-017: Authoritative clock and timestamp policy

- **Status:** implemented (`AuditWriter._db_now`, `events.MAX_FUTURE_SKEW`, migration `20261016_audit_time_size`)
- **Decision:**
  - The **PostgreSQL server clock** (`clock_timestamp()`) is authoritative. The writer reads it inside each append transaction and uses it as `created_at`. The trigger enforces the 5-minute future bound against the same clock.
  - The three timestamp cases:
    - **Valid and within 5 minutes:** accepted. If the head's valid timestamp is up to 5 minutes later, the new record takes it, so the chain stays non-decreasing.
    - **More than 5 minutes in the future:** rejected for new records (writer and trigger). On existing records the verifier reports `created_at_in_future` when the record is more than 5 minutes ahead of a later record (chain evidence, independent of when verification runs), and, only for a record no later record can vouch for (the newest record, or at the start of a chain any record before the first trusted one), when it is more than 5 minutes ahead of the verifying host's clock. That last kind is listed as `provisional` (SD-020).
    - **Impossible or malformed:** rejected at the database boundary. Only real calendar timestamps, ASCII digits and an exact format are accepted.
  - An invalid or far-future predecessor timestamp is never copied into a new record.
- **Clock drift monitoring:**
  - Every append compares the writer host's clock with the database clock, and logs `audit_clock_drift` (WARNING, logger `clw.audit.alert`) when they differ by more than 5 minutes.
  - The database host's own clock must be NTP-synchronized and monitored by the operator. Phase 1 has no independent time source, so a wrong database clock produces wrong but internally consistent timestamps.
- **Threat addressed:** Gate 1 findings N2, N3, M-1 (SD-019) and M-2 (SD-020).
- **Limits:**
  - Provisional findings use the verifying host's clock, so a verifier with a badly wrong clock can report false ones, and a real one disappears if no record is written before the clock passes it. The CRITICAL alert and any `INVALID` checkpoint taken meanwhile are then the only evidence. While a chain has provisional findings, its other findings and the validity of its recoveries can also change as the clock moves, because a provisional record's trust status shifts the baseline for every later record. Once no provisional findings remain, verifying again later reports the same findings, as long as the records and the rules are unchanged and the verifier's clock does not move backwards.
  - Timestamps are evidence of database time, not trusted time (no RFC 3161 in Phase 1).

## SD-018: Query-parameter binding deferred to Task 7 (operation registry)

- **Status:** accepted limitation (to be verified at gate 2)
- **Current state:**
  - An approval (`OP_DECISION`) binds the operation, the HTTP method and the path template. A request's target must be a relative `/v1.0` path matching that template, with placeholders unable to take reserved values (`$…`, `delta`, `microsoft.graph.*`).
  - The **query string is not bound.** The audit chain checks only that it is made of safe characters. The audit subsystem therefore does **not** provide complete request authorization: an approved list-users read does not by itself constrain `$select`, `$expand`, `$filter` or `$top`.
- **Requirement for Task 7:** the operation registry must define, for each operation:
  - the permitted query parameters, with their types and allowed values
  - which parameters affect authorization or the scope of returned data
  - that pagination parameters (`$skiptoken`, `nextLink`) are generated and controlled by the broker only
  - how parameters are normalized before both authorization and execution

  The broker must not execute unbound query parameters.
- **Gate 2 check:** the authorization decision and the actual request are bound to the same validated operation **and** parameter set, and that is recorded in the audit evidence.
- **Task 7 (registry, done):** each operation now defines its permitted query parameters, their types and bounds (SD-002); `$select` bounds the returned properties and so the scope of returned data, while `$top` sets page size only; pagination parameters cannot be passed at all (Task 11 will generate them); and parameters are normalized once, into the immutable `BuiltRequest` (`$select` sorted, GUIDs lowercased, `$select` before `$top`), which is the form to be both authorized and executed.
- **Task 9 (policy, done):** stage 2 now refuses any built request whose query is not exactly the normalized form the registry emits for an operation the manifest allows (SD-003). This is a policy check; nothing is recorded yet.
- **Task 11 (transport, done):** the transport sends exactly `/v1.0` + path + query of the `BuiltRequest` it is given, and later pages only the canonical targets derived from that same request (SD-031); each attempt's `request_target` is passed to the audit hooks. Nothing is recorded yet, and nothing yet connects `evaluate`'s returned request to the transport call.
- **Task 12 (broker service, done; SD-032):** the transport executes the very `BuiltRequest` object `policy.evaluate` returned; nothing in between builds or changes a request. Every allowed `OP_DECISION` records the approved request target, normalized query included, in `details.request_target`. Before each attempt is recorded or sent, the broker refuses it unless its method is the approved one and its target is that approved target, or that target plus the broker's own `$skiptoken` continuation. Every retry and page is re-authorized by the policy, which must return a request equal to the approved one; the parameters are therefore bound for the whole operation, even if the caller's own `params` object is changed while it runs (tested). Each `GRAPH_REQUEST` records the exact target sent and cites its own decision.
- **Still open (gate 2):** the binding is enforced by the broker and recorded in the evidence, but the **verifier does not check it**: `chain.py` (accepted at Gate 1, unchanged) checks a `GRAPH_REQUEST` against its decision's method and template only, not against `details.request_target`. A record written by anything other than this broker (RR-1) is therefore not held to the binding. Adding that verifier rule is a Gate 1 change, so it is left for the gate 2 decision. RR-5 is narrowed to this, not closed.

## SD-019: Database timestamp checks do not depend on session settings

- **Status:** implemented (migrations `20261017_audit_ts_session_free` and `20261019_audit_ts_no_escapes`, `tests/db/test_audit_session_settings.py`)
- **Problem (gate 1 finding M-1, third review):** `clw_valid_created_at` parsed with `to_timestamp()`, which reads the session `TimeZone`. Any role can `SET TIME ZONE`. Under `Europe/London` in summer, a valid head timestamp then looked invalid, so the trigger skipped its "not before the head" rule, and the app role inserted a backdated record. A database whose default `TimeZone` was not UTC also rejected valid timestamps outright. The function was declared `IMMUTABLE`, which was false.
- **Decision:**
  - The validator checks the fixed format, the hour/minute/second ranges and the calendar date with `make_date()`. It calls nothing that reads `TimeZone`, `DateStyle` or `lc_time`.
  - Correction (gate 1 finding F-3, fourth review): as first written in `20261017`, the pattern contained a backslash (`\.`). A plpgsql body is parsed in the calling session, so with `standard_conforming_strings = off` the backslash became an escape and the pattern accepted any character in place of the decimal point. This was not exploitable (the format CHECK constraint, parsed once at creation, still rejected such rows, and every backdating and future-timestamp attack was rejected), but the claim that the function read no session setting was false. Migration `20261019_audit_ts_no_escapes` replaces the pattern with the bracket expression `[.]`. No audit function body now contains a backslash (tested from the catalog), and the validator gives the same answers under 14 further session settings, including `standard_conforming_strings` off and on (tested). With that, `IMMUTABLE` is accurate as far as these tests show.
  - The trigger compares timestamps with `COLLATE "C"`, the code-point order Python uses. For strings that pass the format check, the database collation (`en_US.utf8` here) orders them identically, so this is defence in depth and has no distinguishing test.
  - The upgrade re-validates every existing row. If any row fails, the upgrade aborts and nothing is changed or removed (tested).
- **Tests (as the app role):**
  - validator results under UTC, `Europe/London`, `America/St_Johns`, `Pacific/Kiritimati`, the fixed-offset POSIX zone `<+03>-03` and the POSIX rule `EST5EDT,M3.2.0,M11.1.0`, each with three `DateStyle` values
  - the reviewer's backdated-insert attack is rejected in every zone
  - valid inserts and the 5-minute bound behave the same in every zone
  - a database whose default `TimeZone` is `Europe/London` accepts writer appends and verifies valid, with UTC timestamps
  - mutation check: restoring the `to_timestamp` parser, or removing the range checks, the date check or the re-validation, makes the tests fail
  - `clw_jsonb_compact_size` (SD-005) is declared `IMMUTABLE` but calls `to_jsonb`, which the catalog marks `STABLE`. It applies it to text keys only, and its result is tested to stay the same under eight session settings the app role can change.
- **Limits:** a superuser or table owner can still replace these functions (RR-2).

## SD-020: Timestamp anomalies are judged against the chain, not the wall clock

- **Status:** implemented (`chain._timestamp_findings`, `chain.recovery_record`, `ChainReport.integrity_state` / `provisional`; tests `tests/unit/audit/test_timestamp_durability.py` and `test_recovery_from_records_ahead_of_the_clock_survives_the_passage_of_time`)
- **Problem (gate 1 finding M-2, third review):** whether a record was "in the future" was decided against the verifier's current clock. A record an hour ahead was recovered, but two hours later it was no longer in the future. It became the ordering reference, the recovery and later records were flagged as out of order, the original finding disappeared, and appends were refused again.
- **Decision.** For each record with a well-formed timestamp, with L the last trusted timestamp before it:
  1. Earlier than L: `created_at_not_monotonic`.
  2. More than 5 minutes ahead of a later record's timestamp t: `created_at_in_future`, from chain evidence alone. When L exists, t must be at least L; a later record below L is flagged by rule 1 and is not evidence. When no L exists (the start of the chain, or everything before is flagged), only a later `CHAIN_RECOVERY` is evidence. Without a baseline, "these records are ahead" and "that later record is backdated" look the same; a recovery is written at database time, or at the head's timestamp when the head is at most 5 minutes ahead (kept so the chain stays in order) after a full verification, which settles it when it is more than 5 minutes below the record. When it is not, the record stays provisional and the recovery is refused (SD-016, L-B).
  3. Otherwise, if no record could vouch for it (the newest record; or, when no L exists, any record, since then only a later recovery can be evidence) and it is more than 5 minutes ahead of the verifying host's clock: `created_at_in_future`, listed as **provisional**.
  4. Otherwise it is trusted and becomes L. Flagged records never become L.
- **Properties (tested):**
  - A chain with no provisional findings reports exactly the same findings whenever it is verified later (300 randomized chains, plus fixed cases at T, T+10 s, T+2 h, T+1 day and T+400 days). This assumes the records and rules are unchanged and the verifier's clock does not move backwards.
  - While provisional findings exist, the other findings and recovery validity may change with the clock (gate 1 finding F-2, fourth review). Tested with the reviewer's example, where a finding changes from `created_at_in_future` to `created_at_not_monotonic`.
  - After a recovery that restores appends and leaves nothing provisional, the state stays `recovered` at every later verification time, and further honest appends add no findings on earlier records. A recovery written while the database clock is itself fast is not covered: once the clock is corrected, the recovery can be ahead of it and the state can change (fourth review, simulated).
  - A record backdated in the middle of the chain, or before the chain's first record, is the record flagged; the honest records before it are not.
  - States: `clean`, `unrecovered`, `invalid_recovery`, `recovered`. A recovered chain is never `valid`.
  - With no trusted baseline, the earliest later recovery is the evidence, not the latest; and a later record below the baseline cannot vouch for an earlier record (gate 1 finding F-5, fourth review; both tested, with mutations). The reviewer's remaining surviving mutants (a recovery acknowledging its own seq; recovery exposure judged with the host clock; keeping the cache after a refusal) are equivalent, with the reasons recorded in `scripts/audit_mutation_check.py`.
- **Limits:**
  - A provisional finding becomes permanent only when later evidence is written (with no trusted baseline, only a recovery counts). If nothing is written before the clock passes it, the chain holds no evidence that it was ever ahead. The writer refuses appends meanwhile and logs a CRITICAL alert, so normally an operator recovers first.
  - While a chain has provisional findings, its other findings and the validity of its recoveries can also change as the clock moves, because a provisional record's trust status shifts the baseline for every later record. Once no provisional findings remain, verifying again later reports the same findings, as long as the records and the rules are unchanged and the verifier's clock does not move backwards.
  - At the start of a chain, a non-recovery record that is far behind the records before it is reported as out of order, even if those earlier records are the ones that are wrong. That is the price of not using the wall clock there.
  - All of this is against database time (RR-6), and any INSERT-capable writer can forge a recovery record (RR-1).

## SD-021: Text columns are bounded in UTF-8 bytes

- **Status:** implemented (`events.MAX_TEXT_BYTES`, `events.MAX_REQUEST_TARGET_BYTES`, `events.text_too_long`, migration `20261018_audit_text_limits`)
- **Problem (gate 1 finding L-1, third review):** only `details` was bounded. The app role inserted a 200 MB `reason`, and the chain still verified valid.
- **Decision:**
  - Every text column is limited to 1024 bytes and `request_target` to 4096 bytes, counted as UTF-8 bytes (not characters).
  - The writer refuses over-limit events before hashing (`AuditEventInvalid`, so callers fail closed). The verifier reports stored over-limit records.
  - The database enforces the same bounds with `octet_length()` in the CHECK constraint `ck_audit_events_text_bounds`. The migration requires the database encoding to be UTF8, so `octet_length()` counts UTF-8 bytes.
  - The upgrade counts existing rows over the limits first. If there are any, it aborts and changes nothing; audit evidence is never truncated (tested).
- **Tests:** exact limit accepted and limit + 1 byte rejected, for every free-text column, in 1-, 2-, 3- and 4-byte characters, by direct insert as the app role; the same in the writer; a 50 MB `reason` rejected quickly; the verifier flags a stored over-limit record; the migration abort keeps the row byte for byte. Mutation check: removing any of these, or counting characters instead of bytes, makes the tests fail.
- **Limits:** the columns already constrained more tightly (hashes, timestamps, event type) keep those constraints. A superuser or table owner can drop the constraint (RR-2).

## SD-022: Checkpoint `key_id` is validated before use

- **Status:** implemented (`checkpoint._well_formed`)
- **Problem (gate 1 finding L-2, third review):** a checkpoint file whose `key_id` contained non-ASCII text crashed `audit-verify-checkpoint` with a `TypeError` from `hmac.compare_digest`. It never produced a false `ok`, but the error path was undocumented.
- **Decision:** `key_id` must be exactly 64 lowercase hex characters (a SHA-256 key id). Anything else makes the checkpoint `malformed` before any comparison: exit code 1 (verification failure), JSON output, no traceback.
- **Also (third review, informational):** a correctly signed checkpoint whose `chain_id` matches but whose `tenant_id` names another tenant is rejected as `wrong_chain`. That comparison existed but was untested; it now has a test and a mutation.
- **Tests:** non-ASCII, upper-case, short, trailing-newline, Arabic-Indic-digit and non-string `key_id` values, in the library and through the CLI.

## SD-023: Audit writes have bounded waits

- **Status:** implemented (`writer.LOCK_TIMEOUT_MS`, `writer.STATEMENT_TIMEOUT_MS`, `AuditWriter._bound`)
- **Problem (gate 1 finding L-3, third review):** a session holding a chain's advisory lock made every append to that chain wait indefinitely. That failed closed, but never returned.
- **Decision:**
  - Every append, recovery and post-recovery re-verification runs with `SET LOCAL lock_timeout = 5000` and `SET LOCAL statement_timeout = 30000` (milliseconds). `SET LOCAL` ends with the transaction, so pooled connections are unaffected (tested).
  - Hitting either limit raises `AuditUnavailable`. Nothing is written, and a caller using `audited_attempt` does not send the request (tested).
  - The values are constructor arguments, validated as positive integers before being placed in the `SET` statement, so caller text never reaches SQL.
- **Tests:** the reviewer's held-lock case with the real 5-second default; a slow statement with a short statement timeout; the recovery path; the settings seen inside the transaction; no leak afterwards; the protected request not sent.
- **Limits:** a holder of the lock can still delay one tenant's runs by up to the timeout per attempt, repeatedly. That is a denial of service, not a bypass.

## SD-024: A cached writer position is re-checked against the clock

- **Status:** implemented (`AuditWriter._anchor_trustworthy`, `AuditWriter._verified_head`; tests `tests/db/test_audit_anchor.py`)
- **Problem (gate 1 finding F-1, fourth review):** after each append the writer caches the record it wrote and later verifies only the records after it. That cached record was never judged again against the clock. If the database clock ran fast while a long-lived writer appended, and NTP then stepped it back by more than 5 minutes, the same writer kept appending records stamped earlier than the cached one, with no refusal and no alert, while a fresh writer refused the chain.
- **Decision:**
  - Before using a cached position, the writer checks that its timestamp is well formed and not more than 5 minutes ahead of the database clock read in the same transaction. If not, or if the check itself fails, the writer logs `audit_anchor_untrusted`, drops the position and verifies the whole chain. The full verification then reports the provisional `created_at_in_future` finding and the writer refuses with `AuditChainCompromised` and a CRITICAL alert.
  - Why this was thought sufficient: while the cached record is within the skew window, every trusted earlier record is at most now + 5 minutes, and new records are stamped at least now, so a new record cannot be evidence against any earlier one. The fifth review showed this is not the whole story (findings L-A and L-B): the incremental check can still flag records that the whole chain explains, and an acknowledged provisional finding before the cached record can change the verdict later. SD-026 addresses both, and the targeted review after it found a third case (R1), also addressed there.
- **Tests (PostgreSQL, app role after the step-back):**
  - the same long-lived writer writes the fast records, the clock steps back, and its next append is refused with nothing inserted, repeatedly
  - a restarted writer also refuses; after a recovery by another writer, the long-lived writer appends without treating the valid recovery as out of order (the reviewer's corollary), and the chain stays `recovered` at +2 h and +1 day
  - a cached position within the window keeps the incremental path; malformed, impossible (`9999-99-99...`, `0000-00-00...`) and far-future cached timestamps force a full verification; the trust boundary is tested at exactly 5 minutes and 5 minutes plus one microsecond
  - mutation check: removing the re-check, trusting every cached position, or skipping the format check makes the tests fail
- **Limits:** the fast-clock phase is simulated (patched clock, triggers bypassed as superuser), because the database clock cannot be moved in a test. A database clock stepped back by 5 minutes or less is within the tolerance and is not detected by design.

## SD-025: Timestamps are formatted the same on every platform

- **Status:** implemented (`clw.common.timeutil.to_rfc3339_utc`; tests in `tests/unit/test_timeutil.py` and `tests/unit/audit/test_timestamp_durability.py`)
- **Problem (gate 1 finding L-C, fifth review):** timestamps were formatted with `strftime("%Y-...")`. The C library decides how `%Y` renders years below 1000: glibc writes `500`, Windows writes `0500`. The verifier formats skew bounds with this function, so a year-500 record followed by a 2026 record was flagged `created_at_in_future` on Linux and not on Windows. The database accepts years 0001-0999, so a planted or forged record could verify differently depending on the verifier's platform. Production runs on Linux.
- **Decision:** every field is formatted explicitly with a fixed width (`{year:04d}` and so on). No application code calls `strftime` (enforced by a test that scans `src/clw`, so a regression is caught on Windows too, where `strftime` happens to pad). Parsing uses Python's own `strptime`, which does not depend on the C library.
- **Tests:** exact strings for years 1, 9, 99, 500, 999, 1000, 2026 and 9999; the skew bound across the year-1000 boundary and at year 1; the reviewer's year-500 chain. The unit suite was run in a `python:3.11-slim` (glibc 2.41) container as well as on Windows: 1540 passed (1 skipped) on both at the time of the targeted review. With the old formatting restored in the container, 12 unit tests fail on Linux (the targeted review's count; 10 when first measured, before more tests were added).
- **Limits:** none known beyond the general ones; CI runs on Ubuntu.

## SD-026: The cached position is only a fast path; full verification decides

- **Status:** implemented (`AuditWriter._verified_head`, `AuditWriter.append_recovery`; tests `tests/db/test_audit_cache_recovery.py`)
- **Problems (fifth review):**
  - **L-A:** a writer whose cached record was written while the clock ran fast stayed idle while another writer recovered the chain. When the clock caught up to within 5 minutes of the cached record, the writer verified incrementally from it, flagged the valid recovery and later records as out of order, refused, and raised a false CRITICAL alert, while full verification and a fresh writer accepted the chain. This happens in honest operation.
  - **L-B:** a recovery could succeed while acknowledging a provisional finding (its own timestamp was copied from a head up to 5 minutes ahead, so it was not evidence). When the clock passed the record, full verification reported the recovery invalid and the chain blocked, but a writer with a cached position kept appending.
- **Decision:**
  - The incremental check is a fast path only. It is used only when the records after the cached position produce **no findings at all**. Any finding, even one acknowledged by a recovery inside that segment, sends the decision to full verification of the whole chain in the same transaction, which refuses only if it blocks. Any error while verifying still propagates, so nothing is written (fail closed). (The first version used the fast path whenever the segment had no *blocking* finding; the targeted review showed two forged recoveries from the app role could then make the segment look clean while full verification refused: finding R1.)
  - **What is guaranteed:** every integrity refusal (`AuditChainCompromised`) is full verification's decision at the same database time, so a writer never refuses a chain full verification accepts. An append through the fast path agrees with full verification when: the cached position is within 5 minutes of the database clock (SD-024); it was cached when no finding was provisional; and records up to it have not been rewritten (RR-2). The reasoning: a segment with no findings contains no recovery (a recovery that acknowledges nothing is itself a finding) and only records in order from the cached timestamp, which is at least every trusted earlier timestamp, so they can neither prove earlier records ahead nor vouch for them, and the earlier findings are stable (SD-020). This is supported by the tests below and by model runs, not by a formal proof. The model runs: the targeted reviewer's adversarial model of the real writer code found 55 divergences in 600 runs with the old rule; the implementer then ran the same model against this rule and found none (the implementer's run, not the reviewer's); in the final review the reviewer independently found 0 in 6,400 runs of its own model with this rule (and divergences with the old rule), and 0 failures in 900 seeds of the real-writer fuzzer with the fast path counted (26,496 fast-path appends).
  - The writer caches a position only when verification found no provisional finding at all (acknowledged or not). While an acknowledged provisional finding exists, which `append_recovery` no longer writes but older code or any INSERT-capable writer could (RR-1), every append verifies the whole chain.
  - `append_recovery` refuses, writing nothing, if the chain after the recovery would contain any provisional finding, with the message "retry once the database clock has passed the created_at X of seq N". X is the latest timestamp ahead of the clock (once the clock has passed it, nothing is provisional); N is the first stored record carrying it, which need not be in the list of provisional seqs, because later records can copy a head's timestamp (final review I-2). The message is guidance only: whether a retry succeeds is decided by full verification at that time. The refusal that a recovery would not restore appends gives the same wait when a record is ahead of the clock (targeted review R2: a recovery copies a head timestamp up to 5 minutes ahead and can then itself be out of order until the clock has passed the record). After commit, a re-verification that finds new provisional or blocking findings reports `RECOVERY INCOMPLETE`.
- **Tests (PostgreSQL):**
  - the reviewer's L-A case: the stale cached writer appends after a valid recovery, with no CRITICAL alert, and re-establishes its cache
  - a cached writer still refuses, and inserts nothing, when the whole chain confirms a finding
  - the reviewer's L-B chain at real time as the app role: the recovery is refused with the retry message and nothing is written; once the clock has passed the record, the recovery succeeds and the chain stays `recovered` at +2 h and +1 day
  - with an acknowledged provisional finding planted, a writer appends without caching; once the clock passes the record, that writer and a fresh one refuse at every later time and insert nothing
  - a clock step-back between commit and re-verification is reported as incomplete
  - the targeted reviewer's R1 case as the app role through the real trigger: after two forged recoveries, the cached writer and a fresh writer both refuse, repeatedly, with a CRITICAL alert, and nothing is inserted
  - R2: at T+0:31 the refusal names seq 1's created_at as the wait, and the recovery succeeds once the clock has passed it; with several records ahead, the message names the latest-stamped one, including when that is the first provisional seq rather than the last (I-2)
  - unit (`tests/unit/audit/test_wait_target.py`): latest timestamp rather than latest seq, ties name the first record with the timestamp, a recovery copying the head is never named, malformed timestamps and seqs are ignored, a record exactly at the clock is not ahead
  - mutation check: refusing on the fast path alone, the old fast-path rule (R1), accepting provisional findings in a recovery, caching while one exists, naming the earliest instead of the latest record, dropping the wait target, naming the last copy on a tie, naming the last provisional seq, or accepting malformed timestamps as the target makes the tests fail. The post-commit provisional clause and computing the target over the records plus the recovery being built are equivalent mutants (the reasons are recorded in `scripts/audit_mutation_check.py`).
- **Limits:** while an acknowledged provisional finding exists, every append re-reads the whole chain. The clock is simulated in these tests (patched `_db_now`, triggers bypassed as superuser) because the database clock cannot be moved.

## SD-013: Application-layer encryption with key rotation

- **Status:** implemented (`src/clw/crypto/fernet.py`: `KeyRing`, `get_keyring`, `encrypt_str`, `decrypt_str`, `KeyConfigError`, `DecryptionError`; `Settings.ENCRYPTION_KEYS`). No caller yet; the first is expected with delegated auth, which is out of Phase 1 scope.
- **Decision:**
  - Fernet via `MultiFernet` over an ordered key list (`ENCRYPTION_KEYS`; first key encrypts, all keys decrypt).
  - Decryption failure raises a domain `DecryptionError`, not an HTTP exception.
  - Used for data at rest that must be recoverable (for example, future delegated refresh tokens). Fernet is for confidentiality and integrity of stored secrets only: it is not used for the audit chain's SHA-256 hashing or the Ed25519 checkpoint signatures (SD-005, SD-006).
  - Profile private keys are **not** stored in the database. They are mounted files or secret-store references, read only by `broker`.
  - **Key list:** comma-separated, newest first, from the process environment or a secret store only. Each entry is trimmed and must be canonical URL-safe base64 of exactly 32 bytes (`Fernet.generate_key()` output). A missing, empty, blank, malformed, non-canonical or duplicate entry raises `KeyConfigError` when the ring is built; nothing is skipped, and no default or generated key is used. `ENCRYPTION_KEYS` is optional in `Settings` so processes that never encrypt do not hold it; `get_keyring()` refuses without it. A process that needs it calls `get_keyring()` at startup. Failures are not cached.
  - **Decryption:** anything that does not authenticate under a configured key, has another token version, is not an ASCII string (including `None` and bytes), or decrypts to bytes that are not UTF-8 raises `DecryptionError` with the fixed message "decryption failed". Unverified plaintext is never returned.
  - **No secret material in errors:** key errors name the entry position only. `DecryptionError` and the encrypt-side `ValueError` (lone surrogates) are raised outside any `except` block, so they carry no `__cause__` or `__context__` holding the input or decrypted bytes. The module does not log.
  - **Rotation and retirement:** (1) generate a key; (2) deploy `new,old` (old ciphertext still decrypts, new writes use `new`); (3) re-encrypt stored values with `KeyRing.rotate`; (4) remove `old` only once every ciphertext that must stay readable has been re-encrypted, or the rest has been explicitly declared disposable. After step 4, anything still under `old` fails closed with `DecryptionError`. There is no re-encryption job yet, because nothing stores ciphertext yet.
  - **Legacy compatibility:** legacy `crypto.py` wrote plain Fernet tokens under one `ENCRYPTION_KEY`; such a key can be appended to the list and its tokens decrypt. No legacy ciphertext is migrated to the workbench, so this is tested but not relied on. The legacy token-dict helpers (`encrypt_token_dict`, `decrypt_token_dict`) belonged to the legacy OAuth token store and were not kept.
- **Threat addressed:** Long-lived single keys with no rotation path. HTTP-layer coupling that could leak error detail through the broker.
- **Tests (`tests/unit/test_crypto.py`):** round trip; tampered ciphertext, tampered HMAC, truncation, wrong key, token version 0x81 and non-UTF-8 plaintext under a valid key → `DecryptionError`; garbage, `None`, bytes, ints, lists and non-ASCII strings → `DecryptionError`, not `HTTPException`; rotation (old token decrypts under `[new, old]`, new tokens use `new`, `rotate` rewraps, and after removing `old` its tokens fail closed); legacy single-key tokens; missing, empty, blank, bad-base64, wrong-length, standard-alphabet, non-canonical, non-ASCII, wrong-separator and duplicate keys (including the same bytes spelled differently) → `KeyConfigError` without the entry in the message; key repr and `Settings` repr hide keys; module functions follow the configured keys and fail closed without them; no key, token or plaintext in exception text, chained exceptions or logs; an AST check that the package imports neither `fastapi` nor `starlette`, which is checked against a probe first. An ad-hoc mutation run (not part of `scripts/audit_mutation_check.py`) killed all 12 mutants: lenient decoding, no canonical check, skipping blanks, allowing duplicates, one key only, encrypting with the last key, chaining the error, lossy UTF-8, a generated default key, the key in the message, a no-op `rotate`, and leaking `UnicodeEncodeError`.
- **Limits:**
  - Anyone holding both the stored ciphertext and the applicable key can decrypt. Fernet protects against a database-only compromise. Keys live in process memory and the environment of any process that loads them; Python cannot reliably erase them.
  - Key retirement must wait until all required ciphertext has been re-encrypted or explicitly declared disposable; retiring early makes that data unrecoverable.
  - Ciphertext is not bound to a database row, column or application purpose (Fernet has no associated data), so an attacker with database write access could swap two ciphertexts made under the same keys; callers that need binding must add it.
  - Fernet tokens expose their creation timestamp in clear, and decryption enforces no application-level expiry.
  - SD-013 establishes no rotation design for the Ed25519 checkpoint-signing key; that key is outside this decision.

## SD-027: Rate limits match the routed endpoint's name and fail closed in production

- **Status:** implemented (`src/clw/api/middleware/rate_limit.py`: `RATE_LIMITS`, `enforce_rate_limit`). The routes it names are added in Task 6 onward.
- **Decision:**
  - Limits are keyed by route **name**, never by path. The table names workbench routes only: `auth_microsoft_start` and `auth_microsoft_callback` (20 per minute per IP), `auth_logout` (30 per minute per session user) and `runs_create` (10 per minute per session user). Any other route is unlimited.
  - It runs as an app-level FastAPI dependency (`FastAPI(dependencies=[Depends(enforce_rate_limit)])`) and reads the matched route from `scope["route"]`, which Starlette sets after routing. The legacy middleware re-matched `app.router.routes` before routing; with FastAPI 0.143 included routers are no longer flattened into that list, so it found no name and limited nothing (found by the tests during the import). This changes the mechanism, not the scope.
  - User-scoped rules take the subject from `decode_session` (verified, revocation checked); without a valid session they fall back to the client IP, so a forged token cannot buy a fresh bucket.
  - The window is `INCR` plus `EXPIRE NX` in one Redis transaction: a counter left without an expiry (legacy set it only when `INCR` returned 1) gets one on the next request instead of blocking forever.
  - Production: if Redis cannot answer, limited routes return 429 (fail closed); unlimited routes are unaffected. Outside production a per-process memory window is used, pruned when it exceeds 10,000 keys.
  - Logs name the route and scope only, never the IP, session subject or key.
- **Threat addressed:** Brute force and flooding of sign-in and run creation; legacy path matching that a second router prefix bypassed; a lost expiry that turned a limit into a permanent block.
- **Tests:** `tests/unit/test_rate_limit.py`: the exact rule table; one route under two prefixes and in a nested router shares one limit; unlisted and unmatched paths are not limited; per-IP and per-session-user buckets; a forged token falls back to the IP bucket; production with Redis refused blocks limited routes only; the memory window and its pruning; no IP, subject or token in logs. `tests/redis/test_redis_store.py` (real Redis): the window and its TTL, and a counter without an expiry gets one. Mutation check (ad hoc): failing open in production, dropping `EXPIRE NX`, an off-by-one in the memory window, ignoring user scope, matching by path and logging the key were all killed (6 of 6).
- **Limits:**
  - A rule naming a route that does not exist limits nothing. Once routes exist (Task 6), a test must assert that every `RATE_LIMITS` name is a registered route.
  - Routes in a mounted sub-application do not receive app-level dependencies and are unlimited.
  - The client IP is `request.client.host`; behind a proxy it must be normalised by trusted-proxy middleware, or every client shares the proxy's bucket.
  - Fixed windows allow up to twice the limit across a window boundary.
  - It does not protect against connection-level floods.

## SD-028: Settings validation errors carry no input values

- **Status:** implemented (`src/clw/common/config.py`: `hide_input_in_errors=True`, `Settings.__init__`, `_without_inputs`)
- **Problem:** a `DATABASE_URL` with the wrong driver raised a `ValidationError` whose message contained the whole URL, password included (`input_value=...`). Found during Task 5; the code dates from Task 1.
- **Decision:**
  - `hide_input_in_errors=True` removes input values from `str()` and `repr()`. It does **not** remove them from `errors()` or `json()`, which still carried the URL (checked with pydantic 2.14.1). So `Settings.__init__` re-raises any `ValidationError` as an equivalent one with every `input` replaced by `<hidden>`, raised outside the `except` block so the original is not reachable through `__context__`.
  - The setting (`loc`), error type and message are kept, so an error still says which setting failed and why.
  - This applies to every setting, intentionally: an unknown key rejected by `extra="forbid"` or a mistyped value may itself be a secret.
- **Tests (`tests/unit/test_config_and_db.py`):** a unique password sentinel in `DATABASE_URL` (wrong driver, another driver, a bare value; passed directly and through the environment) and in an unknown key and an invalid `ENVIRONMENT` value is absent from `str()`, `repr()`, `args`, `errors()` (also with context, URL and input requested), `json()`, the formatted traceback and the exception context; `loc`, type and message are still present; a missing `DATABASE_URL` is still reported. Without the fix, and with `hide_input_in_errors` alone, 5 of these tests fail.
- **Limits:** only errors raised by `Settings` construction are covered. A validator message that itself interpolated a value would still show it; the validators here use fixed messages.

## SD-029: Analyst sign-in: code + PKCE, browser-bound single-use state, tenant registry, membership

- **Status:** implemented (`src/clw/auth/signin.py`, `src/clw/api/routes/auth.py`, `src/clw/api/deps.py`, models `tenants`, `workbench_users`, `oidc_logins`, migration `20261020_tenants_users`)
- **Decision (maintainer, 2026-10-16):**
  - **Where `expected_tid` comes from: the tenant registry.** A multi-tenant sign-in learns the user's tenant only from the ID token. The callback reads the token's `tid` **without verification**, only to choose a row; it must be a lowercase GUID naming an `active` row in `tenants`, or sign-in is refused (403) before any verification or JWKS fetch. `verify_id_token` then gets `expected_tid = tenants.id` from the database, so the issuer and the exact `tid` match are checked against the registry's value (SD-009). This is the multi-tenant pattern of A-13 (unverified). Nothing from the request (query, headers, body) selects a tenant; a `tid` query parameter on the callback is ignored.
  - **Client authentication:** a sign-in-only app registration (scopes `openid profile`, no Graph permissions) redeems the code with a client secret (`MICROSOFT_CLIENT_SECRET`, environment or secret store) plus PKCE S256. Authorize and token endpoints are `https://login.microsoftonline.com/organizations/oauth2/v2.0/...` (A-23). The token request has a 10-second timeout and follows no redirects; any failure is 401.
  - **State, nonce and browser binding:** `/start` creates a random `state` (sent to Microsoft) and a random binding value kept only in an HttpOnly login cookie (`clw_login`, `SameSite=Lax`, path `/auth/microsoft/callback`, 10 minutes, `Secure` in production). The OIDC `nonce` and the PKCE verifier are derived from the binding value, so only the browser that started the sign-in can complete it (login CSRF). `oidc_logins` stores SHA-256 hashes of the state, nonce and binding value only.
  - **Single use:** the callback claims the row with one `UPDATE ... WHERE used_at IS NULL AND created_at > now() - 10 minutes RETURNING`, committed before anything else, so a state is consumed even when the rest fails. Unknown, reused and expired states are the same 400. A wrong or missing login cookie is 400 and burns the state.
  - **Membership:** `(tid, oid)` from the verified token must be a `workbench_users` row (T7); the role comes from that row. The session carries `tid` and `oid` from the verified token (SD-011).
  - **Responses:** clients see only `sign_in_failed` (400/401), `access_denied` (403, the same for an unregistered tenant and a non-member, so registered tenants cannot be enumerated) or `sign_in_unavailable` (500). The server logs a fixed reason code and, for ID-token failures, the SD-009 reason; no identifiers or tokens.
  - **Session cookie:** `clw_session`, HttpOnly, `SameSite=Lax`, path `/`, 8 hours, `Secure` in production. `current_principal` reads the cookie only (no `Authorization` header) and is the only source of tenant for public routes. After sign-in the browser goes to `POST_LOGIN_PATH`, a fixed local path from settings (never request input; `//`, schemes and backslashes are refused).
  - **Logout:** `POST /auth/logout` needs a valid session, revokes its `jti` (SD-011) and clears the cookie; if the revocation cannot be recorded it returns 503 and keeps the cookie.
  - **Configuration:** `MICROSOFT_CLIENT_ID` (a GUID), `MICROSOFT_CLIENT_SECRET` and `OIDC_REDIRECT_URI` (https; `http://localhost` or `127.0.0.1` only outside production) are optional settings; without them sign-in refuses to start or complete (500).
- **Deviations from the plan:** the migration is `20261020_tenants_users` (the plan says `20261013_...`; the prefix follows the existing chain). The Postgres-backed flow tests are in `tests/db/test_signin.py`, because the Postgres fixtures live in `tests/db/conftest.py`; `tests/security/test_signin.py` holds the parts that need no database. `oidc_logins` also stores `binding_hash`. The plan's "reused state" test covers the threat model's `..._replay_rejected`.
- **Threat addressed:** T5 (replayed or forged ID token), T7 (non-member sign-in), login CSRF, open redirect after sign-in, tenant enumeration through error responses, and the legacy flow that took `expected_tid` from the unverified access token.
- **Tests:** `tests/db/test_signin.py` (Postgres; Microsoft mocked with respx): a member gets a session whose `tid` and `oid` are the verified token's and whose role is the row's; `/whoami` ignores `tid` in the query and headers and ignores `Authorization`; the callback ignores a `tid` parameter; the token request carries the code, client ID, secret, redirect URI and a verifier whose S256 is the challenge; unknown, reused and expired states are 400 and never redeemed; a missing, empty, foreign or other sign-in's login cookie is 400 and burns the state; an error callback burns the state; a nonce from another sign-in and a token whose issuer names another tenant are 401; an unregistered or disabled tenant is 403 before any JWKS fetch; a non-member and a member of another tenant are 403; token endpoint failures and redirects are 401 and the redirect is not followed; only hashes are stored; cookie flags in test and production; logout revokes, and the session then fails on `/whoami`, on logout and in `decode_session`. `tests/security/test_signin.py`: the exact authorize request (organizations endpoint, parameters, nonce and challenge bound to the cookie); fresh values per sign-in; incomplete configuration and an http redirect in production are refused; the unverified `tid` reader accepts only a lowercase GUID; reason codes and statuses; `POST_LOGIN_PATH` must be local; every rate-limit rule except `runs_create` names a registered route.
- **Mutation check (ad hoc):** 18 mutants; 17 killed (reusable states, no expiry, an uncommitted claim, disabled tenants allowed, membership by `oid` only, the wrong PKCE verifier, the nonce taken from the token, no GUID check on the unverified `tid`, http redirect URIs, following token-endpoint redirects, revealing the reason to the client, a non-`Secure` login cookie, a script-readable session cookie, `SameSite=None`, logout without revocation, an open post-login redirect, sessions from the `Authorization` header). One **survived**: removing the login-cookie hash check, because the nonce-hash check that follows rejects a wrong cookie with the same 400 (and the ID token's nonce and the PKCE verifier are bound to the cookie as well). It is kept as an explicit layer; it is not counted as killed.
- **Limits:**
  - Membership and tenant status are checked at sign-in only. A removed member or a disabled tenant keeps a valid session until it expires (8 hours) or is revoked; nothing revokes sessions when membership changes yet.
  - Guest (B2B) users sign in to their home tenant through the organizations endpoint, so membership is by home `tid` (A-24).
  - The unverified `tid` read selects a row only; a token Microsoft issued for a registered tenant other than the user's intended one would still need a membership row there.
  - The client secret is a standing credential held by `api`; it can sign users in but carries no Graph permissions.
  - Expired `oidc_logins` rows are not purged yet.
  - Sign-in events are not written to the audit chain yet.
  - The api database role and its grants on these tables are created with the deployment; the tests use the admin connection.

## SD-030: Manifests name registered operations only; profiles hold no secrets

- **Status:** implemented (`src/clw/broker/manifest.py`, `profiles.py`, `_loading.py`; `tasks/dormant_account_investigation/manifest.yaml`; `profiles/directory-read-auditlog-read.yaml`; Task 8)
- **Decision:**
  - **No request shaping in a manifest.** `allowed` and `prohibited` are lists of exact registry names (SD-002), checked with the registry at load. A manifest has no field for a method, path, query, `$select`, bound, header or tenant, so it can only narrow what a task may call; the request is always the one `operations.build_request` builds. An `allowed` entry must be a registered read that is executable. A `prohibited` entry must also be registered, so a typo cannot look like a prohibition. Duplicates and any overlap are refused (SD-003).
  - **Fail closed on what Phase 1 cannot honour:** `mode` other than `app_only` (SD-010), and `approval_required: true`, because no approval workflow exists yet and accepting the flag would run the task without the approval it asks for.
  - **Strict YAML:** `yaml.SafeLoader` semantics plus a 64 KiB cap, UTF-8 only, no duplicate keys (PyYAML keeps the last silently), no aliases, string keys only, a mapping at the top; then strict `extra="forbid"` models. `schema_version` must be 1; ids are lowercase slugs; names and purposes have no control characters; `timeout_seconds` is 10–900; task params are integers with `minimum <= default <= maximum`.
  - **Errors never echo values.** A `ManifestError` names the file and a line or field location and the error type only, and is raised outside the `except` block, so the YAML or Pydantic error (which quote the file) is not attached as context (as SD-028).
  - **Profiles:** found by id in a fixed directory (`profiles/`): the id must be a slug, the file `<id>.yaml` must resolve inside that directory, and the file's `id` must equal its name. Profile mode must equal manifest mode. `credential` entries are environment variable **names** matching `CLW_PROFILE_[A-Z0-9_]+`; the loader never reads the environment (Task 10 does). A PEM header anywhere in the file, or 30+ base64 characters in a credential entry, is refused as a likely secret. Phase 1 profiles are read-only: an expected permission containing `Write` is refused, because Task 10 accepts a token whose permissions equal the profile's set exactly.
  - **Digests:** `TaskManifest.sha256` is of the raw manifest bytes (the audit chain's `task_manifest_sha256`, 64 lowercase hex). The resolved `PermissionProfile` is attached to the manifest with its own `sha256`, so a run uses the profile checked at load.
- **Threat addressed:** T10/T11 (manifest is the allowlist), T13 (no path or URL can enter through a manifest), T16 in part (a profile cannot expect a write permission), T19 in part (no secret in profile files), unsafe YAML deserialization, and manifests that read differently from how they load.
- **Tests:** `tests/unit/broker/test_manifest.py` (192; 1 skipped on Windows): the plan's ten refusals (Python tag, unknown key, overlap, unregistered `allowed`, write in `allowed`, `delegated`, missing profile, mode mismatch, timeout outside 10–900, secret-looking profile values) and the valid manifest with a stable `sha256` of the raw bytes; `GET /users`, URLs, wrong case, wildcards and mapping entries refused in `allowed`; request-shaping keys (`path_template`, `method`, `select_allowlist`, `operations`, `headers`, `tenant_id`, …) refused; loading leaves the registry and a built request unchanged; non-executable reads refused; duplicate YAML keys, aliases, `!!python/str`, invalid or non-mapping YAML, oversize and non-UTF-8 files refused; no value from the file appears in any error rendering or context; profile slug, case, file-name, symlink (skipped where symlinks are not permitted), permission-name, write-permission and environment-name checks.
- **Mutation check (ad hoc):** 34 mutants; 33 killed. One **survived on this machine**: removing the check that a profile resolves inside the profiles directory, because the only test that reaches it needs a symlink and is skipped on this Windows account (the slug check already refuses traversal in the id). The test runs on Linux CI, but the mutant was not run there, so it is not counted as killed.
- **Deviations from the plan:** a shared `_loading.py` holds the strict YAML reader and `ManifestError`; `load_manifest` takes an optional `profiles_dir` (default `profiles/` in the repository) and `profiles.load_profile_by_id` resolves a profile id safely. Additions beyond the plan's list: duplicate-key, alias, size and encoding refusals; `approval_required: true` refused; `prohibited` entries must be registered; write permissions refused in profiles.
- **Limits:**
  - The manifest's task `params` schema is validated, but run parameters are not checked against it yet (Task 12/16).
  - The audit chain records `profile_id` and `profile_version`, not the profile's `sha256`. Runs record it (`runs.profile_sha256`, Task 12): the broker refuses any operation, and fails the run (`manifest_changed`), when the catalog's manifest or profile digest, profile id or version, or mode differs from the run's. A profile edited without a version bump is still not distinguishable in the audit records themselves, only in the run row.
  - Manifest and profile files are trusted repository content; these checks catch mistakes and unsafe YAML, not a malicious committer.
  - The expected permission set is A-01, verified against Microsoft Learn (2026-10-20): signInActivity needs `AuditLog.Read.All` with an Entra ID P1/P2 licence, `/users` needs `User.Read.All`, and no write permission is involved.

## SD-031: Graph transport sends only the approved request, to a fixed origin

- **Status:** implemented (`src/clw/broker/transport.py`, `src/clw/broker/pagination.py`; Task 11)
- **Decision:**
  - **Fixed destination.** The origin `https://graph.microsoft.com` and version `v1.0` are constants (`pagination.py`, re-exported by `transport.py`; only these two modules name the Graph host, per the Task 0 boundary test). `Transport.execute(request, token, *, deadline, before_attempt, after_attempt)` has no URL, host, method, header or body parameter. The URL is rendered after the checks, re-parsed, and refused unless its scheme is `https`, its host is the Graph host with no port, and its raw path and query are exactly the intended target.
  - **Request binding.** The transport sends `GRAPH_ORIGIN + "/v1.0" + path + query`, rendered from the `BuiltRequest` as built (values are `[A-Za-z0-9,]`, so nothing is encoded or reordered; httpx was checked to send it byte for byte, and the tests compare the raw request line). It does not rebuild or re-authorize the request; it refuses (`invalid_request`, nothing sent) anything that is not a `BuiltRequest`, not `GET`, not an executable read in the registry (matched by method and template), with query names other than `$select`/`$top` or values outside `[A-Za-z0-9,]`, or whose target fails the audit chain's target rule or 4096-byte limit. Phase 1 executes `GET` only, so every retry repeats an idempotent read.
  - **Pagination.** A nextLink is accepted only if it starts with exactly `https://graph.microsoft.com/v1.0<original path>?`, and its percent-decoded query (a `+` stays a `+`) holds the original parameters with their original values, in any order, plus exactly one `$skiptoken` of printable ASCII. The broker then sends its own canonical target: the original target plus `&$skiptoken=` and the token percent-encoded. A continuation can therefore carry only an opaque token; it cannot choose a destination, change or add a parameter, or reach another path. Paging is followed only for registry operations marked `paginated`, up to `max_pages` (default 200); the next page is `page_cap`.
  - **Credentials.** The token must be a `ValidatedToken` (from SD-004) whose value is bearer-safe (`[A-Za-z0-9._~+/-]+=*`) and not expired before each attempt (`token_expired`). It is sent only as `Authorization: Bearer` to the fixed origin. The transport never reads permissions: authorization is the policy's (SD-003).
  - **Client hardening.** Requests are built by the transport, not the client, so client default headers, cookies and base URLs are never applied; `send` is called with `follow_redirects=False` and `auth=None`. The constructor refuses a client that follows redirects, trusts environment proxy and CA settings (`trust_env`), or carries auth or event hooks; `new_graph_client()` builds one that passes (TLS verification on).
  - **Redirects.** Never followed: any 3xx is `redirect`, so the token cannot be forwarded and no `Location` is contacted.
  - **Timeouts and the deadline.** Each attempt carries explicit connect/read/write/pool timeouts (defaults 5/30/10/5 s, each at most 60 s), none longer than the time left in the run; the whole attempt is also cut off at the deadline (`deadline_exceeded`). No attempt starts at or after the deadline.
  - **Retries.** 429, 503 and 504, timeouts and network errors are retried, up to `max_attempts` per page (default 4). The wait is `Retry-After` (seconds or HTTP-date) capped at `max_single_wait_s` (30 s), or 1, 2, 4 … s without it; if the wait would reach the deadline, the call fails at once with `deadline_exceeded` (Review Focus 4). Nothing else is retried. Every attempt, retried or not, goes through the hooks, so no retry is silent.
  - **Hooks.** `before_attempt` is called before each attempt is sent; if it raises, nothing is sent. `after_attempt` is called for every attempt that was sent, successful or not, with status, request id, duration and item count; if it raises, no data is returned.
  - **Responses.** `Accept-Encoding: identity`; any other `Content-Encoding` is refused, so no decompression happens (no decompression bomb). A success body is at most `max_response_bytes` per page (16 MiB; a declared `Content-Length` over it is refused before reading) and `max_total_bytes` per call (64 MiB); an error body is read only up to 64 KiB. Only `200` is a success. The body must be UTF-8 JSON with no duplicate keys and no `NaN`/`Infinity`, an object whose `value` is a list of objects, and whose `@odata.nextLink`, if any, is a string.
  - **Errors.** `GraphError` has a category and, for the audit (Task 12), `http_status`, a Graph error code (only if it matches `[A-Za-z0-9_.]{1,128}`) and a request id (only if it matches `[A-Za-z0-9-]{1,64}`). Its message is the category; no response body, token or httpx exception is kept or attached as context. A 403 with code `Authentication_RequestFromNonPremiumTenantOrB2CTenant` is `licence_required` (A-02). Nothing in the transport logs.
- **Threat addressed:** T13 (no URL or path reaches the network except the approved one), T15 (nextLink to another host, version or path, or with widened parameters), token forwarding by redirect, decompression and oversized responses, retries past the run deadline.
- **Tests:** `tests/unit/broker/test_transport.py` and `tests/security/test_pagination.py` (208, all respx-mocked; no network): the exact request line and headers; altered, lookalike, non-GET, write and non-executable requests and invalid tokens or deadlines refused with nothing sent; the origin re-check; client auth, headers and cookies never sent; hardened-client checks; `before_attempt` raising sends nothing and `after_attempt` raising returns nothing; the plan's retry, `Retry-After`, deadline, 503/504 and no-retry cases; licence code; network errors and timeouts retried and reported with no context; per-request timeouts bounded by the time left; a slow response cut at the deadline; redirects (5 codes, two destinations) not followed; oversized, undeclared-oversize, declared-oversize, compressed and malformed responses; total size across pages; request-id and error-code filtering; token and body never in errors; `parse_retry_after`; nextLink acceptance (reordered, percent-encoded, `+`) and 55 refusals (host, user info, port, case, scheme, version, path, traversal, dropped, changed, added, duplicated or mis-cased parameters, bad encoding, control characters, length); three-page paging with the token only to Graph and one attempt per page; invalid nextLink sends nothing further; `page_cap`; boundary checks that only broker modules import the transport, pagination or credentials, and that `httpx` is imported only by sign-in and the transport.
- **Mutation check (ad hoc):** 90 mutants in the first pass; 75 killed. Of the 15 survivors, 10 were test gaps, now closed: `$expand` with safe characters, a non-identity encoding over a plain body, an oversized error body, `NaN` outside `value`, a long percent-encoded link, a request with no query, and checks reachable only if an earlier layer failed (`GET` only and executable-only with a changed registry, client auth set after construction, the rendered-origin re-check). Five were redundant code, removed rather than counted: the raw-name character check, the `=`-presence check, strict UTF-8 decoding and the skiptoken length cap in `pagination.py` (each already refused by the value, equality, printable or audit-length checks), and a path regex in `transport.py` (already covered by the audit target rule). Final pass: 85 mutants, 85 killed.
- **Ambiguities in the plan, and how they were resolved:**
  - The plan's eight error categories do not cover invalid input, an expired token, other HTTP statuses, redirects, timeouts, network errors, oversized or malformed responses; ten categories were added (`invalid_request`, `token_expired`, `bad_request`, `unauthorized`, `client_error`, `redirect`, `timeout`, `network`, `response_too_large`, `invalid_response`).
  - Statuses retried were unspecified beyond 429, 503 and 504; 500 and 502 are not retried. Timeouts and network errors are retried (reads only).
  - `Retry-After` beyond the cap: the wait is capped (plan: "capped, or deadline_exceeded").
  - Attempt numbers run across the whole call (pages and retries), so each is unique.
  - `GraphError` and the origin constants live in `pagination.py` and are re-exported from `transport.py`, to avoid a circular import while keeping the host in the two permitted modules.
  - `Transport` also takes `max_response_bytes`, `max_total_bytes`, `timeout`, `sleep` and `clock`; `new_graph_client()` was added.
- **Limits:**
  - **Not tested against live Microsoft Graph, but checked against Microsoft Learn (2026-10-20, Task 17B).** The nextLink shape (A-14), throttling with `Retry-After` (A-15) and the `request-id` header (A-16) are verified against the docs and match this transport. The licence error **code string** (A-02) is still **not** documented officially — only the P1/P2 requirement is — so it is unverified pending a tenant test; an unrecognized 403 maps to `forbidden` (fail closed). A legitimate nextLink in another shape stops paging (fail closed).
  - The transport sends the request it is given. The broker service passes the very object `policy.evaluate` returned and audits every attempt through the hooks (Task 12, SD-032); the verifier's part is in SD-018.
  - TLS trust is the default certifi bundle; no certificate pinning.
  - `ValidatedToken` can be constructed by any broker code; task code cannot import `clw` at all (Task 0 boundary).

## SD-032: Run-token-scoped operations, one approval per attempt, fail-closed orchestration

- **Status:** implemented (`src/clw/broker/capability.py`, `service.py`, `app.py`; `src/clw/db/models/run.py`; migration `20261021_runs`; Task 12)
- **Decision:**
  - **Run tokens (T9, T17, T22).** 256 random bits (`secrets.token_urlsafe(32)`, 43 characters), handed to the task once and stored only as SHA-256 (`runs.run_token_sha256`, unique). `Authorization: RunToken <token>`, exactly; one header only. The token selects exactly one run, and the tenant, task, manifest and profile all come from that run and the broker's manifest catalog, never from the request. Refusals, in order: `run_token_invalid` (malformed, unknown or revoked; 401), `run_halted`, `run_not_running`, `deadline_exceeded` (`now >= deadline_at`, broker clock), `manifest_changed` (the catalog manifest's id, digest or mode, or its profile's id, version or digest, differ from the run's). The token is looked up by its digest; there is no separate constant-time comparison (the plan asks for one), because after an index lookup it could only re-compare equal values, and lookup timing on the SHA-256 of a 256-bit secret reveals nothing usable.
  - **One controlled path** (`BrokerService`): policy `evaluate` → `OP_DECISION` (committed) → if allowed, credentials for the run's tenant and profile → `CREDENTIAL_ACQUIRED` or `CREDENTIAL_REJECTED` → `transport.execute(<the BuiltRequest evaluate returned>)`, with hooks that write `GRAPH_REQUEST` before and `GRAPH_RESPONSE` after every attempt. Data is returned only after every response record has committed.
  - **Binding (SD-018).** The executed request is the very object the policy returned (identity tested); nothing between builds or changes one. The allowed `OP_DECISION` records the approved target (path and normalized query) in `details.request_target`, and its method and template are the request's own. Before an attempt is recorded or sent, the hook refuses it (`request_binding_mismatch`, run failed, nothing sent) unless: it is a `GraphAttempt`; the previous attempt was answered; its number is the next one; its method is the approved method; and its target is the approved target or that target plus `$skiptoken=`. Each attempt's `GRAPH_REQUEST` records the exact target sent, the run-wide attempt number and the decision it consumes.
  - **One approval per attempt (SD-014).** The chain lets a decision be consumed once. The first attempt consumes the operation's decision; every retry and page is re-authorized: `evaluate` runs again and must allow and return a request equal to the approved one, and a new `OP_DECISION` (`details: request_target, for_attempt`) is written before the attempt. If re-authorization denies (or the request differs: `request_changed`), the denial is recorded, nothing more is sent, and the task gets 403 with no data.
  - **Credentials and policy stay separate (SD-003, SD-004).** Credentials are requested only after an allowed decision, so a denied operation acquires no token at all; a valid token cannot turn a denial into an allow. A rejection (`CredentialRejected` reason, or `acquisition_failed` for any other failure or a result that is not a `ValidatedToken`) fails the run and nothing is sent. `CREDENTIAL_ACQUIRED` records the token's permission names, never the token; permissions are not used to authorize.
  - **Attempt numbers** run 1, 2, 3 … per run, as the chain requires, continuing from the run's last `GRAPH_REQUEST` (read from that run's records on the run's tenant chain only). Operations of one run are serialized by a per-run lock in the broker process.
  - **Outcomes.**
    - Policy denial, malformed body, unknown field (`path`, `url`, `method`, `headers`, `tenant_id` …), duplicate keys, non-finite numbers, a body over 64 KiB, deadline passed: `OP_DECISION denied/<reason>`, 403. The run continues (a denied probe does not end a run).
    - Credential rejection, any Graph execution failure (`GraphError` category, including `licence_required`, `invalid_next_link`, `page_cap`, `deadline_exceeded`), a binding violation, `manifest_changed`: the run row is set `failed` with the reason as `outcome` and the token hash cleared (revoked) **first**, then `RUN_FAILED` is written with `http_status`, `graph_error_code` and `graph_request_id` in `details`; 502 with no data. If the row is no longer `running` (ended elsewhere meanwhile), no `RUN_FAILED` is written.
    - Any audit write that fails (`AuditUnavailable`, including the writer's `AuditChainCompromised` refusal), any unexpected error: the run is **halted**: in this process at once, and `runs.status = halted` when the database allows; 503, no data. Later operations get 403 `run_halted`. Marking the run `FAILED / audit_unavailable` afterwards is the runner's (Task 14), as threat-model §5.2 says.
    - Cancellation mid-operation (for example shutdown): halted in this process; the database row is left for the reconciler (Task 14).
  - **Before an operation runs**, inside the run's lock, the run's status is read again, so an operation that resolved its run before another operation ended it records nothing (the chain forbids events after a run's end).
  - **`GRAPH_RESPONSE` fields.** The transport reports status, request id, duration and item count, not the error category, so the record says: `succeeded` (200 with a usable page); `failed/no_response` (no HTTP status: timeout, network, cut at the deadline); `failed/unusable_response` (a 2xx with no usable page; the chain forbids a 2xx status on a failed response, so it is in `details.received_http_status`); `failed/http_<code>`. The category is in `RUN_FAILED`.
  - **What the task sees:** `200 {"status": "ok", "data": [...]}`, `401/403 {"status": "denied", "reason"}`, `502 {"status": "failed", "reason"}` (a credential rejection is reported as `credential_rejected`; the audit has the detail), `503 {"status": "error", "reason"}`. No other route exists (no docs or OpenAPI); responses are `Cache-Control: no-store`.
  - **The `runs` table.** Identity (tenant, task, manifest digest, profile id, version and digest, mode, actor, params, `created_at`) is fixed by trigger `runs_guard_update`; a terminal status is final; transitions are only `queued → running | failed`, `running → halted | completed | failed | timed_out`, `halted → failed | timed_out`; the deadline and token are set only when leaving `queued`, and a started run's token can only be cleared. CHECKs: the actor's tenant is the run's tenant and the actor is a member (composite foreign key to `workbench_users`); digests and the token hash are lowercase hex; a running run has a token and a deadline; an ended run has no token. The function has a pinned `search_path`, is schema-qualified and contains no backslash (SD-019). The broker needs `SELECT` on `runs` and `UPDATE (status, outcome, run_token_sha256, ended_at, updated_at)` only; the test app role has exactly that.
- **Threat addressed:** T9 (a run token selecting another tenant), T10–T14 at the broker boundary, T16 through the run, T17 (token after the run or deadline), substitution of the approved request or its parameters after authorization, data released without an audit record, an execution failure reported as success, evidence that claims an attempt that never happened.
- **Tests:** `tests/db/test_broker_ops.py` (pg; the plan's cases plus): the exact request line equals both `details.request_target` and `GRAPH_REQUEST.request_target`; the executed request is the object `evaluate` returned; eight substitute attempts (other `$top`, `$select`, an extra parameter, another path or collection, a malformed continuation, another method, a skipped attempt number) send nothing and fail the run; parameters changed by the caller mid-operation are not executed (`request_changed`); denials (prohibited, unknown, unlisted, invalid and request-shaping parameters, policy exception) record only `OP_DECISION`, acquire no token and send nothing; request-shaping fields and malformed bodies are denied and audited; invalid, revoked, ended, queued, halted and past-deadline tokens; a stale context records nothing after the run stops (three ways); tenant isolation across two tenants and three runs (credential authority, chains, attempt numbers); manifest, profile digest, profile id, version, mode, task id and missing-catalog changes fail the run; seven credential rejections (extra, missing, tenant, app, audience, delegated, expiry) and provider failures fail the run with nothing sent; a token carrying write roles leaves a denial unchanged; retries and three pages each with their own decision, attempt and response; a second operation continues the run's attempt numbers; four concurrent operations are serialized; licence, later-page, network, malformed-response, foreign-nextLink and deadline failures; no attempt recorded when the transport refuses before sending; five hook-protocol violations; an operation whose run ended elsewhere is not failed again; attempt numbering unaffected by forged records on another tenant's chain or of another kind; a look-alike attempt object refused; a catalog entry holding another task's manifest refused; no token in any audit record, run row or log; the HTTP layer (statuses, one Authorization header, `no-store`, body limit by declaration and while streaming, no other route). `tests/db/test_broker_fail_closed.py` (pg): an audit failure on `OP_DECISION`, `CREDENTIAL_ACQUIRED`, `GRAPH_REQUEST`, a denial or a retry's decision sends nothing (more) and halts the run, also for a fresh broker process; after the response, the data is withheld and the intent is listed by the verifier, also on a later page; a failed `RUN_FAILED` write after the row is failed; a run-state write failure halts in memory; an unreachable database sends nothing; cancellation halts and leaves the intent visible; a tampered chain makes the writer refuse and nothing is sent; an unexpected writer error counts as an audit failure; a failed run cannot later be completed. `tests/db/test_runs_table.py` (pg, as admin): every identity column, the transition matrix, terminal finality, deadline and token rules, CHECKs and foreign keys. `tests/security/test_broker_service.py` (no database): token generation and parsing, the body parser, the response mapping, the continuation rule, the single route, the catalog. Every pg test also runs as the least-privileged app role (`db-app`).
- **Mutation check (ad hoc):** 115 mutants of `service.py`, `capability.py`, `app.py` and the `runs` migration (trigger and constraints), run against the four test files above; a mutant counts as killed only when pytest reports failing tests with no errors. The first pass was cut short when the Postgres container stopped: 59 killed, 3 survived and 53 reported BROKEN (each "88 passed, 1 error", the database gone); the BROKEN ones are an infrastructure failure, not results, and were all re-run. Of the first survivors, two were test gaps, now closed (the 403 status for halted and not-running refusals; an unreadable run status inside the lock), and one was equivalent and removed from the list rather than counted: taking an allowed decision's method and template from the registry instead of the request, which the policy guarantees are equal. One mutant was added for the refusal log line. Final pass, all 115 with Postgres up: 108 killed, 7 survived, 0 broken. Five survivors were test gaps, now closed and then killed: attempt numbering reading another tenant's chain, or responses as well as requests (forged records); a look-alike attempt object; `resolve_run` itself accepting a queued run (masked by the in-lock re-check); a catalog entry filed under the run's task id but holding another task's manifest. **Two survive and are not counted as killed**, both kept as explicit layers: the tenant filter in the run-status update (the run id is a unique UUID), and the trigger's `tenant_id` immutability clause (a tenant change is already refused by `ck_runs_actor_tenant` together with the immutable `actor_tid`). Result: 113 killed, 2 survived, of 115.
- **Ambiguities in the plan, and how they were resolved:**
  - The plan's audit order shows one `OP_DECISION` per operation; the accepted chain (SD-014) lets a decision be consumed by one `GRAPH_REQUEST` only and says retries and pages need a new approval. Followed the chain: each retry and page is re-authorized and gets its own decision.
  - The plan says every record carries the run, task, profile and actor fields; the accepted event rules forbid task, profile and actor fields on `OP_DECISION`, `GRAPH_REQUEST` and `GRAPH_RESPONSE`. Followed the event rules: records carry `run_id`, `RUN_REQUESTED`/`RUN_STARTED` carry task, manifest, profile and actor, and credential records carry the profile.
  - The plan does not say who ends a run on an execution failure. The broker fails the run, so a run whose reads failed cannot later be completed with partial or no data (Review Focus 2's `FAILED / licence_required`; the plan's `FAILED / permissions_extra`). Policy denials do not end the run.
  - The transport numbers attempts per call; the chain numbers them per run. The service adds the run's last recorded attempt.
  - Who creates and starts runs: `RUN_REQUESTED` is the API's (Task 16) and `RUN_STARTED`, token minting, `RUN_COMPLETED`, `RUN_TIMED_OUT` and the reconciler are the runner's (Task 14). Task 12 provides the table, `issue_run_token` and `resolve_run`; the tests start runs the way those tasks will (row plus both records through the real writer).
  - Plan test names: `test_readonly_task_disable_user_denied_and_audited` expects `prohibited`, not `not_in_manifest` (Task 9 acceptance); body problems are 403 (the plan allows 422/403); the broker tests live in `tests/db` (the Postgres fixtures are there, as for sign-in), not `tests/security`.
  - Migration `20261021_runs` (13 characters), not `20261013_runs`: the prefix follows the existing chain. Runs also record `profile_sha256` (SD-030), `started_at`, `ended_at` and `updated_at`.
  - `write_ahead.audited_attempt` is not used: the transport owns the send, and its before/after hooks give the same guarantees (no send without a committed intent, no data without a committed outcome), tested here end to end.
- **Limits:**
  - **Not tested against live Microsoft Graph or Entra.** Graph and MSAL are mocked. These assumptions were checked against Microsoft Learn in Task 17B (A-06, A-07, A-08, A-14, A-15, A-16 verified against the docs; A-10 verified with a deprecation caveat); only A-02's error-code string and A-09's propagation timing remain unresolved pending a real-tenant test.
  - **No exactly-once execution.** A `GRAPH_REQUEST` means "authorized and possibly sent" (RR-4). A request can reach Graph and its response never be recorded (audit failure after the response, cancellation, a crash); the verifier then lists the intent. A transaction cannot undo a read that reached Graph.
  - **Run row and audit chain are not one transaction.** The writer commits each record on its own. When failing a run, the row is written first, so a failed `RUN_FAILED` write leaves a failed run whose chain has no terminal record (visible; `runs.outcome` has the reason). When halting, nothing is written to the chain (the audit is what failed). Recording these later is the runner's or an operator's (Task 14).
  - **One broker process per run.** The per-run lock and the in-memory halt are per process. Two processes serving one run could interleave attempt numbers (the verifier reports `attempt_out_of_order`), and a halt that could not be written to the database holds only in the process that saw it.
  - **Run ends outside the broker race with operations.** The status re-check narrows, but does not close, the window between the runner ending a run (for example at the deadline) and a broker operation already past the check; records written in that window appear after the run's end, which the verifier reports (`event_after_run_end`). **Addressed in Task 14 (SD-034):** the writer refuses any record of a run after its terminal record, under the chain lock, so a late broker record is refused (data withheld, 503) instead of following the end.
  - **The verifier does not check `details.request_target`** (SD-018, RR-5 narrowed, not closed).
  - Deadlines use the broker host's clock (the transport's too); the audit uses the database clock (SD-017).
  - Tenant status (`tenants.status`) and membership are not re-checked per operation; a disabled tenant's running runs continue until they end (as for sessions, SD-029).
  - Refused tokens with no usable run are not audited (there is no run to record them against, and nothing may follow a run's end); they are logged with the reason only (`broker_run_refused`, logger `clw.broker.alert`), as threat-model §5.1 says.

## SD-033: Task SDK sends named operations only; the dormant task fails rather than guess

- **Status:** implemented (`task_sdk/clw_task_sdk/client.py`, `result.py`; `tasks/dormant_account_investigation/task.py`, `classify.py`; Task 13)
- **Decision:**
  - **What the SDK sends (SD-002).** `GraphSecurityClient.call(op, params)` sends exactly `POST <broker>/v1/ops`, `Authorization: RunToken <token>`, body `{"op", "params"}` (JSON, no NaN or infinity). There is no way to pass a path, URL, method, header or tenant; the parameters go unchanged and the broker judges them. `list_users_with_sign_in_activity()` names `users.list_with_sign_in_activity` with `select` = `id, userPrincipalName, displayName, accountEnabled, createdDateTime, signInActivity` (only what the task classifies and reports) and no `top` (A-04, verified 2026-10-20: the documented maximum `$top` with signInActivity is 500; the SDK sends none and the broker pages).
  - **What the SDK reads.** `from_env()` reads `CLW_RUN_TOKEN` and `CLW_BROKER_URL` only. The broker URL must be `http(s)://host[:port]` with nothing else (no user info, path, query or fragment); the token must have the issued shape (43 URL-safe characters), so it cannot inject a header. The HTTP client has `trust_env=False` (no proxy, `.netrc` or certificate variables) and follows no redirects. It builds its own TLS context (certificate and hostname verification, TLS 1.2 minimum, system trust store) because `ssl.create_default_context()`, which httpx would use, reads `SSLKEYLOGFILE` and would write TLS session keys to the file it names. This was found by the environment-recording test.
  - **What the SDK returns.** 200 `ok` with a list → the reply; 401/403 `denied` → `OperationDenied(reason)`; 502 `failed` / 503 `error` → `BrokerError(reason, status_code)`; any other reply → `BrokerError("invalid_broker_response")`; no reply → `BrokerError("broker_unreachable")`. `OperationDenied` is a `BrokerError`. Reasons that are not `[a-z0-9_]{1,64}` become `unknown`. **Nothing is retried**: the broker owns retries (SD-031), and a client retry would execute the operation again (RR-4). The token is in no message, repr or traceback.
  - **Result line.** `emit_result(payload)` writes one line, `CLW_RESULT <json>`, ASCII-only (so U+2028 and U+2029 cannot split it), sorted keys, no NaN, string keys at every level, flushed.
  - **Classification (Review Focus 1; A-03, A-17, A-25).** In order: `disabled` (`accountEnabled` false), `active` (last sign-in less than `inactive_days` ago), `too_new_to_judge` (created less than `inactive_days` ago), `never_signed_in` (`signInActivity` null, omitted or with neither timestamp), `dormant` (exactly `inactive_days` ago is dormant). The last sign-in is `lastSuccessfulSignInDateTime` if present, else `lastSignInDateTime`; `lastNonInteractiveSignInDateTime` is not used. A null `createdDateTime` means the age is unknown and the account is judged on its sign-ins. A present value of the wrong shape (a non-boolean `accountEnabled`, a timestamp that is not ISO 8601 with seconds and an offset, a non-object `signInActivity`) raises `ValueError`. Everything is parsed before a class is chosen, so no class hides a malformed value.
  - **The task.** It reads all users through the one operation, classifies them, and emits `{task_id, inactive_days, evaluated_at, users_evaluated, counts (all five classes), dormant [id, userPrincipalName, displayName, last_sign_in], never_signed_in [id, userPrincipalName, displayName, created], note}`. Disabled and too-new accounts are counted, not listed. Non-text identity values become null. `--inactive-days N` (default 90, bounds 30–365, equal to the manifest's, tested) is its only input. Exit 0: result emitted. Exit 1: denied, failed, halted or unreachable broker, or a user that cannot be classified; **no result is emitted**, so a partial or guessed report never exists. Exit 2: bad arguments or environment, and nothing is called. stderr carries the reason only, never user data or the token.
- **Threat addressed:** T10–T12 at the task side (no task-built request), T19 (the SDK reads nothing beyond the two keys), header injection through the token, result-line forgery by line splitting, a misleading dormancy report (wrong class, partial data, guessed timestamps).
- **Tests:**
  - `tests/unit/tasks/test_dormant_classify.py`:
    - the plan's cases: `test_classify_null_sign_in_activity`, `test_classify_recent_account_not_dormant`, disabled accounts reported separately, and exactly `inactive_days` → dormant;
    - which timestamp is used, the fallback, and the ignored non-interactive time; unknown creation dates; offsets and seven-digit fractions; future times;
    - 17 malformed timestamp forms in each field, also for disabled accounts; a malformed `signInActivity`, `accountEnabled`, user, `now` or `inactive_days`;
    - every combination lands in exactly one class.
  - `tests/unit/tasks/test_dormant_task.py`:
    - the exact result; the threshold; counts without listing; one result line;
    - defaults and bounds equal to the manifest; bad arguments call nothing;
    - refusals and malformed users emit no result and leak no data;
    - `tasks/` imports only the standard library (without network, process or import modules), the SDK and `tasks`.
  - `tests/unit/task_sdk/test_client.py` (respx):
    - the body is exactly `{op, params}`, with no path (the plan's case);
    - the environment read is exactly the two keys; proxy and key-log variables are ignored; the TLS context settings; URL and token shapes;
    - every reply mapping; no redirect followed and nothing retried; reason sanitizing; no token in any text; the result line.
  - `tests/db/test_task_sdk_broker.py` (pg, also as the app role) runs the SDK and the task through the real Task 12 broker over HTTP, with Graph and MSAL mocked:
    - three pages, each with its own decision, attempt and response; Graph sees only the broker-built request; the chain is valid;
    - a prohibited `users.update` through `call` is denied `prohibited`, records only `OP_DECISION`, sends nothing, and the run continues;
    - an invalid token is refused;
    - a licence failure fails the run, the task emits no result, and the revoked token is refused;
    - a `GRAPH_RESPONSE` audit failure reaches the task as `BrokerError("audit_unavailable", 503)` with no data.
- **Mutation check (ad hoc):** 71 mutants of `classify.py`, `task.py`, `client.py` and `result.py`, run against the four test files above (a mutant counts as killed only when pytest reports failing tests with no errors).
  - **First pass:** 66 killed, 5 survived, 0 broken.
  - **Test gaps (3 survivors), now closed and then killed:** a malformed timestamp on a disabled account (parsing after the disabled check); the result line not flushed; the literal `CLW_RESULT ` prefix.
  - **Equivalent (2), removed from the list and not counted as killed:**
    - dropping the explicit TLS 1.2 minimum: `PROTOCOL_TLS_CLIENT` already defaults to it on this platform, and the line stays for platforms where it does not;
    - treating an empty environment value as set: the constructor's shape checks then refuse it, naming the same variable.
  - **Final pass:** 69 killed, 0 survived, 0 broken, of 69.
- **Ambiguities in the plan, and how they were resolved:**
  - **How the task receives `inactive_days`** is not specified. The environment may hold only the two keys, and a broker operation for run parameters would expand the registry. Resolved: a command-line argument, whose bounds the task checks itself. Passing `runs.params` this way is the runner's job (Task 14). The broker does not see it, because it is the task's parameter, not an operation parameter.
  - **The demo's "probe step" `users.update`** (Task 17 step 6) is not part of Task 13 and is **not** in the shipped task. A read-only task that attempted a write on every real run would send write attempts in customer tenants. The SDK can send it (`call`), as the integration test shows. Where the probe lives is Task 17's decision.
  - **"Disabled accounts are reported separately"** is read as their own class and count, not a list, because the result is specified to list dormant and never-signed-in accounts.
  - **Malformed values** are not covered by "never crash", which is about null or missing sign-in data. They fail the task with no result rather than producing a report with guessed classes.
  - **SDK errors other than a denial** are not in the plan's interface. `BrokerError` was added, as the base class of `OperationDenied`.
  - **`architecture.md` §3 says the import test forbids `httpx` in tasks**, but the accepted Task 0 test does not check that. A separate Task 13 test checks it; Task 0's test is unchanged.
- **Limits:**
  - **Not tested against Microsoft Graph.** The user shapes are the assumed ones (A-03, A-17, A-25), and the classification is only as right as those assumptions. A-18 (lag) is reflected in the result's note and is verified against the docs (typically within ~6h, up to 24h; Task 17B).
  - **Not a security boundary.** The SDK is trusted code in the task container. A task can send any `{op, params}` with its token, and the broker policy decides (SD-003, SD-032). The import checks are hygiene (SD-008). The container's limits are Tasks 14 and 15.
  - **The runner's side** (one `CLW_RESULT` line, the 5 MiB limit, `--inactive-days`, completion with `result_sha256`, timeouts) is implemented in Task 14 (SD-034).
  - **Three clocks.** Classification uses the task container's clock, deadlines use the broker's, and the audit uses the database's (SD-017).
  - **No exactly-once.** A task that exits on `broker_unreachable` may still have had its operation executed (RR-4). The SDK retries nothing, so each call executes the operation at most once.
  - **OpenSSL environment.** With an `https` broker URL, OpenSSL may consult its own environment variables at the C level; Python-level reads are only the two keys. In the sandbox the environment holds only those two keys (Task 14).
  - **Carried forward unchanged from SD-032:**
    - RR-5: the verifier does not check the request target against the decision;
    - the broker's per-run lock and halt are per process;
    - the runner-timeout race (Task 14);
    - API-owned run creation (Task 16);
    - tenant status is not re-checked per operation;
    - refused tokens are not audited.

## SD-034: The runner starts and ends runs; nothing is recorded after a run's end

- **Status:** implemented (`src/clw/runner/`: `sandbox_spec.py`, `result.py`, `lifecycle.py`, `launcher.py`, `reconciler.py`, `backend.py`, `catalog.py`, `__main__.py`; the run-state guard in `src/clw/audit/writer.py` and `AuditRunStateRefused` in `events.py`; `docker/task.Dockerfile`, `broker.Dockerfile`, `runner.Dockerfile`; `docker-compose.yml`; `.dockerignore`; Task 14)
- **Decision:**
  - **Starting a run.** The launcher claims the oldest `queued` run (`FOR UPDATE SKIP LOCKED`, so two launchers never take the same run).
    - **Refused before anything starts:**
      - The run's manifest must still be the catalog's (id, digest, mode, profile id, version, digest; the broker's check). Otherwise the run ends `failed / manifest_invalid`.
      - Its params must satisfy the manifest. Only declared names, integers (not bool) within bounds, defaults applied; otherwise the run ends `failed / params_invalid`.

      In both cases no token is minted and no container is started.
    - **Starting.** In one transaction holding the row lock:
      - the token is minted and only its SHA-256 is stored;
      - `deadline_at` is set to the database's `now()` plus the manifest's `timeout_seconds`;
      - the row is set `running`;
      - `RUN_STARTED` is written.

      If `RUN_STARTED` cannot be written, the row change rolls back and the run stays `queued`. The container starts only after both are committed, so a token is never usable for a run whose start the chain lacks.
  - **The container (SD-008, threat-model §7.1).** `sandbox_container_kwargs` is pure.
    - **Fixed settings:** network `clw_tasknet` only; read-only root; `/tmp` a 16 MiB `noexec` tmpfs; user 10001; `cap_drop: ALL`; `no-new-privileges`; 256 MiB memory with no swap; 0.5 CPU; 64 PIDs; no volumes, mounts, devices, ports or privileges.
    - **Environment:** exactly `CLW_RUN_TOKEN` and `CLW_BROKER_URL`.
    - **Command:** `python -m tasks.<module>.task --<param> <int>…`. The module follows from the task id, and the catalog refuses a task directory that is not that module or has no `task.py`. The argument names come from the manifest; the values are the validated integers.
    - **What the run row cannot set:** the image, the broker URL or the network. Those are the runner's own configuration (`CLW_TASK_IMAGE`, `CLW_TASK_BROKER_URL`), validated as a plain image reference and a bare `http(s)://host[:port]`.
    - **The image** holds the Python runtime, httpx, `task_sdk/` and `tasks/` only. It is built onto `scratch` so it carries no base-image `ENV`; Docker still adds `PATH`.
  - **Supervision.** stdout is read while the task runs, until one of these:
    - **it exits:** the run is judged by the exit code and the output;
    - **stdout passes 5 MiB:** the task is killed; `failed / result_too_large`;
    - **the deadline passes:** the task is killed; `timed_out / timeout`, with `details.kill = failed` if the kill failed. The token is revoked with the row either way, and the broker refuses it after the deadline anyway.

    Output written after the deadline is never used.
  - **Results (SD-014).** Accepted only from a task that exited 0. The whole stdout must be exactly one line, `CLW_RESULT <json>\n` (the SDK's format); otherwise the run fails with:
    - `result_missing`;
    - `result_duplicate`;
    - `unexpected_output` (other lines, or no final newline);
    - `result_malformed`:
      - not ASCII, or containing `\r`;
      - not one object;
      - duplicate keys, NaN or infinity;
      - floats, integers outside ±(2^53 − 1), NUL, or more than 16 levels.

    These are exactly the values that survive the JSONB round trip, so the stored result re-hashes. A task that exits non-zero ends `failed / task_error` (`details.exit_code`), and any result line it printed is discarded.

    `result_sha256` is `clw.audit.chain.result_sha256`: SHA-256 of the canonical JSON of the parsed object, the function `verify_run_result` applies to `runs.result`. The value stored and the value hashed are the same object.
  - **Ending a run: one pattern** (`RunLifecycle`) for every terminal transition:
    1. Lock the run row (`SELECT … FOR UPDATE`) and require a status the transition may start from.
    2. Update the row: status, outcome, result, ended time, and token revoked.
    3. Write the terminal record.
    4. Commit.

    If step 3 fails, the row change rolls back. Then:
    - a completion becomes `failed / audit_unavailable`, `outstanding_requests`, or `result_unpersisted` (the row write failed and nothing was recorded);
    - a failure or timeout is applied to the row alone. The token is revoked and an alert raised; the missing terminal record stays visible as a run open in the chain and ended in the table.

    While the row is locked, the broker's own status changes wait. Those changes are conditional on `running`, so afterwards they find the run ended.
  - **Nothing after a run's end (the race SD-032 left to Task 14).** `AuditWriter.append` refuses a run's record (`AuditRunStateRefused`, an `AuditEventInvalid`) in three cases:
    - `run_ended`: the run already has a terminal record on that chain;
    - `run_already_started`: the record is `RUN_STARTED` and the run already has one (added in the Task 14 review);
    - `outstanding_requests`: the record is `RUN_COMPLETED` and one of the run's `GRAPH_REQUEST` attempts has no `GRAPH_RESPONSE`.

    The check reads that run's records under the chain's advisory lock, in the append transaction, so it is atomic with respect to every other append to the chain. A broker operation that passed its status check before the run ended therefore lands in one of two places:
    - its records commit before the terminal record: they stand, the timeout or failure follows open intents, and the verifier lists them;
    - its records come after the terminal record: they are refused. The broker treats that as an audit failure (SD-032): no data, 503, and its halt finds the run ended.

    Without this, every such late record would be a permanent `event_after_run_end` finding: a recovery record cannot acknowledge transition findings, so the tenant's whole chain would stay invalid. **This is a change to accepted Gate 1 code, made because a runner-side ordering alone cannot be atomic with the broker's appends.** It is narrow: one indexed query per run record, no change to hashing, verification or recovery.
  - **Who ends a run:**

    | Component | Outcomes it records |
    |---|---|
    | broker (SD-032) | `failed`, `halted` |
    | launcher | `running`; `failed` (manifest or params invalid, launch failure, task error, invalid or oversized result, result not recordable); `completed`; `timed_out` (deadline) |
    | reconciler | at start-up and every minute, runs whose deadline passed more than 60 s ago: `running` → `timed_out / outcome_unrecorded`; `halted` → `failed / audit_unavailable` |

    - **A halted run** ends `failed / audit_unavailable` when its task ends, whatever the task did (threat-model §5.2).
    - **A run ended elsewhere** (the broker failed it, the reconciler timed it out) is left as it is, and a late result is discarded. The terminal status is final in the table (SD-032 trigger) and in the chain (this guard).
    - **The reconciler's grace** leaves the precise outcome to a live launcher. Its sweep also removes any container still labelled for the run.
- **Threat addressed:**
  - T17 at the runner: the token is revoked on every terminal path, including when the audit is down.
  - T19 and T20: only the two keys in the task environment, and the sandbox limits.
  - A run reported completed whose result was not validated, not stored, or not hashed with the stored value.
  - A partial result from a failed task.
  - A late result or late broker record overwriting or following a run's end.
  - Caller-controlled image, command, environment or network.
- **Tests:**
  - `tests/unit/runner/test_sandbox_spec.py`:
    - every sandbox setting, and the absence of volumes, devices, ports, privileges and the socket;
    - the environment is exactly the two keys, and the token appears only there;
    - the command and `--inactive-days` from params or the default;
    - 15 param shapes that try to shape execution are refused (extra keys, `broker_url`, `CLW_RUN_TOKEN`, `image`, bools, strings, floats, out of range, non-objects);
    - required params; no values in messages; the task id, token, image and broker-URL shapes;
    - the catalog's module and `task.py` rules.
  - `tests/unit/runner/test_result.py`:
    - the SDK's own line is accepted and hashed as `canonical_json`;
    - 27 rejected outputs;
    - the 5 MiB and depth bounds at the edge.
  - `tests/db/test_audit_run_state.py` (pg):
    - every run record after each terminal record is refused, and the chain stays valid;
    - a completion with an unanswered request is refused, and allowed once answered;
    - other runs and chains are unaffected, including a forged terminal record for the run on another tenant's chain;
    - concurrent terminal and broker writers never put a record after the end.
  - `tests/db/test_runner.py` (pg; fake container backend):
    - **valid results:** a valid result completes with the right SHA-256 and `verify_run_result = ok`; altering `runs.result` (trigger disabled by the owner, RR-2) gives `result_mismatch`; a completed run cannot be changed;
    - **start:** the token is stored only as its hash and revoked at the end; the deadline is `timeout_seconds` after the start; the exact container spec; `--inactive-days` 45, default and 365;
    - **refused before start:** 8 shaping params fail the run before start; 5 manifest changes fail it before start;
    - **start and claim failures:** a `RUN_STARTED` failure starts nothing and leaves the run queued; a launch failure; two launchers never start one run; a second launcher takes the next queued run without waiting for the first's lock;
    - **bad output:** 7 invalid outputs; oversized output killed at 5 MiB; a result from a task that exited 1 is discarded; exit 0 without a result;
    - **timeouts:** before any operation, with output after the kill ignored; a kill failure; **while a broker request is in flight**: the run ends at `RUN_TIMED_OUT`, the broker's late response record is refused, its data is withheld (503), the chain stays valid with the intent listed, and the token is dead;
    - **ended elsewhere:** a late result after the run ended elsewhere is discarded; a run the broker failed is not overwritten; ending waits on the row lock for a concurrent broker status change and then leaves it as it is; a halted run ends `failed / audit_unavailable`;
    - **recording failures:** a `RUN_COMPLETED` failure fails the run; with no terminal record possible, the row still ends; a result-persistence failure fails the run with no `RUN_COMPLETED`; a task that exits 0 while its request is in flight cannot complete (`outstanding_requests`);
    - **the reconciler:** overdue running runs, overdue halted runs, the grace period, the token revoked with the audit down, and a row matched to a terminal record already written.
  - `tests/db/test_runner_subprocess.py` (pg): the real task module runs as a local process through the real launcher against a stub broker:
    - `inactive_days = 30` reaches the task, and its own result line is validated, stored and verified;
    - it sent only `{op, params}` with the minted token;
    - a refused task leaves no result.
  - Every pg test also runs as least-privileged roles (`db-app`). The runner role has `SELECT` on runs and `UPDATE` of `status, outcome, result, run_token_sha256, deadline_at, started_at, ended_at, updated_at` only, plus `SELECT, INSERT` on `audit_events`.
- **Observed once, not a test** (2026-10-18, Docker 29.1.2 on Docker Desktop): the real `DockerBackend` with these kwargs and the built `clw-task:phase1` image ran the task as 10001:
  - read-only root, `CapDrop: ALL`, 64 PIDs, 256 MiB;
  - only `clw_tasknet`, internal;
  - config env `CLW_BROKER_URL`, `CLW_RUN_TOKEN` and the image's `PATH`;
  - the task exited 1 with `broker_unreachable` (no broker on that network).

  The broker and runner images build and load their catalogs. The sandbox tests are Task 15.
- **Mutation check (ad hoc):** 77 mutants across the writer guard, `lifecycle.py`, `launcher.py`, `result.py`, `sandbox_spec.py`, `reconciler.py` and `catalog.py`, run against the five Task 14 test files (a mutant counts as killed only when pytest reports failing tests with no errors).
  - **First pass:** 68 killed, 9 survived, 0 broken.
  - **Test gaps (4), closed and then killed:**
    - the chain filter in the writer guard (a forged terminal record for the run on another tenant's chain);
    - the row lock while ending (a concurrent broker status change);
    - `SKIP LOCKED` (a second launcher must take the next run instead of waiting);
    - a bool parameter within bounds that would admit 1.
  - **Equivalent (4), removed from the list and not counted as killed:**
    - three result checks that were redundant with `canonical_json` and the ASCII decode (rejecting floats, NaN and non-ASCII; the redundant code was removed);
    - completing from `halted` (the runs trigger refuses `halted → completed`, so the outcome is the same).
  - **Survived (1), not counted as killed:** the tenant filter in `RunLifecycle.status` (the run id is a unique UUID). It is kept as an explicit layer, like the same filter in the broker (SD-032).
  - **Final:** 72 killed, 1 survived, 0 broken, of 73.
- **Ambiguities in the plan, and how they were resolved:**
  - **The plan's signature `sandbox_container_kwargs(run, token)`** also needs the manifest (argument names and bounds) and the runner's configuration (image, broker URL). Both are keyword arguments, and neither comes from the run.
  - **The plan puts the launcher tests in `tests/unit/runner/test_launcher.py`.** They need the runs table and the audit chain, so they live in `tests/db` (as for the broker). The pure spec and result tests are in `tests/unit/runner`.
  - **"Accept exactly one `CLW_RESULT` line"** is read as the whole stdout being that line. The SDK writes nothing else, and anything else would make the result ambiguous.
  - **`RUN_TIMED_OUT` has no `outcome` field** in the accepted event rules, so the plan's `RUN_TIMED_OUT outcome_unrecorded` is recorded as `reason: outcome_unrecorded`. The row's `outcome` says the same.
  - **A halted run whose task ends** is `failed / audit_unavailable` (threat-model §5.2), not the task's outcome.
  - **`docker/api.Dockerfile`** is listed in Task 14, but `clw.api.main` is Task 16's. It and the api service are deferred to Task 16 rather than written against a module that does not exist.
  - **The deadline is set from the database clock**, the audit's (SD-017), not the runner host's. The broker still compares it with its own clock (SD-032).
  - **Finding:** on Windows, Python's text-mode stdout writes the SDK's line as `...\r\n`, which the runner rejects. The task runs in a Linux container, where this does not happen, so the accepted SDK is unchanged. The subprocess test normalizes line ends on Windows only.
- **Limits:**
  - **No exactly-once.** Killing a task does not cancel a broker operation already sent; Graph may have served it (RR-4). The guard keeps such late records out of the chain, and the verifier lists the open intent.
  - **The row and the record are two transactions.**
    - If the row's commit fails after the terminal record committed, the chain says the run ended while the row is still `running` and its token still resolves. Until the row is ended, every record for the run is refused, so an operation gets 503, no data and no Graph request. The reconciler later ends the row alone; its own record is refused as `run_ended`.
    - If a completion's row commit fails after `RUN_COMPLETED` committed, the run is failed on the row alone (`failed / result_unpersisted`, no result; a `RUN_FAILED` after `RUN_COMPLETED` is refused). The chain says completed, and `verify_run_result` reports `result_mismatch`, so the disagreement stays visible rather than resolved.
    - If `RUN_STARTED` commits but the row's start does not (the row commit failed, or the record's acknowledgement was lost), the run stays `queued` with a start in the chain. The next attempt's `RUN_STARTED` is refused (`run_already_started`), nothing is started, and the run ends `failed / start_unrecorded`. Both records are kept (handled since the Task 14 review).
  - **A failure or timeout whose record cannot be written** leaves a run ended in the table with no terminal record in the chain. It is visible, but nothing later fills it in.
  - **Not tested against Docker:**
    - the sandbox claims (no egress, no credentials, the limits hold) are Task 15's tests;
    - `DockerBackend` and `__main__` are wiring only;
    - Docker adds `PATH` (from the image) and `HOSTNAME` to the process environment beyond the two keys.
  - **One launcher loop runs one run at a time.** A slow run delays queued ones. Several runner processes are safe (`SKIP LOCKED`, row locks), but untested beyond two concurrent claims.
  - **Clocks.** The supervision timer uses the runner host's clock against a database-clock deadline; the broker uses its own clock.
  - **Carried forward from SD-032 and SD-033:**
    - RR-5: the verifier does not check the request target against the decision;
    - the broker's per-process lock and halt;
    - API-owned run creation (Task 16; the tests create queued runs as the API will);
    - Microsoft behaviour checked against Microsoft Learn (Task 17B; A-03, A-06–A-08, A-14–A-18 verified against the docs, A-10 with a caveat) but not against live Graph/Entra; A-02's error-code string, A-09 timing and A-25 remain to a tenant test;
    - tenant status not re-checked per operation;
    - unaudited token refusals.
- **Review (Task 14 follow-up, 2026-10-18).** Scope: the writer guard and the run's transaction boundaries only.
  - **Invariant checks:**
    - **After the end, and completions with an open request:** a record after a run's terminal record and a `RUN_COMPLETED` with an unanswered request are refused, for every record kind (tests above).
    - **Tenant scope:** the check reads only the appending chain (a forged terminal record for the run on another tenant's chain does not end it).
    - **Concurrency:**
      - under concurrent appenders exactly one of a racing request and completion is written (5 races);
      - the same holds for a racing terminal record and broker records.
    - **A refusal** rolls back the append transaction: no row, no sequence gap, and the writer's cached position stays right for its next append.
    - **Isolation level:** the check relies on READ COMMITTED, the default, so that its query, run after the advisory lock is held, sees every append committed before. A probe with sessions defaulting to REPEATABLE READ showed the second of two racing terminal records failing on the `(chain_id, seq)` key instead (`AuditUnavailable`, nothing written, chain valid), so it still fails closed. The writer does not set the isolation level itself; it relies on the default, as the Gate 1 chain-head check also does.
  - **Sent but unanswered:** a request with no recorded response stays in `intents_without_outcome`, also after a timeout or failure (the race test asserts both the listed intent and that Graph was called). Refusing the late record does not mean the request was not served.
  - **Defect found and fixed: the run-start window.** In `_start`, the row update to `running` is in the claim transaction, `RUN_STARTED` commits in the writer's own transaction, then the claim commits. If that commit failed, or the writer's acknowledgement was lost (RR-4), the row stayed `queued`. The next claim then had one of two outcomes:
    - it started the run again with a second `RUN_STARTED` (a permanent `run_already_started` finding);
    - if the chain already held the run's end, it retried forever: a refused start was reported as `not_started`.

    Fix: the writer refuses a second `RUN_STARTED` (`run_already_started`). The launcher treats any refusal of its `RUN_STARTED` as a start already recorded: nothing starts, and the run ends `failed / start_unrecorded`, from `queued`; the row alone if the chain already ended it. Before the fix, the new tests failed exactly this way (4 failed):
    - the run completed after a second start (row commit lost);
    - the same after a lost acknowledgement;
    - it was `not_started` indefinitely when the chain held its end;
    - the writer accepted a second `RUN_STARTED`.
  - **Tests added:**
    - `tests/db/test_audit_run_state.py`: a second start refused; a refused append writes nothing and the writer continues; a racing request and completion.
    - `tests/db/test_runner_boundaries.py`: a test-only `DEFERRABLE INITIALLY DEFERRED` constraint trigger fails the run row's commit after the record has committed, for:
      - the start: the row commit lost, then the acknowledgement lost, then recovery;
      - a run already ended in the chain but still queued;
      - a terminal record committed before a failed row commit: the token still resolves, an operation gets 503 with no data and no Graph call, and the reconciler then ends the row alone;
      - a completion recorded with no stored result.
  - **Mutation check (focused):** 16 mutants of the guard, the start recovery and the paths these tests reach; 15 killed. One was equivalent and was removed, not counted: clearing the writer's cached position after a refusal only forces a full verification on the next append. Result: 15 of 15 killed.
  - **Unchanged:** hashing, verification, recovery, checkpoints and database protections. RR-5 stays open (the verifier still does not bind a request to its decision's target).

## SD-035: The public API binds every run and view to the session's tenant

- **Status:** implemented and accepted (commit `97b9b01`, 2026-10-20) (`src/clw/api/main.py`, `catalog.py`, `runtime.py`; `src/clw/api/routes/tasks.py`, `runs.py`, `audit.py`; Task 16)
- **Decision:**
  - **Tenant and actor come only from the session.** Every route except sign-in depends on `current_principal`, which is derived from the verified, unrevoked session cookie (`tid`, `oid`, internal `user_id`, `role`), never from the path, query, headers or body (Task 6). A missing or invalid session is 401. A new run is stamped with `tenant_id = actor_tid = principal.tid`, `actor_oid = principal.oid`, `actor_user_id = principal.user_id`; the request cannot supply any of them.
  - **The create body is strict.** `POST /runs` takes `{"task_id": str, "params": {str: int}}` with `extra="forbid"` and `strict=True`. A `tenant_id`, `actor_oid`, `status`, `image`, `url`, `path`, `method` or any other field is a 422 before anything is created; a non-integer param is a 422 at the schema. The caller never chooses the image, command, credential, container settings, manifest digest, profile, or any Graph URL/method/header — those come from the catalog manifest the `task_id` selects, or they do not exist at this layer at all.
  - **Catalog and parameters.** The API loads the task catalog through `clw.broker.manifest.load_manifest` (one of the three broker modules the import-boundary test lets the API import; it imports no credential, transport or policy code and names no Graph host). An unknown `task_id` is a 404 before a run exists. `normalized_params` validates the params against the manifest exactly as the runner's `task_arguments` does — declared names only, a plain `int` (never `bool`) within the manifest's bounds, the default filled in — and stores the complete, canonical params on the run; out-of-range, non-integer or unknown params are a 422 (`params_invalid`) before a run exists. The runner re-validates when it claims the run (SD-034), so the API check is fail-fast, not the only gate.
  - **Creating a run is write-ahead and fail-closed (as SD-034's start).** In one transaction: the `runs` row is inserted `queued`, which the composite foreign key `fk_runs_actor_member` makes succeed only if `(tenant_id, actor_oid)` and `actor_user_id` are a current member of the run's tenant; then `RUN_REQUESTED` is written to the tenant's audit chain through the fail-closed `AuditWriter`; then the transaction commits. A membership/tenant foreign-key violation is caught as a 403 (`access_denied`) with **nothing** written to the chain (the insert fails first). An audit failure rolls the row back (503, `audit_unavailable`). The `AuditWriter` commits `RUN_REQUESTED` in its own transaction just before the row commit, so the only residue of a lost row commit (RR-4) is a harmless orphan `RUN_REQUESTED` for a run that never becomes claimable — never a `queued` run with no requested record.
  - **Least privilege for the create.** The run is inserted with a Core `INSERT` that names only the identity columns and `status`; the application database role is granted `INSERT` on exactly those columns (`id, tenant_id, task_id, task_manifest_sha256, profile_id, profile_version, profile_sha256, auth_mode, actor_user_id, actor_oid, actor_tid, params, status`), never `run_token_sha256`, `deadline_at`, `result`, `outcome`, `started_at` or `ended_at`. So the API cannot plant a run that is already running, carries a token, or is pre-authorized; minting the token and setting the deadline stay the runner's (SD-034). The test app role has exactly this grant, and every pg test also runs as that role (`db-app`).
  - **Tenant-scoped reads, no cross-tenant oracle.** `GET /runs/{id}` and `GET /runs/{id}/audit` select the run by `id` **and** `tenant_id = principal.tid`; another tenant's run, an unknown id, and a non-UUID id are all the same 404 (`run_not_found`), so a run id does not reveal whether it exists in another tenant. `GET /audit/verify`, `GET /runs/{id}/audit`'s chain result, and `GET /tasks/{id}`'s `audit.chain_valid` all verify the **caller's own** tenant chain only (`chain_id = principal.tid`).
  - **Views disclose no secret.** A run view is exactly `{id, task_id, status, params, outcome, result, created_at, started_at, ended_at}`: never the run-token hash, the deadline, or an internal error detail. An audit event view carries the record's own fields (`seq`, `event_type`, `status`, `reason`, `operation`, method, template, target, status, attempt, counts, `created_at`), never `previous_hash`/`record_hash`; the chain's validity is reported separately. The audit records hold no token by design (SD-032). The manifest view shows, for every allowed and prohibited operation, the method and path template from the operation registry, and the profile's id, version and expected permission names — never the profile's credential environment-variable names and never a Graph host or URL.
  - **Errors are small and fixed.** A `RequestValidationError` returns `{"detail": "invalid_request"}` (422) rather than the default body, which echoes the submitted input (a smuggled `tenant_id` value, a bad param); an unhandled exception returns `{"detail": "internal_error"}` (500) with no message or traceback. Per-route rate limiting (SD-027) is an app-level dependency; `runs_create` is limited per user.
- **Threat addressed:** T5 and T7 at the API boundary (a caller acting for, reading or auditing another tenant), T9 (a run bound to a tenant the request names rather than the session), request-supplied image/command/URL/credential/container settings, data or audit views that leak a run token or another tenant's records, a run created pre-authorized or already running, and an audit record that is skipped so a run runs unrecorded.
- **Tests:**
  - `tests/unit/api/test_manifest_view.py` (no database): the manifest view names the method and template of every allowed and prohibited op (from the registry, which the manifest cannot change), reports the profile and `audit.enabled`, and exposes no credential variable name or Graph URL; the task summary is the short card; the catalog loads the dormant task; `normalized_params` fills the default, holds the bounds, and refuses non-integers, bools and unknown keys.
  - `tests/db/test_api_tenant_isolation.py` (pg, and as the least-privileged app role): every route refuses a request with no session (401); each of `tenant_id`, `actor_oid`, `status`, `image` in the body is a 422 with nothing created; a created run carries the session's tenant, actor and `user_id`, the manifest digests, the queued status, and no token or deadline; `RUN_REQUESTED` is audited with the actor `oid`; one tenant's run and audit are a 404 to another tenant while the owner reads them; `GET /audit/verify` reports only the caller's chain (length and head), and the run audit view is the run's events plus the chain validity with no chain-internal fields; unknown and malformed run ids are 404; an unknown task and out-of-range, non-integer or unknown params are refused before a run exists; a run whose actor is no longer a member is a 403 with no row and no chain record; the run view never shows the token or deadline; and `POST /runs` is rate limited.
  - The route layer is placed in `tests/db` (not `tests/security`), where the Postgres fixtures live, as the broker and sign-in route tests already are (SD-032).
  - **Where these results come from:** the unit/security, `pg` and least-privileged `db-app` groups above were run locally against a Docker Postgres on 2026-10-20 (unit/security 3257 passed/2 skipped; `pg` and `db-app` 646 passed each). CI runs the same three groups on every push, but a CI run of commit `97b9b01` has not been observed here; the `sandbox`, `tenant` and `e2e` groups are unchanged by this task and add no Task 16 tests.
- **Mutation check (focused):** 12 mutants of the API's enforcement points (the run's tenant/actor filter and audit, the strict body, the create's least-privilege insert and queued status, the param-bounds and unknown-key checks, the write-ahead order, the token-free run view, the 404-not-500 for a malformed id, the manifest view's method/template, the created status code, and the reported chain validity), run against the two test files above; a mutant counts as killed only when pytest reports failing tests with no errors. First pass: 11 killed, 1 survived — hard-coding `/audit/verify`'s `valid` to `True` survived, because no test drove an invalid chain through it. That gap is closed (`test_audit_verify_reports_a_tampered_chain_as_invalid`: a superuser edits a committed record and the endpoint must report `valid: false` with a `hash_mismatch` at seq 1), and the mutant is then killed. Result: 12 killed, 0 survived, of 12.
- **Ambiguities in the plan, and how they were resolved:**
  - **Where `RUN_REQUESTED` sits relative to the row.** The architecture diagram shows the audit record before the row. Fail-closed requires the opposite inside one transaction: the row insert (so the actor-membership foreign key is enforced and a membership failure writes nothing to the chain), then `RUN_REQUESTED`, then commit. A membership failure is a 403 with no record; an audit failure rolls the row back; only a lost row commit leaves a benign orphan record, never a claimable run with no record.
  - **`audit.chain_valid` in the manifest view** is read as the caller's own tenant chain verification (the same chain the audit routes verify), so the detail view also answers "is my audit trail intact". The pure mapping of a manifest to its view is a separate function, tested without a database; the route adds the per-tenant validity.
  - **The isolation tests live in `tests/db`,** not `tests/security` as the plan's filename suggests, because they need the Postgres fixtures (the same resolution as SD-032 for the broker tests). They stay `pg`-marked and run in both the `pg` and `db-app` jobs.
  - **Membership is enforced by the foreign key,** not a separate `SELECT`, so the API role needs no read on `tenants`/`workbench_users` and the check is atomic with the insert (no time-of-check/time-of-use gap).
- **Limits:**
  - **Not an authorization model beyond the tenant.** Any member of a tenant may create and read that tenant's runs; role (`analyst` vs `security_lead`) is carried in the session but not yet used to restrict routes. No per-run owner check within a tenant.
  - **Tenant status and membership are not re-checked per read.** A run is refused at creation if the actor is no longer a member (the foreign key), but `GET` views and `/audit/verify` do not re-check tenant status; a session stays valid until it expires or is revoked (as SD-029, SD-032).
  - **`chain_valid` verifies the whole tenant chain on each detail/verify call**, which is O(chain length); there is no incremental or checkpoint-based fast path at the API (the writer's fast path, SD-026, is internal). Large chains make these reads slower.
  - **No exactly-once and RR-5 unchanged** (SD-032): the API creates the request; a lost row commit can leave an orphan `RUN_REQUESTED`; the verifier still does not bind a request target to its decision.
  - **Not tested against a browser or a real IdP.** Sign-in issues the session (Task 6); these tests mint sessions directly from a verified identity. CSRF/cookie handling for state-changing routes beyond the sign-in flow is not covered here.

## SD-036: Offline Phase 1 E2E demonstrates the broker boundary end to end (Task 17A)

- **Status:** implemented, offline-only (`tests/e2e/`: `test_phase1_demo.py`, `conftest.py`, `fake_graph.py`, `e2e_broker.py`, `demo_task/`, `certs.py`, `compose.e2e.yml`; `docker/e2e/`; `docs/demo.md`; Task 17A). The remaining Task 17 work — Microsoft Learn assumption verification (A-01…A-18) and the dev-tenant integration test — is **not** done.
- **Decision:** Run the real stack in containers — api, postgres, runner, the real hardened task sandbox, broker — against a **fake** Graph, and prove the brief's acceptance criterion 2 (prohibited requests never reach Graph) at the receiving end, not only from the broker's audit.
  - **Real vs mocked.** Real: the API lifecycle (Task 16), the `runs` table and its trigger, the audit chain and writer, the runner and the real sandbox (internal `clw_tasknet`, read-only root, dropped capabilities, no credentials), the task SDK, the broker policy, run-token resolution, write-ahead audit, the real Graph transport (still pinned to `https://graph.microsoft.com`), `validate_next_link` and `validate_token_claims`. Mocked, at the identity-provider boundary only: the browser sign-in (the session is minted from a verified identity) and the Entra token endpoint (a fake MSAL app factory issues the token the broker then validates for real).
  - **Reaching a fake Graph without weakening the pin.** The transport's `https://graph.microsoft.com` pin and certifi-only trust are unchanged. The fake Graph is network-aliased as `graph.microsoft.com` on egress and serves a leaf certificate for that name signed by a one-off test CA; the broker trusts it only because that CA is bind-mounted over the broker container's certifi bundle. No production image or source changes; the E2E-only images are thin layers over the real ones adding a single test-only demo task.
  - **Graph-side proof.** The fake Graph records every request. The happy path shows exactly three `GET /v1.0/users` requests (the three pages), each with an Authorization header, and **no** `PATCH`/`DELETE`/`POST` and no non-`/users` path; the demo task's attempted `users.update` is denied by the broker and absent from the log. A non-premium variant returns the licence error code and the run ends `FAILED / licence_required`.
- **Tests & mutation:** `tests/e2e/test_phase1_demo.py` (marker `e2e`): the eight demo steps plus the licence variant, asserting the fake Graph's own request log. Run repeatedly (deterministic). A focused E2E mutation check (4 mutants of the bind-mounted fake Graph and broker wiring — a missing page, a continuation to another collection, a continuation with an unapproved parameter, an over-consented token) all killed, 0 survivors; these exercise the live broker's real `validate_next_link` and `validate_token_claims` and the three-page assertion. The other enforcement the demo composes (a prohibited write denied, a non-users path, an unexpected method, an invalid chain reported invalid) is mutation-tested in isolation by SD-002/003/031/032/035 — defense in depth means no single E2E mutant can flip those, so they are not re-mutated through the E2E.
- **Limits (what the offline demo does NOT prove):** nothing about Microsoft's real token claims, app-only permission behaviour, licensing responses, Graph pagination/`nextLink` shape (A-14), or real-tenant consent. It is not equivalent to a real Entra integration test. **RR-5 remains open** (the verifier still does not bind a request target to its decision; the E2E does not change this). **SD-015 remains deferred.** No tenant setup occurred. The sandbox's documented limits (threat-model §7.3) are unchanged, and the configuration-verified vs behaviourally-verified resource-limit distinction (SD-008) stands.

## SD-037: Audited redaction of a stored run result

- **Status:** implemented (migration `20261025_result_redaction`; `src/clw/audit/redaction.py`; `RESULT_REDACTED` in `src/clw/audit/events.py` and `chain.py`; `clw audit-redact-result` in `src/clw/cli.py`; `serialize_run` and the run audit view in `src/clw/api/routes/runs.py`; runbook `docs/runbooks/result-redaction.md`).
- **Problem:** a completed run's `runs.result` can hold personal data (the dormant accounts it lists). The runs guard made an ended run immutable, and deleting the row would leave nothing recording why the result is gone.
- **Decision:** one operator procedure removes a result, and the removal is itself evidence.
  - **Write-ahead record.** `RESULT_REDACTED` is appended through the fail-closed writer *before* the row changes: `actor_oid` (the operator), `reason`, and `details` of exactly `{redacted_run_id, result_sha256}`. It never carries the data. It is not part of a run (`run_id` NULL), so it is allowed after the run's terminal record and cannot reopen the run.
  - **Chain rules.** A redaction must name an earlier **completed** run, carry that completion's `result_sha256`, and be the run's only one. Otherwise: `redaction_without_completed_run`, `redaction_digest_mismatch`, `result_already_redacted`. Existing records are untouched: `RUN_COMPLETED` keeps its digest.
  - **`verify_run_result`** returns `redacted` only when the result is gone **and** a matching redaction is supplied. A redaction never vouches for a result that is still present.
  - **Database.** The runs guard allows exactly one change to an ended run: `result` to SQL NULL together with setting `result_redacted_at`, on a `completed` run, once, with status, outcome, token, deadline and start/end times unchanged. `ck_runs_redaction` also refuses an inserted row already marked redacted. No application role is granted `result_redacted_at`, so the api, runner and broker cannot redact; the operator uses the owner role.
  - **Tampering is not erased.** If the stored result does not re-hash to its `RUN_COMPLETED` digest, the procedure refuses and records nothing, so the evidence stays.
  - **Partial failure.** If the record is written but the row commit is lost, running the procedure again finds the record, appends nothing and completes the row change (`resumed`).
- **Tests & mutation:**
  - `tests/unit/audit/test_redaction_records.py`: shape, chain rules, `verify_run_result`; forged malformed records found after re-hashing.
  - `tests/db/test_result_redaction.py`: procedure, trigger, application role refused, CLI, tampered result, writer down, resume, inserts.
  - `tests/db/test_audit_migrations.py`: round trip; downgrade refused once a redaction exists.
  - 10 new mutants in `scripts/audit_mutation_check.py` (record shape, each chain rule, digest binding, "vouches for a present result", the tamper check, the completed-only check, the trigger's unchanged-columns rule, `ck_runs_redaction`), **all killed**. The first run left 2 survivors; both were missing tests (a failed run holding a planted result; an insert already marked redacted), which were added.
- **Limits:**
  - The redaction removes the result from the `runs` table only. It does not reach database backups, checkpoint files, logs, or anything already copied out.
  - Who may redact is enforced by database privileges (the owner role), not by the application.
  - Like every record, a `RESULT_REDACTED` written by a compromised INSERT-capable role is accepted by the verifier (RR-1). Such a record cannot remove data, because removal needs the owner's privilege, and it never makes a present result verify as `redacted`.
  - RR-5 and SD-015 are unchanged.

## SD-038: One role definition per component, provisioned by the operator

- **Status:** implemented (`src/clw/db/roles.py`, `src/clw/db/admin.py`; `clw db-provision-roles`, `clw tenant-add`, `clw member-add` in `src/clw/cli.py`; `docker/api.Dockerfile` and the `api` service in `docker-compose.yml`; Task 17C A3).
- **Problem:** least privilege existed only in the test fixtures (`tests/db/conftest.py`). Nothing shipped created the roles, so a deployment would run as the owner. The API had no container. Tenants and members were added by hand-written SQL.
- **Decision:**
  - **One definition.** `clw.db.roles` states each component's privileges, and both the deployment and the test fixtures apply it, so tests prove what deployments get:
    - api: read tenants and memberships; create and claim sign-ins; read runs; create queued runs naming only their identity;
    - broker: read runs; end or halt them;
    - runner: read runs; start and end them, storing the result.
    - Every component may read and append audit records. No component may set `result_redacted_at` (SD-037), own a table or create objects.
  - **Provisioning from the service URLs.** `clw db-provision-roles` reads `CLW_API_DATABASE_URL`, `CLW_BROKER_DATABASE_URL` and `CLW_RUNNER_DATABASE_URL`, so each credential lives in one place.
    - It creates each role (`LOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION`) or updates its password.
    - It revokes whatever the role held in the database and grants exactly the definition, in one transaction. Re-running removes drift and rotates passwords.
    - It refuses the owner role, a role with administrative attributes, a shared role and a short password.
    - **It never prints or logs a password.** Any database error around the credential statement is replaced with a fixed message, because SQLAlchemy errors quote statements and parameters (found while testing: the first version printed the password in an error).
  - **Exact revocation.** Revokes target only relations where the role holds a table or column privilege. A blanket `REVOKE ... ON ALL TABLES` gives every table with default privileges an explicit ACL; the schema guard caught that.
  - **Tenants and members** are added by `tenant-add` and `member-add`: validated GUIDs and roles, idempotent, never changing an existing row.
  - **The api container** has no Graph credential, no profile certificate and no Docker socket. It is on `backend` and `egress` (Entra sign-in needs `login.microsoftonline.com`), bound to `127.0.0.1:8000`, read-only and with all capabilities dropped. `ENVIRONMENT` defaults to `development` (plain-http localhost) and must not be used for a real deployment.
- **Tests:** `tests/db/test_db_admin.py` (each role's privileges checked by attempt; rotation and drift removal; no administrative attributes; the refusals; the password never revealed when the database errors; the CLI) and the whole pg suite (both role modes) now running on the shared definition.
- **Limits:**
  - The test app role is the api and broker combined (their privileges together); the deployment separates them.
  - Role provisioning runs as the owner role, whose own security is the deployment's.
  - No TLS on the api or between services; no Redis persistence. The production baseline is still required before any real customer tenant (maintainer decision, 2026-10-24).

## SD-039: The verifier binds each request target to its decision (RR-5 closed)

- **Status:** implemented (`continues_approved_target` in `src/clw/audit/events.py`; the `GRAPH_REQUEST` rule in `src/clw/audit/chain.py`; Part B, M1).
- **Problem (RR-5):** the broker executes only the request its policy approved and records the approved target with each allowed `OP_DECISION` (`details.request_target`). But the chain verifier compared a `GRAPH_REQUEST` with its decision on method and path template only. A record carrying a different query (another `$select`, a larger `$top`) under a valid decision verified as valid.
- **Decision:** a `GRAPH_REQUEST`'s `request_target` must equal its cited decision's `details.request_target`, or that target plus exactly one `$skiptoken` continuation and nothing after it. Otherwise: `request_target_not_approved`.
  - Both strings are the broker's own canonical form (`pagination.request_target`, `validate_next_link`: the original parameters in their original order, then `$skiptoken` with a percent-encoded token). So they are compared **exactly**, with no reordering. That is stricter than normalizing.
  - An allowed decision with no recorded target approves nothing.
- **Tests & mutation:**
  - `tests/unit/audit/test_transitions.py`: a parameter added, changed, dropped or prepended; a continuation with another parameter; an empty continuation; a continuation without the approved query; a decision without a target; valid continuations, including an encoded token and a query-less approved target.
  - Existing test chains now record the approved target, as the broker always has. The RR-1 forgery test still shows a rule-following forger accepted, and the pagination test uses the broker's real continuation form.
  - Real broker chains still verify: pg as admin and as the app role (697 each), the offline e2e (2), the dev-tenant tests.
  - 4 new mutants (rule removed; extra parameters after the token; any target with the approved prefix; a decision without a target approving), **all killed**.
- **Limits:**
  - This binds what the records say to each other. It does not authenticate who wrote them: a writer able to insert records can forge a decision and a matching request together (**RR-1, unchanged**; per-component signing is SD-015, still deferred).
  - Exactly-once is still not claimed (RR-4).

## SD-040: Audit schema v3: facade targets and script records

- **Status:** implemented (`src/clw/audit/events.py`, `src/clw/audit/chain.py`, migration `20261101_audit_schema_v3`; Part B, M2). The facade and the script workflow that write these records come in M3 and M4.
- **Problem:** the bring-your-own-script path (a feasibility spike, kept private) needs three things the v2 schema forbids or lacks:
  - request targets under `/beta` (v2 fixes them to `/v1.0`);
  - records of a script's submission, analysis and approval;
  - a script run's binding to its approval.
- **Decision:**
  - **Versioned rules.** New records are written as **v3**. Every stored record is validated under **its own** version's rules, so v2 records keep v2's (`/v1.0` only; no script records), and no existing evidence changes meaning. Both versions are accepted (`SUPPORTED_SCHEMA_VERSIONS`); the database allows exactly 2 and 3.
  - **Targets.** A v3 `GRAPH_REQUEST` may name `/v1.0` or `/beta`. The version is part of the bound target, so RR-5's exact comparison (SD-039) also binds the version. The named-operation path keeps its own `/v1.0`-only check (the default of `target_matches_template`, used by the registry, transport and `validate_next_link`), so built-in tasks cannot emit `/beta`.
  - **Script records** (v3 only, tenant-scoped, never part of a run; exact `details` shapes, never the script text):
    - `SCRIPT_SUBMITTED` (`actor_oid` the submitter; `script_sha256`, `script_bytes`);
    - `SCRIPT_ANALYZED` (`analyzed`: `script_sha256`, `analysis_sha256`, `analyser_version`; or `failed` with a reason);
    - `MANIFEST_APPROVED` (`actor_oid` the approver; `script_sha256`, `manifest_sha256`, `approval_id`).
  - **Chain rules:**
    - an analysis needs an earlier submission of the same script;
    - an approval needs an earlier successful analysis, an approver who is not the submitter, and a fresh approval id;
    - a script run's `RUN_STARTED` (`details`: `script_sha256`, `approval_id`, `bootstrap_sha256`) must cite an earlier approval **of that very script**.
    - Findings: `analysis_without_submission`, `approval_without_analysis`, `approved_by_submitter`, `approval_already_recorded`, `script_run_without_approval`.
  - Downgrading the migration is refused once any v3 record exists.
- **Tests & mutation:**
  - `tests/unit/audit/test_script_records.py`: the full flow; each ordering and separation-of-duties finding; a failed analysis not enabling approval; a script run without, with another, or with a mismatched approval; malformed records refused at write time; script records refused under v2; a v2 chain still valid under v2 rules.
  - `tests/unit/audit/test_events.py`: `/beta` accepted under v3 and refused under v2 and on the named-operation path.
  - `tests/db/test_audit_migrations.py`: round trip; downgrade refused once a v3 record exists.
  - Mutants for each new rule, in `scripts/audit_mutation_check.py`.
- **Limits:**
  - The chain records who approved what. It does not authenticate the records (RR-1): a writer able to insert records could forge an approval. The API and database checks of M4 (role, approver ≠ submitter) are the enforcement; these chain rules are the evidence.
  - RR-4 and SD-015 are unchanged.

## SD-041: The Graph facade for script runs

- **Status:** implemented and tested in isolation (Part B, M3):
  - `src/clw/broker/facade/` (`canonical`, `rules`, `policy`, `pages`, `runs`, `handler`);
  - `Transport.fetch_target`;
  - `POST /v1/facade` in `src/clw/broker/app.py`;
  - `src/clw/facade_proxy/`, `docker/facade-proxy.Dockerfile`, the `facade-proxy` service with `clw_scriptnet` and `facadenet` in `docker-compose.yml`;
  - `clw facade-ca-init` (`src/clw/broker/facade/ca.py`, inside the broker package so the Graph host stays named only by `clw.broker.pagination`).

  **Not yet reachable in a deployment:** where a run's approved script manifest comes from is injected (`script_manifests`), and production passes none until approvals exist (M4). Until then every facade request is refused with `facade_disabled`. No script runs yet (the PowerShell sandbox is M5).
- **Problem:** scripts send real Graph-shaped HTTP. The broker accepted only named operations.
- **Decision:** a second, separate path through the same broker. The named-operation path is unchanged.
  - **Reaching it.** Script runs' task containers are on `clw_scriptnet` (internal), where the credential-less **facade proxy** holds the alias `graph.microsoft.com` and serves TLS with a certificate from a per-deployment, **name-constrained** CA (`graph.microsoft.com` only). The proxy forwards the raw request line, Authorization, ConsistencyLevel and only a body's length to the broker's `POST /v1/facade` over `facadenet` (internal), and decides nothing.
    - **The broker is on neither network that carries the alias.** Docker's DNS answers from every network a container is attached to, so had the broker shared a network with the alias, its own Graph lookups would have reached the proxy. This changes the plan's D2, which had the proxy on the task network.
    - Checked by attempt (`tests/sandbox/test_facade_network.py`: the task resolves Graph to the proxy, the broker never does, the proxy has no egress, the task cannot resolve or reach the broker, the proxy can) and statically (`tests/unit/test_compose_topology.py`: aliases, networks, the proxy's environment and mounts, and an image that copies no profiles, tasks or secrets).
    - **Verified once on the real compose stack (2026-10-25, Docker Desktop 29.1.2):**
      - the proxy container's environment is `CLW_FACADE_BROKER_URL` plus the base image's own; `/run/secrets/facade` holds only `leaf.crt` and `leaf.key`;
      - the proxy has no egress (`login.microsoftonline.com` and `example.com` unresolved; an outside address and an Entra address unreachable);
      - the broker resolves `graph.microsoft.com` to a Microsoft address, not the proxy's;
      - from `clw_scriptnet`, an HTTPS Graph request trusting only the facade CA reached the broker through the proxy (`facade_disabled`, as expected until M4), while the broker's name did not resolve and its `facadenet` address was unreachable;
      - without the facade CA, TLS to the proxy is refused.
  - **Authentication.** The script presents only its run capability, as `Authorization: Bearer`. It is resolved like a built-in task's run token (by SHA-256, from the run row; never the request), with the same refusals, plus `not_a_script_run`.
  - **Canonical form before any decision** (`canonical.py`):
    - **refused:** non-GET methods and GET bodies (Phase 1 is read-only); encoded slashes or backslashes, double encoding, dot or empty segments; any version but `/v1.0` and `/beta`; `$batch`, `/me`, functions and `delta`; unknown `$`-options;
    - **normalized:** case is folded and `$select` normalized;
    - **unknown parameters refused (D1, maintainer decision 2026-10-25):** any parameter that is not a known option, garbled ones included, is refused with a Graph-shaped 403 naming it (`unknown_query_parameter`, `innerError.clw-parameter`). Nothing is silently dropped. The audit records the parameter's name, never its value. *Consequence:* the demo script as published sends a garbled `$<TAB>op` (its ``$`top`` typo) and is refused on its first request.
    - **headers:** only `ConsistencyLevel: eventual` is forwarded.
  - **Policy, deny by default** (`rules.py`, `policy.py`):
    - **manifests:** script manifests have GET entries only, so a write is never approvable;
    - **entries:** each entry names its versions explicitly and its path with GUID-only placeholders;
    - **options:** a required `$select` allowlist, `$filter` off or limited to named properties, a bounded `$top`, `$count`/`$orderby`/`$search`/`ConsistencyLevel` only if the entry turns them on, and `$expand`, `$skip`, `$apply`, `$compute`, `$format` and `$deltatoken` never;
    - **binding:** the manifest's SHA-256 over canonical JSON is what an approval binds to (M4).
  - **Audit, write-ahead, RR-5-bound.**
    - `OP_DECISION` (operation `facade.<entry>`; `details.request_target` the approved canonical target), then `CREDENTIAL_ACQUIRED`, then for each attempt `GRAPH_REQUEST` (committed before sending), then `GRAPH_RESPONSE`.
    - The verifier's exact-target rule (SD-039) holds facade requests to the approved target and its continuation.
    - A refused request is recorded with its method, a bounded path and the reason, **never its query text**.
  - **Paging** (`pages.py`):
    - Graph's `@odata.nextLink` must be the approved request plus one `$skiptoken`, or paging stops and the run fails.
    - It is held by the broker under a random, single-use handle bound to the run and expiring at its deadline. The script only ever sees `…?$skiptoken=clw_<handle>`.
    - A continuation must carry nothing else. Before it is sent, the **original approved request is re-authorized** against the run's current manifest.
  - **Responses** pass through to the script, nextLink rewritten. A final Graph error reaches the script, and the run continues. Anything Cloud Locksmith refuses is a Graph-shaped `403 Authorization_RequestDenied` with `innerError.clw-reason`.
  - **Credentials and fail-closed behaviour are the broker's own:** the same exact-set token check, per-run lock, halt on audit failure, and FAILED on credential, Graph or binding failures.
- **Tests & mutation:**
  - `tests/security/test_facade_{canonical,policy,pages,transport}.py`;
  - `tests/db/test_facade_service.py` against Postgres (write-ahead order, two-page paging with per-page decisions, writes refused and never sent, denials, D1, Graph errors, foreign nextLink, over-consent, audit outage halting, a narrowed manifest refusing a continuation, capability refusals);
  - `tests/unit/test_facade_proxy.py`, `tests/unit/test_facade_ca.py`, `tests/unit/test_compose_topology.py`, `tests/sandbox/test_facade_dns.py`.
  - **18 facade mutants, all killed.** The first run left 2 survivors, both real test gaps (a `$top` bound below the canonical limit; a manifest narrowing between pages), which were added.
- **Limits:**
  - **Personal data in the audit chain:** superseded by SD-042. `$filter` and `$search` values are now recorded only as per-tenant keyed hashes, never as written. Path segments (object GUIDs) and property names are still recorded as they are.
  - **Untested shapes.** Real Graph's nextLink shape for `/beta`, `$count` and `$filter` queries is untested (dev tenant, M6); a different shape stops paging.
  - **Handles** live in the broker's memory: a broker restart refuses a script's next page.
  - **Approval provenance.** Nothing here authenticates who approved a manifest (M4), and RR-1 still holds.
  - **Responses reach the script.** By design, so the run's output can contain everything the manifest let it read.
  - **Isolation.** Third-party scripts still need gVisor or a microVM before any design partner runs them (M5).

## SD-042: Free-text query values are keyed-hashed in the audit chain

- **Status:** implemented (`src/clw/broker/facade/hashing.py`; the handler's decision and request records; migration `20261102_audit_value_keys`; the broker's grant in `src/clw/db/roles.py`; `clw audit-hash-value`).
- **Problem:** the chain records each facade request's exact target, because the verifier binds a request to its approval by that target (SD-039). `$filter` and `$search` values are free text a script chooses (`displayName eq '<a name>'`), and the chain is permanent: redaction (SD-037) cannot reach it. Owner decision (2026-10-25): no raw values in the chain.
- **Options considered:**
  - **(a) A keyed hash per tenant (chosen).** The chain holds no value, and there is no second copy of personal data to retain, grant or back up. An investigator with the owner role can test a candidate value. Deleting the key ("crypto-shredding") permanently unlinks every hash made with it.
  - **(b) A redactable side table.** It keeps a second copy of the values, with its own retention, grants and backups, and the chain would still need a stable reference to it.
- **Decision:**
  - **Format.** The chain records `$filter` and `$search` values as `clwhash.<key_id>.<HMAC-SHA256(key, "<option>\0<decoded value>")>`. Everything else in the target is recorded as it is. Graph always receives the real target.
  - **RR-5.** The decision's approved target and every request's target are hashed with the same key, and the broker's `$skiptoken` continuation is appended after, unhashed. So the verifier's exact comparison (SD-039) still holds, and no audit rule changed.
  - **Keys.** `audit_value_keys` holds one 32-byte random key per tenant with an 8-hex key id, created by the broker on first use and cached in its process. Grants: the broker `SELECT, INSERT` only; no grant to the api or the runner; only the owner can delete.
  - **Fail closed.** If the key cannot be read or created, the request is not sent and the run halts (`AuditUnavailable`). A value is never recorded unhashed.
  - **Investigation.** `clw audit-hash-value --chain <tenant> --option '$filter' --value '<candidate>'` prints the digest the value would have under the current key.
- **Tests & mutation:**
  - `tests/security/test_facade_hashing.py`: only `$filter`/`$search` hashed, the decoded value keyed, RR-5 and the target rule still satisfied, no key in a repr.
  - `tests/db/test_facade_service.py`: no raw filter value anywhere in the tenant's chain, the chain valid, the CLI reproducing the recorded digest, a deleted key replaced under a new key id, a missing key halting the run with nothing sent.
  - `tests/db/test_db_admin.py`: only the broker role reads keys.
  - 4 mutants (not hashed; `$search` left raw; the request recorded unhashed; a missing key not stopping the request), **all killed**.
- **Limits:**
  - **Low-entropy values can be guessed by whoever holds the key:** an owner-role operator, or anyone with the database. A filter like `userType eq 'Member'` is easy to guess with the key, and not without it.
  - **The key sits in the same database as the chain.** Crypto-shredding protects against later readers of the chain and its checkpoints, not against someone who already copied the key.
  - **Not hashed:** object GUIDs in paths, property names in `$select` and `$orderby`, and the `$skiptoken` continuation.
  - **Key rotation** is by deletion only, which unlinks the old hashes.

## SD-043: Bring-your-own scripts: intake, offline analysis, approval, real roles

- **Status:** implemented (Part B, M4):
  - migration `20261103_scripts`;
  - `src/clw/api/routes/scripts.py`, `require_role` in `src/clw/api/deps.py`, script runs in `src/clw/api/routes/runs.py`;
  - `src/clw/runner/analyser.py`, `DockerBackend.analyse`, `docker/analyser.Dockerfile`, `task_pwsh/analyse.ps1`, `src/clw/scripts/analysis.py`;
  - `src/clw/broker/facade/approvals.py` (the facade's production manifest lookup);
  - grants in `src/clw/db/roles.py`.

  **Script runs are created but not launched:** the runner claims built-in task runs only until the PowerShell sandbox (M5).
- **Decision:**
  - **Intake.** `POST /scripts` (analyst or security lead) stores a script's text, at most 256 KiB, under the SHA-256 of its UTF-8 bytes, per tenant, and queues its analysis. It records `SCRIPT_SUBMITTED` write-ahead. Scripts never change (a database trigger): editing one makes a new script with no analysis and no approval.
  - **Analysis, offline.**
    - **Containment:** the **runner** (the API never holds the Docker socket) starts the analyser container with **no network**, a read-only root, every capability dropped, no environment and no mounts. The script goes in on **stdin**; files cannot be copied into a read-only root, and the root stays read-only.
    - **Analysis:** `analyse.ps1` parses it with PowerShell's own parser and the offline cmdlet metadata (`Find-MgGraphCommand`), and **never executes it**. It reports the commands, Graph calls with literal parameters, unresolved items and risk flags.
    - **Result:** the runner accepts exactly one bounded `CLW_ANALYSIS` line and records the analysis, its SHA-256, a **proposed manifest** (GET entries only) and a **plain-English summary** of what it reads, what it tries to change ("this will be blocked"), its risks and what is unknown. It writes `SCRIPT_ANALYZED`.
    - **Failure:** a timeout, a crash, malformed output or an audit failure fails the analysis, and a failed or unrecorded analysis can never be approved.
  - **Approval, three times over.** `POST /scripts/{sha}/approvals` (**security lead only**, via `require_role`) validates the manifest with `clw.broker.facade.rules` (GET entries only) and refuses the submitter's own script and an unfinished analysis. The database's insert guard refuses, whatever the caller:
    - an approver who is not a security lead of the script's tenant;
    - the script's submitter;
    - another digest;
    - a script without a completed analysis;
    - any non-GET entry.

    The chain verifier checks the same order and the separation of duties (SD-040). Approvals never change.
  - **Roles are real:** `require_role` reads the role from the session, which came from the membership row at sign-in. Analysts submit, view and run; security leads also approve.
  - **Script runs.** `POST /runs` takes exactly one of `{task_id, params}` and `{script_sha256[, approval_id]}`. A script run needs an approval of exactly that script. It is bound to the approval's manifest digest and profile, and its `kind`, `script_id` and `approval_id` never change.
  - **The broker.**
    - The named-operation path refuses script runs (`not_a_task_run`).
    - The facade serves only a script run's own approval, re-checking that the stored manifest still loads and that its digest equals both the approval's and the run's. A tampered approval serves nothing.
    - The facade is therefore enabled in production, for approved script runs only.
  - **Import boundary:** the API may now import `clw.broker.facade.rules`, a pure validator with no transport or credentials.
- **Tests & mutation:**
  - `tests/unit/test_script_analysis.py`: the proposal and summary, and strict parsing;
  - `tests/db/test_scripts.py`, as admin and as the least-privileged roles: intake, tenant isolation, analysis with its container options, failed and unrecorded analyses, approval by role, own-script and write refusals, each database guard rule refused alone with a control, immutability, script runs, the runner leaving them, the broker's view, a tampered approval;
  - `tests/sandbox/test_analyser.py`: the real analyser container on a fixture script written for the tests (not copied from any public script). The proposal is approvable, the write named, the risks flagged and the literal request resolved.
  - **14 M4 mutants, all killed.** The first run left 5 survivors, all real test gaps: guard cases that broke several rules at once, and no test of an unrecordable analysis. They were added.
  - **Found by the first CI run (Linux), fixed:**
    - On a Unix Docker socket, closing the attach wrapper did not end the analyser's stdin, so every analysis timed out. The backend now half-closes the socket. Docker Desktop's named pipe had hidden this.
    - `Find-MgGraphCommand` loads the SDK's whole command metadata, about 500 MiB at peak, so the analyser's 512 MiB limit ran it out of memory in about half the runs. `-ErrorAction SilentlyContinue` then reported the script's cmdlets as "not a known Graph SDK cmdlet": a **wrong analysis that looked complete**. It failed closed at run time, but it misled the approver. The limit is now 1 GiB. Only the "not a valid command" error means unknown; any other error fails the whole analysis.
    - Tests: the analysis is repeated and must resolve the cmdlets every time, and an analysis starved of memory must fail, never call cmdlets unknown. That test fails on the old script.
- **Limits:**
  - **A URI held in a variable** resolves from the nearest assignment before its use (M6): `$Uri = "<literal>"; Invoke-MgGraphRequest -Uri $Uri` resolves even when `$Uri` is later set to a next link, and that later use stays unresolved. A loop can make a use see a later assignment at run time.
  - **The analysis explains; it does not enforce.** It can miss or misread a call (`Find-MgGraphCommand` gives several endpoints per cmdlet, and computed URIs are unresolved). The facade denies at run time whatever the approved manifest does not allow.
  - **Script text is stored permanently and is not redactable.** A script with a hard-coded secret keeps it; a risk flag for that is future work.
  - **The analyser runs on the runner's Docker host.** It is parser-only and network-less, but it handles untrusted text, so gVisor/microVM isolation (M5) applies to it too.
  - **Script runs stay queued** until M5. (Since M5 they are launched when the runner has a script image: SD-044.)
  - **RR-1:** a database writer could forge approvals. The guards and the chain are evidence, not authentication.

## SD-044: The PowerShell sandbox for script runs; gVisor before third-party scripts

- **Status:** implemented (Part B, M5):
  - `docker/task-pwsh.Dockerfile`, `task_pwsh/bootstrap.ps1`;
  - `script_container_kwargs`, `ScriptSandboxConfig` and `bootstrap_sha256` in `src/clw/runner/sandbox_spec.py`;
  - the script path in `src/clw/runner/launcher.py`, `parse_script_output` and `bootstrap_refusal` in `src/clw/runner/result.py`;
  - `DockerBackend.start(kwargs, stdin)`;
  - the runner's `SELECT` on `script_approvals` (`src/clw/db/roles.py`);
  - `CLW_SCRIPT_IMAGE`, `CLW_SCRIPT_BROKER_URL` (what scripts see as `CLW_BROKER_URL`: the Graph host, the facade there; runner configuration, so the runner imports no broker internals) and `CLW_TASK_RUNTIME` (runner);
  - `scripts/gvisor_eval.sh`.

  Script runs are launched when the runner has a script image. Without one they stay queued, as in M4.
- **Decision:**
  - **The image.**
    - PowerShell 7.5 (pinned digest) with only `Microsoft.Graph.Authentication` and `Microsoft.Graph.Users` 2.41.2, no package source left registered, user 10006.
    - It trusts this deployment's facade CA, the only extra certificate. The CA's public certificate is built in from its own build context, `public/` of `clw facade-ca-init`'s output, which holds `ca.crt` alone, so no key reaches the Docker daemon. `facade-ca-init` now writes the certificate there.
  - **The container** is the built-in sandbox's hardening:
    - a read-only root, a 16 MiB `noexec` `/tmp`, every capability dropped, `no-new-privileges`;
    - 512 MiB memory without swap, 1 CPU, 64 PIDs and RLIMIT_NPROC 64;
    - the facade proxy by address, in its hosts file (looked up at launch; see the gVisor evaluation below);
    - exactly `CLW_RUN_TOKEN` and `CLW_BROKER_URL` (the Graph host's URL);
    - **only `clw_scriptnet`**, whose one peer is the facade proxy (SD-041).
  - **Script delivery: on stdin from the runner, not fetched from the broker** (a change to plan decision D3). Under the network layout accepted at M3, a script container's only route to the broker is the Graph facade, so a broker fetch would have put a non-Graph route into the facade. The runner already reads scripts (SD-043).
    - The runner starts a script run only if it is still bound: the approval is the tenant's and of the run's script, its manifest digest is the run's, the stored manifest still loads to it, and the script's text hashes to the approved digest. Otherwise the run ends `failed / approval_invalid` and nothing starts.
    - The script's UTF-8 bytes are the container's whole stdin, then end of file.
  - **The bootstrap**, whose digest the runner records in `RUN_STARTED` with the script digest and the approval:
    - **Integrity:** it refuses to run (`CLW_BOOTSTRAP_FAILED <reason>`, exit 70) unless its own file has the recorded digest and the script's bytes have the approved one.
    - **Connection:** it connects the SDK with the capability, then removes the token from the environment.
    - **Disclosed shims:** `Connect-MgGraph` ignores its arguments, `Disconnect-MgGraph` is a no-op, `Out-GridView` writes `CLW_OUTPUT <json>`, and `Read-Host` fails at once.
    - **Execution:** it runs the script as a file, so the script's own `exit` ends only the script. It prints every stream as plain text, with errors reduced to their message, and ends with `CLW_SCRIPT_EXIT <code>`.
  - **The result** is `{"kind": "script_output", "script_exit_code", "output"}`.
    - The output is at most 1 MiB; past that the container is killed and the run fails `result_too_large`.
    - It is decoded as UTF-8, with undecodable bytes and NUL replaced.
    - It is hashed into `RUN_COMPLETED` like any result, and redactable (SD-037).
    - The script's exit code is the script's outcome. The run completed.
    - Without the closing line, the run fails `result_missing`; a bootstrap refusal fails with its reason; a non-zero container exit fails `task_error`.
    - The deadline is the runner's (600 s); script manifests carry none.
  - **Container runtime:** `CLW_TASK_RUNTIME` (for example `runsc`) applies to task, script and analyser containers alike. It is validated as a plain name. Without it, Docker's default (`runc`).
  - **gVisor or a microVM is required before any design partner runs third-party scripts.** This holds whatever the evaluation shows. The runtime option makes it a deployment setting. `scripts/gvisor_eval.sh` runs every sandbox suite under `runc` and `runsc` and records the host's kernel (`uname -r`), OS, Docker and `runsc` versions with the results. **Results from a Kali Linux host are evidence of feasibility there, not of the pilot host**, whose kernel, Docker and gVisor versions may differ and must be tested there.
- **Tests & mutation:**
  - `tests/unit/test_script_sandbox.py`: the container options, digest and runtime validation, the bootstrap digest, the output and refusal parsing.
  - `tests/db/test_script_runs.py`, as admin and as the least-privileged roles. It covers:
    - the launch, the script on stdin, `RUN_STARTED`'s details, the stored result and a valid chain;
    - the script's exit code as its outcome;
    - each unclean ending;
    - an edited script and a tampered approval, which start nothing;
    - a runner without the script sandbox, which leaves runs queued.
  - `tests/sandbox/test_task_pwsh.py`, the real image against a TLS stub as `graph.microsoft.com` on an internal network:
    - an unmodified SDK script reads with `Bearer <run capability>`;
    - a refused write reaches the script as a Graph error and the script carries on;
    - the token is not in the script's environment;
    - the shims work, and the script's `exit` is its own;
    - a wrong script or bootstrap digest runs nothing;
    - the internet is unreachable.
  - Every sandbox suite honours `CLW_TASK_RUNTIME`, and the escape probe asserts the runtime it ran under.
  - **The whole stack, offline (M6, `tests/e2e/test_byos_stack.py`).** Submission, the analyser, a lead's approval, the PowerShell sandbox, the facade proxy and the broker's facade all run in compose against the fake Graph:
    - An unmodified SDK script pages all three pages.
    - The same script plus one `Update-MgUser`: the write is refused before Graph and the script carries on.
    - **Policy attempts** (`tests/e2e/scripts/policy_attempts.ps1`), under an approval of one read only (`GET /v1.0/users`, `id` and `displayName`). 21 attempts are made. Only the approved read and its valid next page are allowed. Refused: writes by cmdlet and by request (POST, PATCH, DELETE, `$batch`), other paths, other properties, `/beta`, `$expand`, `/me`, an unknown parameter, an encoded slash and a double slash, and altered, made-up, reused and redirected page handles. A handle presented on the wrong path is used up, so it cannot be retried.
    - The fake Graph's own log shows only those two GETs.
    - Credential and egress attempts stay in the sandbox and network suites, which attempt them for real.
    - The e2e suite runs locally, not in CI.
  - **8 M5 mutants, all killed.**
- **First gVisor evaluation and its fixes** (owner's Kali machine, 2026-10-26: kernel 6.19.14+kali-amd64, Docker 28.5.2, runsc release-20261019.0, cgroup v2; feasibility evidence for that machine only):
  - **Result:** under `runc`, 42/42 passed; under `runsc`, 35/42 passed. Every "no way out" check passed under both (no egress, no raw sockets, no privilege escalation, the runtime asserted).
  - **Name resolution (5 failures).** Docker's network DNS is unreachable from gVisor's network stack, so `broker` and `graph.microsoft.com` did not resolve. That fails closed, but nothing worked. Confirmed by attempt: a hosts entry resolves under `runsc`, Docker's DNS does not.
    - **Fix:** at launch the runner looks up the one peer a container may reach, the broker on `clw_tasknet` or the facade proxy on `clw_scriptnet` (`DockerBackend.peer_address`: exactly one container known by that name). Its address goes into the container's hosts file (`extra_hosts`) under the configured URL's host name. With no such peer, or more than one, nothing starts (`failed / peer_unavailable`).
    - The peer must be an IP address. No other name is added, so other names still do not resolve. gVisor keeps its own network stack: running it on the host's network stack instead was rejected as weaker isolation.
  - **PID limit (1 failure).** Under gVisor a container's threads live inside the sandbox, so Docker's PID limit did not bound them (300 threads started under a limit of 64). Confirmed by attempt that `RLIMIT_NPROC` is enforced inside gVisor (it stopped at 63).
    - **Fix:** every task, script and analyser container also gets `nproc` 64.
    - Under `runc`, `nproc` counts that user's processes on the host. That is safe today because the runner starts one container at a time and each container kind has its own uid.
  - **Read-only root (1 failure).** Under gVisor a write to `/` failed with EACCES, not EROFS. The protection held, but the test could not tell which one stopped it.
    - **Fix:** the probe image has one directory owned by the task user. A write there must fail with EROFS under both runtimes, which proves the read-only root by attempt again.
  - **Performance.** PowerShell start-up took 8.9 s under gVisor and 1.5 s under runc. The analyser took 30.5 s against 3.3 s, too close to its 60 s timeout.
    - **Fix:** the analyser no longer loads the SDK's whole command metadata per analysis. `task_pwsh/build_command_index.ps1` builds a cmdlet-to-endpoint index once, at image build. It agrees with `Find-MgGraphCommand` on a sample of commands and aliases, checked by attempt in `tests/sandbox/test_analyser.py`.
    - Locally an analysis now takes about 1.6 s instead of 3.3 s and needs under 200 MiB, so the analyser's limit is back to 512 MiB. A starved analysis still fails, and never calls cmdlets unknown.
  - **The rerun** (same host, commit `43b86fc`) passed 42 of 43 under both `runc` and `runsc`. The one failure, under both, was the index-agreement test running its own 2 GiB container out of memory: it held the parsed metadata while `Find-MgGraphCommand` loaded its own copy. The test now drops it first and passes at 1 GiB. The analyser takes 3.7 s under gVisor (was 30.5 s) and 1.0 s under `runc`; PowerShell start-up is 10.1 s under gVisor and 1.5 s under `runc`, acceptable for script runs (A-28).
  - **Mutation:** 4 follow-up mutants, all killed: a run starting with no peer, the peer left to Docker's DNS, any string accepted as the peer, no `nproc` limit.
- **Limits:**
  - **gVisor is feasible on a Kali Linux host, nowhere else yet:** every sandbox test passes under it there. The pilot host's kernel, Docker and gVisor versions must be tested on the pilot host itself. Until a third-party script runs only under gVisor or a microVM on the pilot host, design partners do not run third-party scripts.
  - **A peer's address is looked up once, at launch.** If the proxy or broker restarts with a new address during a run, that run loses its route and fails. It never reaches anything else.
  - **What the bootstrap reports is evidence from inside the sandbox, not proof.** A script can end its own process with any exit code and output, including a false `CLW_BOOTSTRAP_FAILED` line, so a failed run's reason may be the script's doing. Only the script's own run is affected. The digest checks protect against running the wrong script or bootstrap by mistake, not against a malicious image.
  - **Script output is untrusted text.** It is stored as a string and must be shown escaped (M7).
  - **A script whose result is a file** (CSV, Excel) produces nothing we capture (spike section 7.5); the analyser flags file writes.
  - **The SDK could start parsing tokens in a later version.** It is pinned at 2.41.2, and the spike's checks must be rerun on every upgrade.

## SD-045: Demo pages for bring-your-own scripts

- **Status:** implemented (Part B, M7): `src/clw/api/ui/pages.py` and `src/clw/api/ui/templates/`, with Jinja2 3.1.6 as a new pinned dependency (plan decision D4).
- **Decision:**
  - **Pages.** Server-rendered pages under `/ui`, served by the api:
    - sign-in, or submit a script and list the tenant's scripts;
    - the analysis: what the script reads, what it tries to change ("this will be blocked"), risks, unknowns and the proposed manifest;
    - approval, shown only to a security lead who did not submit the script, with the manifest editable before approving;
    - run under the latest approval;
    - the run, with its status, the script's output and its audit trail.

    They are demo pages, not the product UI (a separate workstream).
  - **No second implementation.** Each action calls the JSON route's own function (`scripts.submit`, `scripts.get_script`, `scripts.approve`, `runs.create_run`, `runs.get_run`, `runs.get_run_audit`), so every rule is the API's:
    - the tenant from the session only;
    - roles;
    - the own-script refusal and a completed analysis;
    - GET-only manifests;
    - the write-ahead audit.

    The pages re-check the role themselves and show the API's fixed error code on a refusal, never request input.
  - **Escaping.** Jinja2 autoescapes everything. A script's text and its output are shown as text in `<pre>`, never as HTML.
  - **No JavaScript.** Every page sends `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, plus `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and `Cache-Control: no-store`. It was `no-referrer` at first, but under that policy browsers send `Origin: null` on form posts, so every post was refused: found in the first real browser use, the test client having sent a real Origin. A pending analysis or run refreshes the page with `<meta http-equiv="refresh">`, not script.
  - **Cross-site requests.** A form post must carry an `Origin` equal to the page's own (`scheme://host[:port]`). This is on top of the session cookie's `SameSite=Lax`. A missing, foreign or look-alike origin is refused (403 `cross_origin_refused`) before anything is read or written.
  - **Forms.** They are `application/x-www-form-urlencoded` only, at most about 516 KiB (twice the script limit), with exactly the expected fields, each once. They are parsed here, with no multipart dependency. Browsers submit text areas with CRLF line ends; the script is stored and hashed with LF.
  - **Rate limits.** The three form posts have the same per-user limits as the JSON routes they call (`ui_scripts_submit`, `ui_scripts_approve`, `ui_runs_create`), counted separately.
- **Tests & mutation:**
  - `tests/db/test_ui_pages.py`, as admin and as the least-privileged roles. It covers:
    - sign-in and the security headers;
    - the whole flow, including CRLF to LF;
    - cross-site posts (none, foreign, look-alike), which are refused and change nothing;
    - malformed forms;
    - role, own-script, write and unapproved-run refusals;
    - another tenant's script and run;
    - a hostile script text and a hostile output, both shown escaped, with a valid chain.
  - **4 mutants, all killed:** no origin check, autoescape off, no role check, a CSP that allows scripts.
- **Limits:**
  - **The origin is compared with the request's own URL.** Behind a TLS-terminating proxy, the api must see the public scheme and host, or every post is refused (fail closed). A production deployment sets this explicitly.
  - **The pages are as trustworthy as the session.** Sign-in is the existing Microsoft sign-in (SD-029). The demo's sessions were issued directly.
  - **Displayed output is the script's.** It is escaped, but it can still say anything, including fake "Cloud Locksmith" messages. The audit trail beside it is the evidence.

## SD-046: Production mode, checked in its container; the Redis start-up check wired in

- **Status:** implemented: `_lifespan` in `src/clw/api/main.py`; `tests/unit/test_api_startup.py`; `tests/e2e/test_production_mode.py` (compose profile `prod` in `tests/e2e/compose.e2e.yml`).
- **Finding.** `verify_redis_available_in_production()` existed, and its docstring said production refuses to start without Redis, but nothing called it. A production api would have started without Redis. Each request still failed closed (sessions refused, rate-limited routes refused), but the promised start-up refusal did not happen. It is now the app's lifespan start-up step; outside production it does nothing.
- **Decision: what is checked, in the api's own container with `ENVIRONMENT=production`,** against the e2e database and its own Redis, offline:
  1. **Without Redis, it refuses to start:** the container exits and says why.
  2. **Cookies:** with Redis it starts, and the sign-in cookie is `Secure`, `HttpOnly` and `SameSite=Lax`. Sign-in start only builds the Microsoft authorize URL and contacts nothing; the sign-in values are placeholders.
  3. **Revocation:** logging out revokes the session in Redis, and the revocation survives a Redis restart.
  4. **With Redis down, it fails closed:**
     - a session is refused (401);
     - a rate-limited route is refused (the limiter fails closed, 429, ahead of the session check);
     - logout never answers 204 when it revoked nothing.

     With Redis back, it serves again.
- **Tests & mutation:** the e2e sequence above (local, not CI). Unit tests: production refuses to start with Redis unreachable or unset, other environments start without it. **1 mutant, killed** (the lifespan removed).
- **Limits (still not exercised):**
  - **TLS in front of the api.** The deployment's TLS terminator is not part of this check. The cookie's `Secure` attribute is what is checked, and a browser sends such a cookie only over HTTPS.
  - **The production sign-in round trip.** It needs an `https://` redirect registered in Entra, a tenant change for the owner.
  - **The egress allowlist.** Outbound traffic from the api and broker is not restricted by the application. That belongs to the pilot host's network or firewall configuration, and stays an open item.
  - **Redis persistence.** It relies on the image's default snapshot on shutdown. A pilot deployment should configure it explicitly.

## SD-047: A generic Graph read tool only on the facade's terms: registry-matched, never forwarded

- **Status:** decided (maintainer, 2026-10-28); not built. Applies to any MCP tool that takes a Graph-shaped request (roadmap B; a separate maintainer decision whether to build one).
- **Problem:** the non-negotiable says no interface accepts a Graph URL, path, method or header. A generic read tool (`graph_read`) for an agent takes something URL-shaped.
- **Decision:** such a tool is allowed only as a second front end to the facade's decision path (SD-041). Nothing new is added to the enforcement core.
  - **Input** is a relative Graph path and query, never a host, scheme, method or header. A full URL, another host, any method but GET, a body, or a header is refused before matching.
  - **Canonicalisation and matching** reuse `clw.broker.facade` (`canonical`, `rules`, `policy`) unchanged. The request must match an entry in the session profile on version, path pattern and every query option. Anything unmatched, unknown or ambiguous is refused with a reason (`unknown_query_parameter`, `not_in_profile` and the rest).
  - **Never forwarded.** The agent's string is never sent anywhere. The broker records the decision, and `clw.broker.transport` builds the outgoing URL from the matched entry and the canonical parts, exactly as for facade requests. The non-negotiable holds: only the transport builds Graph URLs.
  - **Paging** stays broker-held (SD-041's single-use handles); the agent sees only handles.
  - **Audit** is the facade's write-ahead sequence, with the refused request recorded as method, bounded path and reason, never its query text (SD-042).
  - **Writes** never pass through this tool. Writes are separate, named, approval-bound operations (roadmap D).
- **Threat addressed:** an agent (or an injected instruction) composing arbitrary Graph calls; URL tricks; a second, weaker policy path.
- **Limits:** the profile decides what's readable. A broad profile with a generic tool lets the agent read everything it allows. Curated tools are the default; a generic tool is a separate maintainer decision with its own tests.

## SD-048: MCP clients authenticate with a Cloud Locksmith session capability, not MCP's OAuth flow

- **Status:** decided (maintainer, spike gate 2026-10-28). Built for v0.1 (2026-10-30):
  - **the gateway side**, in `src/clw/mcp_gateway/app.py`: Protected Resource Metadata, a 401 with `resource_metadata`, Bearer only, the broker asked on every request, and a DNS-rebinding Host check;
  - **the broker side**, in `POST /v1/agent/session` and `/v1/agent/ops`;
  - **sessions**, in SD-049.

  Tests: `tests/unit/test_mcp_gateway_auth.py`, `tests/db/test_broker_agent_ops.py` and `tests/db/test_agent_sessions_api.py`.

  Evidence for the original decision: an MCP feasibility spike (kept private).
- **Deviation:** the MCP authorization spec (revision 2026-07-28) describes HTTP servers as OAuth 2.1 resource servers. Clients discover an authorization server, register (CIMD, pre-registration or DCR) and obtain an audience-bound access token. Authorization is **optional** in MCP. We follow the resource-server half and deliberately do not use the OAuth flow for the agent's credential:
  - **kept:**
    - the server publishes Protected Resource Metadata (RFC 9728);
    - it answers `401` with `WWW-Authenticate: Bearer … resource_metadata=…`;
    - it takes the credential only from the `Authorization: Bearer` header, never a URL;
    - it accepts only its own credential and never passes any token on;
  - **not used:** Entra (or anyone) as the authorization server for the agent's token. The bearer value is a **Cloud Locksmith session capability**, issued from `/ui` after the human's Entra sign-in (SD-029). The client presents it through a header helper (Claude Code `headersHelper`), or through the stdio shim (fallback) for clients without one.
- **Why:**
  1. Entra supports neither Client ID Metadata Documents nor Dynamic Client Registration. Every client would need a pre-registered client id in each customer tenant.
  2. MCP clients MUST send the RFC 8707 `resource` parameter, which Entra's v2.0 endpoint does not document. Client behaviour against Entra varies, and at least one failure has been reported.
  3. An Entra token identifies the human, not the **session**: the profile, tenant binding, TTL and revocation that we need anyway. The capability carries exactly those, resolved server-side.
  4. The maintainer's decision: no authorization server of our own without a separate SD entry and explicit approval. The capability has no `/authorize`, `/token` or client registration. It is the run-token pattern (SD-032) for a human-started session.
- **Decision:**
  - **Capability:** 256 random bits, shown once and stored only as SHA-256.
  - **Binding:** server-side to session → tenant, human `oid`, profile and the profile's digest.
  - **Lifetime:** default TTL **1 h**, maximum 8 h, no refresh. A new session needs a new sign-in.
  - **Revocation:** revocable from the web app by the person who started it or a security lead; signing out ends the person's own sessions (SD-055).
  - **Refusal:** if unknown, expired, revoked, if the profile has changed, if the tenant is disabled, or if the person who started it is no longer a member whose role may use the profile (SD-055).
  - **Correction (security review, 2026-10-31):** the browser-session denylist (SD-011) is **not** consulted on the agent path, and Redis is not involved; an earlier version of this entry said both. Sign-out ending the sessions replaces the denylist link.
  - **Containment:** never logged, never in a URL, never in an audit record (only its session id).
- **Threat addressed:**
  - long-lived agent credentials;
  - a client choosing its own tenant or profile;
  - the agent ever holding a Graph or Entra token;
  - fragile client/Entra OAuth interop.
- **Risk accepted:** the capability is a **bearer** token. Anyone who copies it from the client machine (config, helper output, process memory) can use it until it expires or is revoked, within that session's profile. Mitigations: the short TTL, revocation, the profile ceiling, and the audit of every use. Sender-constraining (DPoP or mTLS) is a later option.
- **Tests required in B:** a revoked, expired, cross-tenant or profile-changed capability; a capability in the query string; reuse after the session ends; a wrong `Authorization` scheme; and no capability in logs or audit records. All refused, and audited where a session is known. Plus the mutation check.
- **Revisit** if Entra adds CIMD or DCR and accepts `resource`, or if customers require their IdP's tokens: that would need its own SD entry.

## SD-052: The MCP endpoint is a separate, credential-less gateway service

- **Status:** decided (v0.1 plan, approved 2026-10-30; the B plan's open decision 2). Built in stages: the scaffold first, then authentication and tools.
- **Decision:** the MCP endpoint AI agents connect to runs in its own container, `mcp-gateway` (`src/clw/mcp_gateway/`), not in the api or the broker.
  - **It holds nothing worth stealing:** no Graph or Entra credential, no database access, no session secret, no volumes. Its environment is the broker's URL and its own public URL only.
  - **It decides nothing:** each tool call becomes named operations on the broker, presented with the agent's session capability (SD-048). The broker resolves the session, applies the profile and audits. The gateway keeps no state between requests.
  - **Networks:**
    - `mcpnet` (internal) is shared with the broker only;
    - `mcpfront` carries the gateway's port, published on 127.0.0.1, and no other service joins it.
- **Why:**
  - The MCP surface is the one most exposed to untrusted input: the agent, and through it, prompt-injected tenant data. Keeping it out of the process that holds sessions, the database and Graph credentials means a parsing or SDK bug there doesn't reach them.
  - The MCP SDK is a large new dependency. Isolating it limits what its bugs can reach.
  - It mirrors the facade proxy (SD-041), which already follows this pattern.
- **Risk accepted:**
  - Docker publishes ports only from non-internal networks, so `mcpfront` gives the gateway outbound internet access. It holds no credential to use there.
  - Each tool call costs one extra hop.
- **Tests:**
  - `tests/unit/test_compose_topology.py`: the gateway's networks, environment, volumes, hardening, loopback port and image contents;
  - `tests/unit/test_mcp_gateway.py`: no imports of the database, broker, auth, audit or msal modules; no Graph host; the broker URL is validated.

## SD-049: Agent sessions are runs, started and ended only through agent-session functions

- **Status:** decided (v0.1 plan, approved 2026-10-30, with the maintainer's change: no general "end a run" right for the api). Built: migration `20261104_agent_sessions`, `src/clw/api/routes/agent_sessions.py`, `resolve_run(kind=...)`.
- **Decision:** an AI agent's session (SD-048) is a row in `runs` of kind `agent_session`. It reuses:
  - the run's binding to tenant, actor, manifest digest and profile digest;
  - capability resolution (SD-032), so a profile changed after the session started is refused (`manifest_changed`);
  - the audit chain's run state machine, so nothing is recorded after the session ends;
  - the reconciler, which ends an expired session as `timed_out / session_expired`.
- **Starting a session requires:**
  - **a verified human:** the browser session cookie from Entra sign-in (SD-029). A capability or `Authorization` header can't start a session;
  - **an explicit profile:** chosen from the agent-profile catalog (`agent_profiles/`), never defaulted or chosen by the agent;
  - **a TTL** of 1 minute to 8 hours (default 60 minutes), enforced by the API and again by the database.

  The tenant and actor come from the browser session only.
- **Write-ahead audit:** the capability is returned only after the row, RUN_REQUESTED and RUN_STARTED are all written. If either record fails, the row rolls back and the capability is discarded unseen. **Correction (security review, 2026-10-31):** these are not one transaction (the audit writer commits each record itself), so RUN_REQUESTED can be in the chain for a session that never started. No capability exists for it.
- **The api's database rights (the maintainer's decision):** the api gets **no** new INSERT columns and **no** UPDATE on `runs`. It gets EXECUTE on two `SECURITY DEFINER` functions only:
  - `clw_start_agent_session(...)` inserts a running `agent_session` row with the capability's hash and `deadline = now() + ttl`, and can insert nothing else;
  - `clw_end_agent_session(run_id, tenant_id, status, outcome)` ends only a **running agent session of that tenant**. It accepts only `completed / revoked` or `failed / revoked_during_request`. For any other row (a task or script run, another tenant's session, an ended session) it changes nothing and returns false.

  Both functions have a fixed `search_path`, and `PUBLIC` has no EXECUTE on them. The broker and runner roles can't call them.
- **Revoking:**
  - **who:** the session's starter, or a security lead of the tenant. Another tenant gets 404;
  - **what is recorded:** RUN_COMPLETED / revoked. If a Graph request is still unanswered, the chain refuses a completion, so it's RUN_FAILED / revoked_during_request;
  - **if the end can't be recorded,** the token is revoked anyway (row only), the response says `"audited": false`, and an operator alert is logged.
- **Risk accepted:**
  - **A compromised api** can still start sessions for its tenants' members and end their *agent sessions* early. It cannot end, start, extend or hijack a task or script run, and it cannot set a token on any existing run.
  - **Commit ordering:** if the session's RUN_STARTED commits but the row's commit is lost, the chain shows a session that never existed as a row. Its capability was never shown, so nothing can use it.
- **Tests:**
  - `tests/db/test_agent_sessions_table.py`, run **as a role with the api's grants alone**: it can't UPDATE any run, can't insert a running run or a token, and can't end a running or queued task run (the row is unchanged). It also covers the TTL bounds, the token-hash format, membership, capability reuse, the two endings only, other tenants' sessions, and that only the api may call the functions.
  - `tests/db/test_agent_sessions_api.py`: sign-in required; profile required and nothing else settable; both records written before any capability exists; the binding to the signed-in human; the kind checks both ways; expiry; profile changed; revocation by the starter or a lead only; the capability dead after revocation; revoked during a request; the token revoked when the end can't be recorded; and the reconciler's `session_expired`.

## SD-053: The agent tools' reads: four new named operations, a registry-fixed `$expand`, and response filtering

- **Status:** decided (v0.1 plan; consent and the `$expand=principal` rule are the maintainer's, 2026-10-30). Built: `src/clw/broker/operations.py`, `policy.py`, `transport.py`, `service.py`.
- **Decision:** four executable reads, all GET, all paginated, under the profile `agent-read-only-investigation` (A-31 to A-33):

  | Operation | Request | Permission |
  |---|---|---|
  | `directory.list_role_definitions` | `/roleManagement/directory/roleDefinitions` | `RoleManagement.Read.Directory` |
  | `directory.list_role_assignments` | `/roleManagement/directory/roleAssignments?$expand=principal` | `RoleManagement.Read.Directory` |
  | `service_principals.list` | `/servicePrincipals?$select=…&$top=…` (≤ 100) | `Application.Read.All` |
  | `service_principals.list_app_role_assigned_to` | `/servicePrincipals/{GUID}/appRoleAssignedTo?$select=…` | `Application.Read.All` |

- **Registry-fixed query parameters:**
  - **Where they come from:** a registry entry may fix extra query parameters itself (`fixed_query`). A caller never supplies them; params models still forbid every unknown field.
  - **What is allowed:** the only fixed parameter allowed is `$expand`, with a plain value, once.
  - **Three independent checks:**
    - the policy's stage 2 captures the fixed parameters at import and requires the query to end with exactly them;
    - the transport refuses any query parameter other than `$select`, `$top` or that operation's own fixed one;
    - a `nextLink` must keep it (the existing rule: original parameters, unchanged, plus one `$skiptoken`).
- **Response filtering:**
  - **What is declared:** each new operation declares the properties its results may carry (`response_properties`), and for an expanded or embedded object, its own (`nested_properties`).
  - **What the broker does:** it drops everything else before returning, whatever Graph sent.
  - **Expanded role-assignment principals** keep exactly `id`, `displayName`, `userPrincipalName` and `@odata.type` (the maintainer's decision).
  - **Service principals** never return `keyCredentials` or `passwordCredentials`, and their `appRoles` keep `id`, `value`, `displayName` and `allowedMemberTypes`.
  - **The audit** records the request and item count as before. Filtering only narrows what is returned.
- **Scope, stated plainly:**
  - **application permissions only.** Delegated consent grants would need `Directory.Read.All`;
  - **active role assignments only.** PIM-eligible assignments are a different API and need P2;
  - the app-permissions tool reports **Microsoft Graph application permissions** (the assignments on Microsoft Graph's service principal). Other resource APIs aren't covered in v0.1.
- **Not changed:** `users.list_with_sign_in_activity` declares no response properties. Its `$select` (required, allowlisted) bounds what Graph returns, as before. Applying a response filter to it too is a candidate hardening for after v0.1.
- **Tests:**
  - `tests/security/test_agent_reads.py`: callers can't add or widen parameters; GUID-only path ids; only `$expand=principal`, on role assignments only; the registry refuses other fixed parameters; a `nextLink` that drops or changes `$expand` is refused; principal and app-role filtering; stage 2 and the transport each refuse a forged query on their own.
  - `tests/db/test_broker_agent_ops.py`: through the whole broker path, a role assignment reaches the agent with only the four principal properties.
  - Six mutants, all killed.

## SD-054: Change proposals: refused, bound to the object ID, looked up by the broker, filed, never executed

- **Status:** decided (v0.1 plan; the lookup's conditions are the maintainer's, 2026-10-30). Built: `src/clw/broker/proposals.py`, `BrokerService.handle_agent_proposal` (`POST /v1/agent/propose`), migration `20261105_change_proposals`, and the gateway tool `entra_disable_user`.
- **Decision:** an agent may ask for one kind of change in v0.1: disable a user. The broker:
  1. **refuses the write and records the binding first** (write-ahead): `OP_DECISION` denied, `users.update`, `write_not_executable`, with `details = {proposal_id, request_sha256}`. The hash is SHA-256 of the canonical request `{method: PATCH, path: /v1.0/users/{id}, body: {accountEnabled: false}}`;
  2. **looks up the target itself** with `users.get_identity`, a GET of that one user;
  3. **files the proposal** in `change_proposals`, which is immutable and accepts only a running agent session of the same tenant (database guard). It answers the agent: `executed: false`, the proposal ID, the effect and the snapshot.
- **The lookup (the maintainer's conditions):**
  - **Who can trigger it:** it runs only inside the proposal flow, for the proposal's own target. It's not an agent tool.
  - **No manifest may list it** (the loader refuses `internal_only` operations), so a task or agent calling it gets `not_in_manifest`.
  - **What it reads:** its `$select` (`accountEnabled,displayName,id,userPrincipalName`) is fixed by the registry, and a caller can set nothing.
  - **Same checks as everything else:** it runs through the normal path. Policy stages 1 and 2 apply under the session's profile, narrowed to this one operation; then write-ahead `OP_DECISION`, credential, `GRAPH_REQUEST` and `GRAPH_RESPONSE`.
  - **What comes back:** the transport accepts a single object for it only, never a collection or a continuation. The broker returns only the snapshot properties and the object's type.
- **Binding versus display:** the proposal binds to `target_id` and `request_sha256`. `target_display_name`, `target_upn` and `target_account_enabled` are a **display snapshot** with `looked_up_at`. They aren't in the hash, and any later execution must re-read them (roadmap D).
- **Untrusted text:** the looked-up display name is tenant data, and the agent's reason is agent text. Both are stored as plain text and shown escaped and labelled (V7), with the UPN and object ID alongside.
- **Not found or not a user:** Graph's 404 for `GET /users/{id}` (a missing ID, or a group's or app's ID), or a returned object that isn't a user, gives `lookup_status = not_found`. There's no snapshot, the proposal carries a clear warning and the raw ID, and **the session continues**: the 404 is recorded, and only `not_found` is tolerated. Any other lookup failure ends the session FAILED as usual, and no proposal row is written. The chain still names the proposal ID, with no row.
- **What the agent is told:** that nothing was executed or changed, the proposal ID, the effect (operation, object type, count, object IDs, change), and the snapshot or the warning.
- **Risk accepted:**
  - every agent session may file proposals, whatever its profile. They're inert;
  - each proposal costs one Graph read under the session's credential.
- **Transport hardening made here:** caller query parameters are now only those the operation's params model declares, and every registry-fixed parameter must be present, exactly. A GET of `/users/{id}` without the fixed `$select` is refused by the transport itself.
- **Tests:**
  - `tests/security/test_identity_lookup.py`;
  - `tests/db/test_change_proposals_table.py`, run as the provisioned roles: only the broker files; nobody, even the owner, changes a row; a running agent session of the same tenant only; the snapshot is present exactly when found;
  - `tests/db/test_broker_proposals.py`: found, missing, not a user, an approval-bait name stored as data, malformed proposals, the agent unable to call the lookup, a task token, a revoked session, and a failed lookup;
  - `tests/unit/test_mcp_gateway_directory_tools.py`.
  - Ten new mutants, all killed (four for the lookup, six for proposals).

## SD-051: Demo mode: the quick start's fictional tenant, impossible to point at anything real

- **Status:** decided (v0.1 plan, with the maintainer's hardening rules, 2026-10-30). Built: `src/clw/demo/`, `src/clw/api/ui/demo_signin.py`, `quickstart/compose.yml`, `docker/quickstart.Dockerfile`.
- **Decision:** the quick start runs the real stack against a fake Microsoft Graph serving a fictional tenant (`clw.demo.fake_graph`, shared with the e2e tests). A person signs in through a demo sign-in. Demo mode must be impossible to use with anything real:
  - **The api** refuses to start in demo mode (`CLW_DEMO_MODE=true`) when `ENVIRONMENT=production`, or when any real Entra sign-in setting is set (`MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `OIDC_REDIRECT_URI`). The check is `clw.demo.check_api`, run in `create_production_app` before the app exists.
  - **The demo sign-in route** exists only in demo mode; otherwise it returns 404. It needs a same-origin form, and signs in only the reserved fictional tenant's registered person, never anything named by the request.
  - **Every page** shows a DEMO MODE banner while the app runs in demo mode.
  - **The demo broker** (`clw.demo.broker`) refuses to start when `ENVIRONMENT=production` or when any `CLW_PROFILE_*` credential is in its environment. Its profile credentials are synthetic and held in memory. Its identity provider is a fake that issues **unsigned** tokens, which the real token validation then checks, and which Microsoft would refuse anyway.
  - **Fake Graph only, three ways:**
    - **The tenant guard, both directions:** the demo broker serves only the reserved fictional tenant (`d3e0d3e0-…-0001`), and **every normal broker refuses that tenant** (`MsalCertificateProvider(demo=False)` gives `tenant_not_allowed`). The demo broker refuses every other tenant.
    - **TLS trust:** the demo broker trusts only the quick start's own CA for TLS.
    - **The network:** inside the quick start, `graph.microsoft.com` is the fake Graph's network alias on an internal network.
- **The quick start's topology:**
  - every shared network is internal;
  - only the api and the MCP gateway publish ports, and only on 127.0.0.1;
  - the broker, api and gateway run read-only, with no capabilities and `no-new-privileges`;
  - one image serves setup, the fake Graph, the broker and the api (one dependency install), while the gateway keeps its own credential-free image;
  - `tests/unit/test_quickstart_compose.py` pins all of this.
- **Risk accepted:**
  - **The quick start's database password** is a fixed throwaway, inside a network with no published port.
  - **Database roles:** the quick start's services use the database owner, not the per-component roles of a deployment (SD-038).
  - **Session secret:** generated once per quick start volume.

  None of these is a deployment pattern, and demo mode refuses production.
- **Tests:**
  - `tests/unit/test_demo_mode.py`: every refusal rule, the tenant guard both ways, the per-profile fake permissions, and the trust-only-the-demo-CA client;
  - `tests/db/test_demo_signin.py`: no route and no banner outside demo mode; only the fictional person signed in; cross-site refused; nothing when not set up; the banner on every page;
  - `tests/unit/test_quickstart_compose.py`.
  - Measured: a cold build plus start took 56 s on the maintainer's machine with the base images cached. The quick start was driven end to end by the MCP SDK client and by Claude Code 2.1.312 (2026-10-31).

## SD-055: Who may start an agent session, with how recent a sign-in, and what keeps it alive

- **Status:** decided (decisions A and B, 2026-10-31, after the pre-release security and docs reviews). Built.
- **Problem:**
  - **Any member could start any session.** A workbench member with no Entra admin role could start a session that reads the whole tenant through the broker's app identity. The docs review called this a confused deputy.
  - **The cookie was the only check.** Session start relied on an 8-hour browser cookie, so an agent able to drive the person's browser could mint its own sessions (security review F1).
  - **Sessions ignored offboarding.** A live session didn't follow tenant disablement or role changes, and signing out didn't end it, although SD-048 said it would (F2).
- **Decision:**
  - **A profile names who may start it** (`start_roles` in the agent profile):
    - `read-only-investigation` reads the role map and every app's permissions: security leads only;
    - `dormant-accounts` reads users' sign-in activity only: analysts and security leads.

    The API refuses anyone else (`role_not_allowed`), and the sessions page offers only what you may start.
  - **A recent, interactive sign-in:**
    - every Microsoft sign-in asks for `prompt=login`, so it is never a silent single sign-on;
    - starting an agent session needs a workbench sign-in from the last **10 minutes** (`FRESH_SIGN_IN_SECONDS`), from the session token's own issue time. The page asks you to sign in again when it's older;
    - the sign-in time is recorded in the session's RUN_STARTED (`details.signed_in_at`).
  - **A live session follows the tenant and the starter, on every use:**
    - `resolve_run` refuses an agent session whose tenant is no longer active (`tenant_disabled`), or whose starter is no longer a member whose current role may start its profile (`actor_not_allowed`);
    - `clw_start_agent_session` refuses a disabled tenant itself (migration `20261107_session_tenant_active`);
    - signing out (`/auth/logout`, `/ui/signout`) ends the person's own running agent sessions, recorded as RUN_COMPLETED / revoked.
- **Not done (stated):**
  - The browser-session denylist (SD-011) is still not consulted on the agent path: sign-out ends the sessions instead.
  - Entra's own `auth_time` isn't checked. Freshness rests on `prompt=login` plus the workbench session's issue time (A-34).
  - An agent that drives the browser *within* those 10 minutes, after the person has just signed in, can still start a session. The capability is still shown on the page that answers.
- **Tests:**
  - `tests/db/test_agent_sessions_api.py`: role gating, sign-in age, tenant disablement, demotion, sign-out;
  - `tests/db/test_agent_sessions_table.py::test_a_disabled_tenant_cannot_start_a_session`;
  - `tests/db/test_agent_ui_pages.py`: the profiles offered, stale sign-in, sign-out from the page;
  - `tests/security/test_signin.py` (`prompt=login`);
  - eight mutants, all killed.
