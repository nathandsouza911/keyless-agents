# Runbook: connecting the dev tenant (Task 17C)

**Purpose:** connect one Microsoft Entra test tenant to a local workbench, with credentials the tenant owns and can revoke. Test accounts only, never real people.

**Credential topology (maintainer decision, 2026-10-24):** both app registrations live **inside the tenant being investigated**. Nothing is registered in a vendor tenant. Revoking access means deleting these two registrations in that tenant (an app registration can't be disabled).

| Registration | Used by | Credential | Permissions |
|---|---|---|---|
| `CLW Sign-in` | api (analyst sign-in, SD-029) | client secret | delegated `openid`, `profile` only |
| `CLW directory-read-auditlog-read` | broker (profile, SD-004) | certificate | **application** `User.Read.All`, `AuditLog.Read.All`, nothing else |

Where each value goes: `.env` (git- and Docker-ignored; names in `.env.example`). The private key goes in `secrets/profiles/` (also ignored). Tenant IDs and object IDs are not secrets; the client secret and the private key are.

## 1. Record the tenant

Entra admin center → **Overview**: copy the **Tenant ID** into `CLW_DEV_TENANT_ID`.

## 2. Sign-in app (`CLW Sign-in`)

1. **App registrations → New registration.**
   - Name: `CLW Sign-in`.
   - Supported account types: **Accounts in this organizational directory only (single tenant)**. Sign-in starts at the `/organizations` endpoint (`src/clw/auth/signin.py`); a single-tenant app works there for this tenant's own users, and Microsoft refuses users from any other tenant itself (AADSTS650059; A-26, verified 2026-10-27). Sign-in still also requires a registered tenant and a `workbench_users` membership. (Multitenant also works, but admits other tenants' users as far as the workbench's own checks.)
   - Redirect URI: platform **Web**, `http://localhost:8000/auth/microsoft/callback`.
2. **Certificates & secrets → New client secret.** Short expiry (for example 90 days). Copy the **Value** (not the Secret ID) into `MICROSOFT_CLIENT_SECRET`.
3. **Overview:** copy the **Application (client) ID** into `MICROSOFT_CLIENT_ID`.
4. **API permissions:** leave only the delegated `openid` and `profile` permissions; remove `User.Read`. Then **Grant admin consent**.
5. **Authentication:** no implicit grant (leave the access-token and ID-token checkboxes off); the api uses the authorization code flow with PKCE.

## 3. Profile app (`CLW directory-read-auditlog-read`)

1. Generate the key pair locally (Git Bash; `MSYS_NO_PATHCONV` stops Git Bash rewriting `/CN=`):

   ```bash
   mkdir -p secrets/profiles
   MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 180 \
     -subj "/CN=clw-directory-read-auditlog-read" \
     -keyout secrets/profiles/directory-read-auditlog-read.pem \
     -out secrets/profiles/directory-read-auditlog-read.cer.pem
   openssl x509 -in secrets/profiles/directory-read-auditlog-read.cer.pem -noout -fingerprint -sha1 | sed 's/.*=//; s/://g'
   ```

   The last line prints the 40-hex-digit SHA-1 thumbprint the broker expects (A-10: this form is deprecated but supported; migrating is a later decision). The `.pem` file is the **private key**. Only the `.cer.pem` file is uploaded.
2. **App registrations → New registration.**
   - Name: `CLW directory-read-auditlog-read`.
   - Supported account types: **Accounts in this organizational directory only**.
   - No redirect URI.
3. **Certificates & secrets → Certificates → Upload certificate:** `directory-read-auditlog-read.cer.pem`. The thumbprint the portal shows must equal the one printed above. Put it in `CLW_PROFILE_DIRREAD_CERT_THUMBPRINT`. Create **no** client secret.
4. **Overview:** copy the **Application (client) ID** into `CLW_PROFILE_DIRREAD_CLIENT_ID`.
5. **API permissions:**
   - Remove the default delegated `User.Read`.
   - **Add a permission → Microsoft Graph → Application permissions:** `User.Read.All` and `AuditLog.Read.All`.
   - **Grant admin consent for <tenant>**.

   The broker refuses any token whose roles are not exactly these two (`permissions_extra` / `permissions_missing`), so adding anything else breaks runs by design.

## 3b. Agent profile app (`CLW agent-read-only-investigation`; v0.1, owner-approved 2026-10-30)

The MCP tools' profile. It's a **separate** registration: adding permissions to the app in section 3 would break the dormant-accounts task, since the broker checks the exact permission set.

**What this changes in the tenant:** one new app registration, its service principal, and admin consent for four **read-only** application permissions. No user, group, role or existing app is changed. None of these permissions can create, change, disable or delete anything.

1. Generate the key pair locally (Git Bash):

   ```bash
   mkdir -p secrets/profiles
   MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 90      -subj "/CN=clw-agent-read-only-investigation"      -keyout secrets/profiles/agent-read-only-investigation.pem      -out secrets/profiles/agent-read-only-investigation.cer.pem
   openssl x509 -in secrets/profiles/agent-read-only-investigation.cer.pem -noout -fingerprint -sha1 | sed 's/.*=//; s/://g'
   ```

   The `.pem` file is the private key: it never leaves `secrets/profiles/`. Only the `.cer.pem` is uploaded.
2. **App registrations → New registration.**
   - Name: `CLW agent-read-only-investigation`.
   - Supported account types: **Accounts in this organizational directory only**.
   - No redirect URI.
3. **Certificates & secrets → Certificates → Upload certificate:** `agent-read-only-investigation.cer.pem`. Check that the portal's thumbprint equals the one printed above, and put it in `CLW_PROFILE_AGENTRO_CERT_THUMBPRINT`. Create **no** client secret.
4. **Overview:** copy the **Application (client) ID** into `CLW_PROFILE_AGENTRO_CLIENT_ID`.
5. **API permissions:**
   - Remove the default delegated `User.Read`.
   - **Add a permission → Microsoft Graph → Application permissions**, exactly these four:
     - `User.Read.All`;
     - `AuditLog.Read.All`;
     - `RoleManagement.Read.Directory`;
     - `Application.Read.All`.
   - **Not** `Directory.Read.All`, and no delegated permissions.
   - **Grant admin consent for <tenant>**. Check that each of the four shows "Granted".

   The broker refuses any token whose roles aren't exactly these four.
6. **Check:** **Enterprise applications → CLW agent-read-only-investigation → Permissions** lists exactly those four, as Application, admin-consented.

**To revoke:** delete the app registration (App registrations → the app → Delete). That removes its service principal and the consent with it. Then delete `secrets/profiles/agent-read-only-investigation.*` and the three `CLW_PROFILE_AGENTRO_*` values from `.env`.

**What the tools cover** (A-31, A-32):
- application permissions only, not delegated consent grants (those would need `Directory.Read.All`);
- active role assignments only, not PIM-eligible ones.

## 4. Session secret

```bash
uv run python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the output in `SESSION_JWT_SECRET`.

## 5. Test accounts

Create them in **Users → New user**: ordinary members, no admin roles, no real names. The dev-tenant tests use these three by object ID (`.env`), and each test skips while its ID is unset:

| Account | Properties | `.env` | What it shows |
|---|---|---|---|
| `clw-test-active` | member, enabled; sign in once | `CLW_DEV_TEST_ACTIVE_ID` | classified `active` (sign-in times can lag up to 24 hours, A-18) |
| `clw-test-never` | member, enabled; **never** sign in | `CLW_DEV_TEST_NEVER_ID` | `signInActivity` null or absent for a never-used account (A-17) |
| `clw-test-disabled` | member; **Block sign-in: Yes** | `CLW_DEV_TEST_DISABLED_ID` | `accountEnabled: false`, classified `disabled` |

Also keep the account you sign into the workbench with, separate from the tenant's global admin.

**Expected in a new tenant:** the task's minimum threshold is 30 days, and an account younger than the threshold is `too_new_to_judge` (`classify.py`). So for the first 30 days no new account can be `dormant` or `never_signed_in`. The never-signed-in test therefore checks Graph's data shape, not the classification.

**If the tenant holds real people:** the user list always returns every user. The tests reduce Graph data to scalars before asserting and redact every stored result when they finish (SD-037). Redact any manual run's result the same way (`docs/runbooks/result-redaction.md`).

## 6. Register the tenant and the analyst (operator)

With the owner's `DATABASE_URL`:

```bash
uv run python -m clw.cli tenant-add --tenant <tenant-id> --name "Dev tenant"
uv run python -m clw.cli member-add --tenant <tenant-id> --oid <analyst-object-id> --role analyst
```

Both are idempotent and never change an existing row.

## 7. Run the stack (least-privileged roles)

1. Set `CLW_API_DATABASE_URL`, `CLW_BROKER_DATABASE_URL` and `CLW_RUNNER_DATABASE_URL` in `.env` (users `clw_api`, `clw_broker`, `clw_runner`, each with its own long random password).
2. Create the roles, with exactly the grants in `src/clw/db/roles.py` (SD-038). Use the owner's `DATABASE_URL` and those three URLs in the environment:

   ```bash
   uv run python -m clw.cli db-provision-roles
   ```

   Re-run it after changing a password; it also removes any privilege added by hand.
3. Build and start the stack:

   ```bash
   docker compose --profile app --profile build-only build
   docker compose --profile app up -d
   ```

   The api is on `http://localhost:8000` (`ENVIRONMENT=development`: local http only, never a real deployment).

## 8. Dev-tenant tests

```bash
CLW_RUN_TENANT_TESTS=1 uv run pytest -m tenant -rs
```

They need Postgres (`docker compose up -d postgres`) and the values above in `.env`. Without `CLW_RUN_TENANT_TESTS=1` they skip; CI never runs them.

**Identity leaks.** The tenant may contain real people, whose identities may only ever sit in a run's result (and those are redacted). `test_no_tenant_identity_leaks` checks logs, test output, the audit chain and every tracked file. After any full-stack run, also scan the container logs, before `docker compose down` removes them:

```bash
CLW_RUN_TENANT_TESTS=1 CLW_SCAN_COMPOSE_LOGS=1 uv run pytest -m tenant -k compose_logs
```

A failure names the place and a count, never the identity.

**Manual: guest sign-in (A-24).** Invite a work account from another Entra tenant as a guest (**Users → Invite external user**) and accept the invitation. Then sign in as that guest at `http://localhost:8000/auth/microsoft/start`. Sign-in starts at `organizations`, so the guest authenticates in their home tenant and the ID token's `tid` is that home tenant. The expected result is **`access_denied`**: the home tenant isn't registered, or the guest isn't a member of it. Record what happened in `docs/assumptions-to-verify.md`.

## Licences

Without Entra ID P1/P2, `signInActivity` is unavailable (A-01, A-02). Before any licence is activated, a dormant-account run is expected to end `FAILED / licence_required`. That run is the real-tenant test for A-02: whether the 403 carries the error code the transport maps. If it ends `FAILED / forbidden` instead, the code differs and A-02 is contradicted. Token claims (A-06, A-08) and sign-in (A-11 to A-13) can be checked on the free tier as well.

## Revoking

Delete both app registrations in the tenant (tokens already issued stay valid for about an hour), delete `secrets/profiles/`, clear the values in `.env`, and set the tenant's row to `disabled`.
