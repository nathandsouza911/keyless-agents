# Permissions: what Cloud Locksmith asks Microsoft for, and why

## v0.1: the agent profile's app

The agent tools use one app registration, `Cloud Locksmith (agent-read-only-investigation)`, created in your own tenant by `deploy/test-tenant/setup.ps1`. It has a certificate (no secret) and these Microsoft Graph **application** permissions:

| Permission | What Microsoft's consent page calls it | What it really allows | Used by |
|---|---|---|---|
| `User.Read.All` | Read all users' full profiles | every user's profile properties | dormant accounts; the proposal lookup |
| `AuditLog.Read.All` | Read all audit log data | the directory audit log, **sign-in logs** (IP addresses, locations, devices, client apps, Conditional Access results) and provisioning logs, plus users' `signInActivity` | dormant accounts (only `signInActivity` is read) |
| `RoleManagement.Read.Directory` | Read all directory RBAC settings | role definitions and assignments, including PIM schedules | admin role holders (active assignments only) |
| `Application.Read.All` | Read all applications | every app registration and service principal, their owners, credentials' metadata (never the secrets) and the permissions they hold | app permissions (Microsoft Graph application permissions only) |

**All four are read-only, and together they are a powerful reconnaissance set.** They show who the admins are, which apps can do what, and how people sign in: roughly what an attacker maps before an attack. Cloud Locksmith reads only the named operations, but **the certificate is a credential for all four**, at Microsoft, outside Cloud Locksmith. Keep the key where only the broker can read it.

**What the broker's exact-permission check does not see:**
- **What it checks:** every token's `roles` claim must be exactly these four, or the broker refuses it (SD-004).
- **What it misses:** rights given to the service principal any other way never appear in that claim:
  - an Entra **directory role** assigned to it;
  - **Exchange RBAC for Applications**;
  - **Azure RBAC**;
  - permissions to other APIs.

  **Don't assign the broker's service principal to directory roles,** and review it.

**Licence:** reading `signInActivity` needs **Microsoft Entra ID P1** (or P2) in the tenant. Without it, the dormant-accounts tool gets a refusal from Microsoft. The other tools need no licence beyond Entra ID Free.

**Who can grant consent:** granting Microsoft Graph application permissions needs the **Privileged Role Administrator** or **Global Administrator** role. Creating the app needs **Application Developer** or higher.

## The core's original task app

The sections below describe the app the core was first built with: one read-only task, **Dormant Account Investigation**. It needs two app registrations, both created **inside the customer's own tenant**, so the customer owns both credentials and can revoke them at any time (`docs/runbooks/dev-tenant-setup.md`).

## The two registrations

| | `CLW Sign-in` (api) | `CLW directory-read-auditlog-read` (broker) |
|---|---|---|
| Purpose | Analysts sign in to the workbench | The broker reads directory data for runs |
| Account types | This organizational directory only (recommended; A-26) | This organizational directory only |
| Credential | Client secret, short expiry | Certificate (private key mounted into the broker only) |
| Permissions | Delegated `openid`, `profile` only (remove the default `User.Read`) | **Application** `User.Read.All`, `AuditLog.Read.All`, and nothing else (remove the default `User.Read`) |
| Admin consent | Granted for the tenant | Required, granted for the tenant |
| Graph access | None | Read only |

## The broker's permission check

On every token it acquires, cached or not, the broker checks that the token's roles are **exactly** `User.Read.All` and `AuditLog.Read.All` (`src/clw/broker/credentials.py`). An extra permission (for example, an admin adding a write permission later) fails the run with `permissions_extra`. A missing one fails it with `permissions_missing`. This check confirms the credential is the expected one. It is not what authorizes an operation: the manifest and the policy do that, separately (SD-003, SD-004).

The broker can call exactly one Graph operation: `GET /v1.0/users` with `$select` from a fixed allowlist (`id`, `displayName`, `userPrincipalName`, `accountEnabled`, `createdDateTime`, `userType`, `signInActivity`) and an optional `$top` of 1 to 500. Every page is re-authorized and every `nextLink` is validated. The registered write operations (`users.update`, `users.delete`, `directory_roles.add_member`) cannot be executed in Phase 1; they exist only to be shown and prohibited.

**What the broker's restriction does not cover.** The certificate itself is a credential for those two application permissions. Anyone who obtains it can call whatever those permissions allow at Microsoft, outside Cloud Locksmith. The broker limits what Cloud Locksmith does with it, not what the credential is worth. What else these permissions allow has not been audited here; check Microsoft's permissions reference.

## Licence

Reading `signInActivity` needs **Microsoft Entra ID P1 or P2** in the tenant. Without it, Graph refuses the request, and the run ends `FAILED / licence_required` with no data.

## Script runs (Part B)

Bring-your-own scripts use the **same registration and the same two permissions**. No new permission was needed for the demo script: its `GET /beta/users` with `$count`, an advanced `$filter` on `assignedLicenses`, `ConsistencyLevel: Eventual` and `signInActivity` was read through the facade on the licensed dev tenant (A-30, 2026-10-26).

- **What a script can reach.** A script never holds the certificate or a Microsoft token. It holds only its run's capability, which works only through the facade (SD-041).
- **What the facade sends.** It sends a request to Graph only if the run's **approved** manifest allows it:
  - a GET, on a listed path and version;
  - with only the approved `$select`, `$filter`, `$top` and other options.

  Writes (POST, PATCH, PUT, DELETE, `$batch`) are refused before they leave the broker, and no write can be approved (SD-043).
- **What Graph would refuse anyway.** Even a request that got past all of that could not change anything: the app holds no write permission, and the broker refuses a token that carries more than these two (above).

## Evidence: documented and observed

Dates are when the behaviour was checked. "Live" means observed on a real tenant (two dev tenants, Entra ID Free and Entra ID P1/P2). Details are in `docs/assumptions-to-verify.md`.

| ID | Behaviour | Documentation (2026-10-20) | Live |
|---|---|---|---|
| A-01 | `signInActivity` on list users needs `User.Read.All` + `AuditLog.Read.All` (application) | verified | 2026-10-24: a token with exactly these two read the data |
| A-02 | Without P1/P2: HTTP 403 `Authentication_RequestFromNonPremiumTenantOrB2CTenant` | P1/P2 requirement documented; error code not | 2026-10-24: 403 with exactly this code |
| A-03 | `signInActivity` timestamps on v1.0 | verified | 2026-10-24: present |
| A-04 | `$top` at most 500 with `signInActivity` | verified (bound corrected to 500) | not exercised at the limit |
| A-06, A-07, A-08 | App-only token: `roles`, `idtyp=app`, no `scp`; v1 token with `appid`; `aud` is Graph | verified | 2026-10-24, both tenants: exactly this shape |
| A-09 | A new token reflects consent changes | partial | 2026-10-24: the first token after consent carried both roles; the delay after a *change* was not measured |
| A-14 | `nextLink`: the same request plus `$skiptoken` | verified | 2026-10-25: `$top=3` paged across several pages, each re-authorized |
| A-16 | `request-id` response header | verified | 2026-10-24: present |
| A-17 | A never-used account has no sign-in time | verified | 2026-10-25: the never-used test account has none |
| A-18 | Sign-in times lag (typically 6 h, up to 24 h) | verified | not measured |
| A-21 to A-23 | ID token signed RS256 by the tenant's keys; v2 issuer; `tid`, `oid`, `nonce` | partly documented | 2026-10-24: a member's sign-in passed the verifier unchanged |
| A-24 | A guest signs in with their home `tid` | unverified | pending (manual guest sign-in) |
| A-25 | Timestamp and `accountEnabled` shapes | unverified | 2026-10-24: 8 users, all in the expected forms |
| A-26 | A single-tenant sign-in app is refused at `organizations` | **refuted** (2026-10-27) | single tenant works for the tenant's own users; Microsoft refuses other tenants' users (AADSTS650059) before the workbench sees them |

**Not shown by the live runs:** they used `ENVIRONMENT=development` on a local machine, so `Secure` cookies, Redis fail-closed behaviour and an egress allowlist were not exercised. They show the permission footprint and the least-privileged roles, not a production configuration.

## Consent

1. **Profile app:** in the tenant, **App registrations → the app → API permissions → Grant admin consent**. Only an admin who may grant tenant-wide consent to application permissions can do this. Check which Entra role that needs against Microsoft's documentation.
2. **Sign-in app:** grant admin consent for `openid` and `profile`. Otherwise each user is asked to consent on first sign-in, if the tenant allows user consent at all.
3. **Changing permissions:** if anyone adds a permission to the profile app, every run fails `permissions_extra` until it is removed. This is by design.

## Revoking access

Delete both app registrations in the tenant (an app registration can't be disabled). The broker's next token request then fails, and every run fails with no data. A token already issued stays valid until it expires (typically about an hour), and a deleted app stays restorable for 30 days. On the workbench side: delete the certificate in `secrets/profiles/`, clear the values in `.env`, and set the tenant's row to `disabled` (new sign-ins are refused; an existing session lasts at most 8 hours).
