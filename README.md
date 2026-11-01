# Cloud Locksmith

> **Status: beta (v0.1). Not for production.** Try it on the fictional tenant in the quick start, or on a test tenant. Never on a production tenant.

**A note first:** this is a project by a student trying to break into identity and cloud security. I built it to learn, and to show what I can do. **Any and all criticism and recommendations are welcome**: on the design, the code, the security reasoning, the docs or the idea itself. Open an issue or a discussion. Blunt is fine.

**Let AI agents work in your Microsoft 365 tenant without giving them your keys.**

## How it got here

This started out as a simple PowerShell script analyser: point it at a Microsoft Graph script from GitHub, and it would tell you what the script would do to your tenant before you ran it.

When I showed it to working professionals, they didn't see a tool to help. They saw a sign of incompetence: if you need a tool to explain a script before you run it, you shouldn't be running it. That was fair, and it was useful to hear early.

So I looked for something that genuinely does need babysitting. **AI agents** do:
- **They're being given admin access** to Entra and Microsoft 365 now, often with the person's own login or an app secret.
- **They can be talked into things** by text they read, tenant data included.
- **Nobody keeps a record** of what they were refused.

The script work wasn't wasted. Its core became this project's core: named operations instead of raw Graph calls, a broker that holds the credentials, and an audit trail written before anything is sent.

## What it does

Cloud Locksmith sits between an AI agent (Claude Code, or any MCP client) and Microsoft Graph:
- **Cloud Locksmith never gives the agent a credential.** An agent connected to it never receives a Graph token, certificate or secret. Credentials it finds elsewhere on its own machine are another matter: see below.
- **The agent works inside a session** a person started, under a profile the person chose, which expires.
- **Cloud Locksmith enforces the profile,** not the agent or the model. A call outside the profile is refused before anything reaches Microsoft, the refusal is audited with its specific reason, and the agent is told it was refused and whether anything reached Microsoft.
- **Profiles limit the data, not just the calls.** Each operation returns only the fields its profile declares, down to nested objects; Cloud Locksmith drops everything else Graph sends before the agent sees it ([below](#data-scoping-which-fields-reach-the-agent)).
- **Changes are never executed.** An agent can ask for one, and the request is filed as a proposal for a person to see.
- **Everything goes into a hash-chained audit trail,** per session: every Graph request and every refusal. It's tamper-evident **only up to your last off-host checkpoint**: whoever controls the host or the database can rewrite everything after it ([how to checkpoint](docs/audit-checkpoints.md)).

## See it working in about 10 minutes

No Microsoft tenant, Azure account or credentials needed. A fake Microsoft Graph serves a fictional organisation inside Docker. You need Docker with Compose v2, and [Claude Code](https://docs.claude.com/en/docs/claude-code).

```sh
git clone https://github.com/nathandsouza911/keyless-agents.git && cd keyless-agents
docker compose -f quickstart/compose.yml up -d --build
```

Then:
1. Open <http://127.0.0.1:8080/ui>, sign in to the fictional demo tenant, and start a session.
2. Put the session's capability in `CLW_MCP_CAPABILITY`, then run `claude` in `quickstart/`.

The full walkthrough is in [`quickstart/README.md`](quickstart/README.md). It covers investigating, asking for a change, the tricks planted in the fictional data, the proposal list and the audit trail.

## What v0.1 does

| | |
|---|---|
| **Tools** | `entra_find_dormant_accounts`, `entra_list_admin_role_holders`, `entra_list_app_permissions` (read-only), and `entra_disable_user`, which only files a proposal |
| **Sessions** | Started by a signed-in person, who chooses a profile and a lifetime (1 minute to 8 hours). Revocable at any time. The agent presents a session capability; it never receives a Microsoft credential |
| **Profiles** | Name the operations a session may call. Each operation fixes its request and the properties it may return, and Cloud Locksmith drops everything else Graph sends |
| **Refusals** | Recorded in the session's audit trail with the specific reason. The agent gets only a short generic one ("Not permitted by this session's profile." or "This session is no longer valid."), and whether anything was sent to Microsoft, so probing tells it nothing about which check refused it |
| **Proposals** | A requested change is refused, bound to the exact object and request by hash, and filed for a person to see. The target's name comes from Cloud Locksmith's own lookup, never from the agent. **Nobody can approve or execute a proposal in v0.1** |
| **Audit** | Write-ahead and hash-chained: the record is written before the request is sent, and if it can't be written, nothing is sent. A changed or deleted record is detected when the chain is verified. **A consistent rewrite of the whole chain is not**, unless a signed checkpoint stored where the host and the DBA can't write still covers it. v0.1 doesn't schedule checkpoints or store them off-host for you: [docs/audit-checkpoints.md](docs/audit-checkpoints.md) shows how |

## Data scoping: which fields reach the agent

A profile doesn't only say *which operations* a session may call. Each operation also fixes **which fields it returns**, and Cloud Locksmith removes every other field from Graph's answer before it reaches the agent. That includes fields inside nested and expanded objects. For example:

| Operation | Fields the agent can see | Nested fields |
|---|---|---|
| `users.list_with_sign_in_activity` (dormant accounts) | `id`, `displayName`, `userPrincipalName`, `userType`, `accountEnabled`, `createdDateTime`, `signInActivity` | `signInActivity`: `lastSignInDateTime`, `lastSuccessfulSignInDateTime`, `lastNonInteractiveSignInDateTime` |
| `directory.list_role_assignments` (admin role holders) | `id`, `principalId`, `roleDefinitionId`, `directoryScopeId`, `principal` | `principal` (expanded): `id`, `displayName`, `userPrincipalName`, `@odata.type` |
| `service_principals.list_app_role_assigned_to` (app permissions) | `id`, `appRoleId`, `principalId`, `principalDisplayName`, `principalType`, `createdDateTime` | none |

So an agent investigating dormant accounts never sees a user's phone numbers, manager, licences or sign-in IP addresses. That holds even though the app's `User.Read.All` and `AuditLog.Read.All` permissions would let the broker read them. The request is fixed too: the `$select` is part of the operation, and the agent can't change it. The tests are in `tests/security/test_agent_reads.py` (SD-053).

## Identity and attribution

- **The credential:** the broker calls Graph with **application permissions** and a **certificate**, never a client secret. The certificate's private key stays with the broker. Neither the agent nor the MCP gateway ever holds it.
- **In Microsoft's logs, the caller is the broker's app,** not the person or the agent. In Microsoft Graph activity logs (if you collect them: they need Entra ID P1 and an Azure log destination), each request shows the broker's `AppId` and `ServicePrincipalId`, with `ClientAuthMethod` 2 (certificate).
- **Cloud Locksmith's audit adds who and why.** Every record carries its session's ID (`run_id`). The session's first record names the person who started it (their tenant and object ID); a later one records the profile, the lifetime and when they signed in. Each Graph response record keeps the `request-id` Microsoft returned, which Microsoft documents for correlating a request. We haven't yet confirmed it matches the `RequestId` in Graph activity logs (A-36).

One Graph response record, from the quick start's fictional tenant:

```json
{
  "seq": 6,
  "created_at": "2026-11-01T09:51:21.774111Z",
  "event_type": "GRAPH_RESPONSE",
  "status": "succeeded",
  "tenant_id": "d3e0d3e0-0000-4000-8000-000000000001",
  "run_id": "e14ee437-d7c5-4855-827f-4dac7ad7ae52",
  "operation": "users.list_with_sign_in_activity",
  "http_status": 200,
  "item_count": 2,
  "duration_ms": 84,
  "graph_request_id": "fake-page-0",
  "previous_hash": "7b1af721a56e9b6371865b2eb2a1e8bf71ff92753d3515c8070eadea094a4069",
  "record_hash": "95ec8571feccc2b8b6e8f6e2663eb8f22d5e6ad9d768ec116fd1a93f71d597b4"
}
```

- **On a real tenant,** `graph_request_id` is the GUID Microsoft returned. The fake Graph used here returns `fake-page-0`.
- **The same session's first record** (`seq` 1, `RUN_REQUESTED`) has `actor_tid` and `actor_oid`: the person.
- **The `GRAPH_REQUEST` record before this one** has the exact request sent, `/v1.0/users?$select=…`, written before it was sent.

## What v0.1 does not do

- **Execute changes.** Proposals are never executed. Approved changes are on the [roadmap](docs/roadmap.md), not in v0.1.
- **Cover everything in its area:**
  - app permissions covers Microsoft Graph **application** permissions only, not delegated consent grants or other APIs;
  - role holders covers **active** role assignments only, not PIM-eligible ones.

  The tools say so in every answer.
- **Generic Graph access.** There's no "call any Graph URL" tool; each tool is a named, fixed operation.
- **Other platforms and products:** Azure Resource Manager, multiple tenants per deployment, a hosted service, or a packaged Azure deployment.

## How it fits together

```mermaid
flowchart LR
    agent["AI agent<br/>(Claude Code, any MCP client)"] -- "MCP over HTTP<br/>Bearer: session capability" --> gateway["MCP gateway<br/>no credential, no database"]
    gateway -- "named operations" --> broker["Broker<br/>policy, credentials, audit"]
    broker -- "only approved, fixed requests" --> graph["Microsoft Graph"]
    person["Person (browser)"] -- "sign in, start or revoke a session,<br/>see proposals and the audit trail" --> api["Web app"]
    api --- db[("Postgres<br/>sessions, proposals, audit chain")]
    broker --- db
```

- **The gateway** holds nothing worth stealing. It asks the broker to vouch for the session capability on every request.
- **The broker** is the one component that holds the profile's certificate and talks to Microsoft. It checks every operation against the session's profile, checks that Microsoft's token carries exactly the profile's permissions, and writes the audit record before sending anything.

More detail: [`docs/architecture.md`](docs/architecture.md).

## What it does not protect against

Read the [threat model](docs/threat-model.md) before trusting it with anything. In short:
- **The agent's own machine.** If the agent has other credentials (an Azure CLI login, a token in a file, a browser session), Cloud Locksmith can't stop it using them. Run the agent where those don't exist.
- **The session capability is a bearer token.** Whoever copies it can use the session until it expires or is revoked, but only within its profile.
- **The broker's own credential is a powerful non-human identity.** Anyone who steals the broker's certificate can do everything its app registration's permissions allow. Keep the permissions read-only, as in this version, and the certificate where only the broker can read it.
- **The model provider sees the data.** The tool results go to whichever model the agent uses.
- **A misled agent.** Instructions hidden in tenant data can't make the agent exceed its profile, but they can still mislead it within the profile, for example into filing a proposal. Proposals are labelled, and never executed in v0.1.
- **A careless person.** When approvals arrive (roadmap), a person who approves without reading will approve a bad change. The proposal list shows the real Graph effect first for that reason.

## How this relates to Microsoft's own tools

Complementary, not competing. This describes Microsoft's products as their docs did in October 2026; check the links for the current state.
- **[Microsoft MCP Server for Enterprise](https://learn.microsoft.com/graph/mcp-server/overview)** (preview when checked, October 2026) gives agents read access to Entra directory data, as the signed-in user, limited by that user's roles and the MCP scopes an admin grants. If read-only investigation in your own name is all you need, it's free, and hosted by Microsoft.
- **Cloud Locksmith is for when you want:**
  - a session narrower than your own access, and one that expires;
  - refusals recorded as well as successes;
  - the agent's calls made with a read-only app's permissions, not your own login;
  - a path towards changes that run only after a person approves the exact change.
- **[Microsoft Entra Agent ID](https://learn.microsoft.com/entra/agent-id/identity-platform/what-is-agent-id)** gives agents their own identities and lifecycle. That decides *which* permissions an agent's identity holds. Cloud Locksmith decides, per request, *which calls within those permissions* are allowed. A future version could run as an Agent ID identity.

## Use it on your test tenant

[`deploy/test-tenant/`](deploy/test-tenant/README.md) creates the read-only app registration, after a test-tenant warning that lists the exact permissions it requests:
- `User.Read.All`
- `AuditLog.Read.All`
- `RoleManagement.Read.Directory`
- `Application.Read.All`

It has an uninstall. Together the four are a strong read-only set (who the admins are, which apps can do what, how people sign in), so read [`docs/permissions.md`](docs/permissions.md) first. The dormant-accounts tool needs Microsoft Entra ID P1.

To run the full stack against the tenant, follow [`docs/test-tenant-guide.md`](docs/test-tenant-guide.md).

## Documentation

- [Security overview](docs/security-overview.md): one page for security leads.
- [Architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [security decisions](docs/security-decisions.md) (every decision, its reason and its tests).
- [What we assume about Microsoft, and what we've verified](docs/assumptions-to-verify.md).
- [Testing](docs/testing.md), including the mutation check: it breaks chosen security checks on purpose and confirms the tests catch each one.

This repository also contains an earlier, frozen feature: bring-your-own PowerShell scripts in a sandbox (`src/clw/runner`, `task_pwsh/`). It isn't part of v0.1, isn't documented or supported here, and must not be used with third-party scripts without gVisor.

## Contributing, security and licence

- **Found a vulnerability?** Please report it privately: [SECURITY.md](SECURITY.md).
- **Contributions:** [CONTRIBUTING.md](CONTRIBUTING.md). Every security change comes with a test and a security-decision entry.
- **Tried it, or have an opinion?** Tell me in Discussions or an issue. As above, criticism is the most useful thing you can give this project.
- **Licence:** [Apache-2.0](LICENSE). No telemetry: Cloud Locksmith contacts nothing but Microsoft Entra (for its tokens and your sign-in) and Microsoft Graph (only what a profile allows).
