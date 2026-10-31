# Security overview for security leads

One page: what Cloud Locksmith v0.1 enforces, how, and what it doesn't cover. Everything here points to a test or a decision record. **Status: beta. Not for production.**

## The problem it addresses

People want AI agents to investigate, and eventually change, Microsoft Entra and Microsoft 365. Often that means handing an agent your own access, or an app's secret, with no limit beyond the permission scopes and no record of what it was refused.

## What v0.1 enforces, and the evidence

| Property | Enforced by | Evidence |
|---|---|---|
| Cloud Locksmith never gives the agent a Graph token, certificate or secret | It talks only to a credential-free gateway; only the broker holds the certificate | leak checks on every answer, the audit chain and every container's log (SD-048, SD-052). Credentials the agent finds elsewhere on its machine are out of scope |
| A session can do only what its profile allows | The broker's policy, per named operation; no tool takes a URL, tenant or profile | profile-refusal tests through the broker and the full stack (SD-049, SD-053) |
| Microsoft's token carries exactly the profile's permissions | The broker compares the token's roles with the profile's set: any extra or missing permission is refused | `broker.credentials` tests (SD-004); checked against a real tenant |
| Only declared fields leave the broker | Per-operation response filtering, including expanded objects | `tests/security/test_agent_reads.py` (SD-053) |
| No change is ever executed | No executable write operation exists; asking files an inert proposal | proposal tests: Graph receives only the lookup GET (SD-054) |
| Every Graph request and refusal is recorded first | Write-ahead audit: no record, no request | the fail-closed broker tests (SD-007, SD-014) |
| Tampering with the record is detectable | A hash chain, verified on each session page and by `clw audit-verify` | chain tests (SD-005, SD-006). *Tamper-evident, not tamper-proof:* someone with database write access can rewrite the whole chain consistently, and v0.1 keeps no copy off the host. Keep your own copy of the chain head if that matters |
| A session ends when you say, or when it expires | A capability stored only as a hash, cleared on revocation; the broker refuses it after its deadline | session and theft/replay tests (SD-048, SD-049) |

The security tests are themselves tested: `scripts/audit_mutation_check.py` breaks a set of chosen checks on purpose, and the suite must catch each break. That covers the listed mutants, not every possible fault.

## What it does not cover

- **The agent's own machine.** Other credentials there are out of reach of any guard. Run the agent where they don't exist.
- **A stolen session capability**, within its profile and lifetime.
- **The broker's own credential.** Keep its app read-only, and its key where only the broker can read it.
- **What the model provider sees** of tool results.
- **Rights outside the token's permissions.** The exact-permission check sees only Graph application permissions. An Entra directory role, Exchange RBAC or Azure RBAC given to the broker's service principal would add rights it can't see. Don't assign it any.
- **Coverage gaps:** active role assignments only (not PIM-eligible, and a group's members aren't expanded); application permissions only (not delegated grants); dormant accounts covers users only.
- **An agent misled within its profile.** Instructions in tenant data can't widen the profile; they can still influence what the agent says or asks for.

## Permissions it asks of your tenant

One app registration, with application permissions, all read-only:
- `User.Read.All`
- `AuditLog.Read.All` (all audit logs, including sign-in logs, though only sign-in activity is read)
- `RoleManagement.Read.Directory`
- `Application.Read.All`

Together they are a strong reconnaissance set: see [permissions.md](permissions.md). You grant consent yourself, and `deploy/test-tenant/uninstall.ps1` removes the app. Tokens already issued stay valid for about an hour after that. The dormant-accounts tool needs Entra ID P1.

## Where to read more

- [Threat model](threat-model.md)
- [Security decisions](security-decisions.md)
- [Assumptions about Microsoft, and which are verified](assumptions-to-verify.md)
