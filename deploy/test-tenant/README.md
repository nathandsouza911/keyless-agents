# Use Cloud Locksmith on your test tenant: the read-only app registration

**Use a test tenant, never a production one.** Cloud Locksmith v0.1 is beta software. Any tenant with only test accounts is the right place. The [Microsoft 365 Developer Program](https://learn.microsoft.com/office/developer-program/microsoft-365-developer-program) can give you one, but Microsoft limits who qualifies.

This creates the agent's app registration only. To run the whole stack against the tenant, follow [docs/test-tenant-guide.md](../../docs/test-tenant-guide.md).

## What `setup.ps1` changes in the tenant

Exactly this, and nothing else:
- **One app registration,** `Cloud Locksmith (agent-read-only-investigation)`. It is single-tenant, with no redirect URI and no client secret.
- **One certificate credential on it.** The certificate is created on your machine, and its private key never leaves it.
- **Its service principal.**
- **A request for these Microsoft Graph application permissions**, which you grant yourself on Microsoft's admin-consent page:

| Permission | Lets the app read | Used by |
|---|---|---|
| `User.Read.All` | users' profiles | dormant accounts; the proposal lookup |
| `AuditLog.Read.All` | all audit logs: the directory audit log, sign-in logs (IP addresses, locations, devices) and users' sign-in activity | dormant accounts (only sign-in activity is read) |
| `RoleManagement.Read.Directory` | directory roles and their assignments, including PIM settings | admin role holders |
| `Application.Read.All` | app registrations and service principals, including which permissions they hold | app permissions |

All four are read-only. None can create, change, disable or delete anything. Together, though, they show who the admins are, which apps can do what and how people sign in: what an attacker maps first. If the certificate leaked, someone could read all of it, so treat the key like a password. More in [docs/permissions.md](../../docs/permissions.md).

**Licence:** the dormant-accounts tool needs Microsoft Entra ID P1 (or P2) in the tenant. The other tools work on Entra ID Free.

**What it doesn't cover:** delegated consent grants (reading them would need `Directory.Read.All`), and PIM-eligible role assignments, which v0.1 doesn't query. The tools say so in every answer.

`-AppProfile dormant-accounts` requests only `User.Read.All` and `AuditLog.Read.All`.

## Run it

You need:
- PowerShell 7.4+ with two Microsoft Graph PowerShell modules: `Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Applications -Scope CurrentUser`.
- In the test tenant, **Application Developer** or higher to create the app, and **Privileged Role Administrator** or **Global Administrator** to grant consent.

```powershell
./deploy/test-tenant/setup.ps1 -TenantId <test-tenant-id> -WhatIf   # shows everything, connects to nothing
./deploy/test-tenant/setup.ps1 -TenantId <test-tenant-id>
```

1. **Confirm the tenant:** type the tenant ID again. The script can't tell a test tenant from a production one; this step is you checking it.
2. **Sign in:** Microsoft Graph PowerShell asks for one scope, `Application.ReadWrite.All` (to create the app). If it's the first time Graph PowerShell is used in the tenant, this adds its own consent, which uninstall leaves in place.
3. **Grant consent:** open the Entra admin center link it prints. Check that the app's **API permissions** list exactly the four permissions above, then select **Grant admin consent**. The page shows their display names ("Read all users' full profiles" and so on), not the names in the table.
4. **Set the environment:** copy the two `CLW_PROFILE_AGENTRO_*` lines it prints into your deployment's `.env`, never into a repository. The private key stays in `secrets/profiles/`, where the broker reads it.

The certificate expires after 90 days. Replace it before then with `./deploy/test-tenant/rotate.ps1 -TenantId <test-tenant-id>`.

## Undo it

```powershell
./deploy/test-tenant/uninstall.ps1 -TenantId <test-tenant-id>
```

It deletes only the app registration `setup.ps1` recorded, and only after checking that its ID and name still match. Its service principal and the admin consent go with it. It then deletes the local key, certificate and state file.

What stays behind:
- **Tokens already issued** stay valid until they expire, about an hour.
- **The deleted app** can be restored for 30 days (**App registrations → Deleted applications**).
- **Microsoft Graph PowerShell's own consent**, if setup added it.
- **The sign-in app,** if you made one for the full stack. Delete it yourself.
