# Changelog

## v0.1.0 (beta), unreleased

The first public release. AI agents work against Microsoft Entra through Cloud Locksmith, read-only, with inert change proposals.

- **MCP gateway:** streamable HTTP. Agents present a session capability (`Authorization: Bearer`); the gateway holds no credential.
- **Agent sessions:**
  - started by a signed-in person with an explicit profile and a lifetime of 1 minute to 8 hours;
  - revocable by the starter or a security lead;
  - expired sessions end on their own.
- **Tools:**
  - `entra_find_dormant_accounts`;
  - `entra_list_admin_role_holders` (active assignments only);
  - `entra_list_app_permissions` (Microsoft Graph application permissions only);
  - `entra_disable_user`, which files a proposal and never executes.
- **Change proposals:**
  - each is bound to the object ID and the canonical request by hash;
  - the target is looked up by Cloud Locksmith itself, as a labelled display snapshot;
  - shown in the proposal list with the Graph effect first.
- **Response filtering:** each operation declares the properties it may return. Expanded role-assignment principals keep only `id`, `displayName`, `userPrincipalName` and `@odata.type`.
- **The session audit trail:** a write-ahead, tamper-evident hash chain, with its validity shown on every session page.
- **Quick start:** a fictional tenant on a fake Microsoft Graph, in demo mode, which refuses production and any real credential.
- **Test-tenant setup:** a script to create the read-only app registration, with an uninstall.
