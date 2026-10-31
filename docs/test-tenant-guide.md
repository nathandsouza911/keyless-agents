# Run Cloud Locksmith on your test tenant

**Beta software: use a test tenant, never a production one.** This guide connects the full stack to a real Microsoft Entra tenant that holds only test accounts. It takes about an hour the first time. If you only want to see it working, the [quick start](../quickstart/README.md) needs no tenant at all.

## What you need

- **A test tenant** where you can create app registrations and grant admin consent:
  - **Granting consent** to Microsoft Graph application permissions needs the **Privileged Role Administrator** or **Global Administrator** role.
  - **Creating the apps** needs **Application Developer** or higher.
  - The [Microsoft 365 Developer Program](https://learn.microsoft.com/office/developer-program/microsoft-365-developer-program) can give you a sandbox tenant, but Microsoft limits who qualifies.
- **Microsoft Entra ID P1** (or P2) in the tenant for the dormant-accounts tool: Microsoft serves sign-in activity only with P1. The other tools work on Entra ID Free.
- **Software:**
  - Docker with Compose v2;
  - [uv](https://docs.astral.sh/uv/);
  - PowerShell 7.4+ with the `Microsoft.Graph.Authentication` and `Microsoft.Graph.Applications` modules;
  - Claude Code or another MCP client.

Values go in `.env` (copy `.env.example`; git-ignored). The private keys go in `secrets/profiles/` (also git-ignored). Tenant and object IDs are not secrets; the client secret and the private keys are.

## 1. The agent's app registration

Follow [`deploy/test-tenant/README.md`](../deploy/test-tenant/README.md). It creates `Cloud Locksmith (agent-read-only-investigation)` with a certificate and four read-only application permissions, and has an uninstall. Read [permissions.md](permissions.md) first: the four permissions together are a powerful read-only set.

## 2. The sign-in app registration

People sign in to the web app with Microsoft. This app has no Graph permissions.

1. **Entra admin center → App registrations → New registration.**
   - Name: `Cloud Locksmith sign-in`.
   - Supported account types: **this organizational directory only (single tenant)**.
   - Redirect URI: platform **Web**, `http://localhost:8000/auth/microsoft/callback`.
2. **Certificates & secrets → New client secret,** with a short expiry. Copy its **Value** into `MICROSOFT_CLIENT_SECRET`.
3. **Overview:** copy the **Application (client) ID** into `MICROSOFT_CLIENT_ID`.
4. **API permissions:** keep only the delegated `openid` and `profile` permissions (remove `User.Read`), then **Grant admin consent**.
5. **Authentication:** leave implicit grant off. The web app uses the authorization code flow with PKCE.

`setup.ps1` does not create this app, and `uninstall.ps1` does not remove it. Delete it yourself when you're done.

## 3. Secrets and database roles

1. **Session secret:** put the output of this command in `SESSION_JWT_SECRET`.

   ```sh
   uv run python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

2. **Database roles:** each component gets its own database role. Set `CLW_API_DATABASE_URL`, `CLW_BROKER_DATABASE_URL` and `CLW_RUNNER_DATABASE_URL` in `.env`, each with its own long random password (the format is in `.env.example`).
3. **Create the roles:** the commands on your machine read their settings from the shell, not from `.env`. In that shell, set:
   - `DATABASE_URL` to the database owner's URL, `postgresql+asyncpg://<POSTGRES_USER>:<POSTGRES_PASSWORD>@127.0.0.1:5433/<POSTGRES_DB>`;
   - the three role URLs from `.env`;
   - `SESSION_JWT_SECRET`.

   Then start Postgres, migrate it, and create the roles with exactly the grants in `src/clw/db/roles.py`:

   ```sh
   uv sync --python 3.11
   docker compose up -d postgres redis
   uv run alembic upgrade head
   uv run python -m clw.cli db-provision-roles
   ```

   Re-run `db-provision-roles` after changing a password. It also removes any privilege added by hand.

## 4. Register the tenant and its people

Cloud Locksmith never takes a tenant from a request. A tenant, and each person in it, must be registered first (in the same shell, as the database owner):

```sh
uv run python -m clw.cli tenant-add --tenant <tenant-id> --name "Test tenant"
uv run python -m clw.cli member-add --tenant <tenant-id> --oid <your-object-id> --role security_lead
```

- **`security_lead`** may start every profile.
- **`analyst`** may start only the profiles that name it (`start_roles` in `agent_profiles/*/manifest.yaml`).

Both commands are idempotent and never change an existing row.

## 5. Start the stack

**Use a fresh shell** that hasn't loaded `.env`: Compose reads `.env` itself. On Windows, Git Bash rewrites values that look like Unix paths (`POST_LOGIN_PATH=/tasks` becomes `C:/Program Files/Git/tasks`) before Docker sees them, and sign-in then fails with `sign_in_unavailable`.

```sh
docker compose --profile app --profile build-only build
docker compose --profile app up -d
```

The web app is at <http://localhost:8000/ui> and the MCP endpoint at `http://127.0.0.1:8090/mcp`, both on loopback only. `ENVIRONMENT=development` means local http, never a real deployment.

## 6. Start a session and connect the agent

1. **Sign in:** go to <http://localhost:8000/ui> and sign in. Microsoft asks for your password even if you're already signed in: starting a session needs a sign-in from the last 10 minutes.
2. **Start a session:** choose the `read-only-investigation` profile and a lifetime. The page shows the session capability **once**.
3. **Pass it to the agent:** put the capability in `CLW_MCP_CAPABILITY` in the shell you start the agent from, and use the `.mcp.json` from `quickstart/`, which sends it as `Authorization: Bearer ${CLW_MCP_CAPABILITY}`. Better still, use your client's header helper to read it from the OS keychain: an agent with a shell tool can read its own environment.
4. **Watch it:** the session page shows each call, each refusal and the audit chain's verification. Proposals appear under **Proposals**.

**Before you ask anything, confirm you're in the tenant you mean:** the session page names it.

## Undo it

1. **Revoke** any open sessions on the web app, then `docker compose --profile app down`.
2. **Run** `./deploy/test-tenant/uninstall.ps1 -TenantId <tenant-id>`. It deletes the agent app (its service principal and admin consent with it) and the local key.
3. **Delete** the sign-in app registration yourself.

What stays behind:
- **Tokens already issued** stay valid until they expire, about an hour.
- **Deleted app registrations** can be restored for 30 days.
- **Microsoft Graph PowerShell's own consent** stays in the tenant, from the sign-in the script used. Remove it under **Enterprise applications** if you don't use Graph PowerShell otherwise.

## What the tools don't see

- **App permissions:** Microsoft Graph **application** permissions only. Not delegated consent grants (reading those needs `Directory.Read.All`, which v0.1 doesn't request), and not other APIs.
- **Admin role holders:** **active** assignments only, not PIM-eligible ones. A role assigned to a group is shown as the group, without its members.
- **Dormant accounts:**
  - covers users only, not service principals;
  - Microsoft has recorded sign-in activity only since about April 2020;
  - sign-in times can lag by up to a day.
