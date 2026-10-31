# Security policy

Cloud Locksmith is security software in **beta (v0.1)**. Reports are welcome, and we'd rather hear about a problem privately first.

## Reporting a vulnerability

- **Privately:** use GitHub's **private vulnerability reporting**, on this repository's **Security** tab, then **Report a vulnerability**. That's the only channel.
- **Please don't** open a public issue or discussion for a vulnerability.

Include what you found, how to reproduce it (the quick start's fictional tenant is ideal), and what you think the impact is. **Never include real tenant data, tokens or credentials**, yours or anyone's.

**What to expect:**
- an acknowledgement within **5 working days**;
- an assessment, and a fix or a plan, as soon as we can.

This is a small project without a bug bounty. With your permission, we'll credit you in the changelog.

## In scope

- **Getting past a session's profile:** making an agent's session call, or read, anything its profile does not allow.
- **Credential exposure:** an agent, the MCP gateway or the web app receiving a Microsoft Graph or Entra credential.
- **Using a session capability:**
  - after it expired or was revoked;
  - from a URL or anything other than the `Authorization` header;
  - for another tenant.
- **Writes and approvals:** a change proposal executing, or any write reaching Microsoft Graph.
- **The audit trail:** recording a request after it was sent, or missing a request or refusal without the chain showing it, or a change to a record that verification does not detect.
- **Demo mode:** demo mode starting in production or beside real credentials, or reaching anything but the fake Graph.
- **The pages:** cross-site actions, or injection into them (tenant data or agent text rendered as markup).

## Out of scope

These are documented limits; see [the threat model](docs/threat-model.md).
- The agent's own machine and any other credentials on it.
- A copied session capability used within its profile and lifetime (it is a bearer token).
- What the model provider sees of tool results.
- An agent misled within its profile.
- The frozen bring-your-own-script feature in this repository, which is not part of v0.1.
