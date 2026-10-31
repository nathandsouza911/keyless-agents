# Roadmap

Driven by what people who try it tell us: open an issue or a discussion. Nothing past v0.1 is promised.

## v0.1 (now): read-only investigation, inert proposals

Agents investigate under a session profile, and can ask for a change, which is filed and never executed. See the [README](../README.md).

## Next, if people want it: changes a person approves

An agent proposes an exact change, a person approves **that** change, outside the agent's reach, and Cloud Locksmith executes exactly what was approved. Planned requirements:
- **The approval:** bound to the canonical request by hash; single-use and expiring; given in a channel the agent can't reach; with an optional two-person rule.
- **Re-reading the target:** at approval and again before execution, refusing if it changed in a way that matters (gone, no longer a user, already in the requested state, newly privileged).
- **Resisting approval fatigue:**
  - the approval page shows the actual Graph effect, never the agent's own labels;
  - high-risk targets are flagged and need an extra step;
  - a batch summarises its whole effect, with nothing hidden behind "and N more".
- **Execution:** write-ahead audited, like every read.
- **Permissions:** one low-risk write first (for example, disabling a test account), on its own app registration with its own permission.

## Later, demand-driven

- A documented sandbox recipe: an agent whose only route to Microsoft is Cloud Locksmith.
- More read tools.
- A packaged deployment in your own Azure.
- Running as a Microsoft Entra Agent ID identity.
- VS Code Copilot and other MCP clients, documented and tested.
