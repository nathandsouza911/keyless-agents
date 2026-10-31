# Runbook: removing a stored run result (personal data)

**When:** a completed run's result holds personal data that must not be kept (a real person in a test tenant, or an erasure request). Design: SD-037.

**What it does:** writes a `RESULT_REDACTED` record to the tenant's audit chain (operator, reason, run ID and the result's SHA-256, never the data), then clears `runs.result` and sets `result_redacted_at`. The chain stays valid. The run still shows `completed / succeeded`, with `result: null` and `result_redacted: true`.

**What it does not do:** reach database backups, checkpoint files, logs or exports. Remove those separately.

**Who:** an operator with the deployment's owner database role. The application roles cannot do this, by design.

## Steps

1. **Identify the run:** the tenant ID (the chain) and the run ID. Check that the run is `completed`.
2. **Run the command** with the owner role's `DATABASE_URL` in the environment:

   ```bash
   uv run python -m clw.cli audit-redact-result --chain <tenant-id> --run <run-id> \
     --operator "<your name or ID>" --reason "<why, no personal data>"
   ```

   The output is the run ID, the removed result's SHA-256, the redaction record's sequence number, and `resumed`.
3. **Verify:** `uv run python -m clw.cli audit-verify --chain <tenant-id>` reports the chain valid, and `GET /runs/<run-id>` shows `result_redacted: true`.

## Refusals (nothing recorded or removed)

- `run is not completed` / `run holds no result`: there is nothing to redact, or it is already redacted.
- `stored result does not match its RUN_COMPLETED digest`: **stop.** The stored result was changed after completion. Treat it as a possible compromise (`docs/runbooks/audit-chain-recovery.md`, step 1). Do not try to force the redaction: the mismatch is the evidence.
- `audit store unavailable`: the record could not be written, so nothing was removed. Fix the audit store and retry.

If a run reports `resumed: true`, an earlier attempt wrote the record but lost the row change. This run completed that change.
