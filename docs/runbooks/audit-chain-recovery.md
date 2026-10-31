# Runbook: audit chain integrity failure

**Trigger:** a CRITICAL log line `audit_chain_integrity_failure chain_id=<tenant> ... action=appends_refused`, or `AuditChainCompromised` raised to a caller.

**What it means:**
- The stored audit chain for that tenant failed an integrity check: a hash mismatch, malformed record, broken link, sequence gap, an impossible, future or backwards timestamp, an invalid recovery record, or an unsupported schema version.
- Every writer refuses to append to that chain, so **every run for that tenant is stopped (fail closed)** until this procedure succeeds.
- Nothing resumes on its own.

**Who:** an operator with database access and authority to declare a security incident. Tell the tenant's security lead before step 6.

## Steps

1. **Contain.**
   - Treat this as a possible compromise of a component with INSERT rights on `audit_events`: api, broker, runner, or anyone holding their database credentials.
   - Rotate those database credentials and the broker's profile credentials.
   - Leave the chain stopped.
2. **Preserve evidence** before anything else writes to the chain:
   ```bash
   pg_dump --table=audit_events --data-only --where="chain_id = '<tenant>'" ... > audit-<tenant>-<date>.sql
   python -m clw.cli audit-checkpoint --chain <tenant> --out <incident-dir> --allow-invalid
   ```
   - The checkpoint is written with status `INVALID`. It signs a fingerprint of every stored record exactly as PostgreSQL holds it, together with the findings. It can be produced for any stored data, including floats, very large integers, or the maximum allowed nesting.
   - It is evidence of the observed state, **not** an integrity attestation, and it never verifies as `ok`.
   - If the chain cannot be read at all, add `--record-unavailable`. That writes a signed `UNAVAILABLE` checkpoint stating so.
   - Copy the existing checkpoint files for the tenant to incident storage as well.
3. **Inspect:**
   ```bash
   python -m clw.cli audit-verify --chain <tenant>
   ```
   - Record the `errors`, the `integrity_state`, the `head_seq`, the `head_hash` and any `recoveries`.
   - `provisional` lists findings that depend on this host's clock: a record more than 5 minutes ahead of it that nothing later vouches for (the newest record, or at the start of a chain any record before the first trusted one). They become permanent only once later evidence exists. Take the checkpoint in step 2 straight away to preserve them; the recovery in step 6 may then have to wait until the database clock has passed the record (see the table in step 6). While `provisional` is not empty, the other findings and `integrity_state` can also change between runs; record the output with its time.
   - Recover only when the database clock is correct. A recovery written while the clock is fast can become ahead of the corrected clock, and the chain's state can then change again.
   - If you have earlier `VALID` checkpoints, run `audit-verify-checkpoint` against the newest one. A `rewritten` or `truncated` result means records it covers were changed, not just appended. `checkpoint_inconsistent` means the checkpoint was signed with your key but does not describe the records it covers: treat the signing key or the signing host as suspect.
4. **Investigate:**
   - Use the Postgres logs and connection records to establish which role and session inserted the failing seq(s).
   - Decide whether runs recorded after the failure point can be trusted.
5. **Decide.** Recovery lets the tenant's runs resume. It does **not** repair or hide anything:
   - The failing records stay in place. UPDATE and DELETE are impossible, by design.
   - `audit-verify` will report the chain as **invalid permanently**. It lists the acknowledged findings and every recovery record, valid or not.
   - Checkpoints of this chain from now on are `INVALID`.
6. **Record the recovery:**
   ```bash
   python -m clw.cli audit-recover --chain <tenant> --operator "<your id>" \
       --reason "<incident ref>: <what happened, credentials rotated>" \
       --expected-head-hash <head_hash from step 3>
   ```
   Possible results:

   | Output / exit code | Meaning | Next step |
   |---|---|---|
   | JSON with `recovery_seq`, exit 0 | The recovery record was committed **and** the chain was re-read and re-verified with no remaining blocking findings. Appends can resume. | Step 7 |
   | `recovery refused (nothing written): chain head is ... not the expected hash`, exit 1 | Something was appended since step 3. | Back to step 3 |
   | `recovery refused (nothing written): chain has no unacknowledged integrity findings`, exit 1, on a first attempt | Nothing to recover. Appends were not blocked by integrity findings. | Check the alert source |
   | The same message on a retry after waiting for the database clock | The earlier findings depended on the clock (the record was ahead of it) and have gone now that the clock has passed it; appends have resumed. Nothing in the chain records that the record was ever ahead (RR-6), so the checkpoint from step 2 and the `audit-verify` output recorded in step 3 are the only evidence. | Run `audit-verify`; confirm `integrity_state` and `errors` are what you expect and `provisional` is empty. Keep the step 2 checkpoint and the step 3 output with the incident record, and still investigate why the clock was behind the record (step 4) |
   | `recovery refused (nothing written): this recovery would not restore appends ...; if the database clock is correct, retry once it has passed the created_at X of seq N ...`, exit 1 | A record is ahead of the database clock; the recovery would take that head's timestamp and be out of order. | Check the database clock. If it is correct, retry once it has passed that `created_at` |
   | `recovery refused (nothing written): this recovery would not restore appends ... manual investigation required` (no retry time given), exit 1 | Some findings cannot be acknowledged. For example, a finding that cannot be tied to a sequence number, which only happens with data written outside the application's constraints. | **Manual intervention** (below) |
   | `recovery refused (nothing written): recovery would leave provisional (clock-dependent) findings ... retry once the database clock has passed the created_at X of seq N`, exit 1 | A record is ahead of the database clock and nothing in the chain proves it yet; acknowledging it now could become invalid later. | Check the database clock. If it is correct, retry once it has passed the `created_at` the message gives. That is the latest timestamp ahead of the clock; seq N is the first record carrying it and need not be one of the provisional seqs listed, because later records can copy a head's timestamp. A retry can still be refused for another reason; follow this table again |
   | `RECOVERY INCOMPLETE: recovery record seq N committed but the chain is still blocked`, exit 1 | The recovery record exists, but verification afterwards still fails. Something changed concurrently, or verification found a further problem. | Back to step 3; treat the new findings as part of the incident |
   | Exit 3, `audit store unavailable` | The database could not be reached or refused the insert. Nothing is confirmed. | Fix connectivity or privileges, then back to step 3 |

   Recovery records:
   - name their real predecessor (seq and stored hash)
   - acknowledge only findings on records before them. That includes the timestamp findings their own record makes provable: when more than 5 minutes below them, a recovery shows which earlier records are ahead (SD-020), so after an hour of a fast database clock it acknowledges every record from that hour, not only the newest.
   - take their timestamp from the database clock, or from the head when the head is at most 5 minutes ahead (to keep the chain in order); never from an invalid or far-future predecessor
7. **Confirm:**
   - Run `audit-verify` again. `integrity_state` is `recovered`, `provisional` is empty, the findings appear under `acknowledged`, and the recovery appears under `recoveries` with `"valid": true`. `valid` stays `false`.
   - Append a test event, or let the next run start, and run `audit-verify` again. New records must carry current database time and add no findings.
   - Take a new checkpoint with `audit-checkpoint --allow-invalid`. It is `INVALID` because the incident records remain, but it fixes the post-recovery state so later changes are detectable.

## When recovery cannot succeed (manual intervention)

`audit-recover` is designed to refuse rather than leave a chain that looks recovered but isn't. It cannot succeed when:
- a finding cannot be attributed to a sequence number (malformed data written by a superuser, or with constraints disabled)
- the database clock has just been corrected to a time earlier than a record that is still trusted (one less than 5 minutes ahead of the corrected clock): the recovery record would itself be out of order. This clears once the clock passes that record; retry then. A clock that is still wrong produces wrong but consistent timestamps, which no procedure here can detect (RR-6).
- the chain changes faster than you can inspect it (an active attacker with INSERT rights)

In these cases:
1. Keep the tenant stopped.
2. Preserve evidence (step 2).
3. Escalate to the database owner.

The options are then:
- **Start a new chain identity** for the tenant, archiving the old chain and its checkpoints as incident evidence. This requires a code change: chain identity is the tenant ID in Phase 1.
- **Restore the database from a backup** taken before the incident, then reconcile against the archived evidence.

Neither option rewrites the original evidence in place.

## Limits

- **Forged recovery records.** A component that can INSERT can also write a `CHAIN_RECOVERY` record (threat-model §6, RR-1). Recovery records are evidence to review, not proof of operator authority. They are always listed by `audit-verify`, and a recovered chain never returns to `valid`.
- **Schema v1 records.** These cannot be recovered with this procedure. Migration `20261015_audit_hardening` refuses to run while any exist (tested), and no automatic conversion is provided, because re-hashing would rewrite evidence. No v1 data exists outside test databases.
