# Gateway managed database upgrade

The C ordinary-ledger cutover is a separate, narrowly supported offline operation. See [C15 SQLite historical cutover](c15-sqlite-historical-cutover.md) and [C16 native PostgreSQL/MySQL cutover](c16-native-historical-cutover.md) for the fixed-main/v12, globally drained zero-target-history subset, explicit source-retention provenance, native backup/recovery and activation/restore boundary. `--db-upgrade run` alone does not perform that cutover. Directly starting the old binary is **not** blocked by the new marker; universal downgrade protection remains unverified and unsupported. The following managed-upgrade procedure is not a substitute for the separate cutover's backup and restore commands.

The managed upgrade path is `pushgo-gateway --db-upgrade plan|run`. Run it with exactly one gateway process against the target database. Do not mix beta and stable gateway processes while applying the 1.3.0 database semantics.

## Preflight

1. Stop every gateway instance using the database.
2. Preserve the exact release binary and configuration used for the upgrade.
3. Run `pushgo-gateway --db-upgrade plan` and review the reported driver, current schema, target schema, and backup policy.
4. For PostgreSQL or MySQL, create and verify an external backup, then prepare the manifest below. SQLite creates and verifies its local backup through the managed upgrade path.
5. Run `pushgo-gateway --db-upgrade run` once. Do not start application traffic until verification reports completion.

A no-op plan/run is read-only: it does not create an upgrade run, lock row, or backup artifact.

## PostgreSQL/MySQL backup artifact admission record

Set `PUSHGO_DB_UPGRADE_BACKUP_MANIFEST` to a regular JSON file. The gateway rejects missing, malformed, stale/future, driver-mismatched, or database-URL-fingerprint-mismatched manifests before migration.

This manifest is operator-supplied admission evidence, not cryptographic provenance. The gateway can prove that the referenced local bytes match the supplied size/SHA-256 and that the manifest names the configured database URL fingerprint; it cannot independently prove that those bytes were produced from the current database or that they are restorable. Production rollout therefore still requires an operator-controlled dump/snapshot command, immutable storage, and a restore test against an isolated database.

```json
{
  "version": 1,
  "driver": "postgres",
  "database_sha256": "<sha256 of the exact trimmed PUSHGO_DB_URL>",
  "artifact_uri": "file:///mnt/verified-backups/pushgo/2026-08-04.dump",
  "artifact_sha256": "<64 lowercase or uppercase hexadecimal characters>",
  "artifact_bytes": 123456789,
  "completed_at_epoch_seconds": 1785830400
}
```

Use `driver: "mysql"` for MySQL. `database_sha256` binds the proof to the exact configured database URL without storing that URL in the manifest. Generate it without printing the URL:

```bash
printf '%s' "$PUSHGO_DB_URL" | shasum -a 256
```

`artifact_uri` must be an absolute local path or `file:///` URI readable by the one-shot upgrade process. If the authoritative copy is in object storage, download or mount that immutable object first and point the manifest at the verified local copy. The gateway streams the artifact, requires the exact `artifact_bytes`, and recomputes `artifact_sha256`; metadata alone cannot authorize an upgrade. `completed_at_epoch_seconds` must describe an operator-declared completion time within the previous 24 hours (a value more than five minutes in the future is also rejected). The gateway validates artifact admission fields but does not perform or attest the dump/snapshot and does not perform a PostgreSQL/MySQL restore; those remain explicit operator responsibilities.

## Failure and recovery

- If planning fails, fix the reported precondition without starting the gateway.
- If migration or verification fails, keep all gateway instances stopped and inspect the recorded upgrade run.
- SQLite automatically restores its managed backup after an injected or real verification failure.
- PostgreSQL/MySQL require restoring the recorded external artifact with the database-native tooling, validating it, then rerunning the upgrade with one process.
- Never bypass an unfinished upgrade-run record or manufacture a backup manifest for production.

## Release acceptance

Before production rollout, run `scripts/preflight_release_audit.sh all` and `scripts/storage_crossdb_parity.sh`. The parity script creates and hashes small test-only artifacts for its ephemeral PostgreSQL/MySQL containers; those files are not production backup evidence.

## Watch reminder setting

`20261013_001_watch_alert_window` is an additive managed migration on the current v12 schema. It adds `devices.watch_alert_window_minutes` with default 30 on SQLite, PostgreSQL and MySQL, independently of provider route revisions. Existing v12 databases with no record for this migration receive a normal managed backfill with the required backup policy. Verification requires the column. Earlier binaries reject the unknown migration record; this change does not claim binary downgrade compatibility.
