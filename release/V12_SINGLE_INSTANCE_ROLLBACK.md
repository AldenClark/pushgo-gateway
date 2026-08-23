# Gateway v12 single-instance rollback and emergency recovery

This is the release contract for the additive `2026-08-20-gateway-v12` durable-dispatch schema. It applies only to the supported single-Gateway-instance topology. It does not authorize a production migration, restore, deployment, or multi-instance rollout.

## Compatibility decision

- The audited v11 source is commit `6c26f420114823a827caa0274a0bbc3739d91211` with schema `2026-08-08-gateway-v11`.
- That v11 binary is deliberately **not** a reader for a v12 database. Its schema check must fail closed before admission. Pointing it at a v12 database is a compatibility check, not a rollback.
- Before the first v12 durable write, rollback to v11 means stopping Gateway, restoring the verified pre-v12 database snapshot, and starting the preserved v11 artifact against only that restored v11 database.
- After any v12 submission or provider-outbox row has been accepted, the database crosses a forward-only data boundary. Do not start v11, relabel schema metadata, drop v12 tables, or delete pending rows.
- The forward-fix maintains a server-issued total order for latest-state Widget and Live Activity work. On an existing v12 database it advances the sequence watermark to at least the maximum positive submission/outbox order. It deliberately does not infer order from producer time, receive time, row IDs, or scan order.
- A legacy `coalesce_order=0` outbox row is a fixed materialized winner against a different zero-order submission generation; replay of the same frozen generation remains idempotent, and future positive-order work can replace it. If any joined `dispatch_submission`/`dispatch_op_dedupe` row is still both pending and `acceptance_order=0`, the forward-fix fails startup with `LegacyAcceptanceOrderPending`. This is intentional: the true historical order cannot be recovered safely.
- The emergency forward-fix artifact is the exact preserved v12-aware release binary. With admission stopped, leave the process stopped to hold durable work. Run its read-only `--db-upgrade plan` to inspect compatibility. After the defect is corrected or the same artifact is redeployed normally, its schedulers resume/drain the durable backlog.

This replaces the design's generic dormant-reader requirement for the declared single-instance deployment. There is no simultaneous old/new writer or scheduler combination and no feature-epoch claim. Multi-instance rollout remains unsupported and requires a separate design and certification.

## Required release assets

Before production enablement, preserve outside the host being upgraded:

1. the v11 binary, SHA-256, source commit, configuration, and restore-tested pre-v12 database snapshot;
2. the v12 binary, SHA-256, source commit, configuration, and this runbook;
3. for PostgreSQL/MySQL, the external snapshot/restore command and its independently verified artifact; for SQLite, the core database and both delivery/dispatch sidecars from the same stopped-writer snapshot;
4. an operator decision naming the hold trigger, drain owner, and provider/device verification to perform after recovery.

## Executable pre-release drill

Build or retrieve the two audited binaries, then run:

```bash
V12_BIN=/immutable/artifacts/v12/pushgo-gateway \
EVIDENCE_FILE=evidence/rollback/v12-single-instance.json \
  scripts/v12_single_instance_rollback_drill.sh
```

When `V11_BIN` is omitted, the drill exports the exact audited v11 source commit into a temporary directory and builds it with the locked release graph. The drill operates only on temporary SQLite files. It creates and snapshots a stopped-writer v11 database family, restores it under a distinct path, verifies schema and sentinel preservation with the exact v11 artifact, then creates a v12 fixture with one pending durable provider row. It proves that v11 rejects v12 without changing core or dispatch bytes and that the v12 emergency artifact can inspect the schema while preserving the backlog. It records both binary hashes and machine-readable evidence.

For PostgreSQL/MySQL, run the same compatibility decision against an isolated restored clone: v11 must reject schema v12; the v12 artifact's `--db-upgrade plan` must succeed; and the durable-row counts must remain unchanged. Never point the drill or an unproven v11 binary at production.

## Incident procedure

1. Stop ingress and the single Gateway instance. Record the current binary hash, schema version, and durable submission/provider/private backlog counts.
2. If no v12 durable write ever occurred and rollback was pre-authorized, restore the pre-v12 snapshot and verify schema v11 before starting the preserved v11 binary.
3. Otherwise keep the v12 database intact. Do not deploy v11. Use the preserved v12-aware artifact in hold mode (process stopped plus optional read-only plan) until the forward fix is ready.
4. Before starting the forward fix, inspect a restored clone for pending zero-order submissions. If present, use the exact prior v12 artifact with ingress stopped to drain/terminalize that backlog under its original semantics, then snapshot again. Do not manually assign order values or delete rows. Confirm the joined pending-zero count is zero.
5. Validate the forward-fix artifact against the restored clone, including durable backlog readability, order-watermark reconciliation, and scheduler recovery. Then deploy it with the same v12 schema and resume ingress.
6. Verify provider backlog movement, sender status, Pull/ACK preservation, private outbox state, and error telemetry. Provider acceptance remains at-least-once; device display is not implied.

## Release gate

For the 1.3.0 pre-release gate, the exact candidate must pass the generated stopped-writer v11 snapshot/restore-clone drill and record both binary hashes. By explicit release decision, no staging environment exists and production restore/provider validation is not a prerequisite for publishing 1.3.0; it remains `NOT RUN`, must not be represented as completed evidence, and is still required operationally before any production migration is authorized. Local tests do not prove production backups, provider credentials, or deployment authority.
