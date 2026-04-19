# Gateway Device Identity V8 Migration Runbook

## Scope

This runbook covers the hard-cut upgrade to `2026-04-17-gateway-v8`.

Goals:

1. Make `device_key` the stable device identity across private and provider routes.
2. Revoke old device identities immediately when the gateway issues a replacement identity.
3. Retire old provider tokens by token identity, without temporarily restoring old routes.
4. Introduce an explicit schema migration planner so future gateway schema changes are auditable and repeatable.

This rollout is intentionally destructive for legacy device runtime state.

## Migration Mechanism

Gateway bootstrap now runs a code-owned append-only migration ledger before runtime DDL repair:

1. Ensure `pushgo_schema_meta` exists.
2. Ensure `pushgo_schema_migrations` exists.
3. Load every recorded migration row and validate it against the code-owned migration list.
4. Read `pushgo_schema_meta.schema_version`.
5. Detect whether legacy runtime tables already exist.
6. Pick one migration action: `FreshInstall`, `BackfillCurrent`, or `HardResetRuntime`.
7. Execute the selected migration action.
8. Run current schema DDL/backfill.
9. Record each pending migration success or failure in `pushgo_schema_migrations`.
10. Write the target schema version.

The current migration catalog contains `20260417_001_device_identity_v8`.
Once a migration id has shipped, its checksum is immutable; checksum drift or
unknown migration ids fail startup with `SchemaVersionMismatch` instead of
silently accepting edited migration history.

`HardResetRuntime` is selected when:

1. runtime tables exist but schema meta is missing;
2. schema version is one of the supported hard-cut legacy versions: `v7`, `v6`, `v5`, or `v4`.

Unknown non-current schema versions fail fast with `SchemaVersionMismatch` instead of being silently treated as current.

## What Will Be Preserved

The upgrade preserves channel definitions and business/message data.

The upgrade does not preserve legacy device runtime state:

1. `devices`
2. `channel_subscriptions`
3. `provider_pull_queue`
4. `private_bindings`
5. `private_outbox`
6. `private_sessions`
7. `private_device_keys`
8. `subscription_audit`
9. `device_route_audit`
10. `device_stats_daily`

## Required Client Contract

All clients must ship startup repair behavior before this rollout.

### Android

Startup and token refresh must run:

1. ensure/read the locally persisted `device_key`
2. upsert `/channel/device` with the current FCM token
3. persist the returned `device_key`
4. run subscription sync
5. if the provider token rotated, call `/channel/device/provider-token/retire` for the old token after the new route succeeds

### iOS and macOS

Startup must run:

1. obtain APNS token
2. upsert `/channel/device` with cached `device_key`, channel type `apns`, and current APNS token
3. persist the returned `device_key`
4. run `/channel/sync`
5. if the APNS token rotated, call `/channel/device/provider-token/retire` for the old token after the new route succeeds

The client must not use provider tokens for device identity recovery.

### watchOS Standalone

Startup must run:

1. restore private `device_key`
2. reconcile APNS provider route with `/channel/device`
3. persist the returned `device_key`
4. run `/channel/sync`
5. retire the old APNS token by `/channel/device/provider-token/retire` after successful route replacement

### Windows

Startup must run:

1. ensure active route (`ensure_wns_provider_route` or `ensure_private_route`)
2. persist the returned `device_key`
3. run `sync_channels()`
4. when WNS token rotates, upsert the new route first, then retire the old token by `/channel/device/provider-token/retire`

## Deployment Order

1. Confirm all clients above are released and configured to talk to the new gateway.
2. Stop gateway writers and workers.
3. Take a full database backup and verify restore procedure.
4. Deploy the new gateway binary.
5. Start gateway on the existing database.
6. Allow schema bootstrap to migrate to `v8`.
7. Verify startup self-heal on Android, iOS/macOS, watchOS standalone, and Windows.

## Expected Upgrade Behavior

When the new binary starts against `v7`, `v6`, `v5`, `v4`, or a database with runtime tables but no schema meta, bootstrap will:

1. drop legacy runtime/device tables;
2. recreate them under the current `v8` model;
3. update `pushgo_schema_meta.schema_version` to `2026-04-17-gateway-v8`.

No partial compatibility mode exists for older runtime state.

## Post-Deploy Verification

### Database

Verify schema version:

```sql
SELECT meta_value
FROM pushgo_schema_meta
WHERE meta_key = 'schema_version';
```

Expected result:

```text
2026-04-17-gateway-v8
```

Verify migration ledger:

```sql
SELECT migration_id, checksum, target_schema_version, success, error
FROM pushgo_schema_migrations
ORDER BY finished_at;
```

Expected current row:

```text
20260417_001_device_identity_v8 | sha256:426de3f380802b8706ddd10151d30d4ba8286fddb234eeefc7800c42d7860a29 | 2026-04-17-gateway-v8 | true/1 | NULL
```

Verify runtime state rebuilds as clients start:

```sql
SELECT platform, channel_type, COUNT(*)
FROM devices
GROUP BY platform, channel_type
ORDER BY platform, channel_type;
```

### Client Flows

For each platform:

1. launch app
2. confirm route upsert succeeds
3. confirm local `device_key` persists
4. confirm channel list re-syncs
5. send a test message and confirm delivery
6. rotate provider token if practical and confirm the old token no longer receives queued provider pulls

### Gateway Logs

Check for:

1. schema version mismatch errors
2. invalid provider token validation errors
3. repeated `device_key_not_found` loops from old clients
4. repeated provider-token retire failures

## Rollback

Rollback is not code-only.

Required rollback steps:

1. stop the `v8` gateway
2. restore the pre-upgrade database backup
3. redeploy the previous gateway build

If the database is not restored, old binaries may start against destructively reset runtime state.

## Accepted Losses

Accepted losses during this hard cut:

1. pending provider pull items
2. pending private outbox items
3. existing private sessions
4. existing subscription/runtime audit history in dropped tables

This is acceptable only because clients rebuild route and subscription state on startup.
