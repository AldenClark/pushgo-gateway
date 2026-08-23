# Gateway Durable Adaptive Dispatch Final Design

> Status: **Durable single-instance architecture implemented; v12/v11 fail-closed rollback contract defined; real-provider, cross-system, exact-artifact drill, and canary gates remain**
>
> Decision date: 2026-08-20
>
> Scope: Gateway ingress admission, provider delivery, Apple Widget/Live Activity pushes, private delivery retry, overload, shutdown, and recovery
> Compatibility: current HTTP/MQTT/MCP wire shapes remain; documented state semantics are tightened as described below.

## 1. Final decision

Do not choose between “many fixed workers” and “no limits.” Use four layers:

```text
HTTP / MQTT / MCP ingress
        |
        v
validate + plan + durable submission manifest
        |
        +--> target materializer
                |
                +--> private payload/outbox ------> private realtime/fallback scheduler
        |
                +--> provider pull cache + provider_dispatch_outbox
                                                   |
                                                   v
                                             APNs / FCM / WNS lane schedulers
                                              |
                                              +--> bounded adaptive concurrency
                                              +--> durable retry scheduling
                                              +--> provider-scoped circuits
```

The architecture has a small constant runtime footprint and scales logical in-flight work quickly when backlog appears. It scales back to the minimum after the burst. Hard limits remain mandatory safety rails for memory, database, sockets, credentials, and upstream-provider health.

The complete decision is:

1. Remove provider dispatch throughput from `GatewayRuntimeProfile`.
2. Replace the common `worker_count` and equal queue sizes with independent provider lanes.
3. Commit a versioned submission/target manifest with operation dedupe before any external send, then make durable outboxes—not in-process queues—the source of truth for every attempt.
4. Make provider clients perform one attempt only; retries release capacity and return to durable scheduling.
5. Use bounded, hysteretic adaptive concurrency per provider, plus fair APNs sublanes.
6. Keep storage/cache/retention profiles where deployment shape genuinely matters.
7. Require private outbox materialization before every realtime send, including the online fast path; remove silent capacity eviction and attempt-count dropping before TTL.
8. Treat in-memory channels as coalesced wakeup hints. Losing a hint must never lose accepted work.

Merely decoupling APNs worker count from the generic worker count is necessary but not sufficient.

## 2. Verified current-state findings

### 2.1 One profile knob couples unrelated providers

`runtime_config.rs` defines one `DispatchRuntimeTuning { worker_count, queue_capacity }`.

- small profile: 2 workers, queue capacity 256;
- public profile: CPU-derived 4-16 workers, queue capacity 2,048-16,384.

`DispatchWorkerPool::spawn` creates that many workers independently for APNs alert, APNs Widget, FCM, and WNS. All four lanes therefore receive the same concurrency and queue policy even though their traffic, quotas, priority, and error semantics differ.

### 2.2 Provider semaphores are mostly unreachable

Current provider hard limits are higher than the worker pool:

- small: APNs 32, FCM 32, WNS 16;
- public: APNs 128, FCM 256, WNS 128.

Each worker receives one job and awaits the entire send/retry operation before receiving the next. Effective provider concurrency is therefore normally `worker_count`, not the provider semaphore value. On the small profile APNs can use only 2 of 32 configured permits.

### 2.3 Retry sleep occupies a worker

APNs, FCM, and WNS clients each implement up to three attempts internally, with exponential sleeps inside `send_to_device`. A slow or throttled request can occupy one of two small-profile workers for a 60-second request timeout plus retries. Fresh work behind it suffers head-of-line delay.

### 2.4 `provider_queued` is volatile, and queue full is terminal for that attempt

`DispatchChannels::try_send_*` uses bounded Flume `try_send`. Full returns `DispatchError::QueueFull`. Message handlers record a provider failure and continue. Widget and Live Activity paths log a skipped dispatch. There is no durable reconstruction record for those volatile jobs.

The current developer documentation correctly says `provider_queued` means only admission to this process's in-memory queue.

### 2.5 A process crash can lose a committed provider job

Workers wait for `ProviderDispatchOutcome.wait_until_committed()` and send only after the op dedupe state has committed. This prevents a send before acceptance, but the job itself remains only in memory.

On startup, `recover_interrupted_provider_dispatches` converts expired `provider_queued` operations to `partial_failure/provider_outcome_unknown`. It does not reconstruct or resend the per-device provider job. A crash between dedupe commit and provider send can therefore produce an accepted operation that is never attempted.

### 2.6 Widget and Live Activity sends have the same volatility

- Widget pushes use a separate in-memory queue and are skipped when full/closed.
- Live Activity pushes call the normal APNs `try_send_apns` path and are skipped when full/closed.

They are latest-state workloads and can be coalesced, but they still need a durable latest intent rather than silent loss.

### 2.7 The private scheduler contains a better recovery pattern

The normal private path writes `private_payloads/private_outbox` before realtime delivery. Its bounded command queue is only a scheduling hint; on hint failure it requests a durable resync. Claims have ownership and leases. This is the correct pattern to generalize, but the current online fast path is an exception.

Two private-path risks remain:

1. `delivery_core/execution/private.rs` can call `try_deliver_to_device` and `continue` before `enqueue_private_deliveries`, so a configured online fast path can report success with no recoverable outbox row;
2. per-device/global capacity currently evicts the oldest pending outbox rows to accept newer rows;
3. fallback retries can drop a still-unacknowledged delivery after `fallback_max_attempts` even if TTL has not expired.

Those policies trade correctness for fixed storage and must be changed explicitly, not hidden by larger limits.

### 2.8 Diagnostic channels are allowed to drop

The runtime counter collector uses best-effort bounded admission. That is acceptable because counters are diagnostic, not delivery correctness state. The redesign does not make every queue durable; it makes every **correctness-bearing** queue durable.

### 2.9 Direct provider delivery already depends on a recovery cache

The current provider dispatcher calls `ensure_provider_pull_cached` before payload-path selection whenever the merged target carries `wakeup_pull_ref`. That includes ordinary direct payloads in the current plan, not only wakeup notifications. This is why a direct APNs notification can later be recovered by device-scoped pull and why client ACK can safely delete the server copy. The redesign must preserve and strengthen this ordering for every provider target that carries recovery/ACK identity; limiting the prerequisite to wakeup jobs would be a regression.

### 2.10 A partial cross-store dispatch can lose its dedupe owner

Current execution materializes private/MQTT targets before provider targets. If a later provider step returns an error, the operation guard's generic error branch clears the pending dedupe reservation even though earlier durable private side effects may already exist. A same-`op_id` retry can then reserve a new delivery identity or repeat only part of the fanout. The final design therefore needs a durable submission/target manifest, not only a provider outbox, to recover and summarize cross-channel materialization.

## 3. Architecture decision record

### Context

Gateway supports small SQLite installations and large PostgreSQL/MySQL installations, while using APNs, FCM, WNS, private QUIC/TCP/WSS/MQTT transports, HTTP, MQTT ingress, and MCP. Static profile-wide worker limits underuse I/O capacity at low cost but still cannot prevent volatile-job loss. Removing bounds would create memory exhaustion, connection storms, database contention, and provider throttling.

### Decision

Adopt durable, independently controlled delivery lanes. Provider jobs are accepted only after a recoverable outbox row exists. One persistent scheduler task per provider owns a bounded set of in-flight futures and adjusts logical concurrency. Profiles no longer select provider worker count.

### What remains profile-dependent

- SQLite versus external database connection pools;
- cache size and retention;
- maintenance batch size and interval;
- private session/handshake admission based on actual host resources;
- diagnostics sampling.

### What becomes profile-independent

- provider lane definitions;
- minimum/initial adaptive concurrency;
- retry classification;
- durable acceptance semantics;
- fairness and priority rules;
- lease/recovery behavior;
- no-silent-eviction rules.

Hard maxima are explicit lane safety configuration and may be overridden operationally. They are not inferred from “small” or “public.”

### Rejected alternatives

1. **Only give APNs its own worker count.** Improves one bottleneck but keeps volatile jobs, inline retry sleeps, queue-full loss, and FCM/WNS coupling.
2. **Spawn one Tokio task per delivery with no bound.** Rejected because bursts become unbounded memory/socket/database work.
3. **Auto-create and destroy worker tasks based on queue depth.** Rejected because Tokio tasks are not the scarce resource. Stable scheduler tasks plus a logical in-flight limit are simpler and react faster.
4. **Use one adaptive limit for all providers.** Rejected because an FCM quota event must not slow APNs or WNS.
5. **Persist only failed sends.** Rejected because a crash can happen before the first send result exists.
6. **Keep oldest-row eviction as overload control.** Rejected because it discards already accepted correctness state. Admission must fail before accepted work is destroyed.

### Consequences

- Delivery remains at-least-once, not exactly-once; provider timeout can leave an unknown outcome.
- Clients must continue deduping by delivery/message/entity identity.
- Durable outbox writes add a small database cost to provider delivery.
- Provider acceptance latency becomes measurable and recoverable.
- Operational tuning moves from arbitrary task counts to SLO, upstream feedback, durable backlog, and byte budgets.

### Recheck triggers

Revisit the controller algorithm after production traces demonstrate persistent oscillation, after a provider publishes new quota/concurrency contracts, or after dispatch-store write amplification becomes the measured bottleneck. Do not revisit durable acceptance without an equivalent recoverable primitive.

## 4. Reliability and overload invariants

| ID | Invariant |
|---|---|
| G1 | A response/state described as accepted or provider-queued has a durable delivery intent. |
| G2 | A full or closed in-memory hint queue cannot turn accepted work into failure or loss. |
| G3 | Provider network work starts only after durable acceptance is committed. |
| G4 | One target has at most one active lease, but expired leases are recoverable. |
| G5 | Retry delay never occupies logical in-flight capacity. |
| G6 | No network request or retry sleep occurs while a database transaction/lock is held. |
| G7 | APNs, FCM, WNS, private, Widget, and Live Activity pressure are isolated by lane and priority. |
| G8 | Hard bounds exist for durable bytes/rows, claims, in-flight requests, connections, and retry rate. |
| G9 | Exceeding a correctness capacity returns explicit retryable backpressure before evicting accepted unexpired data. |
| G10 | Terminal states require provider success, permanent provider/route error, explicit cancellation/supersession, receiver ACK, or TTL expiry. |
| G11 | Shutdown or process kill may delay work but cannot erase a durable pending/leased job. |
| G12 | Provider success means the provider accepted the request, not device display or app persistence. |
| G13 | Concurrency permission and rate permission are separate; an attempt starts only when it has both. |
| G14 | Every target is either represented by the committed submission manifest and later durably materialized, or explicitly rejected; no partial side effect permits the operation dedupe identity to be cleared. |
| G15 | Private realtime send occurs only after the same delivery/device exists in the durable private outbox; “online fast path” means immediate post-enqueue send, never enqueue bypass. |
| G16 | For every provider target carrying recovery/ACK identity, the pull-cache row exists before either direct or wakeup provider send and remains until client ACK/TTL. |
| G17 | Lease settlement is fenced by owner, generation, expected state, and feature epoch. |
| G18 | The lane scheduler is the sole logical-concurrency owner; provider adapters expose one attempt and may retain only transport-level connection/stream safety bounds. |

## 5. Capacity domains

The runtime is divided into independent resource domains:

| Domain | Source of truth | Capacity control |
|---|---|---|
| HTTP/MQTT/MCP ingress | request + dedupe reservation | request/connection admission, validation limits |
| Dispatch acceptance | durable DB rows | row/byte high-water and hard-water marks |
| APNs | provider outbox | adaptive global APNs limit + fair sublanes |
| FCM | provider outbox | independent adaptive limit and project circuit |
| WNS | provider outbox | independent adaptive limit and package circuit |
| Private realtime | private outbox + connection state | per-connection bounded channel, session admission |
| Private fallback | private outbox | leases, due batches, bounded concurrency |
| Diagnostics | memory channel | best-effort bounded drop/coalesce |

No profile-wide worker number crosses these boundaries.

## 6. Durable submission manifest and provider outbox

### 6.1 Cross-channel submission manifest

Before any private realtime, MQTT receiver, or provider network send, commit `dispatch_submission`, all `dispatch_submission_target` rows, and the op-dedupe reservation/fingerprint in the dispatch correctness store. The manifest contains the versioned sanitized payload and immutable target plan needed to reconstruct materialization after restart.

```sql
CREATE TABLE dispatch_submission (
    submission_id          VARCHAR(128) PRIMARY KEY,
    op_dedupe_key          VARCHAR(512) NOT NULL UNIQUE,
    op_id                  VARCHAR(256) NOT NULL,
    delivery_id            VARCHAR(128) NOT NULL UNIQUE,
    request_fingerprint    VARCHAR(128) NOT NULL,
    payload_version        INTEGER NOT NULL,
    payload_blob           BLOB NOT NULL,
    state                  VARCHAR(32) NOT NULL,
    target_count           INTEGER NOT NULL,
    materialized_count     INTEGER NOT NULL DEFAULT 0,
    rejected_count         INTEGER NOT NULL DEFAULT 0,
    feature_epoch          BIGINT NOT NULL,
    accepted_at_ms         BIGINT NOT NULL,
    expires_at_ms          BIGINT NOT NULL,
    finalized_at_ms        BIGINT
);

CREATE TABLE dispatch_submission_target (
    target_id              VARCHAR(128) PRIMARY KEY,
    submission_id          VARCHAR(128) NOT NULL REFERENCES dispatch_submission(submission_id),
    channel_kind           VARCHAR(32) NOT NULL,
    target_identity_blob   BLOB NOT NULL,
    state                  VARCHAR(32) NOT NULL,
    materialization_owner  VARCHAR(128),
    materialization_until_ms BIGINT,
    lease_generation       BIGINT NOT NULL DEFAULT 0,
    last_error_code        VARCHAR(128),
    UNIQUE(submission_id, channel_kind, target_id)
);
```

The manifest commit is the operation's recoverable acceptance point. Target materializers are idempotent:

- provider targets are inserted into `provider_dispatch_outbox` in the same dispatch-store transaction when possible;
- private/MQTT receiver targets are inserted into their existing durable store by `(delivery_id, device_id, channel_kind)`, then the manifest target is fenced to `materialized`;
- a crash after target-store commit but before manifest settlement replays the same identity and observes a duplicate, not a second delivery;
- deterministic route/policy rejection becomes an explicit target `rejected` result; transient storage/capacity failure remains retryable and cannot clear the operation dedupe row.

Implementation decision (2026-08-20): the v12 working-tree implementation stores the immutable target set and all planning inputs in one versioned `dispatch_submission.payload_blob`, committed in the same database transaction as the `dispatch_op_dedupe=pending` reservation. The blob freezes channel, operation, delivery, entity, request, resolved dispatch targets, public Gateway URL, private-runtime eligibility, and private TTL input. Existing private/MQTT outboxes and `provider_dispatch_outbox` remain the normalized per-target materialization ledgers. Recovery replays the frozen set with the same delivery identity; those ledgers' idempotent keys turn an interrupted replay into observation/upsert rather than a second logical delivery. This replaces the draft's separate `dispatch_submission_target` table without weakening the recoverability invariant, but SQL-only per-target observability is correspondingly deferred. Unresolved accepted blobs are excluded from generic stale-pending cleanup and a periodic owned recovery worker retries old pending submissions.

The final operation summary is derived from durable target states and preserves current per-target partial-failure semantics. It does not promise atomic all-target success. If a client disconnects before the final response, the outcome is unknown to that client; retrying the same `op_id` returns the same delivery identity and joins/observes the existing submission.

Closed states are:

```text
submission: materializing -> finalized_accepted | finalized_partial | expired
target:     pending -> leased(owner, generation, epoch)
                     -> materialized | rejected | retry_wait | expired
```

`rejected` is allowed only for deterministic target/route/policy failure and contributes to a stable partial summary. Storage busy, cross-store timeout, process cancellation, or hard-water pressure after manifest acceptance is not a rejection: the target remains recoverable in `retry_wait`. Materializer results use the same owner/generation/epoch compare-and-swap rule as provider attempts.

### 6.2 Storage placement

Add `provider_dispatch_outbox` to the existing dispatch correctness store, next to `dispatch_op_dedupe`. For SQLite this is the dispatch sidecar, allowing provider intent and provider-queued dedupe transition to commit in one database transaction. PostgreSQL and MySQL use their normal transactional database.

Durable acceptance also has a runtime storage-configuration gate; an ACID-capable engine name is not by itself sufficient evidence. SQLite opens the correctness store in rollback-journal `DELETE` mode with `synchronous=EXTRA` and verifies the effective values on an actual pool connection. PostgreSQL startup fails closed when `synchronous_commit=off`, `fsync=off`, or `full_page_writes=off`. MySQL startup requires `innodb_flush_log_at_trx_commit=1`, an enabled/recovering doublewrite mode (not `DETECT_ONLY`), and `sync_binlog=1` whenever binary logging is enabled. Upgrade planning may inspect and report an unsafe server, but upgrade execution and normal runtime stop before correctness writes until the operator restores a safe setting.

Provider-pull payload caching remains in the delivery store. Every provider job carrying recovery/ACK identity—direct or wakeup—is not runnable until its pull item is durably confirmed. The prerequisite transition is idempotent, so cross-store atomicity is not required:

```text
provider outbox blocked_pull_cache
  -> ensure provider_pull_queue row (idempotent)
  -> provider outbox pending
  -> eligible to claim/send
```

If the process dies between steps, the next reconciliation repeats the prerequisite safely.

Provider success never deletes this cache. Only a validated client ACK, explicit device retirement, or TTL expiry may remove it.

### 6.3 Schema

```sql
CREATE TABLE provider_dispatch_outbox (
    job_id                VARCHAR(128) PRIMARY KEY,
    submission_target_id  VARCHAR(128) NOT NULL,
    op_dedupe_key         VARCHAR(512) NOT NULL,
    delivery_id           VARCHAR(128) NOT NULL,
    channel_id            BINARY(16) NOT NULL,
    provider              VARCHAR(16) NOT NULL,
    purpose               VARCHAR(32) NOT NULL,
    priority_class        VARCHAR(16) NOT NULL,
    platform              VARCHAR(16) NOT NULL,
    device_key            VARCHAR(512) NOT NULL,
    route_revision        BIGINT NOT NULL,
    payload_version       INTEGER NOT NULL,
    payload_blob          BLOB NOT NULL,
    state                 VARCHAR(32) NOT NULL,
    attempt_count         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at_ms    BIGINT NOT NULL,
    lease_owner           VARCHAR(128),
    lease_until_ms        BIGINT,
    lease_generation      BIGINT NOT NULL DEFAULT 0,
    feature_epoch         BIGINT NOT NULL,
    last_attempt_at_ms    BIGINT,
    provider_status       INTEGER,
    provider_error_code   VARCHAR(128),
    provider_request_id   VARCHAR(128),
    retry_scope           VARCHAR(128),
    accepted_at_ms        BIGINT NOT NULL,
    expires_at_ms         BIGINT NOT NULL,
    completed_at_ms       BIGINT,
    UNIQUE(delivery_id, device_key, provider, purpose)
);
```

Backend-specific BLOB/BINARY syntax may differ. Required indexes:

- `(provider, state, next_attempt_at_ms, priority_class, accepted_at_ms)`;
- `(state, lease_until_ms)` for crash recovery;
- `(delivery_id)` and `(op_dedupe_key)` for settlement;
- coalescing key indexes for Widget and Live Activity purposes.

### 6.4 Payload envelope

The versioned BLOB contains enough immutable data to attempt delivery after restart:

- direct and wakeup payload variants where applicable;
- initial path and payload-size decision;
- collapse ID;
- topic/push type/priority/expiration headers;
- provider-specific body for FCM/WNS;
- provider-pull prerequisite identity;
- token hash and route revision, not credentials.

At claim time the adapter resolves the current route token. If the route revision/hash no longer matches, the job becomes `superseded_route` or is explicitly replanned according to the route-migration contract; it must never send an old payload to an unrelated replacement route.

### 6.5 States

```text
preparing
  -> blocked_pull_cache
  -> pending
  -> leased(owner, lease_until, attempt)
       -> provider_accepted
       -> retry_wait(next_attempt_at)
       -> permanent_failed
       -> superseded_route
       -> expired
```

`preparing` rows are never sent and are not themselves counted as accepted provider jobs. The manifest acceptance/materialization transaction inserts all prepared provider rows and changes them to `pending` or `blocked_pull_cache` together with the durable target state and `dispatch_op_dedupe=provider_queued`.

Widget/Live Activity work is latest-state and coalescible:

- Widget key: `(device_key, widget_kind, channel/entity scope)`;
- Live Activity key: `(activity_key, provider_token)` so independently registered devices do not overwrite each other's latest generation;
- a newer generation replaces a pending older generation;
- a leased old generation may finish, after which the newer generation remains pending.

Alert notifications are append-only until terminal/expired and are never overwritten by later alerts.

### 6.6 Claim algorithms

PostgreSQL/MySQL use transactional row locking/`SKIP LOCKED` equivalents where supported. SQLite uses a short single-writer claim transaction selecting a bounded batch then updating owner/lease/generation. Settlement compares job ID, expected `leased` state, owner, generation, and feature epoch; a stale result updates zero rows. Every backend must pass one logical conformance suite.

A claim batch is bounded by:

```text
available = current_concurrency - in_flight
claim = min(available, backend_claim_batch_max)
```

The scheduler never preclaims more work than it can start before a meaningful fraction of the lease expires.

## 7. Lane scheduler and task ownership

### 7.1 Runtime shape

Create one owned scheduler task for each physical provider:

- APNs scheduler with alert, Live Activity, and Widget subqueues;
- FCM scheduler;
- WNS scheduler.

Each scheduler owns a `JoinSet<AttemptResult>` or equivalent tracked future set. No attempt task is detached. A capacity-1 coalescing wakeup channel/`Notify` tells the scheduler to query durable due work. A periodic sweep guarantees progress after lost hints or restarts.

The scheduler's logical in-flight limit is the only delivery-concurrency queue. Current APNs/FCM/WNS adapter semaphores and retry loops are removed as logical admission layers. A transport client may retain a separately named hard bound for actual HTTP/2 streams, sockets, or handshake safety, but it must fail/return pressure to the scheduler rather than wait in a hidden adapter queue. Source tests reject a second delivery semaphore or sleep/retry loop below the scheduler.

The sweep is immediate on startup, at most every 250 ms while eligible backlog exists, and otherwise sleeps until the earlier of the next durable due time or a one-second idle reconciliation tick. Hints only shorten that wait. The scheduler does not poll the database at 250 ms when no work is due.

Scheduler loop:

```text
select {
  shutdown                 -> stop claiming, drain/expire leases safely
  durable-work hint        -> fill available slots
  retry/periodic deadline  -> fill available slots
  attempt completion       -> persist result, update controller, refill
}
```

### 7.2 APNs sublane fairness

APNs workloads share connections and provider credentials but not priority:

| Sublane | Weight | Semantics |
|---|---:|---|
| alert/message/event/thing | 8 | append-only, user-visible |
| Live Activity | 4 | latest-state coalescing |
| Widget | 1 | latest-state coalescing |

Use work-conserving deficit round robin. When alert backlog exists, reserve at least 50% of current APNs concurrency for alerts. Idle reservation is borrowable, so Widgets and Live Activities can use all capacity when alerts are absent.

Fresh work and retry work also use a work-conserving split: retries receive at most 25% while fresh urgent work is backlogged, except when retry age approaches TTL.

### 7.3 Ordering contract

Eligible work is selected by priority, due time, and stable acceptance identity, but concurrent provider attempts and retries can complete out of order. Gateway continues the existing semantic-time contract: it offers best-effort transport order and preserves `occurred_at`/entity time plus stable operation identity; it does not serialize every device behind a slow earlier send or rewrite business timestamps to mimic arrival order.

Alert jobs are never coalesced. Widget/Live Activity generations may coalesce only under their explicit latest-state keys. Clients converge business order with the semantic sorting/reducer rules. Any future workflow requiring causal delivery must declare a dependency/sequence key and use a per-key gate; it must not silently turn the whole provider lane into FIFO head-of-line blocking.

## 8. Adaptive concurrency

### 8.1 Default safety envelope

These are the architecture target envelopes, independent of deployment profile:

| Provider | Idle minimum | Burst initial | Hard maximum | Queue-wait target |
|---|---:|---:|---:|---:|
| APNs global | 2 | 8 | 128 | 100 ms alerts / 500 ms derived |
| FCM | 2 | 8 | 256 | 100 ms |
| WNS | 1 | 4 | 64 | 200 ms |

Operational overrides can lower or raise hard maxima within compiled absolute safety bounds. A fixed-concurrency override disables adaptation for incident response and benchmarking.

Implementation note (2026-08-21): the working tree currently uses compiled envelopes APNs 2-64, Live Activity 1-8, Widget 1-8, FCM 2-64, and WNS 1-32. Operational overrides, token buckets, shared quota windows, and credential/token-scoped circuits are not yet implemented. The implemented process-local safety circuit pauses a lane for one second after four consecutive retryable failures and closes on the first success. These omissions are external release gates for shared-credential multi-instance deployments, not evidence that an unbounded worker model is safe.

Idle footprint is a few scheduler tasks and no claimed payload batch. “Scale down” means fewer logical in-flight requests, not destroying and recreating Tokio workers.

### 8.2 Control loop

Controller window: 500 ms, using EWMA latency and rolling error/throttle counters.

Rules in order:

1. On empty-to-nonempty transition, raise immediately to `burst_initial`.
2. On provider/global throttling or circuit-open signal, set `C = max(min, floor(C / 2))` and hold for `Retry-After` or the provider minimum cooldown.
3. On timeout/transport/5xx ratio above 10%, or latency above three times the healthy EWMA, set `C = max(min, floor(C * 0.7))` and hold for at least 2 seconds.
4. If oldest eligible work exceeds the lane target, error ratio is below 2%, and no throttle signal exists, set `C = min(max, max(C + 1, ceil(C * 1.5)))`.
5. If backlog is empty and in-flight stays below `C/4` for three windows, halve toward the minimum.
6. After 10 seconds with no eligible work, return to the minimum.

Hysteresis and cooldown prevent oscillation. CPU utilization is an observability input and an emergency local-overload brake, not the formula for provider I/O concurrency.

### 8.3 Scope-aware throttling

Not every 429 is global:

- APNs `TooManyRequests` for one device token defers that token/job key; it does not halve the entire provider unless aggregate evidence also shows congestion.
- APNs provider-token update throttling opens a credential-scoped circuit.
- FCM quota 429 opens a project-scoped circuit and honors `Retry-After`.
- WNS 406 reduces package-level rate; monthly-quota 429 enters a long blocked state rather than a rapid retry loop.
- DB busy/pool exhaustion reduces claim rate and ingress admission, not the remote provider limit.

### 8.4 Rate policy and multi-instance quota

Adaptive concurrency controls simultaneous requests; it is not a rate limiter. Every lane therefore also has a token-bucket rate policy:

```rust
struct ProviderRatePolicy {
    local_rate_per_second: Option<NonZeroU32>,
    local_burst: NonZeroU32,
    shared_quota: Option<SharedQuotaWindow>,
}

struct SharedQuotaWindow {
    scope: ProviderCredentialScope,
    limit: NonZeroU32,
    window: Duration,
    reservation_chunk_max: NonZeroU32,
}
```

An attempt requires an adaptive-concurrency slot, a local token, and—when configured—a shared quota grant. Waiting for a token or future window holds neither a claim batch beyond its lease budget nor an in-flight network slot.

APNs has no guessed global requests-per-second default; its local bucket is a configurable safety envelope and provider feedback still controls token/credential scopes. FCM and WNS quotas are configured from the actual project/package contract rather than copied from an unrelated deployment profile. Starting more than one Gateway instance with a shared provider credential and no shared quota or explicit per-instance allocation emits a startup warning and a readiness diagnostic.

PostgreSQL/MySQL multi-instance deployments reserve small grants atomically from:

```sql
CREATE TABLE provider_rate_window (
    scope_hash       VARCHAR(128) NOT NULL,
    window_start_ms  BIGINT NOT NULL,
    window_ms        BIGINT NOT NULL,
    limit_value      BIGINT NOT NULL,
    granted          BIGINT NOT NULL,
    expires_at_ms    BIGINT NOT NULL,
    PRIMARY KEY (scope_hash, window_start_ms, window_ms)
);
```

The database update refuses `granted + requested > min(limit_value, locally configured limit)`. Instances with different limits for the same scope fail readiness instead of silently choosing the larger value. Each instance requests `min(remaining_need, reservation_chunk_max, ceil(limit / 10))`; unused grants expire at the window boundary and are not carried forward. A local token bucket smooths fixed-window boundaries. SQLite is single-node and uses the same local policy without distributed reservation. Credential scope is stored only as a keyed hash.

Provider `Retry-After` and circuits override unused tokens. The controller may lower concurrency after throttling but may never manufacture rate grants. This prevents ten healthy instances from each independently ramping to the full credential quota.

### 8.5 Local resource brake

The controller's effective maximum is `min(configured provider maximum, connection/stream budget, file-descriptor headroom, memory budget, and current database claim budget)`. These are measured resource budgets, not `small/public` labels. If database pool wait exceeds the lane target or sustained host pressure crosses the configured emergency threshold, new claims pause and concurrency decreases multiplicatively; active attempts are not abruptly cancelled unless shutdown/TTL requires it. Recovery uses the same cooldown/hysteresis rules.

APNs HTTP/2 multiplexing means an in-flight limit is not assumed to equal a socket count. Connection-pool code separately bounds and reuses connections; the load gate verifies file descriptors, resident memory, database wait, and handshake rate at every proposed hard maximum.

## 9. Provider attempt and retry contracts

Provider adapter API becomes one attempt:

```rust
trait ProviderAdapter {
    async fn attempt(&self, job: ClaimedProviderJob) -> ProviderAttemptResult;
    fn classify(&self, result: &ProviderAttemptResult) -> AttemptDisposition;
}

enum AttemptDisposition {
    Accepted,
    RetryAt(Instant, RetryScope),
    PermanentFailure(ErrorCode),
    InvalidRoute(ErrorCode),
    PayloadTooLargeDowngrade,
}
```

Rules:

- no adapter sleeps for retry;
- credentials may refresh in a single-flight operation and repeat authentication once when provider guidance permits;
- payload-too-large may transactionally switch from direct to the already persisted wakeup variant once;
- timeout outcome is unknown and is retried at-least-once only while TTL remains;
- all retry times use full jitter unless a provider gives a later explicit time;
- provider request IDs/status are stored without payload or credential data.

Provider-specific minimums:

### APNs

- Reuse HTTP/2 connections and allow multiple streams, but never assume an exact APNs stream count.
- `410/Unregistered/ExpiredToken`, bad token/topic/auth configuration, and payload too large after permitted downgrade are permanent for that route/job.
- Delay `TooManyRequests` and reduce the proper scope.
- Apple currently says 5xx payloads may be retried after 15 minutes; do not repeat them after 500 ms/1 second as current code does.
- Preserve stable `apns-id`/delivery correlation across retries for diagnostics; it is not treated as an exactly-once guarantee.

### FCM

- 400/401/403/404-class contract errors are permanent or credential-blocked as appropriate.
- Honor 429 `Retry-After`; if absent, wait at least 60 seconds.
- Use a minimum 10-second interval for failed sends and exponential full jitter for 5xx.
- Stop at TTL or the provider's maximum useful retry horizon; do not amplify an outage.

### WNS

- 410 retires the channel URI.
- 406 indicates throttle and lowers package-scoped concurrency/rate.
- monthly quota 429 is not a short transient retry.
- 500/503 retry only with bounded jitter and TTL; authentication refresh repeats at most once per failure event.

Connection timeout and total request timeout become separate settings. Initial total timeout is 15 seconds for provider attempts, subject to benchmark and provider requirements; no default returns to the current 60-second worker occupation without evidence.

## 10. Admission and storage pressure

### 10.1 Memory queues

There is no memory queue containing correctness-bearing provider payloads. The only in-memory channel is a coalesced wakeup signal. Full means “a wakeup is already pending,” not delivery failure.

### 10.2 Durable high-water behavior

Track both rows and estimated bytes per class. Configure:

- soft high-water: alert, reduce low-priority production, accelerate cleanup of terminal rows;
- hard high-water: reject new non-coalescible work with retryable `server_busy` before acceptance;
- reserved urgent budget: user-visible alerts cannot be crowded out by Widget/Live Activity generations;
- per-tenant/channel rate/fanout quotas so one channel cannot consume the whole durable budget.

Terminal rows are retained only for the compatibility/status window, then removed in bounded batches. Unexpired pending rows are not storage cleanup candidates.

Submission cleanup is dependency ordered: retain the submission payload while any target is `pending`, `leased`, or `retry_wait`; after every target is durably `materialized`, deterministically `rejected`, or expired, retain the compact final manifest until the op-dedupe/sender-status compatibility window closes. High-water cleanup never deletes an unresolved accepted manifest target.

The default terminal compatibility window is seven days, bounded by the existing sender-status/dedupe retention when that is shorter. Cleanup first verifies a terminal `sender_submit_status` projection (or that the public status window has elapsed), then deletes the terminal provider row, and only later deletes expired dedupe/status records. A provider row is not removed while it is still the only recoverable source for a public status. Payload blobs contain no provider credentials, are excluded from logs, and are deleted with the terminal row. Pending payload retention remains governed by delivery TTL, not maintenance pressure.

### 10.3 Private outbox correction

Change the private path as follows:

- enqueue/idempotently confirm the private payload/outbox row before any realtime send; `online_fast_path_enabled` only triggers the immediate post-enqueue attempt and can never `continue` around durability;
- expire TTL-dead rows first;
- coalesce only workloads whose product contract explicitly permits latest-wins;
- never evict an accepted unexpired alert to admit a newer alert;
- if per-device/global hard capacity remains exhausted, fail the new acceptance with retryable backpressure and leave dedupe retryable;
- `fallback_max_attempts` becomes an alert/circuit threshold, not a deletion threshold;
- terminal private deletion requires receiver ACK, explicit unsubscribe/device retirement, deterministic invalid payload, or TTL expiry.

This keeps hard capacity while eliminating hidden loss.

## 11. API and state compatibility

Current HTTP/MQTT/MCP request/response shapes remain. Internal execution moves behind the domain core/store interfaces.

Compatibility semantics:

- existing `provider_queued` response value remains during compatibility, but now means **durably queued**, not in-memory queued;
- `sent/provider_success` still means the upstream provider accepted the request;
- client/device receipt remains represented only by the relevant ACK contract;
- a durable-capacity rejection returns current retryable busy/error shapes and clears the pending dedupe reservation;
- duplicate op IDs return the same delivery identity/status and never create duplicate outbox rows.

For a mixed private/provider/MQTT operation, acceptance and final status are per target but identity is per submission:

- the submission manifest and op dedupe commit first;
- each target then becomes durably materialized or explicitly rejected;
- the public summary may remain partial, matching current behavior, but no target is counted accepted without a recoverable intent;
- a crash or request cancellation during materialization leaves the submission recoverable and keeps the dedupe reservation; startup and same-`op_id` retry resume it;
- the generic error path may clear a pending dedupe row only when no committed submission manifest exists.

For SQLite, `dispatch_op_dedupe` plus the frozen submission in the dispatch sidecar is the atomic acceptance source of truth. The core-database `sender_submit_status` row cannot join that transaction. The implementation therefore advances the sender projection after durable target materialization but before dedupe finalization on every initial or recovered execution. A projection-write failure leaves the frozen submission pending; a crash after the projection and before dedupe finalization is replay-safe under the same identities. The same ordering is used on PostgreSQL/MySQL so recovery semantics do not vary by deployment shape. The outer submit facade may repeat the monotonic projection update after the command returns.

The embedded API docs and website contract must be updated in the same Gateway release that changes `provider_queued` semantics.

## 12. Other channel assessment

### HTTP, MQTT, and MCP ingress

All three must call the same protocol-neutral submit command. They may have independent connection/request admission, but durable dispatch acceptance cannot depend on which ingress adapter was used. MQTT QoS 1 acknowledgment follows the existing command/dedupe result mapping.

### Private QUIC/TCP/WSS/MQTT delivery

Keep the current durable payload/outbox, per-connection bounded channels, resume, ACK, and hint-resync architecture. Its transport session scheduler remains separate from provider concurrency. Apply the no-eviction/no-attempt-drop corrections and expose backlog age/admission metrics.

### Widget and Live Activity

Move both into durable, latest-wins APNs sublanes. They borrow idle APNs capacity but cannot starve alerts. Their producer call completes after durable upsert, not provider network completion.

### Provider pull

Provider pull remains a durable prerequisite/cache retained until client ACK/expiry. Sending either a direct or wakeup provider payload carrying recovery/ACK identity without its pull item is forbidden. Direct provider acceptance does not remove the recovery copy; the Apple `/v2/messages/ack` boundary does. Pull cleanup is fenced and cannot race a pending provider job, client ACK reconciliation, or a late provider result.

### Apple delivery/ACK stable contract

This redesign does not silently change the current Apple wire contract:

1. direct provider payloads carry immutable `base_url + provider_device_key + delivery_id`; clients never infer missing ACK identity from current configuration;
2. legacy `/messages/pull` remains destructive and creates no ACK work;
3. `/v2/messages/pull` remains non-destructive, outer `PullItem.delivery_id` is authoritative, and `has_more` advances only after the client durably classifies/materializes and ACKs the current page;
4. Gateway corrupt historical-row discard operates only on that row's outer provider identity and must not delete a private outbox row named by untrusted embedded payload data;
5. `/v2/messages/ack` remains a separate maximum-200-ID contract returning validated `requested_count/removed_count`; repeated removal is idempotent;
6. provider/pull rows are deleted by client ACK only after Apple has a validated recoverable journal row/canonical row or a durable deterministic-discard tombstone.

The integration oracle joins this Gateway state with Apple state by normalized Gateway URL, device key, and outer delivery ID. HTTP/provider success or log presence alone never satisfies it.

### Runtime counters and traces

Remain best effort and may drop/coalesce. Delivery decisions never depend on their success.

## 13. Multi-instance correctness and shutdown

### Multi-instance

- claim uses owner, generation, and lease expiration;
- result updates compare all claim fields so a late old worker cannot overwrite a reclaimed job;
- token/credential-scoped shared quota grants are database-coordinated when configured, while every instance also enforces its local bucket;
- provider-specific circuits may be process-local, but persisted per-job retry times and shared quota prevent a second instance from immediately replaying the same delayed job;
- optional shared circuit hints may optimize convergence, never as the sole correctness control;
- fairness is local per scheduler while DB claims prevent duplicate active work.

### Shutdown

1. Stop new HTTP/MQTT/MCP admission.
2. Stop claiming new durable jobs.
3. Cancel scheduler wakeups and ask tracked attempts to finish before the absolute deadline.
4. Persist completed results.
5. Let unfinished leases expire or explicitly release them.
6. Await every scheduler/attempt task through owned `JoinSet`/task tracking.
7. Abort only after deadline; durable rows make the abort recoverable.

Unlike the current volatile queue, shutdown correctness does not depend on draining every in-memory job before process exit.

## 14. Observability and SLOs

Per lane/provider/purpose expose:

- durable pending/retry/leased counts and bytes;
- submission targets pending/materialized/rejected and oldest materialization age;
- oldest eligible age and oldest total age;
- submission-accepted-to-target-materialized and target-materialized-to-first-attempt latency, partitioned by target-count bins `1`, `2-10`, `11-100`, `>100`;
- claim latency and DB busy/pool wait;
- current/min/max logical concurrency;
- in-flight count and completion rate;
- provider latency histogram, timeout, status, and classified error rates;
- retry scheduled age, Retry-After use, and circuit state/scope;
- lease expiry/recovery and stale-result rejection;
- feature epoch/schema writer/scheduler cohort;
- direct recovery-cache prerequisite failures and private pre-outbox realtime attempts, both zero invariants;
- hint coalescing count (not a loss counter);
- high-water admission rejection and private no-eviction counters;
- shutdown finished/expired lease counts.

Initial SLOs:

| Measurement | Target |
|---|---|
| Durable acceptance -> first provider attempt, nominal load | p95 < 250 ms, p99 < 1 s |
| Process restart -> due-work scheduler active | p95 < 1 s after storage ready |
| Accepted job lost on hard kill | 0 |
| Accepted submission target neither materialized nor explicitly rejected before TTL | 0 |
| In-memory hint full causing delivery failure | 0 |
| Unexpired accepted private alert evicted | 0 |
| Private realtime send before durable outbox | 0 |
| Direct/wakeup recovery-capable provider send before pull cache | 0 |
| Provider retry sleeping while holding lane capacity | 0 |

Throughput numbers are deliberately not declared without provider credentials, hardware, and backend benchmark evidence. The algorithm and hard limits are implementation defaults, while capacity certification is empirical.

## 15. Implementation work packages

Implementation can be split into reviewable packages, but the durable contract must be enabled only when every producing path is converted.

1. **Schema and store contracts**
   - submission/target manifest and provider outbox schema/migrations for SQLite/PostgreSQL/MySQL;
   - enqueue, claim, settle, retry, recover, coalesce, count/bytes APIs;
   - backend conformance and migration tests.
2. **Single-attempt provider adapters**
   - remove retry sleeps from APNs/FCM/WNS clients;
   - provider-specific classification, Retry-After, stable correlation;
   - payload-too-large durable downgrade.
3. **Owned lane schedulers**
   - APNs fair sublanes, FCM, WNS;
   - adaptive controller, circuits, coalesced hints, periodic sweep;
   - graceful shutdown and lease recovery.
4. **Producer cutover**
   - Message/Event/Thing provider targets;
   - Widget pushes;
   - Live Activity pushes;
   - HTTP/MQTT/MCP shared submission result semantics.
5. **Private-delivery hardening**
   - persist before online realtime fast path;
   - remove accepted-row eviction;
   - TTL/ACK terminal policy;
   - make attempt thresholds observational;
   - independent fallback concurrency/claim budgets.
6. **Operations and compatibility**
   - new concurrency/rate/quota config parsing, validation, and fixed override;
   - API/website docs update;
   - dashboards, alerts, load/chaos tests, rollout and rollback tooling.

### Source-level implementation map

| Action | Repository path / responsibility |
|---|---|
| Add | `src/dispatch/submission.rs`: cross-channel manifest, target materializer, recovery, and summary contracts |
| Add | `src/dispatch/outbox.rs`: storage-neutral provider job/state contracts |
| Add | `src/dispatch/scheduler.rs`: owned provider loop, leases, sweep, shutdown |
| Add | `src/dispatch/adaptive.rs`: deterministic concurrency controller |
| Add | `src/dispatch/rate.rs`: local token bucket and shared quota grants |
| Add | `src/dispatch/apns_lanes.rs`: alert/Live Activity/Widget fairness and coalescing |
| Rewrite | `src/dispatch/workers.rs`, `runtime.rs`, `config.rs`, and `src/runtime_config.rs`: remove volatile payload queues/profile coupling |
| Rewrite | `src/providers/apns_client.rs`, `fcm_client.rs`, `wns_client.rs`: one attempt and classified result, no retry sleep |
| Convert producers | `src/api/handlers/message/dispatch/*`, `activity.rs`, `widget_push.rs`, and MQTT/MCP command adapters: transactional durable acceptance |
| Add storage APIs/migrations | `src/storage/storage/*` plus SQLite/PostgreSQL/MySQL access/bootstrap modules: outbox, quota windows, projection repair, conformance |
| Harden private | `src/delivery_core/execution/private.rs`, `src/private/hub/outbox.rs`, and `src/private/runtime_tasks/fallback.rs`: durable-before-realtime, no eviction/attempt-count deletion |
| Integrate | application startup/shutdown: feature epoch, scheduler ownership, readiness and metrics |

The first implementation change should add a source-boundary test that rejects any correctness-bearing `try_send_*` payload queue, private realtime send before durable enqueue, retry sleep or logical delivery semaphore inside a provider adapter, profile reference in a provider scheduler, or terminal deletion of an unexpired accepted alert.

### Configuration target

Replace:

```rust
DispatchRuntimeTuning { worker_count, queue_capacity }
ProviderRuntimeTuning { apns_max_in_flight, fcm_max_in_flight, wns_max_in_flight }
```

with independently validated policy:

```rust
struct ProviderDispatchPolicy {
    apns: AdaptiveLanePolicy,
    fcm: AdaptiveLanePolicy,
    wns: AdaptiveLanePolicy,
    rate: ProviderRatePolicies,
    durable_capacity: DurableCapacityPolicy,
    retry: ProviderRetryPolicies,
}
```

`GatewayRuntimeProfile` no longer appears in provider scheduler constructors.

## 16. Migration and rollout

### Schema compatibility

- migrations are additive first;
- for the supported single-instance rollout, audited v11 is not a v12 reader and fails closed on the newer schema;
- before the first v12 durable write, v11 rollback requires restoring the verified pre-v12 snapshot; after a v12 durable write, only the preserved v12-aware emergency artifact may inspect, hold, or drain the database;
- new binaries can create/write/claim manifest and outbox rows on all backends;
- destructive cleanup of obsolete provider queue fields happens only in a later release.

### Safe enablement

1. Deploy schema and code with durable scheduler disabled.
2. Shadow-materialize provider jobs and compare payload/target decisions without claiming them; purge shadow rows by explicit namespace.
3. Enable durable production writes while old volatile workers remain disabled for those jobs.
4. Verify all producers use the durable path through source-boundary and runtime counters.
5. Remove volatile job payload queues after the observation window.

Single-node SQLite uses a stopped-writer maintenance restart for the cutover. Multi-instance deployments must not run old and new workers on the same production job and remain outside the certified deployment contract.

### Mixed-version and feature-epoch matrix

| Combination | Required behavior |
|---|---|
| New producer + new scheduler, same active epoch | manifest/materialize/claim normally |
| New producer + old volatile worker | old worker cannot consume the durable namespace; volatile producer path is disabled |
| Old producer + new scheduler during cutover | routed to a separate shadow/legacy namespace; never dual-produces one target |
| v12 database + audited v11 binary | v11 fails closed; it cannot admit, claim, reinterpret, or delete v12 work |
| v12 database + preserved v12 emergency artifact | read-only plan may inspect/hold; normal scheduler may drain after forward-fix validation |
| Stale lease result from prior epoch | fenced update affects zero rows |
| Schema newer than binary's supported reader | fail readiness and admission; do not reinterpret or delete rows |

For the single-instance release, schema mismatch keeps admission closed through the existing startup/upgrade schema check. Writer/scheduler feature epochs remain a future prerequisite for multi-instance operation.

### Rollback

Production enablement is a forward-only data boundary because accepted manifests/outbox rows do not exist in v11. Disable new admission, leave durable rows intact, and use the exact preserved v12-aware emergency artifact to inspect/hold or drain after validation. Never deploy v11 against schema v12, delete pending rows, relabel schema metadata, or reenable a volatile path that reports durable rows complete. The executable single-instance contract is maintained in `release/V12_SINGLE_INSTANCE_ROLLBACK.md`.

## 17. Verification and acceptance gates

### State/store tests

- submission manifest + targets + dedupe acceptance atomicity;
- idempotent cross-store private/MQTT materialization and crash recovery;
- a transient later-target failure cannot clear dedupe after an earlier durable side effect;
- claim exclusivity, lease expiry, stale result rejection;
- retry and TTL transitions;
- direct and wakeup pull-cache prerequisite crash at every boundary; provider success retains the cache until client ACK/TTL;
- Widget/Live Activity coalescing without alert coalescing;
- SQLite/PostgreSQL/MySQL logical conformance.

### Scheduler/controller tests

- empty -> burst initial -> fast ramp -> idle minimum;
- 429/Retry-After, 5xx, latency spike, local DB contention, and recovery;
- APNs token-scoped throttle does not freeze unrelated tokens;
- alert reservation and work-conserving borrowing;
- fresh/retry fairness near TTL;
- fixed-concurrency override;
- local token-bucket behavior, shared-window grant atomicity, expiry, and ten-instance aggregate quota;
- no task/future remains unowned on shutdown.
- no provider adapter contains logical delivery queuing, retry sleep, or a second concurrency semaphore.

### Fault and chaos tests

- kill before/after durable acceptance, claim, provider request, and result commit;
- full/closed hint channel;
- DB busy/pool exhaustion, connection reset, DNS/TLS failure, provider timeout;
- 10x/100x burst on small SQLite and external DB;
- one tenant/channel flood versus unrelated urgent work;
- provider outage followed by recovery without retry wave;
- route replacement during lease;
- hard durable high-water without accepted-row eviction;
- private fallback beyond former max attempts and until TTL/ACK.
- online private fast path under process kill, proving durable enqueue precedes realtime send.

### Native gates

- formatting, lint, unit/integration tests;
- database migration/release tests for all three backends;
- provider adapter mock-server tests for headers/status/Retry-After;
- current API/MQTT/MCP compatibility suite;
- load test with latency histograms and durable-oracle reconciliation;
- single-instance v11 fail-closed and exact v12 emergency-artifact hold/drain tests; feature-epoch rollout remains a future multi-instance gate;
- zero-data-loss gate proving `accepted provider jobs = terminal + blocked_pull_cache + pending + retry_wait + leased`, modulo explicit TTL/cancel/supersession; `preparing` is excluded because it cannot send and is still represented by an accepted manifest target;
- submission gate proving every accepted target is `materialized + explicitly_rejected + pending_materialization + expired_by_TTL`, with no unowned identity;
- cross-system gate proving every Gateway ACK deletion has a prior Apple durable payload or deterministic-discard tombstone.

## 18. Red-team / blue-team review record

### Round 1: “Only decouple APNs workers”

**Red:** APNs gets faster, but queue full still records failure, retry sleeps still occupy workers, Widget/Live Activity still disappear, and process crash still converts queued work to unknown without resend.

**Blue:** Make provider intent durable before acceptance, then decouple all providers. Memory queues become hints, and clients perform one attempt.

**Verdict:** the minimal APNs-only patch is rejected as incomplete. Durable provider outbox is required.

### Round 2: “Remove limits and auto-spawn aggressively”

**Red:** Unbounded tasks and queues turn bursts into OOM, socket exhaustion, DB write storms, and provider 429/5xx retry amplification. Rapid worker churn does not represent actual upstream capacity.

**Blue:** Keep tiny persistent schedulers, scale only logical in-flight work, preserve independent hard maxima and durable byte/row limits, and feed upstream congestion into AIMD-style control.

**Verdict:** hard caps remain. Deployment-profile caps are removed from provider throughput.

### Round 3: controller instability and database bottleneck

**Red:** A queue-delay controller can oscillate, multiple instances can each scale to max, and durable writes may become slower than the network path.

**Blue:** Add 500-ms controller windows, EWMA, cooldown/hysteresis, scope-aware circuits, fixed override, lease-bounded claims, and DB high-water feedback. Concurrency is separated from local rate tokens; multi-instance credential quotas use atomic small database grants rather than trusting every instance to divide the quota correctly. Benchmark gates prevent blind promotion.

**Verdict:** accepted with deterministic algorithm and kill switch; adaptive behavior is not allowed to bypass DB/upstream brakes.

### Round 4: retries, fairness, and other channels

**Red:** Moving retries to storage can let old retries starve fresh alerts. APNs Widgets/Live Activities may steal alert streams. Private outbox still evicts old accepted work and drops after max attempts.

**Blue:** APNs uses weighted work-conserving sublanes with alert reservation; fresh/retry shares are bounded; latest-state workloads coalesce; private terminal policy becomes ACK/TTL/explicit retirement rather than capacity eviction/attempt count.

**Verdict:** accepted. The Gateway plan covers all outbound correctness-bearing channels, not only APNs alerts.

### Round 5: exactly-once claims and rolling deployment

**Red:** A timeout after provider acceptance can be retried and duplicate a notification. Mixed old/new instances can send the same job or leave new rows idle.

**Blue:** State the contract as at-least-once, preserve stable identity/collapse/client dedupe, compare lease generation on result, and gate claim ownership by a deployment feature epoch. Old/new production workers never consume the same job namespace.

**Verdict:** accepted. “Exactly once” is explicitly not promised; durable at-least-once and idempotent presentation are the implementable guarantee.

### Round 6: Dev Flow cross-channel acceptance and recovery challenge

**Red:** A provider outbox alone does not own a mixed private/provider operation. Private work can commit before a later provider error clears dedupe; the private online fast path can bypass durability; a direct provider job can lose the recovery cache if the redesign only blocks wakeup; adapter semaphores can silently double-limit the adaptive scheduler; and a pre-outbox rollback binary cannot see accepted rows.

**Blue:** Commit a cross-channel submission/target manifest with dedupe; idempotently materialize every target and derive partial status from durable target facts; force private durability before realtime; block direct and wakeup recovery-capable jobs on pull cache; make the lane scheduler the sole logical concurrency owner; fence results by lease generation; and, for the single-instance release, require v11 to fail closed plus an exact preserved v12-aware emergency artifact. Feature epochs remain mandatory before multi-instance rollout.

**Verdict:** accepted after design changes. These constraints close loss windows that provider-lane tuning alone cannot address.

### Round 7: terminal replay, saturated capacity, and slow-attempt challenge

**Red:** Releasing a private slot is not enough if the frozen manifest remains on a long retry lease; deleting an ACKed row lets a late frozen replay or stale provider page resurrect it; an idempotent payload upsert can overwrite the original bytes; a malformed frozen submission can consume capacity forever; and a provider request lasting beyond its lease can be attempted concurrently after reclaim.

**Blue:** Capacity waiters are registered non-destructively and ACK/cleanup emits an immediate recovery notification plus fenced lease release, with the periodic sweep retained only as a crash/lost-signal fallback. ACK becomes a 36-day terminal tombstone that outlives the 35-day frozen manifest and is checked before any fallback, WebSocket, or MQTT accelerator. Private payload insertion is immutable. Poison manifests are atomically failed and reclaimed. Provider claims renew through a fenced heartbeat during all slow validation/request/fallback phases, retry claims are given a bounded share, and half-open circuits admit one atomic probe.

**Verdict:** accepted for the single-instance contract. Remaining duplication is limited to the unavoidable external-provider unknown-outcome window of an at-least-once system; clients must still deduplicate stable delivery identity.

The final clean-context performance pass also required a composite retry-expiry index on all three backends: `(provider, state, expires_at, next_attempt_at, accepted_at)`. This supports the near-TTL retry ordering without relying on an in-memory sort or a million-row backlog scan; the ordinary fresh-work due index remains separate.

### Round 8: invalid-candidate race and database power-loss configuration

**Red:** A pull worker can classify candidate bytes as invalid, race with a valid canonical replacement for the same identity, and then terminalize/ACK the newer valid row. Separately, successful SQL commits do not imply the declared durable boundary if SQLite, PostgreSQL, or MySQL is configured for weaker crash persistence.

**Blue:** Invalid-discard settlement now uses compare-and-swap over the exact candidate bytes and immutable identity on SQLite, PostgreSQL, and MySQL; a changed row updates zero records and is re-read/reclassified. Every correctness backend reads effective durability settings at startup and fails closed on the unsafe combinations recorded in section 6.2. Backend tests exercise both safe and unsafe configurations against real PostgreSQL/MySQL processes and an actual SQLite pool.

**Verdict:** accepted for the configured single-instance backends. Filesystem/controller guarantees below the database contract remain an infrastructure property and require production recovery drills.

### Round 9: authentication hard cap and replay-log amplification

**Red:** An unreleased main-branch change reversed the v1.3.0-beta.1 channel-auth policy: it put Argon2 on every channel send and attempted BLAKE3-to-Argon2 migration. A four-slot `try_acquire` then rejected legitimate concurrent sends, so a compatibility change became both a latency and availability failure. Non-deterministic `HashMap` postcard order also makes semantically identical private replays look different, producing a warning storm and obscuring real conflicts.

**Blue:** v1.3.0-beta.1 semantics are restored: new and existing salted BLAKE3 hashes verify synchronously without entering any Argon2 queue, flight, or success cache. Argon2 is legacy-read-only compatibility; identical legacy `(channel, stored hash, input)` checks share one bounded flight, successful verification rewrites the row and channel cache to salted BLAKE3, and failures are never cached or migrated. Legacy Argon2 execution remains globally bounded at four and unique admission at 128; the typed busy result is preserved through Delivery Core and maps to retryable HTTP 503 `server_busy` plus MQTT 5 `QuotaExceeded`, never an internal 500/implementation-specific error. The proof cache retains only a process-keyed digest and the migrated BLAKE3 hash, never plaintext. New private envelopes sort map keys deterministically while retaining the postcard map wire shape; historical raw-byte differences are decoded and compared by full envelope semantics before warning.

**Verdict:** accepted after a 600-way current-BLAKE3 test completed with zero Argon2 executions and no stored-hash rewrite, while a 600-way legacy-Argon2 test completed with exactly one verification and converged every caller plus the database/cache to BLAKE3. Wrong legacy inputs and failed database upgrades were not cached or falsely migrated; leader cancellation woke followers and a subsequent retry converged; a fixed beta.1 fixture remained readable; unknown PHC schemes were rejected; HTTP/MQTT busy mappings remained retryable. One hundred real legacy-order enqueue replays emitted zero conflict events, and final optimized-binary burst/soak runs completed without KDF-capacity or replay-conflict warnings.

## 19. Dev Flow validation and evidence status

The design was revalidated using the Dev Flow routes selected for `persisted-data`, `distributed-state`, `migration`, `ordering`, and `version-compatibility` risk:

| Method | Challenge applied | Result |
|---|---|---|
| Repository grounding | Re-read current dispatch ordering, dedupe settlement, private fast path, provider pull cache, Tokio runtime, provider semaphores, and retry ownership | passed; three current correctness boundaries are recorded in section 2 |
| Requirements/state refinement | Separated submission acceptance, target materialization, provider attempt, provider acceptance, client ACK, and TTL terminality | passed after manifest and revised equations |
| Cross-participant flow | Traced direct/wakeup provider cache through Apple durable ingress and ACK deletion | passed with G16 and the cross-system oracle |
| Single-instance v12/v11 recovery | Audited v11 rejects v12 without mutation; exact v12-aware artifact inspects and preserves durable backlog | passed locally with temporary SQLite drill; exact release artifacts and restore clone remain release gates |
| Parallel expand/contract + mixed versions | Requires old/new producer, scheduler, schema, lease, namespace, and rollback exercise | deferred with multi-instance topology; requires feature epoch and separate certification |
| Weak-oracle challenge | Rejected queue/status/log success and reconciled durable identities across manifest, target stores, provider outbox, pull cache, and Apple ACK | passed in source/state tests; cross-process Gateway/Apple harness is not run |
| Tokio specialist review | Checked multi-thread runtime/features, task ownership, channel semantics, cancellation, blocking inventory, and hidden double limiting | passed; adapters are single-attempt and owned scheduler tasks hold retry/concurrency authority |
| Independent clean-context review | Separate Gateway-capacity and cross-system reviewers challenged leases, fairness, ACK replay, capacity wakeup, payload identity, poison recovery, KDF saturation, durability settings, and log amplification without relying on the implementation author's conclusions | passed after Round 9 fixes; findings were converted into executable regressions |
| Identity-ledger fallback | Formal ontology review lacked a separate domain expert; froze submission, target, Gateway URL/device/delivery, route revision, and contract identities and prohibited lossy merge | conservative fallback applied; domain-owner review remains advisable during implementation review |

Evidence labels are intentionally narrow:

| Evidence | Status |
|---|---|
| Current-source/runtime-configuration facts | VERIFIED by source inspection on 2026-08-21 |
| Architecture/state/migration document closure | PASSED |
| Product implementation | IMPLEMENTED in the working tree through 2026-08-21; not committed or deployed |
| Rust format/lint/unit/integration tests | PASSED on the final working tree: `cargo fmt --all -- --check`, `cargo check --all-targets`, `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check`, shell/Python benchmark-script validation, and `PUSHGO_REQUIRE_EXTERNAL_DB_TESTS=1 cargo test --all-targets` (580 library tests, 19 binary tests, and every integration/black-box/migration/architecture target) |
| Database migration/conformance | SQLite, PostgreSQL, and MySQL migration/runtime tests PASSED against real local/container-backed database processes |
| Provider mock/load/chaos tests | Provider mocks, SIGKILL/restart, authenticated 500-request/eight-target provider outage, 4,000-row Ctrl-C/restart, post-BLAKE3 profiling-binary 600-RPS burst (600/600, p95 289.66 ms, p99 306.47 ms under a saturated single-SQLite write hotspot), post-BLAKE3 1,200-request/40-RPS soak (1,200/1,200, p95 18.65 ms, p99 24.93 ms), release-binary 200-request public flow, release-binary 32-row private hard restart, black-box ingress/ACK, slow-lease heartbeat, fresh/retry fairness, half-open probe, terminal-replay, immediate capacity-recovery, and retry-index query-plan suites PASSED; final load log contained zero KDF-capacity, API-error, or private replay-conflict events |
| Cross-system Gateway/Apple fault harness | NOT RUN |
| Live strangler/canary evidence | NOT RUN; no deployment was authorized |

The implementation is locally certified for the supported single-instance/mock-failure envelope. Multi-instance operation is deliberately outside the current deployment contract and is not a blocker for that topology. Production release still requires authorized real-provider, cross-system, exact-artifact restore-clone/emergency, and canary evidence.

## 20. Release-enablement checklist

No unresolved blocker remains for the tested single-instance local envelope. Before production enablement, owners must confirm operational values and execute the external gates:

- initial durable row/byte budgets per backend;
- actual shared APNs/FCM/WNS credential quota values, or an explicit declaration that only provider-feedback limits are available;
- compatibility observation duration for `provider_queued` semantics;
- release window for the SQLite single-node cutover.

If multi-instance deployment is introduced later, it requires a separate shared-credential quota, partition, feature-epoch, and load certification before that topology is supported.

Unknown throughput is handled by benchmark gates and conservative compiled bounds. Operational overrides must be implemented and verified before they are used as an incident-response control; their absence is not a reason to return to volatile queues or unbounded workers.

## 21. Primary references

- Tokio, [Channels and bounded backpressure](https://tokio.rs/tokio/tutorial/channels)
- Tokio, [Graceful Shutdown](https://tokio.rs/tokio/topics/shutdown)
- Tokio, [JoinSet](https://docs.rs/tokio/latest/tokio/task/struct.JoinSet.html)
- Tokio Util, [TaskTracker](https://docs.rs/tokio-util/latest/tokio_util/task/task_tracker/struct.TaskTracker.html)
- Apple, [Establishing a connection to APNs](https://developer.apple.com/documentation/usernotifications/establishing-a-connection-to-apns)
- Apple, [Handling notification responses from APNs](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns)
- Firebase, [Best practices when sending FCM messages at scale](https://firebase.google.com/docs/cloud-messaging/scale-fcm)
- Firebase, [FCM error codes](https://firebase.google.com/docs/cloud-messaging/error-codes)
- Microsoft, [WNS overview](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/wns-overview)
- Microsoft, [Troubleshooting WNS push notifications](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/troubleshooting)
- AWS Builders' Library, [Timeouts, retries, and backoff with jitter](https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/)
- AWS Builders' Library, [Avoiding insurmountable queue backlogs](https://aws.amazon.com/builders-library/avoiding-insurmountable-queue-backlogs/)
