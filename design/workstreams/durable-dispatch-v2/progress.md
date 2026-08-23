# Durable dispatch v2 progress

Status: 1.3.0 local release gates are complete for the declared single-instance topology. Production provider, device, restore, canary, tag, push, and deployment operations are intentionally not run and are not publication prerequisites for this release decision.

Completed:

- target architecture and Dev Flow design validation;
- repository/Git/runtime baseline;
- additive v12 schema for frozen submissions and durable provider outbox on SQLite/PostgreSQL/MySQL;
- operation dedupe + frozen target snapshot atomic acceptance and owned restart/stale recovery;
- APNs/FCM/WNS single-attempt adapters, provider-minimum-aware Retry-After/backoff ownership, adaptive independent lanes, short aggregate failure probe circuits, fenced leases, route fencing, Widget/Live Activity coalescing;
- direct and wakeup provider recovery copies retained until Apple ACK/TTL;
- invalid provider-pull discard settlement compares the exact candidate bytes and immutable identity on SQLite/PostgreSQL/MySQL, so a stale classifier cannot terminalize a concurrently replaced valid row;
- durable-backend startup gates: SQLite rollback journal + `synchronous=EXTRA` live readback, PostgreSQL `synchronous_commit`/`fsync`/`full_page_writes`, and MySQL redo/doublewrite/binlog settings fail closed before correctness writes when unsafe;
- private/MQTT durable-before-realtime, no accepted-row eviction, and event-driven capacity recovery after ACK/cleanup;
- terminal private-ACK tombstones retained for 36 days (one day longer than frozen submissions), so a late replay cannot resurrect an acknowledged delivery while terminal rows consume no active capacity;
- immutable private payload insertion and post-ACK suppression of fallback/WebSocket/MQTT accelerators;
- poison frozen submissions atomically terminalized with sender-visible failure instead of retrying forever;
- provider leases renewed by fenced heartbeat during slow external attempts, bounded fresh/retry fairness, atomic half-open probes, and independent APNs Alert/Live Activity/Widget lanes behind one global APNs safety gate;
- a backend-neutral `(provider, state, expires_at, next_attempt_at, accepted_at)` retry-expiry index so near-TTL fairness does not degrade into a large-backlog sort/scan on SQLite, PostgreSQL, or MySQL;
- producer cutover, continuous sender-status repair/finalization, startup and shutdown integration that stops new durable claims while preserving backlog for restart;
- recovery-safe sender projection ordering: projection first, dedupe terminal second, with a pending frozen manifest on projection failure;
- public password-guess limiting that does not throttle authenticated SharedToken traffic;
- benchmark v2 pull/ACK semantic validation and private WSS ACK/redelivery black-box coverage;
- Rust format/check/clippy and focused/full local tests, including architecture boundary tests.

Verified locally:

- SQLite, PostgreSQL, and MySQL schema/migration/runtime behavior using real container-backed databases;
- source and state-machine boundaries;
- provider retry/concurrency/lease/coalescing and provider-specific HTTP response behavior under mocks;
- private and provider-ingress black-box paths;
- SIGKILL/restart preservation for provider retry, frozen submission, and private outbox state;
- a 280-request spike plus 1,200-request soak: all HTTP requests succeeded, p95 was approximately 33 ms, RSS settled near 51 MiB, file descriptors stayed at 18-20, and SQLite WAL returned to zero;
- an authenticated 500-request provider-outage run with eight APNs targets per request: 500/500 HTTP 200, p95 36.28 ms, and all 4,000 provider jobs remained durable;
- the same 4,000-row outage backlog restarted and resumed, while the failure probe circuit reduced settled-state CPU from approximately 174% in the reproduced pre-fix build to 2.8% after ingress;
- Ctrl-C with the 4,000-row immediately-due outage backlog exited with code 0 in approximately one second, with no worker abort and all 4,000 rows preserved; restart resumed retry attempts;
- final `PUSHGO_REQUIRE_EXTERNAL_DB_TESTS=1 cargo test --all-targets`: 580 library tests, 19 binary tests, and all integration/black-box/migration/architecture targets passed with zero failures;
- private-capacity regression: ACK capacity release signals recovery and makes the frozen delivery runnable within the test's 500-ms oracle; an injected transient lease-release failure retains the registry entry and succeeds on the next accelerator pass;
- final profiling-binary load after restoring BLAKE3: a 600-RPS hot-channel spike completed 600/600 with p95 289.66 ms and p99 306.47 ms under the intentionally saturated single-SQLite write hotspot; a 1,200-request 40-RPS soak completed 1,200/1,200 with p95 18.65 ms and p99 24.93 ms. Both runs had zero HTTP failures and zero KDF-capacity/API-error warnings; the resulting database contained only salted-BLAKE3 channel hashes and no Argon2 rows;
- final release-binary preflight (binary SHA-256 `3c87d7759a07730efec2602a34f792d741896beb3ce25ec9fa4fea37ac62e768`): SharedToken-authenticated public flow completed 200/200 requests with no 429/503, full and partial channel-sync persistence matched the database oracle, and the private hard-restart flow retained 32/32 active outbox rows with no source drift;
- Apple ingress quality suite: 24 XCTest + 365 Swift Testing = 389 tests plus the opt-in 100,000-item runtime-quality suite passed; unsigned iOS, macOS, and watchOS builds (including NSE/Widget embedding) passed;
- final `cargo fmt --all -- --check`, `cargo check --all-targets`, `cargo clippy --all-targets --all-features -- -D warnings`, `git diff --check`, and Python benchmark-script compilation passed.

Completed release-spike remediation:

- restore the v1.3.0-beta.1 policy: generate and directly verify salted BLAKE3 for current channel credentials, with zero Argon2 work and no rewrite on the normal send path;
- retain Argon2 only as bounded legacy-read compatibility: coalesce identical legacy channel/hash/input verification, then atomically converge the database and cache to salted BLAKE3 after success;
- bound unique KDF admission/wait and return retryable HTTP 503 overload semantics instead of internal-error 500;
- preserve legacy-KDF overload as a typed busy result through Delivery Core and map it to HTTP 503 `server_busy` plus MQTT 5 `QuotaExceeded` for both subscribe and publish;
- serialize new private postcard envelopes with deterministic map order and compare historical canonical/candidate envelopes by full decoded semantics before emitting replay-conflict warnings;
- verified a 600-request current-BLAKE3 burst completes with zero Argon2 executions and no stored-hash rewrite; a 600-request legacy-Argon2 burst completes with one verification and converges all callers plus persisted/cache state to BLAKE3; legacy failures and database-update failures are neither cached nor falsely migrated; leader cancellation wakes waiters and permits a clean retry; fixed beta.1 bytes remain readable; unknown PHC schemes are rejected; typed overload survives HTTP/MQTT adapters;
- verified deterministic encoding preserves the postcard wire shape, 100 repeated historical map-order replays emit zero conflict events, and changed payload content/sent time/expiry still conflict;
- final `cargo test --all-targets` passed 580 library tests, 19 binary tests, all black-box/CLI/architecture targets, and real PostgreSQL/MySQL backend tests; fmt, check, clippy with warnings denied, and diff-check passed.

Current release-audit remediation (2026-08-22):

- Gateway receive time now owns Live Activity durable `accepted_at` and expiry; historical `event_time` remains only in the ActivityKit payload.
- The Live Activity update snapshot is frozen in the core durable submission. A supplemental enqueue error keeps that submission pending while preserving committed HTTP success; the normal recovery worker idempotently fills the missing per-token `APNS_LIVE_ACTIVITY` rows, so clients are not told to retry the already accepted main event.
- Latest-state precedence uses a database-issued `acceptance_order` allocated in the same transaction as the durable submission. Provider outbox coalescing compares that order rather than wall-clock or producer event time, so restart, clock rollback, and delayed recovery cannot regress a newer intent.
- `h2` is locked at patched `0.4.16`.
- v11 is explicitly not a v12 reader. The single-instance rollback drill proves fail-closed behavior and backlog preservation; rollback before v12 writes requires the v11 snapshot, while recovery after v12 writes is forward-only with the preserved v12-aware artifact.
- current all-target/all-feature verification passed 588 library tests, 21 binary tests, every integration suite, and live container-backed PostgreSQL/MySQL cases; format, check, all-feature Clippy with warnings denied, `cargo audit`, `cargo deny`, release static audit, and diff checks also passed.
- the exact audited v11 commit was rebuilt from a temporary archive; a generated stopped-writer v11 SQLite family was snapshotted, restored to an isolated clone, and verified byte-stable/readable before the v11-fails-closed/v12-backlog-preserved drill passed;
- three SQLite/MySQL/PostgreSQL parity rounds passed with identical normalized API/database summaries per backend and round;
- the digest-pinned local Docker image built and passed non-root entrypoint/CLI/read-only-data fail-closed smoke; release CI now validates and carries database-gate artifacts into the final checksum chain.

Operational validation not run and not required for publication:

- real APNs/FCM/WNS credentials and provider dashboards;
- production/staging restore, real-provider credentials/dashboards, physical-device delivery, cross-system production, and canary verification;
- provider-outbox byte budgeting and operational lane-limit overrides (the implementation has a one-million-open-row hard admission cap and compiled lane bounds).

Multi-instance operation is intentionally outside the current deployment contract. It is not a release blocker for the declared single-instance topology; enabling it later requires a separate shared-quota/partition certification.

Constraints:

- local commits are authorized; push, tag, release, deployment, and live database migration are not authorized;
- real-provider evidence must remain separate from local/mock tests;
- the proven delivery contract is durable at-least-once until provider terminality/TTL, not exactly-once and not a guarantee that APNs/FCM/WNS or the device OS will deliver within a fixed time;
- under private-outbox capacity pressure, the frozen manifest remains durable while admission is full. ACK/cleanup now emits an immediate in-process recovery signal and eagerly releases a matching fenced lease; the old 20-24-second deterministic wait is no longer the normal path. The five-second sweep and bounded retry schedule remain only as crash/lost-signal safety nets.
