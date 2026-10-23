# Independent source review: bounded SQLite writer contention

Reviewed candidate delta: uncommitted `prototype/src/store.rs` and `prototype/src/tests.rs` over functional commit `10e59ec97230550216bc00aa3fe8c924b02510e1`. Source SHA256 at review: store `395c54d1034d1dd1422cebac5bc43660704eed0d9e123235a668b8dcf82cecbb`; tests `5676502cd5bc1ac2e71b8b404634acaf62cf988fc91ed28855035b7fd6b9ec04`. Runtime has no diff. Prototype manifest declares edition2024. This report is source and oracle review only; this reviewer ran no build, test, server, or measurement.

Outcome: no verified consequential defect was established in this two-file delta. The change is consistent with the declared policy: SQLite writer contention within the existing three-second budget may recover online; longer contention returns a real error and stops the driver, with previously accepted work recoverable by a later exclusive owner. It does not promise resilience to arbitrary-duration contention.

## Exact change and transaction boundaries

The only production behavioral edit replaces deferred SQLx transaction begins with `begin_with("BEGIN IMMEDIATE")`: initialization/recovery at store.rs:421 and ten existing profiled write transactions at lines472,634,743,839,1236,1407,1529,1616,1686,1816. Added `sqlx::Connection` supplies the connection extension method. The complete diff contains no changed SQL statements inside those transactions, no moved commits, no new retry loop, and no runtime change. The three-second `busy_timeout` remains unchanged. Existing pure reads and standalone autocommit writes are not wrapped in new transactions.

The functions owning these existing transactions were traced through registration, route changes, token retirement, subscription, acceptance, maintenance, destructive legacy Pull, ACK, claim, receipt, and startup recovery. Write reservation moves before transactional reads. Atomic grouping and commit-before-success remain unchanged: acceptance returns its success object only after `tx.commit().await?`; errors propagate rather than fabricate durable acceptance. A duplicate acceptance now also needs the writer reservation because that path already entered a write transaction and maintenance, which is consistent with its prior side effects. The earlier write reservation may extend lock ownership across existing authentication work; no claim of a performance improvement or unchanged latency distribution is inferred.

## Actual SQLx0.8.6 implementation inspected

Read installed sources under `/Users/ethan/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`:

- `sqlx-sqlite-0.8.6/src/connection/mod.rs:250-264`: default `begin` passes no custom statement; `begin_with` invokes SQLx `Transaction::begin` with the supplied statement.
- `sqlx-core-0.8.6/src/pool/mod.rs:391-400`: pool `begin_with` acquires its owned connection and uses the same transaction machinery.
- `sqlx-sqlite-0.8.6/src/transaction.rs`: `SqliteTransactionManager` calls the worker and verifies that a custom BEGIN entered a transaction; nested custom BEGIN is rejected by the worker.
- `sqlx-sqlite-0.8.6/src/connection/worker.rs:210-307`: BEGIN increments transaction depth only on success. A successful BEGIN whose acknowledgement was cancelled is rolled back in the worker. COMMIT decrements depth only on success. A successful COMMIT whose acknowledgement was lost causes the following drop rollback to be ignored; it is not treated as a known rollback.
- `sqlx-core-0.8.6/src/transaction.rs:115-130,260-275`: `commit` consumes the Transaction, leaves it open on a returned error, and Drop queues rollback. The implementation does not add automatic transaction replay.
- `sqlx-sqlite-0.8.6/src/error.rs`: error code reports SQLite extended result codes; no string-based BUSY retry classification was added by this change. `connection/establish.rs` configures SQLite's actual busy timeout.

Therefore SQLx bookkeeping remains intact; this change does not issue raw BEGIN outside its owner. A clearly returned BUSY remains an error, and rollback is queued before subsequent work on that connection. Worker failure, cancellation, or lost COMMIT acknowledgement must not be relabeled a definite rollback or automatically replayed. Final durable identity and restart recovery remain the authority for uncertain outcomes.

## Driver and shutdown behavior

Read the unchanged runtime pump and shutdown paths. Claim futures remain retained across ordinary select events, so an in-progress claim COMMIT is not discarded and replaced. On shutdown the pump drops receipt/attempt futures first, releasing their gate and queuing SQLx rollback, then awaits any preserved claim. Runtime shutdown joins both drivers, closes the SQLx pool, and only then releases the process ownership lock. The existing SQLite wait may delay shutdown by its configured budget; no new sleep, retry task, queue, or kill loop was introduced. Driver errors still request stop and preserve their original error. An accepted external attempt whose receipt was cancelled remains durably running and is recovered after exclusive-owner reopen, retaining the existing bounded unknown-outcome duplicate risk.

## Test oracles inspected

Read the complete `external_writer` helper, both new tests, `idle_runtime`, `ControlledTransport`, and supporting wait/cleanup functions. The blocker uses a distinct real SQLite connection and `BEGIN IMMEDIATE`, independent of the local mutation gate; it is not a fake SQL error.

`sqlite_writer_contention_within_budget_keeps_claims_and_receipts_alive` starts the actual DeliveryRuntime pumps, accepts one delivery, blocks a subsequent claim using the external writer, releases the network result, and checks two live pumps, zero DB errors, one retained attempt, and no committed receipt while blocked. After releasing the external lock it waits for the receipt, ACKs, and expects clean joined shutdown. Its explicit dwell is100ms, not two seconds. This is a focused within-budget engine-contention oracle; the separate two-second capacity lane remains separate execution evidence.

`sqlite_writer_timeout_fails_closed_and_recovers_accepted_identity` retains the external writer until the driver reports code5, checks no committed receipt, releases the lock, observes a failed driver report, reopens under exclusive ownership, and compares entity/message/delivery identities, accepted time, identity expiry, and separately queried absolute payload expiry. It confirms only one original transport start. The corrected `status` lookup is now used for timestamp fields rather than assuming the target-status response contains them. It does not attempt to prove a real provider never accepted the first external attempt; that uncertainty is intentionally handled by recovery.

The first preserved failure diagnostic (`capacity-matched-dbblock-first-failure-diagnostic.json`) proves a real code5 fatal under injected external writer contention and subsequent nonrecovery. It does not identify the exact failed statement/phase, so this review does not claim the initial receipt alone proves the read-to-write upgrade point. Root reports a prior short-lock test pass and a long-lock test oracle failure after reaching its final lookup; the original log is retained. The revised full test run was still root-owned and pending when this report was written; no pass result is inferred from test names or source.

Scope remains local synthetic SQLite/ordinary provider lifecycle. Native execution results, capacity outcomes, real APNs/FCM/Token Service, devices, PostgreSQL/MySQL, production readiness, deployment, push, and merge are not established by this review.
