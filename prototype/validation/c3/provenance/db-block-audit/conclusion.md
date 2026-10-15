# SQLite code-5 owner failure: bounded source audit

Recommendation: change write-lock acquisition, not the runtime retry policy. `BEGIN IMMEDIATE` on the existing claim transaction is the narrowest owner-driver repair supported by this failure. `maintain_tx` does not own a transaction; it must continue using the caller's atomic transaction. Applying explicit write intent consistently to all ten runtime write transactions is also coherent, but extends the behavior change beyond the one observed owner-driver path. It takes the writer reservation before validation/read work and may alter contention latency for unauthorized/no-change control calls. No transaction should be split and no write lock should be added to plain Pull/status/authorization reads.

## Exact evidence and identity

First preserved failed run: `runs/matched-observerfix-baseline-db-block-r1`. Plan binds control commit `cb0da19cfc1ca542e14a19e506a086a830103bcd`, binary SHA-256 `78878755b3a1816b4f0dcd4a4ea1e9e1525e3ce60a868773fae6040f27224f47`, runtime SHA-256 `93f8e77399b8617b3322ff323951a49694d3f2cb4d806a6223b859a2087d02e9`, store SHA-256 `0cf98d145642fcf7005243cee56941e6861e71ea04d6218956d2557e0e0c132a`.

Requested candidate audit is immutable commit `10e59ec97230550216bc00aa3fe8c924b02510e1`; captured `runtime-10e.rs` has the identical runtime hash. Its `store-10e.rs` SHA-256 is `2c1539a481375d7acd8530828de4134c8cf4683d1703739b6424febed2b11488`. Git diff control→10e shows only the retirement JOIN→CROSS JOIN SQL difference, no lock or error-policy change. This audit uses captured commit source, not concurrently edited working-tree bytes.

Recorded blocker acquired at `1792035646541` ms and released at `1792035648562` ms (2,021 ms). Eight first-wave requests received product JSON 503 around `1792035646578–6580`, roughly 32–35 ms after request start, well before the configured 3-second busy wait; subsequent responses were connection-refused proxy HTML. The next same-identity wave also failed after release. Log line 6 is exactly `FATAL owner driver: database: error returned from database: (code: 5) database is locked`. The run's first-failure receipt and classification remain unchanged; no rerun was performed.

## Confirmed propagation, inferred SQL boundary

`runtime-10e.rs`:
- claim future calls `claim_reserved` at line 235; `outcome?` at 249 exits the pump on any claim error.
- attempt errors escape at line 269; authorization error exits attempt at 286, and receipt `settle` error returns at 313/407.
- task owner lines 76–79 count any pump error, publish failure and request stop. Fixture `wait_failure` branch line 155 prints FATAL and exits 70.
- there is no SQLite BUSY/LOCKED classifier, transaction retry, delayed re-claim, or database-backoff state. Provider-result retry at 362–374 is a separate policy (10-second minimum, 429 minimum 60 seconds); it does not handle SQL failures.

`store-10e.rs`:
- SQLite is WAL/FULL with `busy_timeout(3s)` at 316.
- claim uses default SQLx BEGIN at 1683, then immediately runs `maintain_tx` at 1686. `maintain_tx` first calls `retire_token_targets_tx`; that helper SELECTs the marker/target join (777), then, with an empty marker set, next executes marker GC DELETE (787). Thus claim has a definite read-before-write transaction-upgrade window, even when maintenance changes zero rows. Accept has the same pattern after its auth SELECT. `AdmissionWake` is installed before accept BEGIN (1221), so a failed accept can still wake both pumps after releasing the transaction/gate.
- settle uses default BEGIN at 1813 but its first SQLite operation is the target UPDATE; it does not create this same read-before-write upgrade window. A first write can wait via SQLite's busy handler before a read snapshot is retained.

The receipt proves a pump-origin database error and fast process failure during injected contention. It does **not** name the failing SQL, provider pump, extended code, or transaction phase. The static claim→maintenance→SELECT→DELETE chain is the earliest concrete upgrade candidate, not an observed failing SQL location. Last periodic stats show warmup receipt/network work already drained, which supports claim as the likely origin, but cannot replace statement-tagged error evidence.

## Why BEGIN IMMEDIATE is the correct first boundary

Installed SQLx 0.8.6 `connection/worker.rs:210–224` uses default ANSI `BEGIN` when no custom statement is given; `sqlx-core transaction.rs:277–279` confirms this is `BEGIN`, hence deferred. Installed libsqlite3-sys 0.35.0 SQLite source `sqlite3.c:75126–75141` explicitly states an existing read-lock upgrade can return BUSY without invoking the busy handler; the loop at 75263 only invokes it when there was no transaction. WAL writer-lock code at 69572–69590 returns BUSY for an active writer and BUSY_SNAPSHOT if the read snapshot is no longer writable. Therefore increasing busy_timeout alone is not a repair for an already-open read transaction.

Acquire the writer reservation before the transaction's first read using SQLx's existing `Connection::begin_with("BEGIN IMMEDIATE")` interface; preserve the SQLx Transaction guard and explicit post-COMMIT pool return. This moves contention to a boundary that can use the already-configured 3-second busy wait. The measured 2.021-second blocker fits that budget; success remains a prediction until the authorized focused contention oracle passes. Gate/pool/transaction atomicity, adoption-after-COMMIT, durable running grants and provider H32/Q32 remain intact.

The narrowest change is `claim_reserved` only: its maintenance runs in that same transaction, and receipt is write-first already. For consistent declared write intent, all ten runtime transactions may use IMMEDIATE. Existing read-first transactions are claim, standalone maintenance, accept, provider-token retirement, subscription, legacy Pull. Existing write-first transactions are registration (alias DELETE), route update/coalesce, ACK, receipt settlement. Startup initialize is a separate fail-start boundary. Changing only claim is not a promise that every HTTP mutation avoids short-contention 503s; those are already classified retryable at the HTTP boundary and the retained scenario allows first-wave preaccept failures.

## Deliberately unchanged limits

`BEGIN IMMEDIATE` is not a transient-retry policy. Contention exceeding 3 seconds can still return BUSY and follow the existing fail-stop/restart-recovery path. Startup reclaims durable running grants only after exclusive owner acquisition; it cannot guarantee exactly-once external provider execution when a previous provider outcome was unknown.

Adding runtime retries would be a separate product policy: a failed claim needs rollback/fresh whole-transaction retry and preserved cancellation/adoption rules; a failed receipt must retain the already-known provider result and same attempt identity and retry persistence, never blindly repeat the network send or ignore the error and strand running rows. Non-lock database failures remain fail-stop. None of these policies is required to address the measured sub-timeout read→write upgrade, so no helper/backoff/retry machinery is recommended in this slice.

Verification should preserve the original failure, test bounded external write-lock release below the existing timeout, require same-identity recovery and stable wire/ACK outcomes, and retain an explicit beyond-timeout fail-stop boundary if that policy is kept. No load, SQLite execution, Rust build, or product edits were performed by this audit agent.
