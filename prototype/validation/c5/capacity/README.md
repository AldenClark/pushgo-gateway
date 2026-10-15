# Final C5 finite capacity source inputs

These are exact original harness/observer source copies for product commit
`651bf7e7e4691bd5a78b36625ff34b693be83590`. The original final handoff is
`capacity/final-651bf7/final-handoff-manifest.json` under the external C5 evidence
root; its SHA256 and the reduced outcomes are in `../artifact-identities.json`.
`provenance/stable-source-list.json` is the exact original source inventory. The
parent `../source-provenance.json` records original and packaged hashes.
**These moved files have NOT RUN.** Packaging checked bytes/hashes and Python AST
only; it did not build, apply the patch, call a database, run the static-oracle
programs, launch a process, or repeat a workload.

## Actual final outcome and measurement identity

The ordinary uninstrumented binary (3204f8ac...) and Rust test executable
(173d98ea...) remain separate from observer binary
`52731d4a4599a379984e16734c9b9f304593aefe64b86563c6e7032e2a16e4af`.
The observer combines exact final product source with the bounded post-COMMIT
measurement patch; the observer binary is not included. `observer.patch` is the
exact original SHA256
`0a708c8a7e1e9126d63616c9ab549996d5f7197bbd9293ab364fdf5baf7cb6d3`.
Original unified-diff context includes single-space otherwise-empty lines. Keep
those bytes: trimming them changes this experimental input and its hash. Do not
format the patch to satisfy a blanket whitespace check.

Each backend ran the same finite 256 msg/s x 10s input: 2560 messages, 16 targets
per message, 40960 offered targets, 8 HTTP callers, per-Provider H32/Q32 and 20ms
synthetic peer delay. The cutoff was fixed at planned input end plus 180s (about
190s from offer start); HTTP queues, SQL polling and identity witnessing do not
restart or extend it. First failure and deadline use the earlier cutoff. Preserve
late raw completion events but censor them from in-window successes, and keep
all offered targets in the denominator.

PG completed 40960/40960 targets for this lane. MySQL **FAILED this finite
capacity input**: 7169/40960 in-window successes (17.5024%) and 33791 unfinished.
All messages being HTTP-accepted is not all-target completion. MySQL has no
completed full-target/ACK-drain/post-ACK-idle result. Reducer exit0 only means
receipt reduction completed; it cannot convert the lane into PASS. Conditional
successful-sample quantiles cannot establish all-offered p95/p99. There was no
extra retry, deadline extension, lower input or higher budget to erase this result.
Original `final-e7b6d59/` baseline observer1a996105... and its genuine MySQL failure
remain in their old external namespace, not copied or relabelled final evidence.

## Minimal dependencies and relocation

The runner imports adjacent `c3_mock.py` and `db_os_observer.py`; the offline
reducers and both bounded observer Rust files are included. The two static-oracle
Python sources are preserved as inputs, not executed by packaging.
`prepare_observer.py` can generate the sparse overlay only in a new external OUT
against the exact required product source and anchors. `prepare_and_build_651bf7.py`
and `execute_651bf7_lane.py` preserve original local orchestration, with source,
output, binary and shared-target assumptions. They are not portable defaults and
are not authorized to execute merely by inclusion here. No entire source-view,
symlink forest, overlay product file, target directory or binary is bundled.
The documentation-append utility listed in the original source inventory is
excluded because it is not a harness/reproduction dependency.

Any future reproduction needs the exact source Git objects/clean source bytes,
root and prototype Cargo manifests/locks, cached locked dependencies and Rust
1.97.1 release/offline/locked build, a fresh external OUT, one explicit Cargo
build target, and a separately authorized resource window. The source-only
`c3_pid_rusage.c` must be compiled locally for a matching macOS helper; original
orchestration references the external prior helper binary. No helper binary is
included. The Mach clock and libSystem APIs require macOS. Separately parameterize
source root, build/output/state paths, helper/sampler binary, receipts, runtime
binary/hash, source identity and source commit; retain original-source hashes and
mark any adapted version NOT RUN until actually executed.

Real PG/MySQL runs also need fresh cases from the guarded `../env/isolated_db.py`
and the additional test environment adjustments documented in `../README.md`.
No generated URL/ownership-state receipt is included. The final environment was
cleaned up; old receipt paths are historical, not usable current connections.
The runner loads the owned helper and performs read-only SQL/OS observation only
inside its separately authorized runtime; packaging performed none of that.

## Limits of the finite measurements

Post-COMMIT events record caller-visible COMMIT-await return plus observer
callback, not engine fsync. Gate/SQL/receipt/network stages are nested caller-wall
times and cannot be added; MySQL acquire includes owner-check SQL while PG uses
its pinned mutex. SQL charging and reconciliation bundles do not equal literal
engine statement counts. Profile histogram differences are conservative interior
samples, with log2 bucket bounds rather than exact phase percentiles.

Gateway resources and DB resources remain separate. Native DB PID1 RSS is not
cluster/per-connection RAM; CPU is unavailable across PID churn, and RSS0 process
exit sentinels are not idle memory. Baseline/final DB OS-observation overhead
differs. Startup-idle observation cannot establish no other host load throughout;
Aegir compile activity was observed later without causal attribution. PG's slower
unchanged-path witness and MySQL's dominant claim-select label do not establish a
unique cause, dynamic-load query plan or architecture ranking. Bounded tmpfs does
not establish disk/power-loss durability. No further lane, DB query or optimization
is performed by this bundle. The full scoped interpretation remains in
`prototype/docs/c5-capacity.md` and the external original receipts.
