# C3 source-only reproduction bundle

This directory contains experiment source and finite input manifests. It excludes
raw logs, SQLite databases, binaries, APKs, credential files and staged production
source trees. Apple and Android owners contribute only their `apple/` and
`android/` subdirectories. The common harness is in `harness/`; native SQL input
manifests are in `native-diag-inputs/`; the historical production diagnostic
fixture is in `current500/`.

The original evidence workspace was
`gateway/build/quality-results/c-client-loop-gate-20261015`. Every copied common
file's original OUT path and SHA-256, packaged SHA-256 and relocation description
are recorded in `source-provenance.json`. `provenance/` retains historical
artifact/source hash manifests and execution input identities, not their binaries
or results. Paths inside those historical manifests describe original evidence;
they are not portable execution defaults. Apple/Android have their own manifests.

**The packaged portable variants have NOT RUN.** Packaging performs static Python
syntax/hash inspection only. Original OUT results verify their recorded executed
bytes, not subsequent relocation adapters. Exact-byte copies preserve hash
identity, but copying them does not create another execution result. No build,
service, benchmark or native test was launched to validate this bundle.

The final prior native/control restart evidence is bound to source
`10e59ec97230550216bc00aa3fe8c924b02510e1` and final binary SHA-256
`c22a71df7fc12d8b30a63bfbb24d7f3d8d895f62c35dcab58d2f3d894f1d1e9a`.
Later SQLite BUSY handling or any other product correction is outside that
execution identity and requires newly qualified binaries and receipts. The
historical current-500 diagnostic instead uses production mainline
`dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6`; the early native-SQL source snapshot is
identified by `native-diag-inputs/provenance.json` and original `build-A.json`.
Do not mix those identities into a claimed single tested build.

## Dependencies and execution boundaries

The Python harness uses the standard library only. Use Python 3.9+ for core
scripts; individual Apple/Android instructions may require newer versions.
macOS process resource experiments additionally use `clang`, `/usr/bin/time -l`,
`ps`, `lsof` and optionally `vmmap`; `c3_pid_rusage.c` uses macOS process APIs.
The direct SQLite layout probe requires Python SQLite with `dbstat`. The native
SQL engine uses `ctypes` with an explicitly identified SQLite shared library;
its results are not SQLx runtime profiles. Rust fixture builds require the
corresponding checkout's pinned dependency lock/toolchain and available Cargo
cache or explicitly permitted dependency resolution.

All fixture provider and Remote Token Service endpoints are synthetic loopback
peers. Keep loopback proxy bypass and synthetic credentials. Read
`harness/C3_MOCK_API.md` for finite hold/release and capture semantics. A received
capture does not prove provider acceptance, and a local response write does not
prove remote consumption. True FCM/APNs, production service calls, physical-device
acceptance and release readiness are outside these experiments.

Reserve a single runtime window before executing a build, fixture, SQL scale
probe or native run. Run one selected experiment at a time. Always use a fresh
external output directory; preserve the first receipt and diagnose whether it is
a test-system, observation or product failure before rerunning. Do not launch an
entire campaign merely to inspect its plan. Obtain executable identity from a
frozen build receipt instead of inferring it from current checkout HEAD.

The following examples are instructions, **not executed packaging checks**.
`BUNDLE` means this directory, `GATEWAY` an explicit checkout and `RUN_OUT` a new
output directory outside the source bundle. Supply all required placeholders
before execution.

## Actual Gateway SIGKILL/restart control lifecycle

`harness/run_c3_control_restart.py` has explicit binary/hash/source/output CLI
arguments and no embedded workstation path. It exercises one calibrated
three-message scenario: ACK before held receipt; coalesced capability transfer
and old-token epoch retirement; same-token winner acceptance followed by a real
SIGKILL/new PID reopening the same DB. It allows one external-unknown replay of
the fresh winner operation and requires stable IDs/content/first-time/TTL/30-day
identity, then final ACK/body/queue release. Old dead-peer write failures are
allowed only for their exact pre-kill held capture sequences. This does not
substitute for same-process delayed callback tests.

```sh
python3 -B "$BUNDLE/harness/run_c3_control_restart.py" \
  --binary "$FROZEN_BINARY" --binary-sha256 "$FROZEN_SHA256" \
  --source-commit "$FROZEN_COMMIT" --out "$RUN_OUT"
```

Original final execution relationship:
`control-restart-final-01/{plan,result,processes,quiet}.json`, raw snapshots and
peer JSONL remain in original OUT. The preliminary A-01 urllib observation
failure and fresh A-02 repaired run remain there separately.

## Matched capacity / profiling

Required sibling files are copied together in `harness/`: campaign coordinator,
runner, mock, reducers, `analyse_c2.py` and its `analyse_c1_base.py` import,
`resource_monitor.py` and its `common.py` import. The resource monitor provenance
file identifies the exact tracked production helper bytes used by the historical
execution; only its process metrics path is used by the runner.

The portable coordinator accepts explicit `--out` and `--gateway-root`; it no
longer infers Gateway cwd from the original quality-results layout. Start with a
plan-only call (no `--execute`). A manifest must identify frozen binaries,
source archives/trees, build receipts, profiler source and precompiled kernel
sampler with hashes. Use `harness/capacity-manifest.template.json`; replacing
paths requires recomputing the corresponding manifest hashes, never retaining
old values for new files. Historical matched manifest is in `provenance/` for
identity audit only. The shared helper source was copied exactly.

```sh
python3 -B "$BUNDLE/harness/run_c3_campaign.py" \
  --mode ab --diagnostics --quiescence --run-prefix reproduced
# After runtime clearance and populated immutable manifest:
python3 -B "$BUNDLE/harness/run_c3_campaign.py" \
  --mode ab --diagnostics --quiescence --run-prefix reproduced \
  --manifest "$MANIFEST" --gateway-root "$GATEWAY" --out "$RUN_OUT" --execute
```

The coordinator accepts exact `--select` labels for changed/unresolved claims;
use them instead of redundant full reruns. It preserves first failures. Capacity
rates describe business messages/s, not recipients/s. Short lanes are not
long-duration throughput or production capacity claims. Histogram upper bounds,
completed timing deltas, nested phases and sampled occupancy have the precise
limitations described by the reducers; do not add nested durations or peaks as
independent wall time/resources. `summarize_matched.py` accepts explicit run
paths, so pass retained receipt directories when reducing relocated evidence.

## Native SQLite diagnostic source and finite inputs

`harness/sqlite_native_profile.py --database DISPOSABLE_DB --steps STEPS_JSON`
replays finite SQL steps with the chosen native SQLite library and reports its
identity. Never pass a live ledger. `native-diag-inputs/` preserves the actual
prepared step lists/schema/provenance as historical inputs; it contains no DBs,
query result rows, raw execution logs or production source snapshots.

Preparation helpers now accept `--out`; the initial helper also requires
`--store-source` pointing to the exact recorded historical store source obtained
from an explicit checkout/Git object. It writes its working copy into the new
experiment output, not this package. Later helpers require the disposable files
created by the initial preparation/replay. Their fixed SQL extraction/binding
assumptions describe the original schema/coalesce shape; do not apply them to a
later changed store and label that equivalent. Use the retained finite input
manifests for exact original SQL, or update and newly verify preparation helpers
for changed schemas. Their portable relocation has NOT RUN.

```sh
python3 -B "$BUNDLE/harness/prepare_native_diag.py" \
  --store-source "$HISTORICAL_STORE_RS" --out "$RUN_OUT"
python3 -B "$BUNDLE/harness/sqlite_native_profile.py" \
  --database "$RUN_OUT/synthetic-10000.sqlite" \
  --steps "$RUN_OUT/steps-10000.json" --library "$SQLITE_LIBRARY"
```

The original source hash is
`d5d4bdba79f611b3353dfbfa69337614767a18edeb946067d57b9dbbfcbf8d77`.
The target scan/JOIN experiments do not establish that a later product binary is
behaviorally equivalent; native runtime evidence is separate.

## History / body / queue storage

Native ignored probes live in the product's existing `prototype/src/history_tests.rs`
and are not duplicated here. Use the intended frozen source and a fresh
`C2_HISTORY_OUT` / `C2_HISTORY_WIDTH_OUT` with the corresponding explicitly
selected ignored probe; `provenance/history/execution.json` preserves original
test-binary identity and invocation. Python `c3_history_probe.py` accepts
`--source`, `--source-identity`, `--out` and validates the recorded store hash.
It measures direct-SQL layout only. `c3_history_analyze.py --out HISTORY_OUT`
reduces already-produced native-scale/native-width/layout files without starting
providers. Thirty-day arithmetic projections are not 30-day soak evidence, and
no history hard quota is implied.

## Historical production current-500 diagnostic

`current500/fixture.rs` is the small diagnostic executable source; it imports the
production Gateway library through an explicit clean checkout rather than
copying production implementation. The template and lock file preserve dependency
inputs. `prepare_package.py --mainline-source CHECKOUT --out FRESH_PACKAGE`
requires the exact clean `dfb6b7c2...` checkout, substitutes only its local path,
and materializes a standalone package; it does not build or start it.

```sh
python3 -B "$BUNDLE/current500/prepare_package.py" \
  --mainline-source "$HISTORICAL_MAINLINE" --out "$FIXTURE_PACKAGE"
# Build separately, when authorized; preserve toolchain/profile/build hashes.
cargo build --locked --release --manifest-path "$FIXTURE_PACKAGE/Cargo.toml"
```

`harness/current500_run_compare.py` retains original diagnostic workload logic
but imports the packaged resource monitor siblings instead of an absolute
workstation bench path. All binary/source/build/output inputs remain explicit
CLI options. Read its `--help` before selecting the one diagnostic lane. Original
`current500/build-input.json` relationship is recorded under `provenance/`.
Existing production commit outcomes and preexisting failures must not be replaced
by current candidate inference. No production credentials/services are required.

## Prepared writer-transaction follow-up plan

`harness/run_writerfix_followup.py` was prepared by the capacity owner after the
old matched campaign's primary eight lanes passed and its first db-block lane
failed; the old remaining seven lanes were NOT RUN. This nine-lane follow-up
requires a separately frozen, newly corrected candidate and explicitly forbids
relabeling the old 10e candidate as writer-fix evidence. The original follow-up source subsequently executed nine lanes with nine PASS
under the separately frozen 19cc candidate; `provenance/capacity-final-state.json`
and the source handoff preserve the final states and artifact identities. The
packaged portable form has NOT RUN and additionally requires a fresh external
`--out`; plan-only calls still start no service. Use exact
`--select` labels within a separately authorized runtime window. Do not promote
this regression plan to a new matched architecture/performance comparison.

## Later writer transaction source boundary

Root subsequently created product commit
`19cc5c686419255739776611d1fae25b8ed7b6fa` with explicit write transactions
using BEGIN IMMEDIATE, retaining the existing three-second busy budget and
adding no database retry loop. Its build and writer-fix follow-up artifact
manifest are distinct from the 10e final-client/process-restart/history evidence.
Root reported 82 native Rust tests for that source; this packaging worker did
not execute or independently requalify them. Prior client/restart/history
evidence is reused with its original 10e identity because schema/control wire
were unchanged; reuse is not a claimed rerun on 19cc. The writer-fix plan needs
its own final source/build/hash manifest and retained lane outcomes.

## Compact report evidence retained with source identities

`provenance/history/` carries the compact analysis and arithmetic CSV outputs,
not million-row databases or snapshots. Its measurements retain their original
source/test-binary identity; projections are arithmetic, not long-running
acceptance. `provenance/db-block-audit/conclusion.md` and independent-review
documents are historical audits of their explicitly named revisions. An audit's
found issue must be read alongside the later fix and separately qualified build
receipts, not presented as an unresolved final finding by filename alone.
`provenance/build-final*.json` binds 10e; `build-writer-final*.json` and
`artifacts-profile-writerfix.json` bind the separately corrected 19cc source.
These compact identity/evidence documents are included at root's request and do
not add raw logs, database files or executable artifacts to the bundle.

Final source handoff confirms all twelve common executed-source hashes remained
unchanged through the writer-fix campaign. Historical matched primary8 PASS and
old DBblock FAIL/original7 NOT RUN remain preserved as their original identities;
the later nine writer-fix PASS outcomes have separate labels/source IDs. See
`provenance/capacity-final-state.json` and
`provenance/capacity-source-handoff-current.json`. All owned campaign processes
joined and the capacity owner reported QUIET. No portable package was executed
to obtain those results.
