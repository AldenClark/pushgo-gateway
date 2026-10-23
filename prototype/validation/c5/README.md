# C5 validation source-only bundle

This bundle preserves the exact original environment, MySQL fault and final
native harness input bytes. Source copies at this packaged location have **NOT RUN**. Packaging
performs byte/hash and Python AST checks only; it does not build, start containers,
connect to databases, execute a fault, or establish a new runtime result.
`source-provenance.json` binds each included input to its original absolute path,
original SHA256, packaged SHA256, and relocation execution status.

The original external evidence root is
`gateway/build/quality-results/c5-mysql-ordinary-20261015/`.
`artifact-identities.json` is an explicitly reduced historical artifact identity
receipt. It identifies the ordinary uninstrumented binary and implementation
commit; the binary is not included, and this packaging does not rerun or validate
its behavior. Full original identities and runtime receipts remain external.
Final attempt03 native source inputs are included after their original lane reached QUIET. Earlier attempt02 identities and changed coordinator sources remain explicitly named baselines.
Final capacity source inputs and their exact patch are now included under
`capacity/`; no intermediate dirty overlay or full product override files are
bundled. The finite MySQL capacity failure is preserved and qualified there.

## Included inputs and prerequisites

- `env/isolated_db.py` is the original guarded local lifecycle helper. It requires
  Unix file locks, Docker's existing OrbStack context and socket, and the exact
  cached PostgreSQL/MySQL image digests recorded in the script. It uses
  `--pull=never`, captured ownership checks and fresh synthetic case databases.
  At execution it generates private ownership receipts and URL files; none are
  included here. Run only under the separate task authorization and lifecycle
  ownership appropriate to a new experiment, with fresh external state/output.
- `env/capture_config.py` imports its adjacent helper. Its historical initial
  OrbStack-state description is embedded original experiment context, not a fresh
  observation of another machine. The original environment used bounded tmpfs
  datadirs in the OrbStack Linux VM: transaction/process-crash evidence does not
  establish disk or power-loss durability.
- `fault/mysql_wire_fault.py` accepts explicit `--binary`, `--out`, `--mode` and
  `--env-helper`. It requires a separately verified frozen fixture, a fresh OUT
  and the guarded environment helper's newly owned synthetic MySQL case. The
  loopback packet proxy disables TLS for protocol observation. Modes preserve
  distinct before-COMMIT, lost-OK/unknown outcome, and process/session boundaries;
  this source package itself claims no execution or PASS.
- `fault/mysql_released_session_fence.py` is the exact original focused supplement,
  not a portable runner. It embeds the original source commit, binary SHA256,
  binary/workspace/helper/output paths and depends on the external
  `fault/final-process-first/product-hashes-after.json`. It checks server lock
  absence while the stopped old process still owns the OS file fence. The
  baseline hash receipt and old fault output are not copied here.

## Real-database test environment adjustments

The raw lifecycle helper creates the generated role and fresh databases, but it
is **not a one-command reproduction of the complete executed MySQL test
prerequisites**. This experiment separately adjusted only its owned disposable
MySQL instance after preserving the original environment failures:

- Fresh-case database lifecycle used an explicitly restricted privilege pattern
  `c5\_synthetic\_%` with escaped literal underscores and a final prefix wildcard
  (`partial_revokes=0` in this experiment). Earlier unescaped database-specific
  grants were revoked/replaced to prevent underscore wildcard broadening. The
  helper's later per-case grants escape underscores, but its raw startup does
  not automatically reconstruct the separate prefix-limited role grant used by
  the Rust fresh-case database harness.
- Native fault-injection tests create synthetic triggers. On this instance with
  binary logging enabled, the environment owner separately set
  `log_bin_trust_function_creators=1`; the generated test role was not granted
  `SUPER`. This setting enables the fault harness, not the product ledger's
  accounting implementation.
- The read-only native InnoDB transaction/row-wait observer separately received
  `PROCESS` on this isolated synthetic instance; selective
  `performance_schema` SELECT permission was also recorded. The actual blocking
  witness used the exact connection ID in `INFORMATION_SCHEMA.INNODB_TRX`;
  `performance_schema` was disabled, so its empty lock-wait view was not treated
  as proof that no wait existed. No `SUPER` privilege was required or granted.

These are test-harness/environment prerequisites. Ordinary product operation
does not require the observer's `PROCESS` privilege or the fault-trigger trust
setting. The unchanged raw helper does not automatically apply all these manual
adjustments; inspect and explicitly provision the corresponding scoped test
prerequisites before attempting a future isolated reproduction. Do not grant
these permissions to an unrelated product role or database based on this bundle.
The original nonsecret adjustment receipts remain external under
`env/environment-adjustment-prefix-grants.json`,
`env/environment-adjustment-trigger-trust.json`, and
`env/environment-adjustment-process-row-wait.json`; generated role credentials
and ownership receipts are not packaged. No environment change or database
operation is performed by this documentation update.

## Relocation and absolute paths

Original absolute paths in scripts and provenance describe the original execution
source. They are not working defaults promised by this repository bundle. Never
execute these scripts in the tracked bundle: the environment scripts write state
beside themselves, and the released-session supplement writes its original OUT.
Before a future run, copy to a fresh external OUT, inspect the ownership guards,
and parameterize source root, binary plus hash, env/state root, output root and
baseline hash-receipt input. Preserve the original bytes and provenance; any
parameterized adaptation gets its own hash and an explicit NOT RUN status until
actually executed. Do not relabel moved scripts, AST checks, or a generated
measurement overlay as a runtime result. No automatic build or rerun is supplied.

`references/mysql-is-observer-cache-source.json` records only the official
MySQL 8.4.11 raw-source URL, source SHA256 and original-file line references plus
the bounded observer conclusion. The referenced third-party source is external;
no MySQL source file is redistributed in this bundle. Its `local_file` value is
an original download location, not a packaged dependency. This observation is
scoped to the C5 MySQL native test observer and says nothing about C4 SQLite.

## Excluded material

Explicit whitelist only: no usable database URL or generated credentials,
ownership-state JSON, lock files, logs, database/WAL/SHM, container data,
executables, APK/JNI, wheel/vendor/third-party source trees, Python bytecode,
native source staging trees, previous frozen artifacts or large runtime captures.
Existing C3/C4 evidence remains in its own namespace and is not recast as C5.

## Final native source inputs

`native/` contains exact copies of the final original-location coordinator,
read-only observer/calibration, mock, Apple/Android loops, Android build/identity
verifier, and the single new C5 instrumentation Kotlin file. Small original
hash/identity JSON inputs are preserved byte-for-byte; no native binary or client
production source tree is included. `artifact-identities.json` separates the
final normal Gateway binary (3204f8ac...), Rust test executable (173d98ea...),
and reused C5 instrumentation APK (c95c2dda...), all qualified against final
product commit `651bf7e7e4691bd5a78b36625ff34b693be83590`. Original execution
and QUIET summaries are explicitly derived from the external
`native/attempt-03-summary.json` and `attempt-03-quiet.json`;
these statements are historical receipts, not execution of this relocated bundle.
Original test-system failures and calibration corrections remain qualified in the
summary. Packaging has not rerun native clients, an emulator, a DB or a build.

The C5 Kotlin source SHA256 is 7edf7e40... and is stored under
`native/android/source/`. The preserved `harness-source-identity.json` describes
the older baseline C3 test source (257fced2...), so it must not be used as the
identity of this new C5 test. `c5-test-apk-manifest.json` binds the actual C5 source
to the new test APK and distinguishes the unchanged cached main APK/JNI.
Apple reuses the existing C3 Swift source-only harness in `../c3/apple`; its
cached compiled test bundle is external and its native build was NOT RUN.
Android built the isolated test APK offline; cloned-path dependency tasks also
recompiled production Kotlin, while the installed cached main APK/JNI bytes
remained unchanged. The exact cached JNI source revision remains UNVERIFIED.

`native/observer-dependencies.json` preserves only package/wheel names, versions,
SHA256 and noncredential dependency provenance. No wheel or vendor source is
included. Provide the recorded pg8000/PyMySQL dependency set separately in an
external environment. The original observer adds an adjacent `vendor/` search
path; an empty relocated package does not recreate that dependency environment.
`native/source-dependencies.json` records the original external cache-manifest
path and SHA256 without copying its 626-entry inventory or old frozen artifacts.
The original run-matrix and staging verifier still require that external manifest,
client caches and source staging inputs; this is not a portable runner bundle.

Before future use, parameterize a fresh external output/state root, existing cache
manifest, source/staging roots, Swift package/scratch paths, Android SDK/JDK,
AVD/serial and resource-lease Python/helper path. The coordinator/emulator scripts
write beside themselves, inspect external files and control an owned emulator;
the build wrapper requires an authorized build window. No such future action is
authorized or performed by preserving these exact original sources. A modified
portable adaptation must have a new hash and must remain NOT RUN until executed.
Native evidence is macOS host controllers/GRDB and API37 Android emulator with
explicit ACK draining and real process restarts; it does not establish physical
device, real FCM/APNs, OS scheduling/background, release or production acceptance.

## Final function freeze and preserved baselines

`artifact-identities.json` is the final-function identity summary, reduced from
`binaries/c5-final-identity.json` and the exact external native attempt03 and
MySQL final-index receipts. Six native/control loops and four MySQL fault cases
are recorded as historical PASS/QUIET; packaging does not rerun those checks.
Normal/test binary hashes are distinct from any capacity observer build.
`artifact-identities-baseline-753a1836.json` preserves the previously bundled
7324bc7a... normal / 055fde93... test identities and attempt02 qualification.
The attempt02 complete lane remains a baseline and is not final-product evidence.

Changed attempt02 coordinator/emulator source bytes remain under
`native/baseline-attempt02/`; their original captured sources are recorded in
provenance. `native/run-matrix.py` and `emulator_lifecycle.py` are the final
attempt03 versions, with `finalize-native-attempt03.py` as the final read-only
verification-source input. Every packaged native source found in the actual
attempt03 execution manifest was checked against that manifest's SHA256.
`native/provenance/attempt-03-executed-adapter-manifest.json` is the exact small
source/identity inventory; filenames of excluded vendor/wheel/cache inputs may
appear in it, but their bytes are not included. Attempt03 reused all native
builds and performed no new download or native build.

`fault/mysql_final_released_session_fence.py` is the actually executed final
parameterized supplement (932e9ee9...). It takes explicit binary, workspace,
OUT, commit, expected SHA256, env-helper and baseline hash-receipt arguments.
Its original hardcoded predecessor `mysql_released_session_fence.py` is retained
as an explicitly historical baseline source. `mysql_wire_fault.py` is unchanged
and matches the final-index execution hash. Final four-case status/quiet and
original receipt hashes are summarized in artifact identities; raw fault results,
logs, baselines and live URLs remain external. The final source copies here have
NOT RUN. Capacity now has its separate final source-only freeze in `capacity/README.md`;
its observer identity and finite MySQL failure are distinct from functional PASS.

## Final capacity entry point

See `capacity/README.md` for the stable final harness/observer sources and exact
patch, external build/runtime dependencies, fixed cutoff/censor semantics and
resource limits. The original final651bf7 lane completed PG 40960/40960 targets;
MySQL failed the finite deadline with 7169/40960 successes and 33791 unfinished.
No reducer success is reported as a capacity PASS. The historical final handoff
records owned-process QUIET and environment cleanup; this source packaging did
not reobserve the database or environment. Source copies remain NOT RUN here.
