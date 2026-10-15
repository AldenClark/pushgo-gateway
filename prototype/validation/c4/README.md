# C4 validation source and reproduction boundaries

The in-crate `backend_contract_tests.rs` is the executable shared SQLite/PG oracle.
Build with Rust **1.97.1**, cached locked dependencies and the committed root plus
prototype manifests. Run `cargo +1.97.1 test --release --offline --locked
--manifest-path prototype/Cargo.toml --lib` from the candidate root.
The ignored PG aggregate is explicitly selected with `-- --ignored --exact
backend_contract_tests::postgres_shared_ordinary_contract_and_native_failures
--nocapture`. It requires C4_PG_DISPOSABLE=YES_NEW_SYNTHETIC and C4_PG_TEST_URL,
pointing to an explicitly authorized, new loopback c4_synthetic_* database.
Use a generated synthetic user in URL userinfo; do not use DSN query overrides.
The harness creates and removes only its own seven fresh case DB names. Missing
prerequisites fail, never silently pass. Do not use production/user databases.

`pg-env/isolated_pg.py` is the exact executed lifecycle source, for a local cached
pinned image and the existing local OrbStack context only. It never starts
OrbStack, pulls images or reuses a DB. Copy the script into a fresh external OUT
before execution, inspect its guards, set its explicit synthetic launch marker,
and later use its ownership-checked cleanup. Its generated query-user URL must be
converted to equivalent URL userinfo for the stricter Rust harness; retain no
real secrets. This repository bundle contains no ownership receipt or usable URL.

`fault/` accepts explicit --binary/--out, and PG additionally --pg-env. Each OUT
must be new. The PG test operates only the captured, verified owned container and
a fresh generated DB. It tests process/session recovery, not powerloss.

`capacity/` contains the original finite driver/Mock, bounded observer, reducers,
resource helper C source and patch sources. See ../../docs/c4-capacity.md for exact
commits, inputs, observer bounds, first-failure policy and metric definitions.
Compile the helper locally; no helper or Gateway binary is distributed. Capacity
runs require macOS Mach clock, Python 3.13, native source Git objects, external
fresh OUT, one reused Cargo target, and an exclusive runtime window. The copied
resource/helper path defaults and reducer paths describe the original experiment:
inspect and parameterize them before use. This is **not** a tested portable runner.
The old analyse_c1_base token seed is wrong for four derived fields; those fields
must be excluded. summarize_abba uses the exact new COMMIT reducer and rebuilds
Provider duration from complete raw Mock records; never report the invalid join.

The relocated scripts have **NOT RUN**. Python syntax and byte hashes alone were
checked. source-provenance.json binds the actual original executed sources to
these exact copies. Original receipts remain in build/quality-results/
c4-sqlite-postgres-20261015. No binary, DB/WAL, raw large log, production source
staging tree, APK or credentials are included. Native C3 source-only client
harnesses remain in ../c3; C4 final native evidence qualifies the unchanged cached
production paths on the final C4 binary, not a new execution of relocated files.

The additional final-C4 patch and exact local coordinator/reducer, source identity,
plan/build/large-evidence hash manifest are in capacity/final-c4. They bind the two
executed d925b97 lanes. The local coordinator has hardcoded original paths and
has NOT RUN from this relocated bundle. This bundle deliberately does not claim
portable orchestration; the Rust shared contract tests are the native executable
oracles. artifact-identities.json separates normal, PG test, SQLite test and
measurement identities.
