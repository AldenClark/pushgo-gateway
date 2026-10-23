# C10 fixture source boundary

The normal product `src/main.rs` and `src/ordinary` own the only running ordinary implementation. The former independent fixture is now a process launcher, and its library is a re-export. No old fixture-admin router or copied control authority is retained.

The historical source baseline is `86e073dec487903cb27f2e67d6e5cbdcb06a6900`. Only files in this C10 worktree are removed. The frozen C9 worktree, its binaries, databases and all external evidence remain unchanged.

Removed duplicate runtime and historical fixture-only test source (42 files):

- `prototype/src/backend_contract_tests.rs`
- `prototype/src/control_tests.rs`
- `prototype/src/control_wire_tests.rs`
- `prototype/src/credentials.rs`
- `prototype/src/credentials_tests.rs`
- `prototype/src/history_tests.rs`
- `prototype/src/http.rs`
- `prototype/src/http_budget_tests.rs`
- `prototype/src/ingress.rs`
- `prototype/src/metrics.rs`
- `prototype/src/mysql_control.rs`
- `prototype/src/mysql_native_tests.rs`
- `prototype/src/mysql_next_due_tests.rs`
- `prototype/src/mysql_plan_probe.rs`
- `prototype/src/mysql_private.rs`
- `prototype/src/mysql_schema.sql`
- `prototype/src/mysql_store.rs`
- `prototype/src/ordinary_store.rs`
- `prototype/src/pg_control.rs`
- `prototype/src/pg_private.rs`
- `prototype/src/pg_schema.sql`
- `prototype/src/pg_store.rs`
- `prototype/src/private_boundary_tests.rs`
- `prototype/src/private_contract_tests.rs`
- `prototype/src/private_http.rs`
- `prototype/src/private_http_tests.rs`
- `prototype/src/private_listeners.rs`
- `prototype/src/private_model.rs`
- `prototype/src/private_mqtt.rs`
- `prototype/src/private_runtime.rs`
- `prototype/src/private_runtime_tests.rs`
- `prototype/src/profiling.rs`
- `prototype/src/runtime.rs`
- `prototype/src/sender.rs`
- `prototype/src/server.rs`
- `prototype/src/sqlite_private.rs`
- `prototype/src/store.rs`
- `prototype/src/store_contract_tests.rs`
- `prototype/src/tests.rs`
- `prototype/src/transport.rs`
- `prototype/src/types.rs`
- `prototype/src/wire_tests.rs`

Retained or replaced deliberately:

- `prototype/src/lib.rs`: re-exports the product ordinary module; no second implementation.
- `prototype/src/bin/free_architecture_fixture.rs`: forwards normal Gateway arguments to an explicit product binary; Unix uses process replacement.
- `prototype/Cargo.toml`: only the normal Gateway path dependency remains. `prototype/Cargo.lock` was refreshed for that dependency graph; the final offline check verifies this wrapper against the product implementation.
- `prototype/validation/**` and existing `prototype/docs/**`: original reports, failure records, manifests, reference scripts and receipts are preserved. They are historical and do not certify the product path.
- All build outputs, database files, logs and evidence outside the removed tracked source list are preserved.

No server, build or test is started by this source change. Product verification must identify the normal Gateway binary and final source commit. The old C9 capacity harness is not a product benchmark and its results must not be combined with a launcher run.
