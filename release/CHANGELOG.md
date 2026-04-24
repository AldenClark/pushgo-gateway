# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/).

PushGo Gateway policy:
- Release tags use `vX.Y.Z`.
- Beta tags use `vX.Y.Z-beta.N`.
- GitHub Releases read end-user copy from `release/RELEASE_NOTES.md`:
  - beta tags read `[vX.Y.Z-beta.N]`
  - release tags read `[vX.Y.Z]`
- Engineering implementation history stays in `release/CHANGELOG.md`.

## [v1.2.6] - 2026-04-24

### Changed
- Bumped package/runtime version to `1.2.6` (release tag target: `v1.2.6`) and aligned lock metadata.
- This `v1.2.6` publication is intentionally scoped to the full gateway snapshot after `v1.2.5`, including both already committed changes and release-window pending changes.
- Release documentation was updated to reflect the all-in scope for this release cut.

## [v1.2.5] - 2026-04-22

### Changed
- Bumped package/runtime version to `1.2.5` (release tag target: `v1.2.5`) and aligned lock metadata.
- Fixed SQLite private maintenance cleanup SQL compatibility for environments where SQLite is built without `SQLITE_ENABLE_UPDATE_DELETE_LIMIT`:
  - replaced `DELETE ... LIMIT ?` usage with rowid-subquery based bounded deletes in SQLite private dedupe cleanup paths.
- Aligned private transport hints so advertised `wss_port` follows `PUSHGO_PUBLIC_BASE_URL` when an explicit port is present:
  - `https://host:55555` now advertises `wss_port=55555`
  - no explicit port keeps scheme default (`https -> 443`, `http -> 80`)
  - missing/invalid base URL falls back to `443`.
- Added targeted gateway unit tests covering WSS advertised-port derivation behavior.

## [v1.2.4] - 2026-04-22

### Changed
- Bumped package/runtime version to `1.2.4` (release tag target: `v1.2.4`) and aligned lock metadata.
- This `v1.2.4` publication includes all current code/doc/workflow/test changes in the `gateway` repository at release cut time.
- Switched private transport entry config from legacy boolean `PUSHGO_PRIVATE_CHANNEL_ENABLED` to explicit `PUSHGO_PRIVATE_TRANSPORTS` / `--private-transports`, with parser support for `true/false/none` and explicit transport sets (`quic,tcp,wss`).
- Added transport-aware dependency validation in CLI args normalization path:
  - `quic` requires `PUSHGO_PRIVATE_TLS_CERT` + `PUSHGO_PRIVATE_TLS_KEY`
  - `tcp` requires cert/key only when `PUSHGO_PRIVATE_TCP_TLS_OFFLOAD=false`
  - partial TLS identity is rejected early.
- Updated app/runtime wiring so private runtime, QUIC bind, TCP bind, and profile transport flags are all driven by the parsed transport set.
- Tightened private router behavior:
  - `/private/ws` route is mounted only when `wss` transport is enabled
  - websocket handler returns `503` when WSS transport is disabled
  - added route coverage tests for WSS-disabled state.
- Updated release audit and blackbox coverage to use `--private-transports quic,tcp,wss` where full private transport matrix is required.
- Refreshed gateway docs (`readme.md`, `src/api/docs.html`) and self-hosting website docs (EN/ZH + generated `dist`) to document explicit transport selection and certificate dependency rules.
- Refreshed release workflow:
  - GitHub Release body no longer repeats tag heading already provided by release title
  - uploaded release binaries now include explicit OS marker in filenames (for example `pushgo-gateway-linux-amd64-gnu`).
- Replaced hardcoded `pushgo-gateway/<version>` user-agent strings with `env!("CARGO_PKG_VERSION")` binding to keep runtime UA aligned with package version on every release bump.

## [v1.2.3] - 2026-04-22

### Changed
- Bumped package/runtime version to `1.2.3` (release tag target: `v1.2.3`), including Cargo package metadata and gateway user-agent identifiers.
- Migrated runtime observability configuration from a standalone diagnostics switch to profile-driven controls (`prod_min/ops/incident/debug`) with override flags and trace-log file configuration.
- Reworked runtime telemetry pipeline around structured trace events and sampled high-signal emissions (startup/listening, dispatch failures, private transport failures, HTTP 5xx, panic hook).
- Refactored stats collection and persistence paths to align dispatch/private/provider/runtime counters with the new observability model.
- Consolidated diagnostics routing/surfaces around private-channel operational endpoints and removed legacy diagnostics handler wiring.
- Removed deprecated delivery-audit modules/tables/typed access paths and aligned storage abstractions/backends/tests with the observability v9 schema direction.
- Updated storage schema migration catalog with `20260422_001_observability_v9` to finalize diagnostics + tracing + stats matrix transitions.
- Updated release binary build script to compile GNU artifacts inside `debian:bookworm-slim`, aligning glibc baseline with runtime images.
- Updated local Docker source-build script to use `debian:bookworm-slim` for both build and runtime stages, keeping container baselines consistent.
- Removed `zero-data-loss-gate` GitHub workflow from this release line.
- Refreshed README and release documentation to match the full `v1.2.3` publication scope.

## [v1.2.2] - 2026-04-19

### Changed
- Bumped package/runtime version to `1.2.2` (release tag target: `v1.2.2`), including Cargo package metadata and gateway user-agent identifiers.
- Folded all gateway changes since `v1.2.1` (including this release checkpoint window) into this release line as the production publication baseline.
- Updated release documentation to align with the `v1.2.2` publication target and release-audit pass.

## [v1.2.1] - 2026-04-15

### Changed
- Bumped package version to `1.2.1` (release tag target: `v1.2.1`).
- Added provider-pull cache pre-enqueue on provider dispatch path; provider delivery is now gated by successful cache enqueue to prevent unpullable wakeups.
- Removed legacy "skip provider when private realtime already succeeded" branch to keep provider ACK/pull behavior deterministic.
- Promoted provider pull route resolution to require concrete provider device identity, and added failure telemetry for cache-enqueue rejection paths.
- Channel subscribe/sync handlers now proactively initialize provider pull subscription data to reduce cold-start pull misses.
- Storage bootstrap for SQLite/Postgres/MySQL now enforces provider-pull subscription schema initialization during startup.

### Added
- Added runtime/storage tests covering provider-pull schema bootstrap, SQLite initialization path, and dispatch runtime behavior under pull-cache preconditions.

## [v1.2.0] - 2026-04-10

### Added
- Established SemVer-based release governance for gateway (`vX.Y.Z`, `vX.Y.Z-beta.N`).
- Added release documentation files:
  - `release/CHANGELOG.md`
  - `release/RELEASE_NOTES.md`

### Changed
- Bumped package version to `1.2.0` (release tag target: `v1.2.0`).
- Release workflow now enforces SemVer tag parsing and sectioned release notes extraction.
- Migrated gateway release workflow tag policy from `Release-*` to SemVer tags (`vX.Y.Z`, `vX.Y.Z-beta.N`).
- Migrated GitHub Release notes source from autogenerated content to `release/RELEASE_NOTES.md`.
- Corrected private ACK-timeout fallback behavior to retry through private transport instead of provider wakeup path.

### Test
- Added provider wakeup title propagation coverage for FCM/WNS/APNS wakeup payload construction.
- Added private fallback white-box coverage for claim->redeliver and failure->defer paths.
- Added private channel black-box coverage to validate ACK-timeout redelivery over `/private/ws`.
