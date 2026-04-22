# Release Notes

This file contains end-user-facing release notes for Gateway GitHub Releases.

Policy:
- Beta tags use `vX.Y.Z-beta.N`, and read from `[vX.Y.Z-beta.N]`.
- Release tags use `vX.Y.Z`, and read from `[vX.Y.Z]`.
- Keep entries user-visible and outcome-focused.
- Internal refactors, CI changes, and implementation details belong in `release/CHANGELOG.md`.

## [v1.2.3]

### Improved
- Gateway now ships the full observability refresh in `v1.2.3`: profile-driven diagnostics/tracing/stats behavior, structured trace events, and tighter startup/runtime telemetry.
- Diagnostics surfaces are streamlined around private-channel operational endpoints, while dispatch/runtime telemetry is unified into stats + trace paths for clearer production triage.
- Runtime/storage migration for this release line is synchronized with observability cleanup, including deprecated delivery-audit path removal and schema/state convergence.
- Linux release artifact and runtime container baselines are aligned on Debian `bookworm-slim` to reduce libc drift risks during deployment.
- This release entry now reflects the complete gateway optimization set currently in the repository (not only the initial version-bump subset).

## [v1.2.2]

### Improved
- Release baseline now includes all gateway changes accumulated after `v1.2.1` and before this publication checkpoint.
- Gateway runtime package/version metadata is aligned to `v1.2.2` for consistent rollout and diagnostics.
- Release documentation and audit metadata are synchronized for this production release line.

## [v1.2.1]

### Improved
- Improved ACK + pull delivery reliability by ensuring provider wakeup deliveries are cached before dispatch.
- Improved first-sync behavior for provider pull routes, reducing missed pulls right after subscribe/sync.
- Improved cross-database startup consistency for provider-pull subscription initialization (SQLite/Postgres/MySQL).

## [v1.2.0]

### Improved
- Gateway now adopts SemVer-aligned release naming (`vX.Y.Z`, `vX.Y.Z-beta.N`) for consistent cross-platform release governance.
- Added formal release notes and changelog governance for clearer operator-facing release communication.
- Wakeup notification consistency is now aligned across APNS/FCM/WNS title propagation paths.
- Private channel fallback reliability is improved by keeping ACK-timeout retries on private transport.
