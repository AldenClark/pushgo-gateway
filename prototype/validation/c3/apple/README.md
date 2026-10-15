# Apple native source-only reproduction

Original final execution used candidate source
`10e59ec97230550216bc00aa3fe8c924b02510e1` and frozen binary SHA-256
`c22a71df7fc12d8b30a63bfbb24d7f3d8d895f62c35dcab58d2f3d894f1d1e9a`.
That original OUT run (`apple/run-final-01`) passed seven native phases in seven
independent processes with twenty actual Gateway HTTP requests. Direct legacy
ACK, filtered V2 oversized wakeup, durable ACK503 followed by actual production
backoff/new-process recovery, pending unsubscribe and running-route logout were
observed against that identity. The earlier A03 run remains separately bound to
`13c2e741bc47970ee423aa06eeea9660a8ff5e83`; earlier calibration failures remain in
original OUT. No execution against later product corrections is claimed here.

**Portable adapters in this directory have NOT RUN.** Only static syntax and
hash inspection was performed during packaging. `executed/run-loop.py` and
`executed/run-native.sh` preserve the exact original executed runner bytes;
`Package.swift`, `Package.resolved`, and both Swift files are exact executed
inputs. The portable top-level runners add explicit external work-directory and
frozen-binary identity inputs. `source-provenance.json` records original and
packaged hashes and the relocation differences. The `executed/` copies are
archival bytes from the original OUT layout; use the top-level portable runner
with explicit staging instead of executing those relocated archival copies. The original source hash list
contains metadata only; no production Shared source bodies are included.

## Explicit staging and dependencies

Use macOS with zsh, Swift 6/Xcode's macOS SDK and Python 3.9+. The original native
product used macOS 27 SDK with a macOS 14 minimum. GRDB is pinned by
`Package.resolved` to 7.11.0, revision
`9ed8c8457e00ff9c7aedb3bf213f20a2cfdf509e`. Supply an explicitly selected,
read-only Apple repository with `Shared/` identical to the original source-copy
manifest (primary source was `151d50c`), plus the required offline dependency
cache if resolution is disabled. Staging rejects any mismatched Shared file;
it does not silently use the current checkout or edit production sources.

The following examples are **instructions only, NOT RUN**. Replace every
placeholder. `BUNDLE` is `validation/c3`, `APPLE_SOURCE` is the explicitly chosen
read-only Apple repository, and `WORK`/`RUN_OUT` are fresh external paths.
`SWIFT_CACHE` is an existing Swift scratch directory with the pinned dependency.
No filesystem path defaults point to the author's workstation.

```sh
python3 "$BUNDLE/apple/stage.py" \
  --apple-source "$APPLE_SOURCE" --work-root "$WORK" \
  --offline-cache "$SWIFT_CACHE"
```

This stages the manifest's 111 unchanged Shared source files, package inputs and
Swift tests into `$WORK/package`. It copies only dependency `checkouts`,
`repositories` and `workspace-state.json` to `$WORK/build`; it copies no old
compiled products. It never builds, starts a service or runs a test. Omitting
`--offline-cache` leaves dependency preparation to the operator; the runner
still disables automatic resolution and updates.

After a separately allocated runtime window and an explicit frozen build receipt:

```sh
python3 "$BUNDLE/apple/run-loop.py" \
  --apple-work-root "$WORK" --binary "$FROZEN_BINARY" \
  --binary-sha256 "$FROZEN_BINARY_SHA256" \
  --source-commit "$FROZEN_SOURCE_COMMIT" --out "$RUN_OUT"
```

The common Python mock dependency is `../harness/c3_mock.py`; it is a synthetic
loopback APNs/Remote Token Service peer, never a successful Gateway API stub.
The candidate must provide the fixture CLI used by `run-loop.py`, including
`--mock-token-service-endpoint`, prefixed control/message/ACK endpoints, SQLite
ledger and shutdown receipt. A matching recorded original binary is not shipped.

## Boundaries and storage

The selected test exercises real production ChannelSubscriptionController,
ChannelSyncController, ProviderRouteController and NotificationIngressController
with real URLSession calls and disk GRDB. Ordinary send is explicit sender HTTP;
the receiver app has no ordinary sender API. The package also compiles the exact
SQLite migration child fixture required by its unchanged Package.swift; that
executable is not invoked by this selected loop.

Each run requires a fresh output directory and captures first failure, actual
provider bytes, HTTP requests, read-only ledger/native GRDB observations and
shutdown state there. Startup requires automation storage-root isolation,
`blocksCrossAppDataAccess == true`, and shared defaults being the test executable's
standard defaults. Only the exact config/macOS-device fallback caches are reset
through production owners; no whole preference domain is cleared. Protected
configuration uses the automation filesystem backend, not the user's Keychain.
The original test bundle ID was `package.PushGoAppleCoreTests`.

Provider responses are held only after exact capture, with a bounded 60-second
hold. ACK503 is injected only at the forwarding proxy; exact canonical GRDB and
a leased durable marker are observed before the ACK HTTP response. Recovery
honors the production marker due time; the original final recovery took 62.660
seconds. Do not compress time or rewrite markers/SQL to turn this into a pass.

This is native macOS-host SwiftPM-process evidence, excluding Settings UI,
OS/APNs delegate/background behavior, physical devices and release readiness.
Gateway-process restart and unknown-API behavior were not exercised by the Apple
loop. The full control restart evidence is documented in the parent bundle.
