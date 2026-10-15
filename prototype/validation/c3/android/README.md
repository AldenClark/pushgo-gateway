# Android ordinary-client source reproduction

This directory contains source and hash provenance only. The two Kotlin test files are the exact bytes executed in the successful final Android run. Portable shell/Python scripts have only received static packaging checks: **NOT RUN**, no build, instrumentation, emulator, daemon or benchmark was started while packaging.

Actual execution binds Gateway source `10e59ec97230550216bc00aa3fe8c924b02510e1` and binary SHA-256 `c22a71df7fc12d8b30a63bfbb24d7f3d8d895f62c35dcab58d2f3d894f1d1e9a`. Two AndroidJUnit4 methods executed, zero skipped, PID 3992 -> 4093; exact Room canonical rows 5 -> 6 and pending ACK outbox 1 -> 0. These native results do not establish execution against subsequent Gateway source commits. Original evidence remains external at the locator in `provenance/packaging-inputs.json`; no logs, databases or artifacts are packaged here.

The production paths are unchanged ChannelSubscriptionRepository/Service, real SettingsRepository, AndroidKeystoreSecretStore, parser, canonical Room persistence, delivery ledger/outbox and ACK coordinator. A synthetic HTTP sender calls the real candidate `/message` route because Android has no production ordinary sender API. Only exact captured FCM `data` enters the real inbound processor. Direct delivery retains the production legacy-single ACK contract; oversized wakeup uses filtered V2 Pull and batch ACK. The transparent boundary forwards real candidate responses and models network loss before forwarding or after commit. It does not fabricate successful Gateway responses.

The methods cover register/create/rename/sync, interrupted sync concurrent direct delivery, direct dedupe and ACK before a held provider receipt, oversized wakeup, a real SQL failure with no ACK and explicit retry, unavailable/unknown ACK results, durable recovery in an independently launched process, interrupted route cleanup with an already frozen delivery, unsubscribe preserving history and durable route deletion. Explicit drains call the same coordinator and repository callbacks as the production worker. WorkManager OS scheduling, real FCM delivery, physical devices, release and production acceptance are outside this evidence.

`run-native.sh` waits for phase 1 success, force-stops only the isolated `.c3evidence` package, requires no surviving PID, then runs phase 2. Phase 2 asserts durable settings/secure credentials/content/pending ACK before network recovery. Closed main Room files are exported after native `@After db.close()`; there was no explicit checkpoint/SQLite backup and no WAL/shm export. The qualifier reads those main files with `immutable=1` and checks exact latest delivery/message IDs, full title/body, ledger and ACK state against captured provider data. It does not prove arbitrary live-WAL snapshot completeness; phase 2's real Android reopen is the primary process-recovery evidence.

External dependencies:

- The actual Android checkout, with production source hashes matching `provenance/production-main-source-hashes.json`; no production source files are included.
- A compatible JDK (the executed run used Android Studio JBR), Android SDK and an explicitly selected, already running owned API37 arm64 emulator. The original emulator used read-only/no-snapshot/no-window flags. No script creates an emulator.
- Cached Gradle dependencies and existing Rust JNI libraries under that checkout. Cached JNI hashes are recorded, but their exact source revision is **UNVERIFIED**. This ordinary HTTP/parser/Room/ACK journey does not invoke JNI and makes no fresh Rust/JNI build or private-channel claim.
- A freshly built candidate fixture supplied by the operator with its verified source commit. The runner launches it using both mock provider and mock Remote Token Service flags.
- Shared synthetic peer `../harness/c3_mock.py` (Python standard library only).

Portable preparation uses explicit external locations and never writes generated outputs into this source package:

```sh
export ANDROID_HOME=/path/to/Android/sdk
export JAVA_HOME=/path/to/compatible/jdk
export C3_ANDROID_STAGE_ROOT=/external/empty/android-stage
export C3_RUN_OUT=/external/empty/android-build-evidence
./stage-native.sh /path/to/actual/pushgo-android
```

Build the staged APK/test APK once through `run-native.sh` with `C3_BUILD_ONLY=1`, an explicitly selected `ANDROID_SERIAL`, and explicit loopback `C3_PUBLIC_URL`, `C3_GATEWAY_UPSTREAM_URL`, `C3_MOCK_URL` values. Its native APK manifest uses paths relative to the external stage. The native Rust/JNI task is excluded and Gradle workers remain two. The build path is **NOT RUN in this portable package**.

Then, in an authorized isolated runtime window with no concurrent capacity run:

```sh
./run-loop.py --binary /path/to/frozen/candidate \
  --source /path/to/candidate-checkout --source-commit VERIFIED_COMMIT \
  --stage-root "$C3_ANDROID_STAGE_ROOT" \
  --apk-manifest /external/android-build-evidence/native-apk-manifest.json \
  --serial OWNED_EMULATOR_SERIAL --out /external/new-android-run
```

The host chooses a free candidate loopback port and uses it unchanged as the public URL. Only a separate Android upstream port 18335 is reversed to the actual candidate; the advertised port is left for the on-emulator transparent boundary. The mock port is separately reversed. New output directories are required, the APK hashes are checked before reuse, first failures are retained, and no product assertion retry is performed. The host stops/joins its candidate/mock and removes its reverse mappings; the operator remains responsible for shutting down the owned emulator afterward.

Portable differences from executed scripts: explicit external checkout/stage/run/SDK/JDK/APK-manifest arguments replace machine-local defaults; APK paths are relative to the external stage; ordinary `cp -R` replaces macOS clone-copy; the emulator serial is explicit. Original and packaged hashes and the execution distinction are recorded in `source-manifest.json`. None of these portability edits has been executed.
