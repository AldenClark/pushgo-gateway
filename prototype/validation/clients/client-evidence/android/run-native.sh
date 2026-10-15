#!/usr/bin/env bash
set -euo pipefail
artifact_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
staged_root="$artifact_root/staged-pushgo-android"
: "${ANDROID_SERIAL:?Choose one already-running authorized emulator serial explicitly}"
[[ -f "$staged_root/app/src/androidTest/java/io/ethan/pushgo/ProviderWakeupC2DeviceTest.kt" ]] || {
  echo "Run stage-native.sh first" >&2; exit 2;
}
# One native repository invocation builds and executes selected methods.
cd "$staged_root"
printf '\norg.gradle.workers.max=2\n' >> gradle.properties
# The native runner invokes Gradle itself. Disable only the native Rust task in
# this copied build file; cached JNI files already supplied above stay unchanged.
printf '\n// C2 isolated harness: reuse cached JNI, no transport/native-code claim.\ntasks.named("buildRustJniLibs").configure { enabled = false }\n' >> app/build.gradle.kts
export QUALITY_RESULTS_ROOT="$artifact_root/native-results"
export ANDROID_TEST_CLASS=io.ethan.pushgo.ProviderWakeupC2DeviceTest
scripts/quality_test.sh focused 2>&1 | tee "$artifact_root/native-test.log"
