#!/usr/bin/env bash
set -euo pipefail
artifact_root="/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-client-loop-gate-20261015/android"
run_root="${C3_RUN_OUT:-$artifact_root}"
mkdir -p "$run_root"
staged_root="$artifact_root/staged-pushgo-android"
: "${ANDROID_SERIAL:?owned emulator required}"
: "${C3_PUBLIC_URL:?candidate public URL required}"
: "${C3_GATEWAY_UPSTREAM_URL:?reversed upstream candidate URL required}"
: "${C3_MOCK_URL:?reversed mock URL required}"
[[ -f "$staged_root/app/src/androidTest/java/io/ethan/pushgo/CandidateOrdinaryC3DeviceTest.kt" ]]
# Root coordinates the resource window. This script never starts an emulator or daemon.
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export PATH="$JAVA_HOME/bin:/Users/ethan/Library/Android/sdk/platform-tools:$PATH"
cd "$staged_root"
collect_owned_receipts() {
    adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c3evidence cat files/c3-session.json > "$run_root/session-on-exit.json" 2>/dev/null || true
    adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c3evidence cat files/c3-network.jsonl > "$run_root/network-on-exit.jsonl" 2>/dev/null || true
}
if [[ "${C3_SKIP_BUILD:-0}" != "1" ]]; then
[[ ! -e "$artifact_root/native-build-first.log" ]] || { echo "First-run evidence already exists; refusing overwrite" >&2; exit 2; }
./gradlew --offline --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest -x :app:buildRustJniLibs 2>&1 | tee "$artifact_root/native-build-first.log"
python3 - "$artifact_root" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);staged=root/'staged-pushgo-android'
files=[staged/'app/build/outputs/apk/debug/app-universal-debug.apk',staged/'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk']
(root/'native-apk-manifest.json').write_text(json.dumps({'files':[{'path':str(p.relative_to(root)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}for p in files]},indent=2)+'\n')
PY
else
python3 - "$artifact_root" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1])
for row in json.loads((root/'native-apk-manifest.json').read_text())['files']:
 assert hashlib.sha256((root/row['path']).read_bytes()).hexdigest()==row['sha256'],row['path']
PY
fi
[[ "${C3_BUILD_ONLY:-0}" != "1" ]] || exit 0
[[ ! -e "$run_root/phase1OrdinaryLoopAndPersistUnknownAck-first.log" ]] || { echo "Native first-run evidence already exists; refusing overwrite" >&2; exit 2; }
trap collect_owned_receipts EXIT
adb -s "$ANDROID_SERIAL" install app/build/outputs/apk/debug/app-universal-debug.apk
python3 - "${C5_TEST_APK:?}" "${C5_TEST_APK_SHA256:?}" <<'CHECK'
import pathlib,hashlib,sys
assert hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()==sys.argv[2], 'C5 test APK hash mismatch'
CHECK
adb -s "$ANDROID_SERIAL" install "$C5_TEST_APK"
# Only the isolated application ID is installed/cleared. The primary app/data is untouched.
adb -s "$ANDROID_SERIAL" shell pm clear io.ethan.pushgo.c3evidence
run_phase() {
    local method="$1"
    local log="$run_root/$method-first.log"
    local auth_args=()
    if [[ -n "${C3_GATEWAY_AUTH:-}" ]]; then auth_args=(-e c3GatewayAuth "$C3_GATEWAY_AUTH"); fi
    adb -s "$ANDROID_SERIAL" shell am instrument -w -r \
      -e class "io.ethan.pushgo.CandidateOrdinaryC3DeviceTest#$method" \
      -e c3GatewayUrl "$C3_GATEWAY_UPSTREAM_URL" -e c3PublicUrl "$C3_PUBLIC_URL" \
      -e c3MockUrl "$C3_MOCK_URL" \
      "${auth_args[@]}" \
      io.ethan.pushgo.c3evidence.test/io.ethan.pushgo.test.PushGoAndroidJUnitRunner | tee "$log"
    python3 - "$log" <<'PY'
import pathlib,sys
s=pathlib.Path(sys.argv[1]).read_text()
assert 'OK (1 test)' in s,s
assert 'FAILURES!!!' not in s,s
assert 'INSTRUMENTATION_FAILED' not in s,s
PY
}
run_phase phase1OrdinaryLoopAndPersistUnknownAck
adb -s "$ANDROID_SERIAL" shell am force-stop io.ethan.pushgo.c3evidence
pid_after_stop="$(adb -s "$ANDROID_SERIAL" shell pidof io.ethan.pushgo.c3evidence || true)"
[[ -z "$pid_after_stop" ]] || { echo "Owned app process survived force-stop" >&2; exit 2; }
printf 'force_stop_pid_empty=true\n' > "$run_root/process-restart.txt"
adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c3evidence cat databases/c3_candidate_ordinary.db > "$run_root/room-before-restart.sqlite"
run_phase phase2NewProcessRecoverUnsubscribeAndLogout
adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c3evidence cat files/c3-session.json > "$run_root/session.json"
adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c3evidence cat files/c3-network.jsonl > "$run_root/network.jsonl"
adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c3evidence cat databases/c3_candidate_ordinary.db > "$run_root/room-after-restart.sqlite"
