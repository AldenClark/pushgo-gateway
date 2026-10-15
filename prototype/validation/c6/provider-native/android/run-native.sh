#!/usr/bin/env bash
set -euo pipefail
: "${ANDROID_SERIAL:?owned shared emulator window required}"
: "${C3_RUN_OUT:?fresh evidence directory required}"
: "${C3_PUBLIC_URL:?}" "${C3_GATEWAY_UPSTREAM_URL:?}" "${C3_MOCK_URL:?}"
: "${C6_MAIN_APK:?}" "${C6_MAIN_APK_SHA256:?}" "${C6_TEST_APK:?}" "${C6_TEST_APK_SHA256:?}"
export PATH="/Users/ethan/Library/Android/sdk/platform-tools:$PATH"
run_root="$C3_RUN_OUT"
mkdir -p "$run_root"
# Consume native owner's frozen C6 APKs. No Gradle, downloads, JNI or emulator startup.
python3 - "$C6_MAIN_APK" "$C6_MAIN_APK_SHA256" "$C6_TEST_APK" "$C6_TEST_APK_SHA256" <<'CHECK'
import pathlib,hashlib,sys
for p,h in zip(sys.argv[1::2],sys.argv[2::2]):
 assert hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h,'C6 APK identity mismatch'
CHECK
collect_owned_receipts() {
    adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c6evidence cat files/c3-session.json > "$run_root/session-on-exit.json" 2>/dev/null || true
    adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c6evidence cat files/c3-network.jsonl > "$run_root/network-on-exit.jsonl" 2>/dev/null || true
}
[[ ! -e "$run_root/phase1OrdinaryLoopAndPersistUnknownAck-first.log" ]] || { echo "Native first-run evidence already exists; refusing overwrite" >&2; exit 2; }
trap collect_owned_receipts EXIT
adb -s "$ANDROID_SERIAL" install "$C6_MAIN_APK"
adb -s "$ANDROID_SERIAL" install "$C6_TEST_APK"
# Only the isolated application ID is installed/cleared. The primary app/data is untouched.
adb -s "$ANDROID_SERIAL" shell pm clear io.ethan.pushgo.c6evidence
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
      io.ethan.pushgo.c6evidence.test/io.ethan.pushgo.test.PushGoAndroidJUnitRunner | tee "$log"
    python3 - "$log" <<'PY'
import pathlib,sys
s=pathlib.Path(sys.argv[1]).read_text()
assert 'OK (1 test)' in s,s
assert 'FAILURES!!!' not in s,s
assert 'INSTRUMENTATION_FAILED' not in s,s
PY
}
run_phase phase1OrdinaryLoopAndPersistUnknownAck
adb -s "$ANDROID_SERIAL" shell am force-stop io.ethan.pushgo.c6evidence
pid_after_stop="$(adb -s "$ANDROID_SERIAL" shell pidof io.ethan.pushgo.c6evidence || true)"
[[ -z "$pid_after_stop" ]] || { echo "Owned app process survived force-stop" >&2; exit 2; }
printf 'force_stop_pid_empty=true\n' > "$run_root/process-restart.txt"
adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c6evidence cat databases/c3_candidate_ordinary.db > "$run_root/room-before-restart.sqlite"
run_phase phase2NewProcessRecoverUnsubscribeAndLogout
adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c6evidence cat files/c3-session.json > "$run_root/session.json"
adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c6evidence cat files/c3-network.jsonl > "$run_root/network.jsonl"
adb -s "$ANDROID_SERIAL" exec-out run-as io.ethan.pushgo.c6evidence cat databases/c3_candidate_ordinary.db > "$run_root/room-after-restart.sqlite"
