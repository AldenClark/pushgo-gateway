#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
staged="$here/c5-staged-pushgo-android"
[[ "${C5_BUILD_WINDOW_AUTHORIZED:-}" == "1" ]] || { echo 'Root build window required' >&2; exit 2; }
[[ ! -e "$here/c5-test-build-first.log" ]] || { echo 'Refusing overwrite of first build log' >&2; exit 2; }
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"
python3 "$here/verify-c5-staging.py" before
cd "$staged"
./gradlew --offline --no-daemon --max-workers=2 --console=plain \
  '-Dorg.gradle.jvmargs=-Xmx1536m -Dfile.encoding=UTF-8' \
  -Pkotlin.compiler.execution.strategy=in-process \
  :app:assembleDebugAndroidTest -x :app:buildRustJniLibs 2>&1 | tee "$here/c5-test-build-first.log"
python3 "$here/verify-c5-staging.py" after
