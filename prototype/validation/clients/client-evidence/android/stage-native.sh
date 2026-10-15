#!/usr/bin/env bash
set -euo pipefail
artifact_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_root="${1:-/Users/ethan/Repo/PushGo/pushgo-android}"
staged_root="$artifact_root/staged-pushgo-android"
[[ ! -e "$staged_root" ]] || { echo "Staged project already exists; refusing to overwrite" >&2; exit 2; }
mkdir -p "$staged_root"
# Copy source/config/scripts only. No hardlinks or symlinks back to product inputs.
rsync -a --exclude=.git --exclude=.gradle --exclude=.kotlin --exclude=build --exclude=target \
  --exclude=google-services.json --exclude='*.jks' --exclude='*.keystore' "$source_root/" "$staged_root/"
# Keep local SDK location without copying signing, secrets, or private configuration.
printf 'sdk.dir=/Users/ethan/Library/Android/sdk\n' > "$staged_root/local.properties"
cp "$artifact_root/source/ProviderWakeupC2DeviceTest.kt" \
  "$staged_root/app/src/androidTest/java/io/ethan/pushgo/ProviderWakeupC2DeviceTest.kt"
# Separate installed app/data namespace keeps default-hook WorkManager effects
# away from an existing user's primary app and DB. Runtime source stays unchanged.
printf '\n// C2 isolated instrumented app identity.\nandroid { buildTypes.getByName("debug") { applicationIdSuffix = ".c2evidence" } }\n' >> "$staged_root/app/build.gradle.kts"
# This journey does not invoke JNI. Reuse cached compiled native libraries; exclude the
# buildRustJniLibs task at execution so Android does not start another Rust build.
[[ -d "$source_root/app/build/generated/rustJniLibs/main" ]] || {
  echo "No cached Rust JNI libraries; staged native build NOT RUN" >&2; exit 2;
}
mkdir -p "$staged_root/app/build/generated/rustJniLibs"
cp -cR "$source_root/app/build/generated/rustJniLibs/main" "$staged_root/app/build/generated/rustJniLibs/main"
python3 - "$source_root" "$staged_root" "$artifact_root" <<'PYTHON'
import hashlib,json,pathlib,sys
source,staged,artifact=map(pathlib.Path,sys.argv[1:])
files=['notifications/InboundMessageProcessor.kt','notifications/ProviderIngressCoordinator.kt','notifications/ProviderAckDrainCoordinator.kt','notifications/InboundPersistenceCoordinator.kt','data/InboundDeliveryLedger.kt','data/db/PushGoDatabase.kt']
rows=[]
for rel in files:
    rel='app/src/main/java/io/ethan/pushgo/'+rel
    a,b=source/rel,staged/rel
    h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    assert h(a)==h(b),rel
    rows.append({'path':rel,'source_sha256':h(a),'staged_sha256':h(b)})
(artifact/'staged-source-identity.json').write_text(json.dumps({'production_source_unchanged':True,'files':rows},indent=2)+'\n')
PYTHON
printf '%s\n' "$staged_root"
