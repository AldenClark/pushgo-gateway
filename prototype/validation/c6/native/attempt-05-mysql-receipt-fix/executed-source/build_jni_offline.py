"""Single-ABI C6 compiler. Requires an approved PUBLIC synthetic CA DER input.
Does not generate/read private material, start devices, or start Gateway.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-ca-der", required=True, type=Path)
    parser.add_argument("--public-ca-sha256", required=True)
    parser.add_argument("--exclusive-window-authorized", action="store_true")
    args = parser.parse_args()
    if not args.exclusive_window_authorized:
        raise RuntimeError("root exclusive compiler window required")
    output = Path(__file__).resolve().parents[1]
    manifest_dir = output / "android-staging/native/quinn-jni"
    public = args.public_ca_der.resolve()
    assert hashlib.sha256(public.read_bytes()).hexdigest() == args.public_ca_sha256
    assert public.suffix == ".der"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PUSHGO_RELEASE_", "ORG_GRADLE_PROJECT_PUSHGO_RELEASE_"))}
    env.update({"ANDROID_NDK_HOME": "/Users/ethan/Library/Android/sdk/ndk/29.0.14206865",
                "ANDROID_NDK_ROOT": "/Users/ethan/Library/Android/sdk/ndk/29.0.14206865",
                "ANDROID_SDK_ROOT": "/Users/ethan/Library/Android/sdk",
                "CARGO_TARGET_DIR": str(output / "jni-target"),
                "PUSHGO_C6_TEST_CA_DER": str(public), "CARGO_NET_OFFLINE": "true"})
    command = ["cargo", "ndk", "-t", "arm64-v8a", "-P", "28", "build", "--release", "--frozen", "--offline"]
    free_before = shutil.disk_usage(output).free
    started = time.time()
    with (output / "jni-build-first.log").open("xb") as log:
        result = subprocess.run(command, cwd=manifest_dir, env=env, stdout=log, stderr=subprocess.STDOUT)
    receipt = {"command": command, "exit": result.returncode, "seconds": time.time() - started,
               "public_ca_der_sha256": args.public_ca_sha256,
               "free_before": free_before, "free_after": shutil.disk_usage(output).free}
    (output / "jni-build-first-receipt.json").write_text(json.dumps(receipt, indent=2))
    if result.returncode:
        raise SystemExit(result.returncode)
    source = output / "jni-target/aarch64-linux-android/release/libpushgo_quinn_jni.so"
    dest = output / "android-staging/app/build/generated/rustJniLibs/main/arm64-v8a/libpushgo_quinn_jni.so"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, dest)
    receipt["so_sha256"] = hashlib.sha256(dest.read_bytes()).hexdigest()
    (output / "jni-build-first-receipt.json").write_text(json.dumps(receipt, indent=2))
    if free_before - receipt["free_after"] > 2 * 1024**3:
        raise RuntimeError("C6 physical disk growth exceeded root 2GiB budget; stop before Gradle")


if __name__ == "__main__":
    main()
