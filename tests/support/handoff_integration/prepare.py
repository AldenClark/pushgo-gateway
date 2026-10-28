#!/usr/bin/env python3
"""Stage the exact two-repository handoff regression without editing either checkout.

Python 3.11+, Git and Rust 1.97.1. Preparation does not resolve, compile or test.
Use --run to resolve offline, check retained lock versions, then run two tests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

GATEWAY = "5eba92c1941cf3e467bdcc80da1c0145b8b1667b"
WARP = "344a0486a69764da2e52441618d481fdcb43fbcf"
PACKAGES = ("warp-link", "warp-link-core", "warp-link-coordination",
            "warp-link-transport", "warp-link-ffi", "pushgo-warp-profile")
ROOT_FILES = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "build.rs"}


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stage(root: Path, revision: str, destination: Path, prefix: str) -> dict:
    actual = git(root, "rev-parse", revision + "^{commit}").decode().strip()
    if actual != revision:
        raise RuntimeError("Expected a complete exact commit identity")
    files = {}
    for entry in git(root, "ls-tree", "-rz", revision).split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        path = raw_path.decode()
        if path not in ROOT_FILES and not path.startswith((prefix, ".cargo/")):
            continue
        mode, kind, oid = metadata.decode().split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise RuntimeError(f"Unsupported source entry: {path}")
        data = git(root, "cat-file", "blob", oid)
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(int(mode[-3:], 8))
        files[path] = sha(data)
    return {"commit": revision, "files": files}


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"Expected one seam anchor in {path.name}: {old}")
    path.write_text(text.replace(old, new, 1))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", type=Path, required=True)
    parser.add_argument("--warp", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True,
                        help="New directory; existing paths are never overwritten")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    sources = {
        "gateway": stage(args.gateway, GATEWAY, output / "gateway", "src/"),
        "warp": stage(args.warp, WARP, output / "warp", "crates/"),
    }
    warp = output / "warp"
    gateway = output / "gateway"
    manifest = warp / "Cargo.toml"
    manifest.write_text(manifest.read_text() +
                        '\n# TASK-ONLY cross-repository test supply; not product configuration.\n'
                        '[patch."https://github.com/AldenClark/warp-link"]\n' +
                        "".join(f'{name} = {{ path = "crates/{name}" }}\n' for name in PACKAGES))
    replace(warp / "crates/warp-link/Cargo.toml", "[dev-dependencies]\n",
            '[dev-dependencies]\npushgo-gateway = { path = "../../../gateway" }\n'
            'sqlx = { version = "=0.9.0", default-features = false, features = ["sqlite", "runtime-tokio"] }\n'
            'tempfile = "=3.27.0"\n')
    replace(gateway / "Cargo.toml", "[dependencies]\n",
            '[dependencies]\ntempfile = "=3.27.0" # TASK-ONLY fixture constructor\n')
    module = gateway / "src/private/warp_engine"
    fixture = module / "handoff_fixture.rs"
    fixture.write_bytes((module / "handoff_integration_tests.rs").read_bytes())
    replace(fixture, "struct Product {", "pub struct Product {")
    for field in ("directory", "state", "app", "client_db"):
        replace(fixture, f"    {field}:", f"    pub {field}:")
    for method in ("open", "accept", "snapshot", "save", "stop"):
        replace(fixture, f"    async fn {method}(", f"    pub async fn {method}(")
    fixture.write_text("// TASK-ONLY fixture visibility; no production behavior edits.\n" + fixture.read_text())
    hook = module / "mod.rs"
    hook.write_text(hook.read_text() + '\n// TASK-ONLY visibility seam.\n#[path = "handoff_fixture.rs"]\npub mod handoff_fixture;\n')
    hook = warp / "crates/warp-link/src/lib.rs"
    hook.write_text(hook.read_text() + '\n#[cfg(all(test, feature = "wss"))]\nmod combined_handoff_tests;\n')
    tests = Path(__file__).with_name("combined_handoff_tests.rs").read_bytes()
    (warp / "crates/warp-link/src/combined_handoff_tests.rs").write_bytes(tests)
    lock = (gateway / "Cargo.lock").read_bytes()
    (warp / "Cargo.lock").write_bytes(lock)
    receipt = {"status": "PREPARED_NOT_COMPILED_OR_TESTED", "sources": sources,
               "test_sha256": sha(tests), "gateway_lock_seed_sha256": sha(lock),
               "scope": "Loopback production modules and synthetic SQLite; not TLS, apps or outer reconnect"}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if args.run:
        command = ["cargo", "+1.97.1", "metadata", "--offline", "--format-version", "1",
                   "--manifest-path", str(manifest)]
        with (output / "metadata.json").open("w") as handle:
            subprocess.run(command, check=True, stdout=handle)
        original = {(p["name"], p["version"]) for p in tomllib.loads(lock.decode())["package"]}
        resolved = {(p["name"], p["version"]) for p in tomllib.loads((warp / "Cargo.lock").read_text())["package"]}
        if original - resolved:
            raise RuntimeError(f"Gateway locked name/versions removed: {sorted(original - resolved)}")
        command = ["cargo", "+1.97.1", "test", "--offline", "--locked", "--manifest-path", str(manifest),
                   "-j1", "-p", "warp-link", "--lib", "combined_handoff_tests", "--",
                   "--nocapture", "--test-threads=1"]
        with (output / "test.log").open("w") as handle:
            result = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT)
        receipt.update(status="TEST_COMMAND_COMPLETED", command=command, exit=result.returncode,
                       locked_name_versions_removed=[])
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if result.returncode:
            raise SystemExit(result.returncode)
        if "test result: ok. 2 passed; 0 failed; 0 ignored;" not in (output / "test.log").read_text():
            raise RuntimeError("Successful command did not report exactly two passing tests")
        receipt.update(status="PASS_TWO_TESTS", passed=2, failed=0, ignored=0)
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "source_files": sum(len(s["files"]) for s in sources.values())}))


if __name__ == "__main__":
    main()
