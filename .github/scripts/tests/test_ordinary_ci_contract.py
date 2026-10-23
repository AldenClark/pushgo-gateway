import os
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PREFLIGHT = ROOT / "scripts/preflight_release_audit.sh"
DRILL = ROOT / "scripts/v12_single_instance_rollback_drill.sh"
V12 = "dfb6b7c2cfd1b2f8e6d7fe7c95d8bf59473ed0b6"


def function(path, name, following):
    text = path.read_text()
    return text[text.index(name + "() {"):text.index(following)]


SNAPSHOT = function(PREFLIGHT, "private_ledger_snapshot", "run_private_flow() {")
BUILD = function(DRILL, "build_historical_binary", 'if [[ -z "$V11_BIN" ]]')
AUDIT_CHECK = (ROOT / ".github/scripts/static_release_audit.sh").read_text().split(
    "<<'PY_AUDIT'\n", 1
)[1].split("\nPY_AUDIT", 1)[0]


class AdvisoryPolicyTests(unittest.TestCase):
    def check_policy(self, contents):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "audit.toml"
            path.write_text(contents)
            return subprocess.run([sys.executable, "-", str(path)], input=AUDIT_CHECK,
                                  text=True, capture_output=True)

    def test_explicit_empty_advisory_ignore_list_passes(self):
        self.assertEqual(self.check_policy("[advisories]\nignore = []\n").returncode, 0)

    def test_any_advisory_ignore_is_rejected(self):
        for advisory in ("RUSTSEC-2023-0071", "RUSTSEC-2099-0001"):
            with self.subTest(advisory=advisory):
                result = self.check_policy(f'[advisories]\nignore = ["{advisory}"]\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("advisories.ignore = []", result.stderr)

    def test_empty_list_in_another_section_cannot_mask_an_exception(self):
        result = self.check_policy('[output]\nignore = []\n[advisories]\n'
                                   'ignore = ["RUSTSEC-2023-0071"]\n')
        self.assertNotEqual(result.returncode, 0)


class OrdinaryPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.core = self.root / "core.sqlite"
        self.delivery = self.root / "delivery.sqlite"
        with sqlite3.connect(self.core) as db:
            db.executescript("""
                CREATE TABLE ordinary_messages(op_id TEXT,message_id TEXT,delivery_id TEXT,
                  channel_id TEXT,accepted_at INTEGER,expires_at INTEGER,payload_blob BLOB,
                  payload_bytes INTEGER,private_enqueued_count INTEGER,provider_target_count INTEGER,
                  pending_targets INTEGER,identity_state TEXT);
                CREATE TABLE ordinary_targets(delivery_id TEXT,device_key TEXT,pull_owner TEXT,
                  delivery_mode TEXT,provider TEXT,acked_at INTEGER,route_generation INTEGER,delivery_epoch INTEGER);
                INSERT INTO ordinary_messages VALUES('op-a','msg-a','del-a','channel',1000,61000,
                  X'7b7d',2,1,0,1,'live'),('op-b','msg-b','del-b','channel',1001,61001,
                  X'7b7d',2,1,0,1,'live');
                INSERT INTO ordinary_targets VALUES('del-a','device','device','private','PRIVATE',NULL,1,0),
                  ('del-b','device','device','private','PRIVATE',NULL,1,0);
            """)
        with sqlite3.connect(self.delivery) as db:
            db.executescript("CREATE TABLE private_outbox(id); CREATE TABLE private_payloads(id);")

    def snapshot(self, output="facts.json"):
        args = " ".join(shlex.quote(str(v)) for v in
                        (self.core, self.delivery, 2, self.root / output))
        return subprocess.run(["bash", "-c", SNAPSHOT + "\nprivate_ledger_snapshot " + args],
                              text=True, capture_output=True)

    def mutate(self, sql, delivery=False):
        with sqlite3.connect(self.delivery if delivery else self.core) as db:
            db.executescript(sql)

    def test_complete_ledger_survives_reopen_with_identical_facts(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.assertEqual(self.snapshot("after.json").returncode, 0)
        self.assertEqual((self.root / "facts.json").read_bytes(),
                         (self.root / "after.json").read_bytes())

    def test_missing_target_is_rejected(self):
        self.mutate("DELETE FROM ordinary_targets WHERE delivery_id='del-a';")
        self.assertNotEqual(self.snapshot().returncode, 0)

    def test_sibling_cannot_mask_missing_logical_target(self):
        self.mutate("UPDATE ordinary_targets SET delivery_id='del-a' WHERE delivery_id='del-b';")
        self.assertNotEqual(self.snapshot().returncode, 0)

    def test_empty_body_is_rejected(self):
        self.mutate("UPDATE ordinary_messages SET payload_blob=X'',payload_bytes=0 WHERE op_id='op-a';")
        self.assertNotEqual(self.snapshot().returncode, 0)

    def test_legacy_double_write_is_rejected(self):
        self.mutate("INSERT INTO private_outbox VALUES('duplicate');", delivery=True)
        self.assertNotEqual(self.snapshot().returncode, 0)

    def test_each_ttl_is_checked_not_only_maximum(self):
        self.mutate("UPDATE ordinary_messages SET expires_at=accepted_at WHERE op_id='op-a';")
        self.assertNotEqual(self.snapshot().returncode, 0)

    def test_oversized_ttl_is_rejected(self):
        self.mutate("UPDATE ordinary_messages SET expires_at=accepted_at+2592000001 WHERE op_id='op-a';")
        self.assertNotEqual(self.snapshot().returncode, 0)

    def test_restart_identity_change_is_visible_to_exact_comparison(self):
        self.assertEqual(self.snapshot().returncode, 0)
        self.mutate("UPDATE ordinary_messages SET message_id='changed' WHERE op_id='op-a';")
        self.assertEqual(self.snapshot("after.json").returncode, 0)
        result = subprocess.run(["cmp", "-s", str(self.root / "facts.json"),
                                 str(self.root / "after.json")])
        self.assertEqual(result.returncode, 1)
        self.assertIn('cmp -s "$before" "$after"', PREFLIGHT.read_text())


class HistoricalRollbackTests(unittest.TestCase):
    def test_both_workflows_pin_historical_v12_without_candidate_override(self):
        for name in ("release.yml", "route-transition-quality.yml"):
            text = (ROOT / ".github/workflows" / name).read_text()
            self.assertIn("V12_SOURCE_COMMIT: " + V12, text)
            self.assertNotIn("V12_BIN: target/release/pushgo-gateway", text)
        self.assertIn('V12_BIN="${V12_BIN:-}"', DRILL.read_text())

    def run_fake_build(self, resolved):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            (fixture / "Cargo.toml").write_text("# synthetic archive only\n")
            # Shell functions replace build tools; no git export or Rust build runs.
            code = BUILD + """
fixture_dir=$1
ROOT_DIR=$2
fake_resolved=$3
git() {
  case "$3" in
    rev-parse) printf '%s\\n' "$fake_resolved";;
    archive) tar -cf - -C "$fixture_dir" Cargo.toml;;
    *) return 91;;
  esac
}
cargo() {
  printf '%s\\n' "$*" > "$fixture_dir/cargo-args"
  mkdir -p "$CARGO_TARGET_DIR/release"
  touch "$CARGO_TARGET_DIR/release/pushgo-gateway"
}
build_historical_binary v12 "$4"
"""
            result = subprocess.run(["bash", "-c", code, "test", str(fixture),
                                     str(ROOT), resolved, V12], text=True, capture_output=True)
            return result, (fixture / "cargo-args").read_text() if (fixture / "cargo-args").exists() else None

    def test_historical_build_uses_exact_commit_and_locked_release(self):
        result, args = self.run_fake_build(V12)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--locked --release --bin pushgo-gateway", args)
        self.assertIn("/v12-source/Cargo.toml", args)

    def test_mismatched_resolved_source_is_rejected_before_build(self):
        result, args = self.run_fake_build("0" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not resolve exactly", result.stderr)
        self.assertIsNone(args)

    def test_explicit_v13_artifact_is_refused_by_full_historical_drill(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for version in ("v11", "v13"):
                artifact = root / version
                artifact.write_text("#!" + sys.executable + "\n" + """
import sqlite3, sys
if sys.argv[-1] == 'run':
    path = sys.argv[sys.argv.index('--db-url')+1].removeprefix('sqlite://').split('?')[0]
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE pushgo_schema_meta(meta_key TEXT PRIMARY KEY,meta_value TEXT)')
        db.execute("INSERT INTO pushgo_schema_meta VALUES('schema_version',?)", (VERSION,))
""".replace("VERSION", repr("2026-08-08-gateway-v11" if version == "v11" else "2026-10-17-gateway-v13")))
                artifact.chmod(0o755)
            env = dict(os.environ, V11_BIN=str(root / "v11"), V12_BIN=str(root / "v13"),
                       TMPDIR=str(root), KEEP_FIXTURE="0")
            result = subprocess.run(["bash", str(DRILL)], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("historical v12 artifact required", result.stderr)


if __name__ == "__main__":
    unittest.main()
