"""Focused tests for evidence preservation, not product migration acceptance."""
import contextlib
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import legacy_cutover_probe as probe


class EvidenceHelpers(unittest.TestCase):
    def test_snapshot_includes_committed_uncheckpointed_wal_and_all_family_files(self):
        with tempfile.TemporaryDirectory(prefix="c14-backup-helper-") as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            # Quiescent test-owned connections keep committed WAL files alive;
            # no transaction or concurrent writer runs during the snapshots.
            with contextlib.ExitStack() as stack:
                for index, name in enumerate(("gateway.sqlite", "gateway.delivery.sqlite",
                                              "gateway.dispatch.sqlite", "gateway.runtime.sqlite")):
                    connection = stack.enter_context(contextlib.closing(sqlite3.connect(source / name)))
                    self.assertEqual(connection.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
                    connection.execute("PRAGMA wal_autocheckpoint=0")
                    connection.execute("CREATE TABLE marker(id INTEGER PRIMARY KEY, content TEXT)")
                    connection.execute("INSERT INTO marker VALUES (?,?)", (index, "committed WAL 内容"))
                    connection.commit()
                    self.assertGreater(Path(str(source / name) + "-wal").stat().st_size, 0)
                before = probe.logical_snapshot(source)
                probe.backup_family(source, root / "backup")
                self.assertEqual(probe.logical_snapshot(root / "backup"), before)
                self.assertEqual(len(probe.family(root / "backup")), 4)
                for path in probe.family(root / "backup"):
                    self.assertEqual(probe.scalar(path, "SELECT content FROM marker"), "committed WAL 内容")

    def test_existing_backup_target_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="c14-preserve-helper-") as temp:
            root = Path(temp)
            source, target = root / "source", root / "backup"
            source.mkdir()
            target.mkdir()
            evidence = target / "preserved.txt"
            evidence.write_text("original evidence")
            with self.assertRaises(FileExistsError):
                probe.backup_family(source, target)
            self.assertEqual(evidence.read_text(), "original evidence")

    def test_json_receipt_is_create_only(self):
        with tempfile.TemporaryDirectory(prefix="c14-receipt-helper-") as temp:
            path = Path(temp) / "receipt.json"
            probe.write_json(path, {"result": "original failure"})
            with self.assertRaises(FileExistsError):
                probe.write_json(path, {"result": "replacement pass"})
            self.assertIn("original failure", path.read_text())

    def test_probe_refuses_existing_evidence_without_adding_failure_file(self):
        with tempfile.TemporaryDirectory(prefix="c14-existing-run-") as temp:
            root = Path(temp)
            marker = root / "original.json"
            marker.write_text("original")
            result = subprocess.run([
                sys.executable, "-B", probe.__file__, "--source-binary", "/not-used",
                "--candidate-binary", "/not-used", "--evidence-root", str(root),
            ], capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(root.iterdir()), [marker])
            self.assertEqual(marker.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
