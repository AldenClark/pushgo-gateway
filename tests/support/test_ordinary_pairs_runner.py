"""Focused negative controls for the C13 runner, without a Gateway process."""
import json
from pathlib import Path
import tempfile
import unittest

from ordinary_pairs_runner import passed_receipt, prepare_parents, verify_run, write_new


class RunnerIntegrityTests(unittest.TestCase):
    def test_binary_change_on_last_slot_is_still_a_failure(self):
        receipt = {"exit_code":0,"evidence_valid":True,"binary_unchanged":True,"stop":None}
        self.assertTrue(passed_receipt(receipt))
        receipt["binary_unchanged"] = False
        self.assertFalse(passed_receipt(receipt))

    def test_nested_parents_are_writable_and_leaf_stays_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            spec = {"directory":str(root/"evidence"/"new"/"run"),
                    "receipt":str(root/"audit"/"run.json"),
                    "log":str(root/"audit"/"run.log")}
            prepare_parents([spec])
            self.assertTrue((root/"evidence"/"new").is_dir())
            self.assertFalse(Path(spec["directory"]).exists())
            self.assertFalse(list(root.rglob(".write-probe-*")))
            write_new(Path(spec["receipt"]), {"failed":True})
            with self.assertRaises(AssertionError):
                prepare_parents([spec])
            with self.assertRaises(FileExistsError):
                write_new(Path(spec["receipt"]), {"passed":True})

    def fixture(self, root, mode="preflight"):
        n = 3 if mode == "preflight" else 136
        events = [("configuration", {"mode":mode,"qa":False,"messages":n,"targets":2*n}),
                  ("control_preflight", {"passed":True,"selected_targets":2,"canonical_active_subscriptions":2}),
                  ("shutdown_complete", {"success":True,"exit_code":0}),
                  ("result", {"passed":True,"mode":mode,"messages":n,"targets":2*n,
                              "persisted_messages":n,"received_targets":2*n,"puback_targets":2*n,
                              "positive_terminal_targets":2*n,"body_released":n,"residual_targets":0,
                              "unfinished":0,"failed":0}),
                  ("database_sample", {"pending_targets":0,"payload_count":0})]
        for kind, count in (("planned_offer",n),("http_started",n),("http_accepted",n),
                            ("peer_receive",2*n),("ack_sent",2*n),("ack_commit_visible_upper_bound",2*n),
                            ("body_release_commit_visible_upper_bound",n),("peer_connected",2),
                            ("database_configuration",3),("idle_complete",1),
                            ("phase_resources",1),("resources",1)):
            events.extend((kind, {"op_id":f"fixture-{i//2}","device_key":f"device-{i%2}"})
                          for i in range(count))
        for name in ("gateway.log","gateway.config.json","gateway.sqlite",
                     "gateway.delivery.sqlite","gateway.dispatch.sqlite"):
            (root/name).touch()
        return [{"elapsed_us":i,"kind":kind,"data":value} for i,(kind,value) in enumerate(events)]

    def save(self, root, rows):
        (root/"journey.jsonl").write_text("".join(json.dumps(row)+"\n" for row in rows))

    def test_http_success_cannot_replace_ack_or_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = self.fixture(root)
            self.save(root, rows)
            self.assertTrue(verify_run(root,"preflight")[0])
            self.save(root,[row for row in rows if row["kind"] != "ack_sent"])
            self.assertFalse(verify_run(root,"preflight")[0])
            control = next(row for row in rows if row["kind"] == "control_preflight")
            control["data"]["selected_targets"] = 0
            self.save(root, rows)
            self.assertFalse(verify_run(root,"preflight")[0])

    def test_crash_or_incomplete_evidence_cannot_be_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = self.fixture(root)
            self.save(root,[row for row in rows if row["kind"] != "shutdown_complete"])
            self.assertFalse(verify_run(root,"preflight")[0])
            rows.append({"elapsed_us":100,"kind":"error","data":{"reason":"seeded wrong actor"}})
            self.save(root, rows)
            self.assertFalse(verify_run(root,"preflight")[0])

    def test_formal_qos1_repeat_does_not_invent_an_extra_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = self.fixture(root,"formal")
            receive = next(row for row in rows if row["kind"] == "peer_receive")
            rows.append(receive)
            rows.append({"elapsed_us":10000,"kind":"duplicate_peer_receive","data":receive["data"]})
            self.save(root, rows)
            self.assertTrue(verify_run(root,"formal")[0])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = self.fixture(root)
            rows.append(next(row for row in rows if row["kind"] == "peer_receive"))
            self.save(root, rows)
            self.assertFalse(verify_run(root,"preflight")[0])


if __name__ == "__main__":
    unittest.main()
