"""Offline C7 observation only: compare stopped Room export to HTTP input receipts.
Does not start devices, servers, DB engines or read credentials. Not yet executed.
"""
import argparse
import hashlib
import json
from pathlib import Path


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify(snapshot, checkpoints):
    accepted = {}
    for path in sorted(checkpoints.glob("checkpoint-*-submit.json")):
        item = json.loads(path.read_text())
        source, result = item["request"]["data"], item["result"]
        assert result["body"] == source["body"]
        assert len(source["raw_request"].encode("utf-8")) == 49152
        assert digest(source["raw_request"]) == source["request_sha256"]
        assert json.loads(source["raw_request"])["body"] == source["body"]
        accepted[result["message_id"]] = source
    room = json.loads(snapshot.read_text())
    evidence = []
    for message in room["messages"]:
        source = accepted[message["message_id"]]
        assert message["title"] == source["title"]
        assert len(message["body"].encode("utf-8")) == len(source["body"].encode("utf-8"))
        assert digest(message["body"]) == digest(source["body"])
        if "metadata_keys" in source:
            from decimal import Decimal
            payload = json.loads(message["raw_payload_json"])
            metadata = payload["metadata"]
            if isinstance(metadata, str):
                metadata = json.loads(metadata)
            count = source["metadata_keys"]
            assert len(metadata) == count > 3500
            assert set(metadata) == {format(i, "x") for i in range(count)}
            assert all(Decimal(str(v)) == Decimal("1e15") for v in metadata.values())
            canonical = "\n".join(f"{i:x}=1000000000000000" for i in range(count))
            evidence.append({"metadata_keys": count, "semantic_sha256": digest(canonical)})
        evidence.append({"message_id": message["message_id"], "utf8_bytes": len(source["body"].encode("utf-8")),
                         "body_sha256": digest(source["body"])})
    assert evidence, "zero observed messages is not a native body proof"
    return evidence


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--snapshot", required=True, type=Path)
    cli.add_argument("--checkpoints", required=True, type=Path)
    args = cli.parse_args()
    print(json.dumps(verify(args.snapshot, args.checkpoints), indent=2))
