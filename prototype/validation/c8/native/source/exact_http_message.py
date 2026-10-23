"""C7 host adapter: preserve the legal entire HTTP entity byte for byte.
Call from the existing real coordinator submit action; no runtime on import.
"""
import hashlib
import json
import uuid
import urllib.request


def post_exact_message(candidate, data):
    raw = data["raw_request"].encode("utf-8")
    assert len(raw) == 49152
    sha = hashlib.sha256(raw).hexdigest()
    assert sha == data["request_sha256"]
    parsed = json.loads(raw)
    assert set(parsed) == ({"channel_id", "password", "title", "body", "op_id", "metadata"}
                           if "metadata_keys" in data else {"channel_id", "password", "title", "body", "op_id"})
    if "metadata_keys" in data:
        from decimal import Decimal
        metadata = parsed["metadata"]
        assert len(metadata) == data["metadata_keys"] > 3500
        assert set(metadata) == {format(i, "x") for i in range(data["metadata_keys"])}
        assert all(Decimal(str(value)) == Decimal("1e15") for value in metadata.values())
    assert str(uuid.UUID(parsed["op_id"])) == parsed["op_id"]
    for key in ("channel_id", "password", "title", "body"):
        assert parsed[key] == data[key]
    request = urllib.request.Request(candidate.base + "/message", data=raw, method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + candidate.auth})
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.loads(response.read())
    assert value["success"] is True
    # Public synthetic input only; root final runner stores this receipt before
    # dependent product oracles. Never reserialize parsed JSON for transmission.
    (candidate.output / ("http-accept-" + parsed["op_id"] + ".json")).write_text(json.dumps({
        "request": parsed, "raw_request": raw.decode("utf-8"), "request_sha256": sha,
        "request_utf8_bytes": len(raw), "response": value["data"]}, ensure_ascii=False, indent=2))
    return value["data"], {"request_sha256": sha, "request_utf8_bytes": len(raw),
                           **({"metadata_keys": data["metadata_keys"]} if "metadata_keys" in data else {})}
