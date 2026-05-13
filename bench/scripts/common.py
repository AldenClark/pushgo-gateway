#!/usr/bin/env python3
"""Shared helpers for PushGo gateway benchmark scripts."""

from __future__ import annotations

import json
import os
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_BASE_URL = "http://127.0.0.1:6666"
DEFAULT_DB_URL = f"sqlite://{REPO_ROOT / 'target' / 'bench' / 'pushgo-bench.sqlite'}?mode=rwc"
DEFAULT_RESULT_DIR = REPO_ROOT / "bench" / "results"
DEFAULT_CHANNEL_PASSWORD = "bench-password-2026"


def env_str(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def env_int(name: str, default: int) -> int:
    value = env_str(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    value = env_str(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def utc_millis() -> int:
    return int(time.time() * 1000)


def run_id(prefix: str = "bench") -> str:
    return f"{prefix}-{time.strftime('%Y%m%dT%H%M%S', time.gmtime())}"


def result_dir(name: str | None = None) -> pathlib.Path:
    base = pathlib.Path(env_str("PUSHGO_BENCH_RESULT_DIR", str(DEFAULT_RESULT_DIR)))
    path = base / (name or run_id())
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_file_from_url(db_url: str | None) -> pathlib.Path | None:
    if not db_url or not db_url.startswith("sqlite://"):
        return None
    raw = db_url[len("sqlite://") :].split("?", 1)[0]
    if raw.startswith("./"):
        return (REPO_ROOT / raw[2:]).resolve()
    return pathlib.Path(raw).expanduser().resolve()


@dataclass
class BenchConfig:
    base_url: str
    token: str | None
    db_url: str
    channel_id: str | None
    channel_password: str
    vus: int
    rps: float
    duration: float
    payload_size: int
    result_dir: pathlib.Path
    pid: int | None

    @classmethod
    def from_env(cls, scenario: str | None = None) -> "BenchConfig":
        pid_raw = env_str("PUSHGO_BENCH_PID")
        pid = None
        if pid_raw:
            try:
                pid = int(pid_raw)
            except ValueError:
                pid = None
        return cls(
            base_url=env_str("PUSHGO_BENCH_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            token=env_str("PUSHGO_BENCH_TOKEN"),
            db_url=env_str("PUSHGO_BENCH_DB_URL", DEFAULT_DB_URL),
            channel_id=env_str("PUSHGO_BENCH_CHANNEL_ID"),
            channel_password=env_str(
                "PUSHGO_BENCH_CHANNEL_PASSWORD", DEFAULT_CHANNEL_PASSWORD
            ),
            vus=max(1, env_int("PUSHGO_BENCH_VUS", 4)),
            rps=max(0.0, env_float("PUSHGO_BENCH_RPS", 20.0)),
            duration=max(1.0, env_float("PUSHGO_BENCH_DURATION", 10.0)),
            payload_size=max(0, env_int("PUSHGO_BENCH_PAYLOAD_SIZE", 1024)),
            result_dir=result_dir(scenario),
            pid=pid,
        )

    def as_public_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "token_configured": bool(self.token),
            "db_url": self.db_url,
            "channel_id": self.channel_id,
            "channel_password_configured": bool(self.channel_password),
            "vus": self.vus,
            "rps": self.rps,
            "duration": self.duration,
            "payload_size": self.payload_size,
            "result_dir": str(self.result_dir),
            "pid": self.pid,
        }


class HttpClient:
    def __init__(self, config: BenchConfig, timeout: float = 10.0) -> None:
        self.config = config
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        body: Any | None = None,
        *,
        token_mode: str = "normal",
        headers: dict[str, str] | None = None,
        raw_body: bytes | None = None,
    ) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{self.config.base_url}{path}"
        req_headers = dict(headers or {})
        if token_mode == "normal" and self.config.token:
            req_headers["Authorization"] = f"Bearer {self.config.token}"
        elif token_mode == "wrong":
            req_headers["Authorization"] = "Bearer wrong-bench-token"
        started = time.perf_counter()
        data = raw_body
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
        status = 0
        response_body = ""
        error = None
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                response_body = resp.read(256 * 1024).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_body = exc.read(256 * 1024).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 - benchmark should record all failures.
            error = f"{type(exc).__name__}: {exc}"
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        parsed = None
        if response_body:
            try:
                parsed = json.loads(response_body)
            except json.JSONDecodeError:
                parsed = None
        return {
            "method": method,
            "path": path,
            "status": status,
            "ok": 200 <= status < 300 and error is None,
            "latency_ms": elapsed_ms,
            "error": error,
            "response": parsed,
        }


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def append_jsonl(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")


def url_query(params: dict[str, Any]) -> str:
    return urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})


def extract_data(result: dict[str, Any]) -> dict[str, Any]:
    response = result.get("response")
    if isinstance(response, dict) and isinstance(response.get("data"), dict):
        return response["data"]
    return {}


def benchmark_text(size: int, seed: str) -> str:
    base = (
        f"# PushGo benchmark {seed}\n\n"
        "- gateway ingress\n"
        "- dispatch queue\n"
        "- private fallback and pull ack\n\n"
    )
    if size <= len(base):
        return base[:size]
    filler = (
        "This markdown paragraph contains mock incident details, image references, "
        "tags, status changes, and operator notes for repeatable load generation.\n"
    )
    chunks = [base]
    while sum(len(item) for item in chunks) < size:
        chunks.append(filler)
    return "".join(chunks)[:size]


def message_payload(
    channel_id: str,
    password: str,
    i: int,
    *,
    payload_size: int = 1024,
    variant: str = "normal",
    op_id: str | None = None,
    thing_id: str | None = None,
) -> dict[str, Any]:
    body_size = max(64, payload_size)
    payload: dict[str, Any] = {
        "channel_id": channel_id,
        "password": password,
        "op_id": op_id or f"bench-message-{variant}-{i}-{utc_millis()}",
        "occurred_at": utc_millis(),
        "title": f"Bench {variant} message {i}",
        "body": benchmark_text(body_size, f"{variant}-{i}"),
        "severity": "warning" if i % 5 == 0 else "info",
        "ttl": 3600,
        "url": f"https://example.invalid/pushgo/bench/{variant}/{i}",
        "images": [f"https://example.invalid/assets/{variant}-{i % 8}.png"],
        "tags": ["bench", variant, f"shard-{i % 8}"],
        "metadata": {
            "bench": True,
            "variant": variant,
            "iteration": i,
            "source": "pushgo-gateway-bench",
        },
    }
    if variant in {"complex", "ciphertext"}:
        payload["metadata"]["routing"] = {
            "tenant": f"tenant-{i % 12}",
            "priority": "high" if i % 11 == 0 else "normal",
        }
        payload["ciphertext"] = "bench-ciphertext-" + ("x" * min(2048, body_size // 4))
    if thing_id:
        payload["thing_id"] = thing_id
    return payload


def event_create_payload(channel_id: str, password: str, i: int) -> dict[str, Any]:
    now = utc_millis()
    return {
        "channel_id": channel_id,
        "password": password,
        "op_id": f"bench-event-create-{i}-{now}",
        "event_time": now,
        "title": f"Bench event {i}",
        "description": "Mock event lifecycle load sample",
        "status": "open",
        "message": "event opened",
        "severity": "high",
        "tags": ["bench", "event", f"bucket-{i % 16}"],
        "images": [f"https://example.invalid/event/{i % 8}.png"],
        "attrs": {"temperature": 20 + (i % 20), "stage": "create"},
        "metadata": {"bench": True, "kind": "event"},
        "started_at": now,
    }


def event_update_payload(
    channel_id: str, password: str, event_id: str, i: int, step: int
) -> dict[str, Any]:
    now = utc_millis()
    return {
        "channel_id": channel_id,
        "password": password,
        "event_id": event_id,
        "op_id": f"bench-event-update-{i}-{step}-{now}",
        "event_time": now,
        "status": "acknowledged" if step % 2 else "open",
        "message": f"event update {step}",
        "severity": "critical" if step % 3 == 0 else "high",
        "attrs": {"step": step, "load": i % 100},
        "metadata": {"bench": True, "step": step},
    }


def event_close_payload(channel_id: str, password: str, event_id: str, i: int) -> dict[str, Any]:
    now = utc_millis()
    return {
        "channel_id": channel_id,
        "password": password,
        "event_id": event_id,
        "op_id": f"bench-event-close-{i}-{now}",
        "event_time": now,
        "status": "closed",
        "message": "event closed",
        "severity": "low",
        "ended_at": now,
        "attrs": {"closed": True},
        "metadata": {"bench": True, "kind": "event_close"},
    }


def thing_create_payload(channel_id: str, password: str, i: int) -> dict[str, Any]:
    now = utc_millis()
    return {
        "channel_id": channel_id,
        "password": password,
        "op_id": f"bench-thing-create-{i}-{now}",
        "created_at": now,
        "observed_at": now,
        "title": f"Bench thing {i}",
        "description": "Mock PushGo thing used for lifecycle pressure",
        "tags": ["bench", "thing", f"group-{i % 10}"],
        "external_ids": {"serial": f"BENCH-{i:06d}"},
        "location_type": "physical",
        "location_value": f"lab-{i % 5}",
        "primary_image": f"https://example.invalid/thing/{i % 8}.png",
        "images": [f"https://example.invalid/thing/gallery/{i % 8}.png"],
        "attrs": {"battery": 80 + (i % 20), "online": True},
        "metadata": {"bench": True, "kind": "thing"},
    }


def thing_update_payload(
    channel_id: str, password: str, thing_id: str, i: int, step: int
) -> dict[str, Any]:
    now = utc_millis()
    return {
        "channel_id": channel_id,
        "password": password,
        "thing_id": thing_id,
        "op_id": f"bench-thing-update-{i}-{step}-{now}",
        "observed_at": now,
        "title": f"Bench thing {i}",
        "tags": ["bench", "thing", "updated"],
        "attrs": {"battery": max(1, 100 - step), "step": step, "online": step % 2 == 0},
        "metadata": {"bench": True, "step": step},
    }


def ensure_seed(
    client: HttpClient,
    config: BenchConfig,
    *,
    channels: int = 1,
    devices: int = 1,
    private_route: bool = True,
    scenario: str = "seed",
) -> dict[str, Any]:
    seed_path = config.result_dir / f"{scenario}-seed.json"
    channel_records: list[dict[str, Any]] = []
    device_records: list[dict[str, Any]] = []
    device_count = max(1, devices)
    channel_count = max(1, channels)

    for device_index in range(device_count):
        device_key = f"bench-device-{scenario}-{device_index}"
        register = client.request(
            "POST",
            "/device/register",
            {"device_key": device_key, "platform": "ios"},
        )
        if not register["ok"]:
            raise RuntimeError(f"device/register failed: {register}")
        registered_key = extract_data(register).get("device_key") or device_key
        route_type = "private" if private_route else "apns"
        route_body: dict[str, Any] = {
            "device_key": registered_key,
            "channel_type": route_type,
            "platform": "ios",
        }
        if not private_route:
            route_body["provider_token"] = f"{device_index:064x}"[-64:].rjust(64, "a")
        route = client.request("POST", "/channel/device", route_body)
        if not route["ok"]:
            raise RuntimeError(f"channel/device failed: {route}")
        routed_key = extract_data(route).get("device_key") or registered_key
        device_records.append({"device_key": routed_key, "channel_type": route_type})

    for channel_index in range(channel_count):
        preferred_channel = config.channel_id if channel_count == 1 else None
        channel_name = None if preferred_channel else f"bench-channel-{scenario}-{channel_index}"
        first_device = device_records[channel_index % len(device_records)]["device_key"]
        subscribe_body: dict[str, Any] = {
            "device_key": first_device,
            "password": config.channel_password,
        }
        if preferred_channel:
            subscribe_body["channel_id"] = preferred_channel
        else:
            subscribe_body["channel_name"] = channel_name
        subscribed = client.request("POST", "/channel/subscribe", subscribe_body)
        if not subscribed["ok"]:
            raise RuntimeError(f"channel/subscribe failed: {subscribed}")
        data = extract_data(subscribed)
        channel_id = data.get("channel_id") or preferred_channel
        if not channel_id:
            raise RuntimeError(f"channel/subscribe did not return channel_id: {subscribed}")
        channel_record = {
            "channel_id": channel_id,
            "channel_name": data.get("channel_name") or channel_name,
            "password": config.channel_password,
        }
        channel_records.append(channel_record)
        for device in device_records:
            if device["device_key"] == first_device:
                continue
            body = {
                "device_key": device["device_key"],
                "channel_id": channel_id,
                "password": config.channel_password,
            }
            resubscribe = client.request("POST", "/channel/subscribe", body)
            if not resubscribe["ok"]:
                raise RuntimeError(f"channel/subscribe fanout failed: {resubscribe}")

    seed = {
        "generated_at": utc_millis(),
        "private_route": private_route,
        "channels": channel_records,
        "devices": device_records,
    }
    write_json(seed_path, seed)
    return seed
