#!/usr/bin/env python3
"""Bounded process driver for real normal Gateway/client-module interoperability.

This is not an HTTP server or protocol substitute. It starts the supplied normal
binary on loopback with a new SQLite family and publishes only a private synthetic
connection context. Clients use the product's real registration/Pull/ACK routes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def post(base, authentication, route, body):
    request = urllib.request.Request(base + route, method="POST",
                                    data=json.dumps(body).encode(), headers={
                                        "Authorization": "Bearer " + authentication,
                                        "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
        assert response.status == 200 and result.get("success") is True, route
        return result["data"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--duration", type=int, default=900)
    args = parser.parse_args()
    assert 30 <= args.duration <= 1800, "bounded30..1800second service lifetime"
    binary = args.binary.resolve(strict=True)
    assert binary.is_file() and os.access(binary, os.X_OK)
    directory = args.directory
    assert directory.is_absolute() and ".." not in directory.parts and not directory.exists()
    directory.parent.mkdir(parents=True, exist_ok=True)
    assert directory.parent.resolve() == directory.parent, "no symlinked evidence parent"
    assert shutil.disk_usage(directory.parent).free >= 5 * 2**30, "resource STOP before start"
    directory.mkdir(mode=0o700)
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    synthetic = uuid.uuid4().hex + uuid.uuid4().hex
    database = directory / "gateway.sqlite"
    command = [str(binary), "--http-addr", f"127.0.0.1:{port}", "--db-url",
               f"sqlite://{database}?mode=rwc", "--runtime-profile", "small",
               "--private-transports", "false", "--token", synthetic,
               "--token-service-url", "http://127.0.0.1:1", "--observability-log-level", "info"]
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PUSHGO_", "FCM_", "APNS_", "WNS_", "GOOGLE_"))}
    record = {"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "base_url": base, "sqlite": str(database), "started_epoch": time.time(),
              "duration_limit_seconds": args.duration, "normal_qa_feature": False,
              "external_provider": False, "token_service": "unavailable loopback port1",
              "credentials": "runtime-generated synthetic values only in0600 context, never logs",
              "command_redacted": ["<synthetic>" if value == synthetic else value for value in command]}
    log_descriptor = os.open(directory / "gateway.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    process = None
    try:
        with os.fdopen(log_descriptor, "w") as log:
            process = subprocess.Popen(command, env=environment, stdout=log, stderr=log,
                                       start_new_session=True)
            record["pid"] = process.pid
            deadline = time.monotonic() + 20
            while True:
                assert process.poll() is None, "normal Gateway exited before readiness"
                request = urllib.request.Request(base, headers={"Authorization": "Bearer " + synthetic})
                try:
                    with urllib.request.urlopen(request, timeout=1) as response:
                        if response.status == 200:
                            response.read()
                            break
                except (urllib.error.URLError, TimeoutError):
                    pass
                assert time.monotonic() < deadline, "normal Gateway readiness deadline"
                time.sleep(0.05)
            # Exactly the same normal control calls as provider-ingress blackbox:
            # no direct business-table insertion and no actual Provider credentials.
            context_paths = {}
            for consumer in ("apple", "android", "windows"):
                device = post(base, synthetic, "/device/register", {"platform": "android"})["device_key"]
                post(base, synthetic, "/channel/device", {"device_key": device,
                     "platform": "android", "channel_type": "fcm",
                     "provider_token": "synthetic-fcm-" + uuid.uuid4().hex})
                channel_secret = uuid.uuid4().hex
                channel = post(base, synthetic, "/channel/subscribe", {"device_key": device,
                     "channel_name": "delivery-interop-" + consumer + "-" + uuid.uuid4().hex,
                     "password": channel_secret})["channel_id"]
                context = {
                "origin": base, "base_url": base, "token": synthetic,
                "submit_authentication": "Bearer token from this private context",
                "channel_id": channel, "channel_password": channel_secret,
                "device_key": device, "device_secret": None,
                "consumer": consumer, "platform": "android",
                "provider_route": "synthetic FCM for V2 HTTP tests; not OS Provider acceptance",
                "api_paths": {"register": "/device/register", "route": "/channel/device",
                              "subscribe": "/channel/subscribe", "submit": "/message",
                              "pull": "/v2/messages/pull", "ack": "/v2/messages/ack"},
                "database": str(database), "stop_file": str(directory / "stop"),
                "synthetic_only": True, "normal_product": True}
                destination = directory / ("connection-" + consumer + ".json")
                private_json(destination, context)
                context_paths[consumer] = str(destination)
                if consumer == "android":
                    private_json(directory / "connection.json", context)
            record["private_contexts"] = context_paths
            private_json(directory / "ready.json", record)
            print(json.dumps({"ready": True, "base_url": base,
                              "private_context": str(directory / "connection.json"),
                              "private_contexts": context_paths}), flush=True)
            deadline = time.monotonic() + args.duration
            reason = "duration limit"
            while time.monotonic() < deadline:
                assert process.poll() is None, "normal Gateway exited during interoperability"
                if (directory / "stop").exists():
                    reason = "owner stop file"
                    break
                if shutil.disk_usage(directory).free < 5 * 2**30:
                    reason = "resource STOP below5GiB"
                    break
                time.sleep(0.25)
            record["stop_reason"] = reason
    finally:
        if process is not None:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                record["exit_code"] = process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                record["exit_code"] = process.wait()
                record["forced_after_shutdown_timeout"] = True
        record["finished_epoch"] = time.time()
        private_json(directory / "exit.json", record)


if __name__ == "__main__":
    main()
