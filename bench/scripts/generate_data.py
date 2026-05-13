#!/usr/bin/env python3
"""Generate repeatable PushGo gateway benchmark mock data."""

from __future__ import annotations

import argparse
import pathlib

from common import (
    BenchConfig,
    DEFAULT_CHANNEL_PASSWORD,
    event_create_payload,
    message_payload,
    thing_create_payload,
    utc_millis,
    write_json,
)


def build_dataset(config: BenchConfig, channels: int, devices: int, messages: int) -> dict:
    channel_records = []
    for i in range(max(1, channels)):
        channel_records.append(
            {
                "channel_name": f"bench-channel-dataset-{i}",
                "channel_id": config.channel_id if i == 0 else None,
                "password": config.channel_password or DEFAULT_CHANNEL_PASSWORD,
                "purpose": "mock channel for PushGo gateway benchmark isolation",
            }
        )
    device_records = []
    for i in range(max(1, devices)):
        device_records.append(
            {
                "device_key": f"bench-device-dataset-{i}",
                "platform": ["ios", "macos", "android", "windows"][i % 4],
                "channel_type": "private",
                "provider_token": None,
                "subscription_channel_index": i % len(channel_records),
            }
        )
    first_channel = config.channel_id or "CHANNEL_ID_RETURNED_BY_SEED"
    samples = {
        "messages": [
            message_payload(
                first_channel,
                config.channel_password,
                i,
                payload_size=config.payload_size,
                variant="complex" if i % 3 == 0 else "normal",
            )
            for i in range(max(1, messages))
        ],
        "event_create": event_create_payload(first_channel, config.channel_password, 0),
        "thing_create": thing_create_payload(first_channel, config.channel_password, 0),
    }
    return {
        "generated_at": utc_millis(),
        "warning": "Mock data only. Do not point benchmark scripts at production databases.",
        "database": {
            "recommended_url": config.db_url,
            "cleanup": "rm -f target/bench/pushgo-bench.sqlite target/bench/pushgo-bench.sqlite-*",
        },
        "channels": channel_records,
        "devices": device_records,
        "subscriptions": [
            {
                "device_key": device["device_key"],
                "channel_index": device["subscription_channel_index"],
            }
            for device in device_records
        ],
        "payload_samples": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channels", type=int, default=4)
    parser.add_argument("--devices", type=int, default=100)
    parser.add_argument("--messages", type=int, default=32)
    parser.add_argument(
        "--out",
        type=pathlib.Path,
        default=None,
        help="Output JSON path. Defaults to <result-dir>/bench-data.json.",
    )
    args = parser.parse_args()

    config = BenchConfig.from_env("generate-data")
    out = args.out or (config.result_dir / "bench-data.json")
    write_json(out, build_dataset(config, args.channels, args.devices, args.messages))
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
