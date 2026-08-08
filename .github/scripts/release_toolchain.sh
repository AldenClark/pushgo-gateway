#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
toolchain_file="${ROOT_DIR}/rust-toolchain.toml"

if [[ ! -f "$toolchain_file" ]]; then
  echo "missing Rust toolchain contract: $toolchain_file" >&2
  exit 1
fi

channel="$(sed -n -E 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' "$toolchain_file")"
if [[ ! "$channel" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "rust-toolchain.toml must pin one exact numeric channel; found: ${channel:-<missing>}" >&2
  exit 1
fi

printf '%s\n' "$channel"
