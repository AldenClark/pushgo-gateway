#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
workflow="$ROOT_DIR/.github/workflows/release.yml"
dockerfile="$ROOT_DIR/Dockerfile.gha"
local_dockerfile="$ROOT_DIR/Dockerfile.local"
preflight="$ROOT_DIR/scripts/preflight_release_audit.sh"
rollback_drill="$ROOT_DIR/scripts/v12_single_instance_rollback_drill.sh"
rollback_runbook="$ROOT_DIR/release/V12_SINGLE_INSTANCE_ROLLBACK.md"
crossdb_parity="$ROOT_DIR/scripts/storage_crossdb_parity.sh"

for file in "$workflow" "$dockerfile" "$local_dockerfile" "$preflight" "$rollback_drill" "$rollback_runbook" "$crossdb_parity" "$ROOT_DIR/rust-toolchain.toml"; do
  if [[ ! -f "$file" ]]; then
    echo "missing release contract file: $file" >&2
    exit 1
  fi
done

bash -n "$rollback_drill"
grep -Fq '2026-08-20-gateway-v12' "$rollback_runbook"
grep -Fq '6c26f420114823a827caa0274a0bbc3739d91211' "$rollback_runbook"
grep -Fq 'scripts/v12_single_instance_rollback_drill.sh' "$workflow"
grep -Fq 'scripts/storage_crossdb_parity.sh' "$workflow"
grep -Fq 'ROUNDS: "3"' "$workflow"
grep -Fq 'EVIDENCE_FILE: evidence/rollback/v12-single-instance.json' "$workflow"
grep -Fq 'name: pushgo-release-gate-evidence' "$workflow"
grep -Fq 'production_validation == false' "$workflow"
grep -Fq 'crossdb_parity_rounds: 3' "$workflow"
grep -Fq 'SYFT_VERSION: "1.51.0"' "$workflow"
grep -Fq 'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6' "$workflow"
grep -Fq 'docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a' "$workflow"

for pinned_dockerfile in "$dockerfile" "$local_dockerfile"; do
  from_count="$(grep -Ec '^FROM[[:space:]]+' "$pinned_dockerfile")"
  pinned_from_count="$(grep -Ec '^FROM[[:space:]]+[^[:space:]]+@sha256:[0-9a-f]{64}([[:space:]]+AS[[:space:]]+[A-Za-z0-9_.-]+)?$' "$pinned_dockerfile")"
  if [[ "$from_count" != "$pinned_from_count" || "$from_count" -lt 1 ]]; then
    echo "every base image must be digest pinned: $pinned_dockerfile" >&2
    exit 1
  fi
  if ! grep -Eq '^# syntax=docker/dockerfile:[^@[:space:]]+@sha256:[0-9a-f]{64}$' "$pinned_dockerfile"; then
    echo "Dockerfile frontend is not digest pinned: $pinned_dockerfile" >&2
    exit 1
  fi
  grep -Fq 'PUSHGO_TOKEN_SERVICE_URL=http://127.0.0.1:6766' "$pinned_dockerfile"
  grep -Fq 'exec /usr/local/bin/pushgo-gateway "$@"' "$pinned_dockerfile"
done

local_toolchain="$(.github/scripts/release_toolchain.sh)"
if ! grep -Eq "^FROM rust:${local_toolchain}-bookworm@sha256:[0-9a-f]{64} AS builder$" "$local_dockerfile"; then
  echo "Dockerfile.local does not use the release Rust toolchain at an immutable digest" >&2
  exit 1
fi
if grep -Eq 'apt-get|rustup\.rs|rustup toolchain' "$local_dockerfile"; then
  echo "Dockerfile.local contains a mutable package or toolchain installation" >&2
  exit 1
fi

grep -Fq "locked) printf '%s\n' --locked" "$preflight"
grep -Fq "frozen) printf '%s\n' --frozen" "$preflight"
while IFS= read -r line; do
  if [[ "$line" != *'"$cargo_arg"'* ]]; then
    echo "preflight cargo command bypasses the locked/frozen contract: $line" >&2
    exit 1
  fi
done < <(grep -E '^[[:space:]]+cargo (check|test|build)[[:space:]]' "$preflight")

invalid_actions="$(sed -n -E 's/^[[:space:]]*uses:[[:space:]]*([^[:space:]#]+).*/\1/p' "$workflow" | grep -Ev '^[^@]+@[0-9a-f]{40}$' || true)"
if [[ -n "$invalid_actions" ]]; then
  echo "GitHub Actions must use full commit SHAs:" >&2
  printf '%s\n' "$invalid_actions" >&2
  exit 1
fi

for variable in DEBIAN_RUNTIME_IMAGE ALPINE_RUNTIME_IMAGE; do
  if ! grep -Eq "^[[:space:]]+${variable}:[[:space:]]+[^[:space:]]+@sha256:[0-9a-f]{64}$" "$workflow"; then
    echo "workflow image is not digest pinned: $variable" >&2
    exit 1
  fi
done

cross_image_count="$(grep -Ec '^[[:space:]]+image: ghcr\.io/cross-rs/[^[:space:]]+@sha256:[0-9a-f]{64}$' "$workflow")"
if [[ "$cross_image_count" != "6" ]]; then
  echo "expected six digest-pinned cross images; found $cross_image_count" >&2
  exit 1
fi

stable_tags="$(.github/scripts/image_tags.sh ghcr.io/example/pushgo-gateway v1.3.0 1111111111111111111111111111111111111111 true false)"
beta_tags="$(.github/scripts/image_tags.sh ghcr.io/example/pushgo-gateway v1.3.0-beta.2 2222222222222222222222222222222222222222 false false)"
if ! grep -Fxq 'ghcr.io/example/pushgo-gateway:latest' <<<"$stable_tags"; then
  echo "stable channel did not produce latest" >&2
  exit 1
fi
if grep -Fq ':latest' <<<"$beta_tags"; then
  echo "beta channel produced latest" >&2
  exit 1
fi

stable_contract="$(.github/scripts/release_contract.sh v1.3.0 1.3.0)"
beta_contract="$(.github/scripts/release_contract.sh v1.3.0-beta.2 1.3.0)"
grep -Fxq 'stable=true' <<<"$stable_contract"
grep -Fxq 'stable=false' <<<"$beta_contract"
if .github/scripts/release_contract.sh v1.3.0-beta.0 1.3.0 >/dev/null 2>&1; then
  echo "invalid beta sequence passed the release contract" >&2
  exit 1
fi

docker_job="$(awk '/^  docker:/{capture=1} /^  docker-smoke:/{capture=0} capture{print}' "$workflow")"
if grep -Fq ':latest' <<<"$docker_job" || ! grep -Fq 'candidate-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}' <<<"$docker_job"; then
  echo "unverified Docker build must publish only an isolated candidate" >&2
  exit 1
fi
if ! grep -Fq 'needs: [release-gate, docker, release-evidence]' "$workflow"; then
  echo "immutable image promotion is not gated by release evidence" >&2
  exit 1
fi
if ! grep -Fq 'needs: [release-gate, docker, release]' "$workflow"; then
  echo "stable latest promotion is not gated by the GitHub Release" >&2
  exit 1
fi
if .github/scripts/release_contract.sh v1.3.1 1.3.0 >/dev/null 2>&1; then
  echo "mismatched tag/package version passed the release contract" >&2
  exit 1
fi

toolchain="$(.github/scripts/release_toolchain.sh)"
if [[ ! "$toolchain" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Rust toolchain is not an exact numeric release pin" >&2
  exit 1
fi

for command in metadata fetch clippy build; do
  while IFS= read -r line; do
    if [[ "$line" != *"--locked"* && "$line" != *"--frozen"* ]]; then
      echo "unlocked cargo $command command in release workflow: $line" >&2
      exit 1
    fi
  done < <(grep -E "cargo ${command}([[:space:]]|$)" "$workflow" || true)
done

grep -Fq 'CARGO_DENY_VERSION: "0.20.2"' "$workflow"
grep -Fq 'cargo install cargo-deny --version "${CARGO_DENY_VERSION}" --locked' "$workflow"
grep -Fq 'cargo deny --frozen check -D warnings' "$workflow"

echo "release workflow static audit passed"
