#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="${1:-$ROOT_DIR/dist}"
EVIDENCE_DIR="${2:-$ROOT_DIR/evidence}"
BINARY_NAME="${BINARY_NAME:-pushgo-gateway}"

for command in file jq readelf sha256sum stat; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

targets=(
  linux-amd64-gnu
  linux-arm64-gnu
  linux-armv7-gnu
  linux-amd64-musl
  linux-arm64-musl
  linux-armv7-musl
)

mkdir -p "$EVIDENCE_DIR"
manifest="$EVIDENCE_DIR/release-assets.json"
tmp_manifest="$(mktemp "${TMPDIR:-/tmp}/pushgo-release-assets.XXXXXX")"
trap 'rm -f "$tmp_manifest"' EXIT
printf '[]' > "$tmp_manifest"

asset_names=()
for target in "${targets[@]}"; do
  path="$DIST_DIR/$BINARY_NAME-$target"
  asset_names+=("$(basename "$path")")
  if [[ ! -f "$path" || ! -x "$path" ]]; then
    echo "missing or non-executable release asset: $path" >&2
    exit 1
  fi

  description="$(file -b "$path")"
  case "$target" in
    linux-amd64-*) pattern='x86-64' ;;
    linux-arm64-*) pattern='ARM aarch64' ;;
    linux-armv7-*) pattern='ARM' ;;
  esac
  if [[ "$description" != *"$pattern"* ]]; then
    echo "release asset architecture mismatch: target=$target file=$description" >&2
    exit 1
  fi
  if [[ "$target" == *-gnu ]]; then
    if ! readelf -l "$path" | grep -Fq 'Requesting program interpreter:'; then
      echo "GNU release asset is not dynamically linked through an ELF interpreter: $target" >&2
      exit 1
    fi
    linkage="gnu-dynamic"
  else
    if readelf -l "$path" | grep -Fq 'Requesting program interpreter:'; then
      echo "musl release asset must be static for portable release use: $target" >&2
      exit 1
    fi
    linkage="musl-static"
  fi

  sha256="$(sha256sum "$path" | awk '{print $1}')"
  bytes="$(stat -c '%s' "$path")"
  jq \
    --arg target "$target" \
    --arg file "$(basename "$path")" \
    --arg sha256 "$sha256" \
    --arg description "$description" \
    --arg linkage "$linkage" \
    --argjson bytes "$bytes" \
    '. + [{target: $target, file: $file, sha256: $sha256, bytes: $bytes, description: $description, linkage: $linkage}]' \
    "$tmp_manifest" > "${tmp_manifest}.next"
  mv "${tmp_manifest}.next" "$tmp_manifest"
done

actual_count="$(find "$DIST_DIR" -maxdepth 1 -type f -name "${BINARY_NAME}-linux-*" | wc -l | tr -d '[:space:]')"
if [[ "$actual_count" != "${#targets[@]}" ]]; then
  echo "unexpected release asset count: actual=$actual_count expected=${#targets[@]}" >&2
  find "$DIST_DIR" -maxdepth 1 -type f -print >&2
  exit 1
fi

(
  cd "$DIST_DIR"
  sha256sum "${asset_names[@]}" | LC_ALL=C sort -k2 > SHA256SUMS
)

jq \
  --arg schema_version "1" \
  --arg git_sha "${GITHUB_SHA:-$(git -C "$ROOT_DIR" rev-parse HEAD)}" \
  --arg git_ref "${GITHUB_REF_NAME:-local}" \
  --arg cargo_lock_sha256 "$(sha256sum "$ROOT_DIR/Cargo.lock" | awk '{print $1}')" \
  --arg release_workflow_sha256 "$(sha256sum "$ROOT_DIR/.github/workflows/release.yml" | awk '{print $1}')" \
  --arg dockerfile_sha256 "$(sha256sum "$ROOT_DIR/Dockerfile.gha" | awk '{print $1}')" \
  --arg rust_toolchain "$("$ROOT_DIR/.github/scripts/release_toolchain.sh")" \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  '{schema_version: ($schema_version | tonumber), git_sha: $git_sha, git_ref: $git_ref, cargo_lock_sha256: $cargo_lock_sha256, release_workflow_sha256: $release_workflow_sha256, dockerfile_sha256: $dockerfile_sha256, rust_toolchain: $rust_toolchain, generated_at: $generated_at, assets: .}' \
  "$tmp_manifest" > "$manifest"

jq -e '(.assets | length == 6) and ([.assets[].target] | sort == ["linux-amd64-gnu", "linux-amd64-musl", "linux-arm64-gnu", "linux-arm64-musl", "linux-armv7-gnu", "linux-armv7-musl"]) and ([.assets[].sha256] | unique | length == 6)' "$manifest" >/dev/null
echo "verified six release assets; manifest=$manifest"
