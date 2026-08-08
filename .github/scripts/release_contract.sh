#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <vX.Y.Z|vX.Y.Z-beta.N> <package-version>" >&2
  exit 2
}

tag="${1:-}"
package_version="${2:-}"
if [[ -z "$tag" || -z "$package_version" ]]; then
  usage
fi

stable="false"
prerelease="true"
channel="beta"

if [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  base_version="${BASH_REMATCH[1]}"
  stable="true"
  prerelease="false"
  channel="stable"
elif [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)-beta\.([1-9][0-9]*)$ ]]; then
  base_version="${BASH_REMATCH[1]}"
else
  echo "unsupported release tag: $tag" >&2
  echo "allowed formats: vX.Y.Z or vX.Y.Z-beta.N" >&2
  exit 1
fi

if [[ "$base_version" != "$package_version" ]]; then
  echo "tag/package version mismatch: tag=$tag package=$package_version" >&2
  exit 1
fi

printf 'tag=%s\n' "$tag"
printf 'base_version=%s\n' "$base_version"
printf 'notes_section=%s\n' "$tag"
printf 'stable=%s\n' "$stable"
printf 'prerelease=%s\n' "$prerelease"
printf 'channel=%s\n' "$channel"
