#!/usr/bin/env bash
set -euo pipefail

ghcr_image="${1:-}"
release_tag="${2:-}"
git_sha="${3:-}"
stable="${4:-}"
dockerhub_namespace="${5:-}"

if [[ -z "$ghcr_image" || -z "$release_tag" || ! "$git_sha" =~ ^[0-9a-f]{40}$ || -z "$dockerhub_namespace" ]]; then
  echo "invalid image tag inputs" >&2
  exit 1
fi
if [[ "$stable" != "true" && "$stable" != "false" ]]; then
  echo "stable must be true or false" >&2
  exit 1
fi
printf '%s:%s\n' "$ghcr_image" "$release_tag"
printf '%s:sha-%s\n' "$ghcr_image" "$git_sha"
if [[ "$stable" == "true" ]]; then
  printf '%s:latest\n' "$ghcr_image"
fi

dockerhub_image="$dockerhub_namespace/${ghcr_image##*/}"
printf '%s:%s\n' "$dockerhub_image" "$release_tag"
printf '%s:sha-%s\n' "$dockerhub_image" "$git_sha"
if [[ "$stable" == "true" ]]; then
  printf '%s:latest\n' "$dockerhub_image"
fi
