#!/usr/bin/env bash
set -euo pipefail

file="${1:-}"
section="${2:-}"
if [[ -z "$file" || -z "$section" || ! -f "$file" ]]; then
  echo "usage: $0 <release-notes-file> <section>" >&2
  exit 2
fi

body="$(awk -v sec="$section" '
  BEGIN { in_section = 0 }
  /^## \[/ {
    if (in_section == 1) exit
    if ($0 == "## [" sec "]") {
      in_section = 1
      next
    }
  }
  in_section == 1 { print }
' "$file")"

if [[ -z "${body//[[:space:]]/}" ]]; then
  echo "release notes section is missing or empty: [$section]" >&2
  exit 1
fi

printf '%s\n' "$body"
