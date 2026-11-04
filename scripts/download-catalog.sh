#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Download the Vulners catalogue JSON files into a local data directory.
#
# Usage: scripts/download-catalog.sh [-b BASE_URL] [-d DEST_DIR]
#
#   -b BASE_URL  Catalogue base URL (default: CATALOG_BASE or the
#                vulnersCom/nmap-vulners catalog branch).
#   -d DEST_DIR  Destination directory (default: data in the repo root).
#   -h           Show this help.
#
# Files are written only when all of them download and parse correctly.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname -- "$SCRIPT_DIR")"

DEFAULT_BASE="https://raw.githubusercontent.com/vulnersCom/nmap-vulners/catalog/"
BASE_URL="${CATALOG_BASE:-$DEFAULT_BASE}"
DEST_DIR="$REPO_ROOT/data"
NAMES=(index fingerprints paths probes)

usage() {
    cat <<'EOF'
Usage: download-catalog.sh [-b BASE_URL] [-d DEST_DIR]

  -b BASE_URL  Catalogue base URL (env: CATALOG_BASE).
  -d DEST_DIR  Destination directory (default: data in the repo root).
  -h           Show this help.
EOF
}

validate_json() {
    local file="$1"

    test -s "$file" || return 1
    if command -v jq >/dev/null 2>&1; then
        jq -e . "$file" >/dev/null 2>&1
    elif command -v python3 >/dev/null 2>&1; then
        python3 -I -m json.tool "$file" >/dev/null 2>&1
    fi
}

while getopts ':b:d:h' opt; do
    case "$opt" in
        b) BASE_URL="$OPTARG" ;;
        d) DEST_DIR="$OPTARG" ;;
        h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
if [[ $# -gt 0 ]]; then
    echo "error: unexpected argument: $1" >&2
    usage >&2
    exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "error: curl is required" >&2
    exit 1
fi

if [[ "$BASE_URL" != */ ]]; then
    BASE_URL="$BASE_URL/"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

for name in "${NAMES[@]}"; do
    url="${BASE_URL}${name}.json"
    file="$TMP_DIR/$name.json"
    if ! curl -fsSL --retry 3 -o "$file" "$url"; then
        echo "error: download failed: $url" >&2
        exit 1
    fi
    if ! validate_json "$file"; then
        echo "error: empty or invalid JSON: $url" >&2
        exit 1
    fi
done

mkdir -p -- "$DEST_DIR"
for name in "${NAMES[@]}"; do
    mv -f -- "$TMP_DIR/$name.json" "$DEST_DIR/$name.json"
done

echo "Catalogue saved to $DEST_DIR"
