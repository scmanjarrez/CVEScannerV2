#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Set or verify the project version across the files that carry it.
#
# Usage: scripts/bump-version.sh [--check] X.Y.Z
#
#   X.Y.Z        Set the version everywhere (a leading "v" is ignored).
#   --check      Verify the version in the source locations; change nothing.
#   -h, --help   Show this help.
#
# Set mode rewrites:
#   nmap/src/cvescannerv2.nse   local version = "..."
#   db-manager/pyproject.toml   first version = "..." ([project])
#   db-manager/uv.lock          version after name = "db-manager"
#   README.md                   log header and example scanner version
# Check mode reads the first three locations only.
#
# All locations are validated before any file is written.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname -- "$SCRIPT_DIR")"

NSE_FILE="$REPO_ROOT/nmap/src/cvescannerv2.nse"
PYPROJECT_FILE="$REPO_ROOT/db-manager/pyproject.toml"
UVLOCK_FILE="$REPO_ROOT/db-manager/uv.lock"
README_FILE="$REPO_ROOT/README.md"

usage() {
    cat <<'EOF'
Usage: bump-version.sh [--check] X.Y.Z

  X.Y.Z      Set the version everywhere (a leading "v" is ignored).
  --check    Verify the version in the source locations; change nothing.
  -h, --help Show this help.
EOF
}

die() {
    echo "error: $*" >&2
    exit 2
}

# Print the version found at each location (one per line: label<TAB>value).
read_nse() {
    sed -n -E 's/^local version = "([^"]*)".*/\1/p' "$NSE_FILE" | head -n 1
}

read_pyproject() {
    grep -m 1 -E '^version = "' "$PYPROJECT_FILE" | sed -E 's/^version = "([^"]*)".*/\1/'
}

read_uvlock() {
    awk -F'"' '/^name = "db-manager"$/ {f = 1; next} f && /^version = / {print $2; exit}' "$UVLOCK_FILE"
}

# Preflight: every set-mode location must exist before anything is written.
check_locations() {
    [[ -f "$NSE_FILE" ]] || die "missing file: $NSE_FILE"
    [[ -f "$PYPROJECT_FILE" ]] || die "missing file: $PYPROJECT_FILE"
    [[ -f "$UVLOCK_FILE" ]] || die "missing file: $UVLOCK_FILE"
    [[ -f "$README_FILE" ]] || die "missing file: $README_FILE"

    [[ -n "$(read_nse)" ]] || die "no 'local version' line in ${NSE_FILE#"$REPO_ROOT"/}"
    [[ -n "$(read_pyproject)" ]] || die "no 'version' line in ${PYPROJECT_FILE#"$REPO_ROOT"/}"
    [[ -n "$(read_uvlock)" ]] || die "no db-manager 'version' line in ${UVLOCK_FILE#"$REPO_ROOT"/}"
    grep -q -E '^=== cvescannerv2 [^ ]+  ' "$README_FILE" \
        || die "no log header '=== cvescannerv2 <ver>  ' in ${README_FILE#"$REPO_ROOT"/}"
    grep -q -E '"scanner": \{ "name": "cvescannerv2", "version": "[^"]*" \}' "$README_FILE" \
        || die "no scanner version example in ${README_FILE#"$REPO_ROOT"/}"
}

set_version() {
    local ver="$1"
    local rel old

    check_locations

    rel="${NSE_FILE#"$REPO_ROOT"/}"
    old="$(read_nse)"
    sed -i -E "s/^local version = \"[^\"]*\"/local version = \"$ver\"/" "$NSE_FILE"
    echo "$rel: $old -> $ver"

    rel="${PYPROJECT_FILE#"$REPO_ROOT"/}"
    old="$(read_pyproject)"
    sed -i -E "0,/^version = \"[^\"]*\"/s//version = \"$ver\"/" "$PYPROJECT_FILE"
    echo "$rel: $old -> $ver"

    rel="${UVLOCK_FILE#"$REPO_ROOT"/}"
    old="$(read_uvlock)"
    sed -i -E "/^name = \"db-manager\"\$/{n;s/^version = \"[^\"]*\"\$/version = \"$ver\"/}" "$UVLOCK_FILE"
    echo "$rel: $old -> $ver"

    rel="${README_FILE#"$REPO_ROOT"/}"
    sed -i -E \
        -e "s/^(=== cvescannerv2 )[^ ]+(  )/\1$ver\2/" \
        -e "s/(\"scanner\": \\{ \"name\": \"cvescannerv2\", \"version\": \")[^\"]*(\" \\})/\1$ver\2/" \
        "$README_FILE"
    echo "$rel: log header and scanner example -> $ver"
}

check_version() {
    local ver="$1"
    local -a labels=() values=()
    local i status=0 val

    [[ -f "$NSE_FILE" && -f "$PYPROJECT_FILE" && -f "$UVLOCK_FILE" ]] \
        || die "missing version files under $REPO_ROOT"

    labels=(
        "nmap/src/cvescannerv2.nse"
        "db-manager/pyproject.toml"
        "db-manager/uv.lock"
    )
    values=(
        "$(read_nse)"
        "$(read_pyproject)"
        "$(read_uvlock)"
    )

    for i in "${!labels[@]}"; do
        val="${values[$i]}"
        [[ -n "$val" ]] || die "no version found in ${labels[$i]}"
        echo "${labels[$i]}: $val"
    done

    for i in "${!labels[@]}"; do
        if [[ "${values[$i]}" != "$ver" ]]; then
            echo "MISMATCH: ${labels[$i]} has ${values[$i]}, expected $ver" >&2
            status=1
        fi
    done

    if [[ $status -eq 0 ]]; then
        echo "OK: all locations are at $ver"
    fi
    return "$status"
}

main() {
    local mode="set"
    local ver=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --check)
                mode="check"
                shift
                ;;
            -*)
                usage >&2
                die "unknown option: $1"
                ;;
            *)
                [[ -z "$ver" ]] || { usage >&2; die "only one version may be given"; }
                ver="$1"
                shift
                ;;
        esac
    done

    [[ -n "$ver" ]] || { usage >&2; exit 2; }

    ver="${ver#v}"
    if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        die "invalid version '$ver' (expected X.Y.Z)"
    fi

    if [[ "$mode" == "check" ]]; then
        check_version "$ver"
    else
        set_version "$ver"
    fi
}

main "$@"
