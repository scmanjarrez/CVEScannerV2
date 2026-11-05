#!/bin/sh

# SPDX-License-Identifier: GPL-3.0-or-later

# build - Database builder.

# Copyright (C) 2021-2026 Sergio Chica Manjarrez @ pervasive.it.uc3m.es.
# Universidad Carlos III de Madrid.

# This file is part of CVEScannerV2DB.

# CVEScannerV2DB is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# CVEScannerV2DB is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
OUTPUT="cve.db"
REMOVE=0

usage ()
{
    echo "Usage: $0 [OPTS]"
    echo "OPTS:"
    echo "    -h, --help          Show this help."
    echo "    -o, --output FILE   Output database. Default: $OUTPUT"
    echo "    --remove            Remove database if present"
}

fail ()
{
    rm -f "$OUTPUT"
    echo "Error: $1" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -o|--output)
            if [ $# -lt 2 ]; then
                usage >&2
                exit 1
            fi
            OUTPUT=$2
            shift
            ;;
        --remove)
            REMOVE=1
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
    shift
done

if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "Error: package sqlite3 missing" >&2
    exit 1
fi

set -- "$DIR"/dump.p*
if [ ! -f "$1" ]; then
    echo "Error: no dump.p* parts in $DIR" >&2
    exit 1
fi

if [ -e "$OUTPUT" ]; then
    if [ "$REMOVE" -eq 1 ]; then
        rm -f "$OUTPUT"
    else
        echo "Error: $OUTPUT already exists (use --remove)" >&2
        exit 1
    fi
fi

if ! cat "$DIR"/dump.p* | sqlite3 -bail "$OUTPUT"; then
    fail "import into $OUTPUT failed"
fi

RESULT=$(sqlite3 "$OUTPUT" "PRAGMA quick_check;" 2>/dev/null || true)
if [ "$RESULT" != "ok" ]; then
    fail "quick_check failed on $OUTPUT"
fi

echo "Database built: $OUTPUT"
exit 0
