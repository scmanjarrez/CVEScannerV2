#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Run every scanner test without Nmap. Requires lua5.4 and, for the
# database suite, lua5.4-sql-sqlite3 (skipped when missing).
set -eu

cd "$(dirname "$0")/.."
LUA="${LUA:-lua5.4}"
status=0

echo '### tests/test_scanner.lua (HTTP redirects and catalogue cache)'
"$LUA" tests/test_scanner.lua || status=1

echo
echo '### tests/lua (versions, scoping, catalogue, SQLite integration)'
"$LUA" tests/lua/run.lua || status=1

exit "$status"
