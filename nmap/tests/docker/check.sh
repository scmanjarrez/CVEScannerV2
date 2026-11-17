#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Integration checks of the scanner images. Needs Docker and network access.
#   sh nmap/tests/docker/check.sh [--fresh]
# --fresh rebuilds the CVE database and the Vulners catalogue (no cache).
# Prints PASS/FAIL per check and exits non-zero when any check fails.
set -u

cd "$(dirname "$0")/../../.." || exit 1

fresh=0
case "${1:-}" in
  '') ;;
  --fresh) fresh=1 ;;
  *) echo 'usage: sh nmap/tests/docker/check.sh [--fresh]' >&2; exit 2 ;;
esac

PASS=0
FAIL=0
NODB=cvescannerv2:test-nodb
DB=cvescannerv2:test-db
SUFFIX=$$
EXP_NODB="cvescannerv2-test-nodb-$SUFFIX"
EXP_DB="cvescannerv2-test-db-$SUFFIX"
NET="cvescannerv2-test-net-$SUFFIX"
WEB="cvescannerv2-test-web-$SUFFIX"
TMP=$(mktemp -d) || exit 1

cleanup() {
  docker rm -f "$WEB" "$EXP_NODB" "$EXP_DB" >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

report() { # name status
  if [ "$2" = ok ]; then
    echo "PASS  $1"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $1"
    FAIL=$((FAIL + 1))
  fi
}

check() { # name command...
  check_label=$1
  shift
  if "$@" >/dev/null 2>&1; then
    report "$check_label" ok
  else
    report "$check_label" fail
  fi
}

in_list() { # list-file name
  grep -Fxq "CVEScannerV2/data/$2" "$1"
}

not_in_list() { # list-file name
  ! grep -Fxq "CVEScannerV2/data/$2" "$1"
}

export_image() { # image container list-file
  docker rm -f "$2" >/dev/null 2>&1
  docker create --name "$2" "$1" >/dev/null || return 1
  docker export "$2" | tar -t \
    | sed -e 's#^\./##' -e 's#^/##' >"$3"
}

scan_logged() { # pattern
  grep -q "$1" "$TMP/scan.log"
}

scan_has_apache() {
  sed -n '/cvescannerv2:/,$p' "$TMP/scan.log" | grep -qi apache
}

command -v docker >/dev/null 2>&1 || {
  echo 'FAIL  docker is installed'
  exit 1
}

BUILD_ARGS=''
if [ "$fresh" -eq 1 ]; then
  epoch=$(date +%s)
  BUILD_ARGS="--build-arg DATABASE_REFRESH=$epoch --build-arg CATALOG_REFRESH=$epoch"
  echo "### fresh build (refresh $epoch)"
fi

echo '### build'
# shellcheck disable=SC2086
if docker build --target nodb $BUILD_ARGS -f docker/Dockerfile \
    -t "$NODB" . >"$TMP/build-nodb.log" 2>&1; then
  report 'build nodb image' ok
else
  report 'build nodb image' fail
  tail -n 20 "$TMP/build-nodb.log"
fi
# shellcheck disable=SC2086
if docker build --target db $BUILD_ARGS -f docker/Dockerfile \
    -t "$DB" . >"$TMP/build-db.log" 2>&1; then
  report 'build db image' ok
else
  report 'build db image' fail
  tail -n 20 "$TMP/build-db.log"
fi

echo '### image contents'
export_image "$NODB" "$EXP_NODB" "$TMP/nodb.list" \
  && report 'export nodb image' ok || report 'export nodb image' fail
export_image "$DB" "$EXP_DB" "$TMP/db.list" \
  && report 'export db image' ok || report 'export db image' fail

for name in vulnerscom-index.json vulnerscom-fingerprints.json \
    vulnerscom-paths.json vulnerscom-probes.json local-catalog.json product-aliases.json \
    vendor-aliases.json platform-families.json product-cpe.json; do
  check "nodb has data/$name" in_list "$TMP/nodb.list" "$name"
  check "db has data/$name" in_list "$TMP/db.list" "$name"
done
check 'nodb has no data/cve.db' not_in_list "$TMP/nodb.list" cve.db
check 'db has data/cve.db' in_list "$TMP/db.list" cve.db

echo '### cve.db'
docker cp "$EXP_DB:/CVEScannerV2/data/cve.db" "$TMP/cve.db" >/dev/null 2>&1
cat >"$TMP/check_db.py" <<'PYEOF'
import sqlite3
import sys

TABLES = ('products', 'cves', 'affected', 'multiaffected')

con = sqlite3.connect(sys.argv[1])
names = {row[0] for row in con.execute(
    "SELECT name FROM sqlite_master WHERE type = 'table'")}
missing = [name for name in TABLES if name not in names]
if missing:
    sys.exit('missing tables: ' + ', '.join(missing))
for name in TABLES:
    count = con.execute(f'SELECT count(*) FROM {name}').fetchone()[0]
    if count == 0:
        sys.exit(f'empty table: {name}')
cves = con.execute('SELECT count(*) FROM cves').fetchone()[0]
if cves <= 100000:
    sys.exit(f'too few CVEs: {cves}')
quick = con.execute('PRAGMA quick_check').fetchone()[0]
if quick != 'ok':
    sys.exit(f'quick_check: {quick}')
PYEOF
check 'cve.db has tables, rows and quick_check ok' \
  python3 -I "$TMP/check_db.py" "$TMP/cve.db"

echo '### scan'
if docker network create "$NET" >/dev/null 2>&1 \
    && docker run -d --rm --name "$WEB" --network "$NET" \
        php:5.6-apache >/dev/null 2>&1; then
  sleep 5
  ip=$(docker inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$WEB")
  docker run --rm --network "$NET" "$DB" -v -n -Pn -p 80 \
    --script-args json=/tmp/out.json "$ip" >"$TMP/scan.log" 2>&1
  check 'scan: catalogue read from the image cache' \
    scan_logged 'Using cached Vulners catalogue from data'
  check 'scan: local catalogue merged' \
    scan_logged 'Local catalogue data/local-catalog.json merged'
  check 'scan: cvescannerv2 block reports apache' scan_has_apache
else
  report 'scan: start php:5.6-apache target' fail
fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
