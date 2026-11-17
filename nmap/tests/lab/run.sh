#!/bin/sh
# Ejecuta cvescannerv2 contra el lab, con probes=none y probes=all.
# Uso: nmap/tests/lab/run.sh <servicio|all>
# Servicios: ntp weblogic cups php wordpress drupal mongo redis upnp
# Salida: results/lab/<servicio>-{none,all}.json

set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
COMPOSE="$ROOT/nmap/tests/lab/compose.yaml"
OUT_DIR="$ROOT/results/lab"
WAIT_SECS="${LAB_WAIT_SECS:-30}"
ALL_SERVICES="ntp weblogic cups php wordpress drupal mongo redis upnp"

usage() {
    echo "Uso: $0 <servicio|all>" >&2
    echo "Servicios: $ALL_SERVICES" >&2
    exit 1
}

# Devuelve puerto y opciones de nmap para un servicio.
port_of() {
    case "$1" in
        ntp) echo 123 ;;
        weblogic) echo 7001 ;;
        cups) echo 1631 ;;
        php) echo 8056 ;;
        wordpress) echo 8057 ;;
        drupal) echo 8058 ;;
        mongo) echo 27017 ;;
        redis) echo 6379 ;;
        upnp) echo 1900 ;;
        *) return 1 ;;
    esac
}

scan_one() {
    svc="$1"
    port=$(port_of "$svc") || usage
    proto_opt=""
    if [ "$svc" = "ntp" ] || [ "$svc" = "upnp" ]; then
        proto_opt="-sU"
    fi
    for mode in none all; do
        out="$OUT_DIR/$svc-$mode.json"
        echo ">> $svc probes=$mode -> $out"
        # shellcheck disable=SC2086
        nmap -n -sV $proto_opt -p "$port" \
            --script "$ROOT/nmap/src/cvescannerv2.nse" \
            --script-args "probes=$mode,json=$out" \
            127.0.0.1
    done
}

[ $# -eq 1 ] || usage
TARGET="$1"

if [ "$TARGET" = "all" ]; then
    SERVICES="$ALL_SERVICES"
else
    port_of "$TARGET" >/dev/null || usage
    SERVICES="$TARGET"
fi

mkdir -p "$OUT_DIR"

cleanup() {
    docker compose -f "$COMPOSE" down
}
trap cleanup EXIT INT TERM

docker compose -f "$COMPOSE" up -d $SERVICES
echo "Esperando ${WAIT_SECS}s a que arranquen los servicios..."
sleep "$WAIT_SECS"

for svc in $SERVICES; do
    scan_one "$svc"
done
