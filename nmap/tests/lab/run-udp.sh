#!/bin/sh
# Ejecuta el lab UDP (ntp, upnp) con probes=none y probes=all.
# Requiere root (nmap -sU): sudo sh nmap/tests/lab/run-udp.sh
# Salida: results/lab/<servicio>-{none,all}.json, results/lab/udp-summary.txt
# Variables: LAB_WAIT_SECS (espera de arranque, defecto 90: apt-get install)

set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
OUT_DIR="$ROOT/results/lab"
SUMMARY="$OUT_DIR/udp-summary.txt"
SERVICES="ntp upnp"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ejecuta con sudo: sudo sh $0" >&2
    exit 1
fi

cd "$ROOT"
mkdir -p "$OUT_DIR"
: > "$SUMMARY"

for svc in $SERVICES; do
    LAB_WAIT_SECS="${LAB_WAIT_SECS:-90}" sh nmap/tests/lab/run.sh "$svc" \
        > "$OUT_DIR/$svc.log" 2>&1 || echo "[!] $svc fallo, ver $svc.log" \
        | tee -a "$SUMMARY"
done

python3 - "$OUT_DIR" $SERVICES >> "$SUMMARY" <<'PY'
import json
import sys

out, services = sys.argv[1], sys.argv[2:]
for svc in services:
    for mode in ("none", "all"):
        path = f"{out}/{svc}-{mode}.json"
        try:
            with open(path) as handle:
                data = json.loads(handle.read().strip().splitlines()[-1])
        except (OSError, ValueError, IndexError):
            print(f"{svc:6} {mode:4} sin resultado")
            continue
        rows = []
        for host in data.get("hosts", []):
            for port in host.get("ports", []):
                label = f"{port['port']}/{port['protocol']}"
                for product in port.get("products", []):
                    rows.append((label, product.get("product"),
                                 product.get("version"),
                                 product.get("version_source"),
                                 len(product.get("cves", []))))
        if not rows:
            print(f"{svc:6} {mode:4} sin servicios analizados")
        for port, prod, ver, src, n in rows:
            print(f"{svc:6} {mode:4} {port} {prod} {ver} "
                  f"src={src} cves={n}")
PY

# Los JSON los crea root: devolverlos al usuario que invoco sudo.
if [ -n "${SUDO_USER:-}" ]; then
    chown -R "$SUDO_USER" "$OUT_DIR"
fi

cat "$SUMMARY"
echo "Logs completos: $OUT_DIR/<servicio>.log"
