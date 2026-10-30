# TASK-01 — verify_nvd.py: medir FN y evaluar AND (F0)
Plan: 002-nmap-detection-limits (PLAN.md §1 L2/L3/L9, §3.6)
Archivos permitidos: `results/compare/verify_nvd.py` (único).
Script de análisis suelto (no paquete): aplica ruff/basedpyright SOLO si
ya pasaba; si no, solo mantener estilo actual y verificar ejecución.

## Objetivo
Extender el script sin romper su salida actual (tabla y `verify.json`):
1. **FN**: para cada producto de `T` (sondas ya definidas), recorrer TODAS
   las CVE de `data/nvd-raw` (no solo `need`) cuya config `vulnerable=true`
   afecte alguna sonda (`affected()=='yes'`) y que NO estén en
   `new.json`. Imprimir tras la tabla: `FN|producto|n` y escribir
   `fn.json` (`{producto: [cve,...]}`). Ampliar `idx` en el escaneo
   para guardar también CVEs candidatas (lo hace una sola pasada).
2. **AND/plataforma**: guardar por CVE las configs (`cf['operator']`,
   nodos con `cpeMatch` `vulnerable=false`). CVE es `SOLO_AND` si en
   ninguna configuración raíz aparece el producto vulnerable sin una
   CPE `vulnerable=false` acompañante. Para cada CVE reportada en
   `new.json` clasificada SOLO_AND, clasificar plataforma por vendor de las
   CPE no vulnerables: `microsoft→windows`, `apple→macos`,
   `freebsd→bsd`, `canonical|debian|redhat|suse|fedoraproject|gentoo|linux→linux`,
   `a:`→`component`. Imprimir `AND|familia|n` y escribir `and.json`
   (`{cve: {producto, familias:[...]}}`). Objetivo MS2 = Linux.
3. Mantener `verify.json` y la tabla original idénticos.

## Verificación
`cd results/compare && python3 verify_nvd.py` termina sin error, imprime
la tabla original + líneas `FN|...` y `AND|...`; `ls fn.json and.json`.
No leer/modificar otros ficheros. Devuelve el bloque STATUS del protocolo
(en CHECKS indica `run=PASS` en lugar de ruff/basedpyright).
