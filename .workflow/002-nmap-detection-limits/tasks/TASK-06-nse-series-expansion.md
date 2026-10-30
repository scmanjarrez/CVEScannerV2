# TASK-06 — NSE: expansión de versión "de serie" (F2, L2)
Plan: 002-nmap-detection-limits (PLAN.md §1 L2, §2.A, riesgo F2).
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_scoping.lua`.
Gate Lua: `LUA=texlua sh tests/run.sh` verde (lua5.4 no instalado).

## Problema
Versión de Nmap `x.y` (p. ej. `5.5`, `1.8`, `8.3`) con 2 componentes se
trata como `x.y.0` exacta ⇒ FN (Tomcat 5.5.x, Ruby 1.8.x, PG 8.3.x).

## Cambios
1. En `vulnerabilities(...)` (y/o `version_parser`/`scoped_*`, lo mínimo
   necesario) detectar versión de serie: `ver` con exactamente 2
   componentes numéricos (`^%d+%.%d+$`), sin update (`vup` '*' o vacío),
   NO rango, y fuente `nmap_cpe`/`nmap_version` (no inventar para
   versiones ya específicas).
2. Solo si la BD tiene filas del producto con versión `x.y.%` (consulta
   SQL análoga a las ya existentes en `query`/`vulnerabilities`, p.
   `version LIKE 'x.y.%'` sobre la tabla de productos), tratar la versión
   como rango `from = x.y.0`, `to = x.y.9999999999` (mismo patrón que el
   caso `wildcard_prefix` de `version_parser`) además de la coincidencia
   exacta `x.y`; deduplicar CVEs. Si la BD no tiene hijas, comportamiento
   actual intacto.
3. Marcar el resultado con un flag interno `series_expanded = true` por
   CVE añadida por la expansión (almacenar en la estructura que ya usan
   las CVEs, p. ej. campo extra en `result`); NO cambiar la salida
   JSON/tabla (eso es F7). Si es difícil sin refactor grande, deja el flag
   en `info.series_expanded` y anótalo en NOTES.
4. Tests en `tests/lua/test_scoping.lua` con el estilo existente (stub
   de `query`/BD como hagan los tests actuales): serie `5.5` con hijas
   ⇒ expande; sin hijas ⇒ igual que antes; versión `5.5.3` ⇒ no expande;
   rango Nmap ⇒ no cambia.

## Verificación
`LUA=texlua sh tests/run.sh` sin fallos y sin regresión (≥89 passed).
Devuelve STATUS (CHECKS: lua_tests=PASS).
