# TASK-07 — F4b: la caché de `analysis` no debe saltarse la sonda de SO de otro host

Hueco detectado en TASK-06: `analysis` busca en `registry.cache` con la
clave previa a la sonda (sin host). Un host con SO desconocido puede
acertar una entrada cacheada de otro host con SO desconocido y no
sondear el suyo; y la entrada guardada tras sondear (clave recalculada
con SO final) nunca coincide con la de un host sin sonda.

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/test_catalog.lua` (casos nuevos en suite `os probe`)

No tocar `load_luasql()`.

## Cambio
En `analysis`, al construir `cache_key`: si `ctx.os.family == nil`
(SO desconocido), añadir `host.ip` a la clave (`'|' .. host.ip`). Con SO
conocido la clave queda como hoy (se comparte entre hosts). Mantener la
recalculación de TASK-06 (clave con el SO final tras la sonda).

## Tests
1. Dos hosts distintos, mismo producto/versión, SO desconocido, el
   primero sondea y obtiene `windows`: el segundo NO reutiliza la entrada
   cacheada del primero (se evalúa y sondea por su cuenta).
2. Mismo host, dos puertos con mismo producto/versión: la segunda llamada
   usa la caché (`log "cached"` o contador de `vulnerabilities`).
3. SO conocido (`linux`) en dos hosts ⇒ la caché se comparte.
Si no es alcanzable sin exportar nuevas funciones, cubrir con `analysis`
(exportada) y un contador sobre `registry.conn:execute`; anotar límites.

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
201 previos + nuevos en verde. No ejecutar nmap. Devolver SOLO el bloque
de estado (`TASK: TASK-07`, `CHECKS: lua_tests=PASS`).
