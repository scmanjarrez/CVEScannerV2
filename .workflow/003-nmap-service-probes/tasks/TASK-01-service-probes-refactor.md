# TASK-01 — F1: refactor `SERVICE_PROBES` + despachador + arg `probes`

Plan: 003-nmap-service-probes (PLAN.md §3.A, §3.C, §4). Pura refactorización:
**comportamiento idéntico** para SMB.

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/harness.lua` (solo ampliar la lista `EXPORTS`)

NO tocar tests (`test_*.lua`): van en TASK-02. Los 172 tests existentes
deben seguir pasando sin cambios.

## Cambios en `cvescannerv2.nse`
1. Nuevo arg `probes` (`all|none|<csv>`, defecto `all`), junto a `smb_arg`.
   Documentarlo en la cabecera de args. Función local
   `probe_enabled(name)`: `none` → false; `all` → true; csv → pertenencia.
   `smb=0` sigue siendo alias que desactiva la sonda `smb`.
2. Tabla local `SERVICE_PROBES` (lista plana de entradas):
   `{ name, kind = 'version'|'os', services = {set}, products = {set}|nil,
   ports = {set}|nil, run = function(host, port) -> {cpe=, version=}|nil }`.
   Disparador = `port.service` en `services` o puerto en `ports` (conserva
   `SMB_PORTS`/`SMB_SERVICES`), y producto de la CPE en `products` si se
   define.
3. Despachador `run_version_probe(host, port, probe)`:
   - comprueba `probe_enabled(probe.name)`;
   - `pcall(probe.run, host, port)`, fallo → `stdnse.verbose(2, ...)` y `nil`;
   - caché en `registry.probes[probe.name][host.ip..':'..port.number]`
     (`false` = negativo). Añadir `probes = {}` al registry inicial.
4. Migrar SMB: la entrada `smb` (kind `version`, products `samba`) envuelve
   la lógica actual de `smb_version` (`smb.get_os`, regex de `lanmanager`).
   La caché de SMB sigue siendo **por host** (una sola llamada a
   `smb.get_os` por host aunque varios puertos): usar clave `host.ip` en
   la entrada SMB mediante un campo opcional `cache_key = function(host,
   port)`. Mantener `smb_version(host, port)` como función exportada con la
   misma firma/resultado (los tests la llaman) y `registry.smb` puede
   quedar como alias o sustituirse por `registry.probes.smb`.
5. `add_nmap_matches`: iterar `SERVICE_PROBES` de kind `version` aplicables
   al puerto en vez del `if product == 'samba'`. Si la sonda devuelve
   `{cpe, version}` → `add_cpe_version(cpe, version, matches, probe.name)`
   y `return` (sustituye a Nmap). Para SMB el origen sigue siendo `'smb'`.
6. `analysis`: `version_source = origin` para todo origen distinto de
   `'nmap'` (hoy solo `smb`/`http`). `portaction` crea `matches.data` con
   `nmap/http/smb`; no añadir claves nuevas aún.
7. Con `probes=none` no se llama a ningún `run`.

## Cambios en `tests/lua/harness.lua`
Añadir a `EXPORTS`: `'SERVICE_PROBES'`, `'run_version_probe'`,
`'probe_enabled'`.

## Estilo
Lua del repo: 2 espacios, ≤ 80 col, comentarios `---` como las demás
funciones, sin dependencias nuevas. Nada de abstracciones extra (KISS).

## Verificación (sustituye al gate Python de AGENTS.md §5: aquí es Lua)
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
Debe dar `172 passed, 0 failed`. No ejecutar `ruff`/`basedpyright` (no hay
`.py`). Devolver SOLO el bloque de estado (con
`CHECKS: lua_tests=PASS`).
