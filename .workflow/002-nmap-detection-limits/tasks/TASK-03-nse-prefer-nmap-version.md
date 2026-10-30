# TASK-03 — NSE: preferir port.version.version sobre CPE (F1, L3)
Plan: 002-nmap-detection-limits (PLAN.md §2.A, L3)
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_versions.lua`.
(Lua: sin ruff/basedpyright; gate = `sh tests/run.sh` verde.)

## Problema
`portaction` pasa `port.version.version` a `add_cpe_version`, pero
`cpe_parser(cpe, version)` solo usa la versión de Nmap si la de la CPE es
vacía/`*`. Caso PG: Nmap `8.3.0 - 8.3.7`, CPE `...:8.3` ⇒ gana `8.3`.

## Cambios
1. En `cvescannerv2.nse` (cerca de `cpe_parser`) nueva función local
   `prefer_version(cpe_version, nmap_version)` → `(version, source)`:
   - nmap vacío/`*` ⇒ (cpe_version, 'nmap_cpe');
   - cpe vacía/`*` ⇒ (nmap_version, 'nmap_version');
   - nmap es rango (`^(.-)%s+%-%s+(.+)$`) ⇒ nmap, 'nmap_version';
   - nmap empieza por cpe_version y el resto empieza por `.` (p. ej.
     cpe `8.3`, nmap `8.3.5`; NO `4.7p1` vs `4.7p1 Debian 8ubuntu1`) ⇒ nmap, 'nmap_version';
   - resto ⇒ cpe_version, 'nmap_cpe'.
   Cuando se elija la versión de Nmap, `cpe_update = nil` (como ya hace
   la rama `*`).
2. `cpe_parser` usa `prefer_version` y devuelve un 4.º valor `source`
   (`vendor, product, info, source`). Los llamadores existentes ignoran el
   4.º valor (comprobar que `analysis` y `log_info` siguen igual); no
   cambiar la salida JSON/tabla (eso es F7).
3. Tests nuevos en `tests/lua/test_versions.lua` (usar su estilo):
   rango Nmap vs CPE `8.3` ⇒ `from=8.3.0,to=8.3.7`, source
   `nmap_version`; CPE `8.3` + nmap `8.3.5` ⇒ ver `8.3.5`; CPE `2.2.8` +
   nmap `2.2.8` ⇒ `nmap_cpe`; CPE `*` + nmap `1.0` ⇒ `nmap_version`;
   nmap vacío ⇒ `nmap_cpe`. Los tests existentes de `cpe_parser` deben
   seguir verdes.

## Verificación
`sh tests/run.sh` sin fallos (informa nº de tests). Devuelve el bloque
STATUS (CHECKS: `lua_tests=PASS`).

## Enmienda
Lua: usar `LUA=texlua sh tests/run.sh` (lua5.4 no instalado). El test existente 'CPE version wins over the Nmap version string' debe seguir verde.
