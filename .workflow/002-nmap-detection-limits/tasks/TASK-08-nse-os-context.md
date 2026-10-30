# TASK-08 — NSE: contexto de SO y distro (F5a + F6)
Plan: 002-nmap-detection-limits (PLAN.md §2.B "Contexto de SO", L7)
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_versions.lua`
(+ `tests/lua/harness.lua` solo EXPORTS). Gate: `LUA=texlua sh tests/run.sh`
verde (≥101).

## Cambios
1. Carga de `data/platform-families.json` (mapa vendor→familia) con el
   mismo mecanismo que el resto de datos (`read_catalog_json`/ruta de
   datos junto al script). Fallo de carga ⇒ mapa vacío + log (no abortar).
   Guardar en `registry.platform_families`.
2. Función local `os_context(host, port)` → tabla
   `{ family = 'linux'|'windows'|'macos'|'bsd'|'solaris'|nil,
      distro = 'ubuntu'|'debian'|'redhat'|'suse'|... |nil,
      source = 'cpe'|'ostype'|'host_os'|'extrainfo'|nil }`.
   Fuentes en orden: CPEs `o:` de `port.version.cpe[]` (vendor→familia
   por el mapa); `port.version.ostype` (`Linux`, `Windows`, `Unix`…);
   `host.os` (si existe: clases/`cpe` de la primera coincidencia, con
   `pcall`); texto `version`/`extrainfo` (`Ubuntu`, `Debian`, `Red Hat`,
   `CentOS`, `Windows`). Desconocido ⇒ `{}`. Cachear en
   `registry` por `host.ip` el resultado de host.os (el de puerto no).
3. Función local `distro_backport(port)` → `true` si `version`/`extrainfo`
   contiene indicios de paquete de distro (`ubuntu%d`, `debian`,
   `%(Ubuntu%)`, `%(Debian%)`, `el%d`, `deb%d`, `Red Hat`) — solo
   informativa.
4. En `portaction` calcular ambos y guardarlos en variables locales
   pasadas a `analysis` (nuevo parámetro opcional `ctx`), sin cambiar
   la salida JSON/tabla (F7). Mínimo: que `analysis` los reciba.
5. Tests en `tests/lua/test_versions.lua` (estilo existente): CPE
   `cpe:/o:linux:linux_kernel` ⇒ linux; `ostype='Windows'` ⇒ windows;
   `extrainfo='Ubuntu'` ⇒ distro ubuntu; sin datos ⇒ `{}`;
   `host.os` stub; backport: `4.7p1 Debian 8ubuntu1` ⇒ true, `2.2.8` ⇒ false.
Exportar `os_context`, `distro_backport` en EXPORTS del harness.
Devuelve STATUS.
