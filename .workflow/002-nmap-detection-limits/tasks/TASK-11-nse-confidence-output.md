# TASK-11 — NSE: salida con confianza (JSON, tabla, log) + minconf (F7b)
Plan: 002-nmap-detection-limits (PLAN.md §2.C Formato). Depende de TASK-10.
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_database.lua` o
`test_scoping.lua` (el que ya pruebe `analysis`/salida; ver cuál) +
`tests/lua/harness.lua` EXPORTS. Gate: `LUA=texlua sh tests/run.sh`.

## Cambios
1. Script-arg `cvescannerv2.minconf` = low|medium|high (defecto `low`);
   inválido ⇒ `low` + aviso. Documentar en `@args`.
2. **JSON** (solo campos añadidos; claves actuales intactas): por CVE
   `confidence`, `reasons`; por servicio `version_source` (de
   `cpe_parser`: smb|nmap_version|nmap_cpe; `smb` si vino de la sonda),
   `os_context` ({family, distro, source}), `warnings`, `summary`
   ({high,medium,low}). El JSON conserva SIEMPRE todas las CVEs
   (minconf no filtra JSON). Mantener la estructura actual de
   `registry.json_out` (incluida la rama de caché).
3. **Tabla Nmap**: columna nueva `Conf` (`HIGH|MED|LOW`) tras ID;
   orden por confianza (high>medium>low) y luego CVSS (reutiliza
   `cvss_comparator`); línea de cabecera por servicio con
   `version_source` y avisos (`distro_backport`: "CVEs pueden estar
   parcheadas por backport"); `maxcve` se aplica DESPUÉS de ordenar;
   `minconf` filtra tabla (CVEs con nivel < minconf se omiten; el
   contador `cves: N` refleja las mostradas y añade `(total M)`).
4. **Log** (`log(...)`): por CVE `confidence` + `reasons`; por servicio
   `version_source`, `os_context`, `warnings`, resumen por nivel;
   `minconf` filtra también el log de CVEs.
5. La caché `registry.cache` debe seguir funcionando con los campos
   nuevos (no perderlos al reusar).
6. Tests: orden por confianza y `maxcve` tras ordenar; `minconf=medium`
   oculta `low` en tabla pero JSON conserva todas; cabecera con
   version_source/aviso; JSON con campos nuevos y claves previas intactas.
Devuelve STATUS.
