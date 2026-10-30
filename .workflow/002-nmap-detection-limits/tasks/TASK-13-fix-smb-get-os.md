# TASK-13 — Corregir uso de smb.get_os (bug hallado con MS2 real)
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_catalog.lua`
(+ `tests/lua/harness.lua` si el stub de smb vive allí).
Gate: `sh tests/run.sh` (lua5.4 ya instalado, con luasql: ≥159 passed, 0 skipped).

## Bug
`smb.get_os(host)` devuelve `(status, result)`: `status` booleano y
`result` tabla con `lanmanager` (p. ej. `Samba 3.0.20-Debian`).
`smb_version` hace `local ok, info = pcall(smb.get_os, host)` y trata
`info` (el booleano `status`) como resultado ⇒ nunca extrae la versión.
## Cambios
1. `smb_version`: `local ok, status, info = pcall(smb.get_os, host)`;
   éxito solo si `ok and status and type(info)=='table'`; si
   `ok and not status`, `info` es el mensaje de error ⇒ log nivel 2 y
   `false` (cae a Nmap). Mantener caché por host y el resto igual.
2. Stubs de test de `smb.get_os`: deben devolver `true, {lanmanager=...}`
   (forma real). Casos: éxito, `false, 'error'`, `error()` (pcall falla),
   `smb=0`, puerto 80, caché.
Devuelve STATUS.
