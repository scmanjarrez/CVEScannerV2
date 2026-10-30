# TASK-19 — version_source = 'http' cuando la versión viene de una sonda HTTP
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_scoping.lua`
(o el test que ya cubra `version_source`). Gate: `sh tests/run.sh` (≥169, 0 skipped).

Hoy `analysis` calcula `version_source` con `cpe_parser` (nmap_cpe /
nmap_version) y 'smb' si la versión salió de `matches.data.smb`. Falta: si la
versión analizada procede de `matches.data.http` (sonda dirigida o barrido
del catálogo) y no de `nmap`/`smb`, `version_source` debe ser `'http'`
(en JSON, tabla, log y clave de caché). Prioridad si una versión aparece en
varias fuentes: smb > http > nmap_version > nmap_cpe según de dónde se
iteró en `analysis` (`for _, data in pairs(matches['data'])`: usa el nombre
de la fuente iterada). Tests: versión solo en `http` ⇒ 'http'; en `smb` ⇒
'smb'; en `nmap` ⇒ como hoy. Devuelve STATUS.
