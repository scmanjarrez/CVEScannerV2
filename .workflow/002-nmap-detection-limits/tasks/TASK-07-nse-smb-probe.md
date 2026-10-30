# TASK-07 — NSE: sonda SMB para versión exacta de Samba (F3, L1)
Plan: 002-nmap-detection-limits (PLAN.md §2.A, riesgos F3, invariante 4)
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_catalog.lua`
(+ `tests/lua/harness.lua` solo para stub de `smb` y EXPORTS).
Gate Lua: `LUA=texlua sh tests/run.sh` verde (≥96 passed).

## Cambios
1. Nuevo script-arg `cvescannerv2.smb` (defecto `'1'`), leído como los
   demás (`http_arg`, etc.); documentar en la cabecera `@args` del NSE.
2. `local ok, smb = pcall(require, 'smb')` (tolerar ausencia).
3. Nueva función local `smb_version(host, port)`: si `smb_arg == '1'`, `smb`
   disponible y `port.number` ∈ {139, 445} (o `port.service` ∈
   {microsoft-ds, netbios-ssn}), `pcall(smb.get_os, host)`; si devuelve
   tabla con `lanmanager` que case `^Samba%s+([%d%.]+[%w%.]*)` extrae la
   versión (`Samba 3.0.20-Debian` ⇒ `3.0.20`; descarta sufijo `-Debian`
   etc.); si falla/vacío ⇒ `nil` (fallo silencioso, log nivel 2).
   Cachear por host en `registry` para no repetir por puerto.
4. `portaction`: si `smb_version` devuelve versión y el CPE de Nmap es
   `samba:samba` (o producto samba), añadir
   `add_cpe_version('cpe:/a:samba:samba', ver, matches, 'smb')` y NO añadir
   la versión (rango) de Nmap para ese CPE (la SMB gana). Si no hay
   sonda ⇒ comportamiento actual intacto.
   Asegúrate de que `matches['data']` admita la nueva ubicación `'smb'`
   (init en `portaction` y cualquier iteración por ubicaciones).
5. Tests (stub `smb.get_os` vía `package.loaded.smb` o `opts` en el
   harness): lanmanager `Samba 3.0.20-Debian` ⇒ matches con `3.0.20`
   y sin el rango `3.X - 4.X`; `smb.get_os` lanza error ⇒ cae a Nmap;
   `smb=0` ⇒ no se invoca; puerto 80 ⇒ no se invoca.
No cambiar salida JSON/tabla (F7). Devuelve STATUS (CHECKS: lua_tests=PASS).
