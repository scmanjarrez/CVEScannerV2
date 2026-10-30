# TASK-04 — F2b: la sonda `irc` reintenta una vez si el IRCd responde "Throttled"

Evidencia (F0, MS2 real): tras el `-sV`, UnrealIRCd responde
`ERROR :Closing Link: [ip] (Throttled: Reconnecting too fast) ...` a la
conexión de la sonda y la cierra. El bloqueo se levanta en < 10 s.

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/test_catalog.lua` (añadir casos a la suite `irc probe`)

NO tocar el bloque `load_luasql()` (lo añadió el usuario).

## Cambio
En la sonda `irc` (`irc_probe` / `irc_read_version` / `irc_exchange`):
- Si alguna línea leída empieza por `ERROR` y contiene `Throttled`,
  la lectura termina marcando "throttled" (devolver un segundo valor o un
  centinela; a tu elección, simple).
- `irc_probe`: ante throttled, cerrar el socket, `stdnse.sleep(10)`
  (usar `stdnse` ya cargado) y repetir el intercambio **una sola vez**
  con un socket nuevo. Máximo 2 conexiones por (sonda, puerto).
  Segundo intento fallido (throttled u otro) ⇒ `nil` (fallback a Nmap).
- Registrar con `stdnse.verbose(2, ...)` el reintento.
- Cada socket creado se cierra siempre.

## Tests (stub de socket y `scanner.stubs.stdnse.sleep` contador)
1. Primer socket responde ERROR Throttled, segundo da 351 ⇒ versión
   `3.2.8.1`; `new_socket` llamado 2 veces; `sleep` llamado con 10 y 1 vez.
2. Dos throttled ⇒ `nil`, exactamente 2 sockets, ambos cerrados.
3. Sin throttle ⇒ 1 socket, `sleep` no llamado.

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
Todo verde (189 previos + nuevos). Estilo 2 espacios, ≤ 80 col. Devolver
SOLO el bloque de estado (`TASK: TASK-04`, `CHECKS: lua_tests=PASS`).
