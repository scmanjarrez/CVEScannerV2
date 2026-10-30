# TASK-05 — F2c: espera de reintento `irc` 10 s → 20 s

Medido en MS2: los intentos rechazados prolongan el throttle; tras la
ráfaga de `-sV` hacen falta ≥ 15 s sin conexiones.

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/test_catalog.lua`

## Cambio
- En la sonda `irc`, el `stdnse.sleep(10)` del reintento pasa a una
  constante local `IRC_RETRY_DELAY = 20` (usarla en el sleep y en el
  mensaje de log si lo menciona).
- Actualizar los tests de TASK-04 que esperan `sleep` con 10 para que
  esperen 20.
- No tocar `load_luasql()`.

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
192 passed. Devolver SOLO el bloque de estado (`TASK: TASK-05`,
`CHECKS: lua_tests=PASS`). No ejecutar nmap.
