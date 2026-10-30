# TASK-10 — Fix: el motor HTTP corta si el puerto no responde HTTP

Defensa en profundidad tras TASK-09: un puerto mal clasificado no debe
bloquear el escaneo recorriendo todas las rutas. Requiere TASK-09.

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/test_catalog.lua` (suite `http engine abort`)

No tocar `load_luasql()`.

## Cambio
- Constante local `HTTP_MAX_FAILURES = 5`.
- `http_match_legacy`: contador de fallos **consecutivos** de
  `http.get(...)` (respuesta sin `status`); se reinicia con cualquier
  respuesta con `status`. Al llegar a `HTTP_MAX_FAILURES`, registrar con
  `stdnse.verbose(2, ...)` y salir de la función (return) sin más
  peticiones. Aplicar a las peticiones de rutas, no a las de librerías JS.
- `sweep_catalog`: si un lote completo de `pipeline_go` no devuelve
  ninguna respuesta con `status` (nil, no-tabla o sin status), abandonar el
  barrido de ese puerto (break) con `stdnse.verbose(2, ...)`. Un lote con
  al menos una respuesta válida continúa como hoy.
- `run_targeted_probes` no cambia.

## Tests (stubs de `http`)
1. Legacy: `http.get` siempre devuelve `{}` (sin status) ⇒ exactamente 5
   llamadas y retorna sin error. Ruta que empieza a fallar tras 3 éxitos
   (éxito, éxito, éxito, 5 fallos) ⇒ corta tras los 5 fallos.
2. Legacy: fallos intermitentes (fallo, éxito, fallo, éxito, ...) ⇒ no
   corta (recorre todas las rutas).
3. Catálogo: `pipeline_go` devuelve lote sin status ⇒ solo se pide 1 lote
   (`pipeline_go` llamado 1 vez aunque haya más rutas en el catálogo).
4. Catálogo: lote con al menos una respuesta con status ⇒ continúa con
   el siguiente lote.
Usar el catálogo y `registry.path` mínimos que ya montan los tests
existentes; si `http_match_legacy`/`sweep_catalog` no están exportados
llamar a través de `http_match` (exportada indirectamente por
`portaction`); NO modificar `harness.lua`.

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
Todo en verde. No ejecutar nmap. Devolver SOLO el bloque de estado
(`TASK: TASK-10`, `CHECKS: lua_tests=PASS`).
