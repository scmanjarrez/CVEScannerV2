# TASK-14 — Fase B: prefetch ordenado de páginas offline

Plan: database-write-optimization (W4). Ficheros (2):
- `db-manager/src/db_manager/infrastructure/nvd.py`
- `db-manager/tests/test_offline.py` (añadir tests; no alterar los existentes)

## Objetivo
Mientras el writer confirma la página N, leer+validar+convertir a comandos
la página N+1 en un hilo (`asyncio.to_thread`). El ORDEN de commit y los
checkpoints no cambian (IDs idénticos al baseline).

## Cambios en nvd.py
1. Nueva función SÍNCRONA
   `_prepare_raw_page(job: RawScopeJob, start_index: int) -> list[DatabaseCommand]`
   que hace: ruta = `job.directory / RAW_PAGE_NAME.format(...)`; si no
   `is_file()` → `RuntimeError("Raw NVD page is missing: {path}")` (mismo
   mensaje que hoy); `read_bytes`; `_validate_raw_page`;
   `_raw_page_commands`; devuelve los comandos. Sustituye a
   `_read_raw_page` (borrarla si queda sin uso) y a la parte de lectura de
   `_import_page`.
2. `_import_page` pasa a recibir los comandos ya preparados:
   `_import_page(job, start_index, commands, queue, writer_task)`; solo
   hace `queue.put(NvdPageBatch(...))` + `wait_for_writer_flush`.
3. `_import_scope`: sustituir el bucle por prefetch con ventana
   `RAW_PREFETCH_WINDOW: int = 2` (constante de módulo):
   - Mantener una `collections.deque` de `asyncio.Task` creadas con
     `asyncio.create_task(asyncio.to_thread(_prepare_raw_page, job, s))`
     para los próximos `starts`, en orden.
   - Para cada `start_index` en orden: `commands = await tasks.popleft()`,
     rellenar la ventana con la siguiente página (antes de esperar el
     flush, para solapar), luego `_import_page(...)` y `progress.update`.
   - Si algo falla (excepción de la preparación o del writer), en un
     `finally` cancelar las tareas pendientes y recoger sus excepciones
     (`await asyncio.gather(*pending, return_exceptions=True)`) para no
     dejar "Task exception was never retrieved". Debe relanzarse la
     excepción ORIGINAL; los errores (`RuntimeError`, `ValueError`)
     conservan tipo y mensaje.
   - Los commits ocurren estrictamente en el orden de `starts`.
4. No tocar el camino online ni el writer.

## Tests nuevos (test_offline.py, estilo existente, BD y raw temporales)
- Orden: importar un scope de ≥3 páginas y comprobar (p. ej. observando
  `nvd_pages` o parcheando `Database.mark_nvd_page` con un wrapper que
  registre llamadas) que las páginas se marcan en orden ascendente de
  `start_index`.
- Error en página intermedia: con la página 2 inválida/ausente, la
  importación lanza `RuntimeError`, la página 1 queda marcada y la 2 no
  (reanudación posterior funciona si ya hay un test análogo, no duplicar).
Reutiliza los helpers de fixtures existentes en el fichero.

## Verificación
- `cd db-manager && uv run python -m unittest discover -s tests`
- Gate AGENTS.md §5 sobre ambos ficheros.
