# TASK-11 — A2: `_queue_*` sin asyncio.Queue (listas puras)

Plan: database-write-optimization (W2). Fichero (1):
`db-manager/src/db_manager/infrastructure/nvd.py`.

## Cambios (mismos tipos de comando, MISMO ORDEN de comandos)
1. Convertir a funciones SÍNCRONAS que devuelven resultado en vez de
   encolar:
   - `_queue_cpe_records(content, url, queue) -> int` pasa a
     `_cpe_commands(content: bytes, url: str) -> tuple[int, list[DatabaseCommand]]`
     (nº de registros de la página, comandos).
   - `_queue_cve_records(content, url, queue, *, populate)` pasa a
     `_cve_commands(content, url, *, populate) -> tuple[int, list[DatabaseCommand]]`.
   - `_queue_cve_record`, `_queue_affected_products`,
     `_queue_exploit_references` pasan a síncronas que reciben
     `commands: list[DatabaseCommand]` como último parámetro posicional y
     hacen `.append(...)` (sin `await`). Renombrar `_queue_*` → `_append_*`
     para las tres últimas.
   Mantener docstrings Google (Args/Returns/Raises) actualizados, mismas
   excepciones (RuntimeError por validación, ValueError por CPE).
2. Actualizar los dos consumidores:
   - Online (`_query_api`, ~líneas 487-515): usar `_cpe_commands` /
     `_cve_commands`, comprobar `count < request.batch` igual que ahora,
     y `NvdPageBatch(..., commands=commands)`.
   - Offline `_raw_page_commands` (~980-1015): igual; mantener la
     comprobación `expected = min(page_size, total - start_index)` y su
     RuntimeError. Puede quedar `async` o pasar a síncrona; si pasa a
     síncrona, ajustar su única llamada en `_import_page`.
3. No tocar nada más (pipeline, orden de commit, red, checkpoints).
   Eliminar imports que queden sin uso.

## Verificación
- `cd db-manager && uv run python -m unittest discover -s tests` (17 OK).
- Gate AGENTS.md §5 sobre `nvd.py`.
