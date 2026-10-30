# TASK-15 — Revertir Fase B (TASK-14): sin prefetch

Plan: database-write-optimization (W4 revertido). Ficheros (2):
- `db-manager/src/db_manager/infrastructure/nvd.py`
- `db-manager/tests/test_offline.py`

Motivo: medido 165,2 s con B vs 156,6 s sin B (GIL; sin ganancia).

## Objetivo: dejar el código EXACTAMENTE como antes de TASK-14
1. nvd.py: eliminar `RAW_PREFETCH_WINDOW`, `_prepare_raw_page`, el uso de
   `deque`/tareas/`finally` en `_import_scope`, y los imports que queden
   sin uso. Restaurar:
   - `async def _read_raw_page(path: Path) -> bytes`: si
     `not await asyncio.to_thread(path.is_file)` →
     `RuntimeError(f"Raw NVD page is missing: {path}")`; devuelve
     `await asyncio.to_thread(path.read_bytes)`. (Docstring Google con
     Args/Returns/Raises.)
   - `_import_page(job, start_index, queue, writer_task)` (async): calcula
     `path = job.directory / RAW_PAGE_NAME.format(start_index=start_index)`,
     `url = str(path)`, `content = await _read_raw_page(path)`,
     `_validate_raw_page(content, start_index, url)`,
     `commands = _raw_page_commands(job, content, url, start_index)`,
     `await queue.put(NvdPageBatch(collection=job.collection,
     start_index=start_index, commands=commands))`,
     `await wait_for_writer_flush(queue, writer_task)`.
   - Bucle de `_import_scope`: 
     `for start_index in starts:` `await _import_page(job, start_index,
     queue, writer_task)` y `progress.update(task_id, advance=min(
     job.page_size, job.total - start_index))`.
   Mantener TODO lo demás (TASK-08..13: `_cpe_commands`, `_cve_commands`,
   `_append_*`, `_raw_page_commands` síncrona).
2. test_offline.py: eliminar SOLO los 2 tests añadidos por TASK-14
   (orden ascendente de commits; fallo en página intermedia) y los
   helpers/imports que solo ellos usaban. Los 17 tests previos intactos.

## Verificación
- `cd db-manager && uv run python -m unittest discover -s tests` → 17 OK.
- Gate AGENTS.md §5 sobre ambos ficheros.
