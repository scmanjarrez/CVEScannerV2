# TASK-09 — A3: wait_for_writer_flush sin polling

Plan: database-write-optimization (W1). Fichero (1):
`db-manager/src/db_manager/infrastructure/writer.py`.

## Cambio
En `wait_for_writer_flush` (líneas ~164-184) sustituir el bucle
`while not flush_event.is_set(): ... asyncio.sleep(0.05)` por una espera
del evento o de la finalización del writer:

```
flush_wait = asyncio.ensure_future(flush_event.wait())  # nombre libre
try:
    await asyncio.wait({flush_wait, writer_task},
                       return_when=asyncio.FIRST_COMPLETED)
finally:
    flush_wait.cancel()
if not flush_event.is_set():
    await writer_task   # propaga la excepción original del writer
    message = "The database writer stopped before flushing"
    raise RuntimeError(message)
```
Mismo contrato: si el writer termina (con o sin error) antes de marcar el
flush → se re-lanza su excepción o `RuntimeError` con ese mensaje exacto.
Si el evento ya está activo cuando el writer termina a la vez, éxito.
Ajusta el docstring solo si cambia algo observable (no debería).
No tocar el resto del fichero.

## Verificación
- `cd db-manager && uv run python -m unittest discover -s tests`
- Gate AGENTS.md §5 sobre `writer.py`.
