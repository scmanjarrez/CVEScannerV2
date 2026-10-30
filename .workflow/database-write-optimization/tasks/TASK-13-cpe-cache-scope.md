# TASK-13 — Acotar caché de split (memoria 1 GB, CPE únicos no repiten)

Plan: database-write-optimization (W3). Fichero (1):
`db-manager/src/db_manager/domain/cpe.py`.

## Problema
`split` público está cacheado con maxsize 1 048 576. Los 1,86 M nombres de
producto (`_queue_cpe_records`) son únicos → llenan la caché sin ningún
acierto (RSS pasó de 339 MB a 1 GB). La repetición (87 %) está en los
criterios CVE que llegan por `parse_node`.

## Cambio
Estado actual: `_split_cached` (lru_cache) contiene la lógica y `split`
lo llama; `parse_node` (línea ~178) llama a `split`.
Objetivo: mover la lógica a `_split_uncached` (sin decorador); `split` la
llama directamente; `_split_cached` pasa a ser un wrapper con lru_cache
que llama a `split`, usado SOLO por `parse_node`.
1. `split` público vuelve a ser SIN caché (conserva fast path sin
   backslash). Misma firma y docstring.
2. La caché se aplica solo al camino de `parse_node`: función interna
   `_split_cached(cpe_uri: str) -> CpeIdentity` con
   `@functools.lru_cache(maxsize=_SPLIT_CACHE_SIZE)` que llama a `split`;
   `parse_node` (y cualquier helper que hoy llame a `split` para criterios)
   usa `_split_cached`. `_SPLIT_CACHE_SIZE: int = 524_288`.
3. Nada más. Los errores (`ValueError`) siguen propagándose igual.

## Verificación
- `cd db-manager && uv run python -m unittest discover -s tests`
- Gate AGENTS.md §5 sobre `cpe.py`.
