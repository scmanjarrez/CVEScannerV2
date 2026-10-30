# TASK-08 — A1: fast path + caché en domain/cpe.py

Plan: database-write-optimization (W1). Fichero (1):
`db-manager/src/db_manager/domain/cpe.py`. Requiere TASK-06 hecha.

## Cambios (semántica EXACTAMENTE igual; el oráculo
`tests/reference_cpe.py` lo verifica)
1. Precompilar a nivel de módulo `_ESCAPE = re.compile(r"\\(.)")` y usarlo
   en `_unescape_cpe_component` (`_ESCAPE.sub(r"\1", value)`).
2. En `_split_cpe_components`: si `"\\" not in value`, usar
   `components = value.split(":")` (equivale al bucle sin escapes); si
   contiene backslash, conservar el bucle actual. Mantener el recorte del
   `/` inicial, el chequeo `MIN_CPE_COMPONENTS` y los mismos mensajes.
   Si no hay backslash en `value`, saltar el unescape (devolver la lista
   tal cual).
3. `split(cpe_uri)`: envolver en caché. Extraer la lógica a
   `_split_cached(cpe_uri: str) -> CpeIdentity` decorada con
   `@functools.lru_cache(maxsize=1_048_576)` y que `split` la invoque (o
   decorar `split` directamente). Devuelve tupla inmutable (ya lo es).
   Nombrar la constante `_SPLIT_CACHE_SIZE: int = 1_048_576` en el módulo.
   `lru_cache` no cachea excepciones: el error se relanza igual.
4. Mantener `split` público con la misma firma y docstring (Raises incl.).
   No tocar `parse_node`, `_version_bound` ni otras funciones.

## Verificación
- `cd db-manager && uv run python -m unittest discover -s tests`
  (todo verde, incluye test_cpe_equivalence).
- Gate AGENTS.md §5 sobre `cpe.py`.
