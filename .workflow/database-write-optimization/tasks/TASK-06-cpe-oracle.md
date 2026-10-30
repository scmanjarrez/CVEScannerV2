# TASK-06 — Oráculo CPE congelado + test de equivalencia

Plan: database-write-optimization (W0). Ficheros (máx 2, ambos NUEVOS):
- `db-manager/tests/reference_cpe.py`
- `db-manager/tests/test_cpe_equivalence.py`

## Objetivo
Congelar el algoritmo ACTUAL de `db-manager/src/db_manager/domain/cpe.py`
(`_unescape_cpe_component`, `_split_cpe_components`, `split`) como
referencia, y comprobar que `db_manager.domain.cpe.split` produce idéntico
resultado (valor o excepción) sobre casos límite.

## `reference_cpe.py`
- Copia literal (no importar de `cpe.py`) de la lógica actual: bucle char a
  char, `re.sub(r"\\(.)", r"\1", ...)`, mismas excepciones/mensajes.
- Expone `reference_split(cpe_uri: str) -> CpeIdentity` (misma firma que
  `split`). Importa `MIN_CPE_COMPONENTS` de `db_manager.constants` y
  `CpeIdentity` de `db_manager.domain.models`.
- Docstring de módulo: "Frozen copy of the pre-optimisation CPE parser."

## `test_cpe_equivalence.py` (unittest, estilo de tests existentes)
Un `TestCase` con `subTest` sobre estos casos, comparando
`split(x)` vs `reference_split(x)`; si la referencia lanza, `split` debe
lanzar la misma clase con el mismo mensaje (`assertRaises` + comparar `str`):
- `cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*`
- `cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*`
- `cpe:/a:vendor:product:1.0` , `cpe:/a:vendor:product` , `cpe:/a:v:p:1:upd`
- escapes: `cpe:2.3:a:ven\:dor:prod\\uct:1\.0:*:*:*:*:*:*:*`,
  `cpe:2.3:a:v:p:1\\:2:*:*:*:*:*:*:*`, backslash final `cpe:2.3:a:v:p:1\`
- campos vacíos: `cpe:2.3:a::p:1:*`
- error: `cpe:2.3:a:v` , `cpe:2.3:a` , `foo:bar` , `""`, `cpe:/`
- Test explícito: llamar dos veces a `split` con un CPE inválido y exigir
  el mismo `ValueError` las dos veces (para validar futura caché).
- Test: dos llamadas a `split` con CPE válido devuelven valores iguales.

## Verificación
- `cd db-manager && uv run python -m unittest tests.test_cpe_equivalence`
  debe pasar contra el código ACTUAL (aún sin optimizar).
- Gate AGENTS.md §5 sobre ambos ficheros.
