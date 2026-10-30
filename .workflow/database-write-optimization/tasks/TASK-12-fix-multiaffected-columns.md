# TASK-12 — Fix regresión: columnas de multiaffected en insert Core

Plan: database-write-optimization (W3, bug hallado por db_diff).
Fichero (1): `db-manager/src/db_manager/infrastructure/storage.py`.

## Bug
`insert_multiaffected` (tras TASK-10) pasa a Core dicts con claves de
atributo ORM (`version_start_including`, ...). En Core las claves deben ser
los NOMBRES DE COLUMNA reales (`versionStartIncluding`,
`versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`),
si no, las cotas se pierden y se guardan como NULL (db_diff: 259 537 filas
distintas).

## Cambio
1. En `insert_multiaffected` usar como claves los nombres de columna reales
   (los strings del primer argumento de `mapped_column` en
   `MultiAffectedModel`). Ajustar el tipo del dict si hace falta.
2. REVISA los otros 7 inserts Core (`insert_products`, `insert_cves`,
   `insert_exploits`, `insert_metasploits`, `insert_affected`,
   `insert_referenced_exploits`, `insert_referenced_metasploits`) y las
   cláusulas `on_conflict_*` (`set_`, `index_elements`) contra los modelos:
   toda clave de dict / `set_` debe ser nombre de columna real. Corrige
   cualquier otra discrepancia (reporta cuáles en NOTES).
3. Añadir un test en `db-manager/tests/test_offline.py`? NO (fuera de
   alcance). No tocar otros ficheros.

## Verificación
- `cd db-manager && uv run python -m unittest discover -s tests`
- Gate AGENTS.md §5 sobre `storage.py`.
