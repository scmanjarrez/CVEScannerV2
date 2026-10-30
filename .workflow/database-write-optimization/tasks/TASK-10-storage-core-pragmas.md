# TASK-10 — A4: inserts vía Core + PRAGMAs por conexión

Plan: database-write-optimization (W1). Fichero (1):
`db-manager/src/db_manager/infrastructure/storage.py`.

## Cambios
1. Los inserts masivos (`insert_products`, `insert_cves`,
   `insert_exploits`, `insert_metasploits`, `insert_affected`,
   `insert_multiaffected`, `insert_referenced_exploits`,
   `insert_referenced_metasploits`) hoy hacen
   `await self.session.execute(sqlite_insert(Model)..., rows)` (ORM bulk
   persistence). Cambiar a Core: usar `sqlite_insert(Model.__table__)`
   (o `Model.__table__.insert()` vía dialecto sqlite) y ejecutar con
   `(await self.session.connection()).execute(statement, rows)`.
   Misma transacción de sesión (el commit sigue siendo `session.commit()`).
   MANTENER exactamente las mismas cláusulas `on_conflict_do_nothing` /
   `on_conflict_do_update`, mismas columnas y mismos dicts. Para
   `index_elements=[CveModel.cve_id]` usar la columna de la tabla
   (`CveModel.__table__.c.cve_id`) si el tipado lo exige.
   Respeta tipado estricto sin `cast`/`type: ignore`; si
   `Model.__table__` no tipa limpio, usa `sqlalchemy.inspect(Model).local_table`
   o `Model.__table__` con anotación `Table` (importar de sqlalchemy).
   No tocar inserts de 1 fila (`save_nvd_sync`, `mark_nvd_page`,
   `prepare_nvd_collection`, `update_metadata`) ni `remove_cves`.
2. `_enable_foreign_keys` (listener `connect`) además de `foreign_keys=ON`
   ejecuta: `PRAGMA synchronous=NORMAL`, `PRAGMA cache_size=-262144`,
   `PRAGMA temp_store=MEMORY`. Renombrar a `_configure_connection` y
   actualizar el docstring y el `event.listen`. NO usar WAL, NO cambiar
   `journal_mode`.
3. Nada más: esquema, modelos y firmas públicas intactos.

## Verificación
- `cd db-manager && uv run python -m unittest discover -s tests`
- Gate AGENTS.md §5 sobre `storage.py`.
