# TASK-04 — db-manager: tabla `conditions` (storage + writer) (F4b)
Plan: 002-nmap-detection-limits (PLAN.md §2.B). Depende de TASK-02 (hecho:
`ConditionRecord` ya existe en `domain/models.py` y está en `DatabaseCommand`).
Archivos permitidos (<=2): `db-manager/src/db_manager/infrastructure/storage.py`,
`db-manager/src/db_manager/infrastructure/writer.py`.

## Cambios
1. `storage.py`: nuevo modelo `ConditionModel(Base)`, tabla `conditions`:
   `cve_id` (FK cves.cve_id), `product_id` (FK products.product_id),
   `config_idx` int, `part`, `vendor`, `product` (str, plataforma);
   PK compuesta de todas. Mismo estilo que `MultiAffectedModel`
   (docstring `Attributes:`). `create_all` ya crea tablas nuevas en BDs
   existentes: no tocar tablas actuales.
2. `Database.insert_conditions(records: Sequence[tuple[str, CpeIdentity,
   int, CpeIdentity]])`: resuelve `product_id` con `_product_ids` (como
   `insert_multiaffected`, `LookupError` si falta) e inserta con
   `on_conflict_do_nothing`. (cve_id, identidad producto, config_idx,
   identidad plataforma → part=platform[0], vendor=platform[1],
   product=platform[2].)
3. `remove_cves`: borrar también filas de `ConditionModel` por `cve_id`
   (antes de borrar `CveModel`).
4. `writer.py`: en el flush, extraer los `ConditionRecord` (campos
   `cve_id, identity, config_idx, platform`) y llamar a
   `database.insert_conditions(...)` justo después de
   `insert_multiaffected`.

## Verificación
Gate AGENTS.md §5 sobre ambos ficheros (si `--venv .venv` no existe, usa
el venv de scratchpad `.../scratchpad/venv` y `pyright.json` equivalente
como hizo TASK-02). Suite: `cd db-manager && PYTHONPATH=src <venv>/bin/python
-m unittest discover -s tests` sin regresión. Devuelve STATUS.
