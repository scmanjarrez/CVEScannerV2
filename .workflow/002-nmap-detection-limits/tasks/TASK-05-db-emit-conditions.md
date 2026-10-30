# TASK-05 — db-manager: emitir ConditionRecord al importar CVEs (F4c)
Plan: 002-nmap-detection-limits (PLAN.md §2.B). Depende de TASK-02 y TASK-04.
Archivos permitidos: `db-manager/src/db_manager/infrastructure/nvd.py`,
`db-manager/tests/test_conditions_import.py` (nuevo).

## Cambios
1. `nvd.py::_append_affected_products`: para cada `(config_idx,
   configuration)` de `enumerate(configurations)`, además de lo actual
   (sin cambios), llamar a `parse_conditions(configuration)`
   (`domain/cpe.py`) y, por cada `(producto, plataforma)` con
   `producto[0] == "a"`, añadir `ProductRecord` (si no se añadió ya) y
   `ConditionRecord(cve_id, identity=producto, config_idx, platform)`.
   `config_idx` = índice de la configuración RAÍZ.
2. Test (unittest, siguiendo el estilo de `tests/test_offline.py`):
   importar una CVE sintética con config AND (`a:php:php:5.2.4` +
   `o:microsoft:windows` no vulnerable) y otra OR pura; comprobar que la
   BD resultante tiene `conditions` con 1 fila para la primera y 0 para la
   segunda, y que `affected`/`multiaffected` son idénticas a antes del
   cambio (mismas filas).

## Verificación
Gate §5 sobre ambos ficheros .py + suite completa db-manager verde
(mismo método de venv que TASK-04). Devuelve STATUS.
