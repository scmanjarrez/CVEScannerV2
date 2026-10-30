# TASK-07 — Herramientas manuales: db_diff y check_cpe_corpus

Plan: database-write-optimization (W0). Ficheros (máx 2, NUEVOS; crear
también `db-manager/tests/tools/__init__.py` vacío con solo la cabecera SPDX
— cuenta como parte del paquete, no como contrato extra):
- `db-manager/tests/tools/db_diff.py`
- `db-manager/tests/tools/check_cpe_corpus.py`

Son scripts CLI manuales (`if __name__ == "__main__"`, `argparse`),
NO tests de unittest. No deben ser recogidos por `unittest discover`
(nombres sin prefijo `test_`).

## db_diff.py
Uso: `python -m tests.tools.db_diff BASE.db NEW.db` (desde `db-manager/`).
- Abre ambas BD en solo lectura con `sqlite3` (URI `mode=ro`).
- Volcado canónico por CLAVE NATURAL (nunca por id autoincremental), cada
  tabla como conjunto ordenado de tuplas:
  - `products`: `(vendor, product, version, version_update)`
  - `affected` y `multiaffected`: JOIN con `products` → clave natural de
    producto + resto de columnas (excepto ids). Lee el esquema real en
    `db-manager/src/db_manager/infrastructure/storage.py` para columnas.
  - `cves`, `exploits`, `metasploits`, `referenced_exploit`,
    `referenced_metasploit`, `metadata`: todas las columnas.
  - Excluir tablas de checkpoint de sync/colección/páginas
    (`nvd_sync`, `nvd_collection`, `nvd_page`) salvo conteo de filas, y
    excluir timestamps volátiles de `metadata` que dependan del reloj
    (decide leyendo el esquema; documéntalo en el docstring).
- Compara tabla a tabla (conteo + diferencia simétrica de conjuntos).
  Imprime por tabla `OK n filas` o `DIFF` con hasta 5 ejemplos por lado.
- Código de salida 0 si todo igual, 1 si hay diferencias.
- Memoria: iterar con cursores y comparar con hash incremental ordenado
  por `ORDER BY` de la clave natural (las tablas llegan a ~2 M filas); si
  hay DIFF, relanzar esa tabla y sacar ejemplos.

## check_cpe_corpus.py
Uso: `python -m tests.tools.check_cpe_corpus [RAW_DIR]` (por defecto
`../data/nvd-raw`).
- Recorre `RAW_DIR/cpes/full/page-*.json` y `RAW_DIR/cves/full/page-*.json`.
- Extrae recursivamente (walk genérico del JSON, sin Pydantic) todos los
  strings bajo las claves `cpeName` y `criteria`. Conjunto único.
- Para cada nombre compara `db_manager.domain.cpe.split` contra
  `tests.reference_cpe.reference_split` (de TASK-06; si no existe aún,
  abortar con mensaje claro): mismo resultado, o misma clase de excepción y
  mensaje. Cuenta y lista (máx 20) discrepancias.
- Imprime total de nombres únicos y nº de diferencias; salida 1 si > 0.
- Barra de progreso opcional con `rich` (ya dependencia del proyecto).

## Verificación
- Gate AGENTS.md §5 sobre ambos ficheros.
- Smoke: `uv run python -m tests.tools.db_diff ../data/cve.db ../data/cve.db`
  debe salir 0. NO ejecutes el corpus completo (lo hace el Orquestador).
