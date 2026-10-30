# PLAN — optimización de parseo y populate (db-manager)

Fecha: 2026-10-29. Autor: Tier 1 (Architect). Ámbito: `db-manager/` solo.

## 1. Diagnóstico (medido, no supuesto)

Build offline completo sobre BD vacía (`update_db_offline`, 188 páginas
CPE + 209 CVE, 1,86 M CPE + 416 k CVE) con cProfile: **384 s**
(el perfilador infla la parte Python; falta baseline sin perfilador → W0).

| Zona | cumtime | Causa |
|------|--------:|-------|
| `cpe.split` / `_split_cpe_components` | **157 s (41 %)** | bucle char a char + `re.sub` por componente (50 M llamadas, regex sin precompilar) |
| SQLAlchemy ORM bulk insert (`_bulk_insert`) | 66 s | `session.execute(insert(Model), dicts)` pasa por ORM bulk persistence |
| Comandos Pydantic + `asyncio.Queue` interna | ~27 s | 4,78 M `ImmutableModel.__init__` + 4,78 M `put/get` en cola temporal por página |
| `validate_json` (Pydantic, páginas) | 29 s | razonable, no es prioridad |
| `insert_multiaffected` / `_product_ids` | 30 s | lookup por chunks (ya optimizado en TASK-05) |
| Pipeline serie | — | parsear página N → esperar commit → parsear N+1; sin solape CPU/IO |
| `wait_for_writer_flush` | ≤50 ms/pág | polling con `sleep(0.05)` en vez de esperar el evento |
| SQLite | — | `journal_mode=delete`, `synchronous=FULL`, cache por defecto |

Corpus CVE: **3,27 M criterios CPE, 430 k únicos (87 % repetidos)**, 5,5 %
con `\`. ⇒ caché + fast path sin escapes elimina casi todo el coste de split.

## 2. Contrato de no regresión (invariantes)

1. **Esquema SQLite idéntico** (tablas, columnas, PK, UNIQUE). El NSE
   (`cvescannerv2.nse:1283-1341`) y `db-query` no cambian.
2. **Contenido idéntico** frente a baseline, comparado por clave natural:
   products `(vendor, product, version, version_update)`, affected/
   multiaffected unidos a la clave natural de producto, cves, exploits,
   referenced_*. Si el orden de páginas se mantiene, también `product_id`.
3. **Semántica de checkpoints intacta**: datos de página + `mark_nvd_page`
   en la misma transacción; reanudación; `prepare_nvd_collection`
   (crecimiento/encogimiento) sin cambios.
4. **Modo online y modo incremental** (`populate=False`, `DeleteCveRecord`)
   usan el mismo camino de código y deben comportarse igual.
5. Errores igual: `RuntimeError` en página inválida/incompleta, `ValueError`
   en CPE no soportado, `LookupError` en identidad ausente.
6. Gates: `unittest` db-manager (13 tests) verde, batería Lua
   (`tests/run.sh`, 87 PASS / 16 XFAIL) sin cambios, ruff + basedpyright 0.

### Herramientas de verificación (se crean ANTES de optimizar)
- **Oráculo CPE**: copia congelada del algoritmo actual en
  `db-manager/tests/reference_cpe.py`; test que compara `split()` nuevo vs
  referencia sobre casos límite (escapes `\:`, `\\`, `cpe:/`, campos
  faltantes, errores).
- **Corpus completo**: script manual (`db-manager/tests/tools/check_cpe_corpus.py`)
  que recorre `data/nvd-raw` y exige igualdad exacta en los ~2,3 M nombres
  únicos (CPE + criterios CVE).
- **Diff de BD**: `db-manager/tests/tools/db_diff.py BASE NEW` — volcado
  canónico por clave natural de cada tabla, sale ≠0 si difiere.
- **Baseline**: `data/cve-baseline.db` construida con el código actual
  desde `data/nvd-raw` (+ tiempo real sin perfilador).

## 3. Arquitectura objetivo

Se mantiene la forma actual (productor → cola → writer único con commit por
página). Cambios por capa, de menor a mayor riesgo:

### Fase A — micro-optimizaciones locales (sin cambio de arquitectura)
- **A1 `domain/cpe.py`**: fast path `if "\\" not in value: value.split(":")`
  (exactamente equivalente al bucle sin escapes); regex de unescape
  precompilada a nivel de módulo; `split` con `functools.lru_cache`
  (maxsize acotado, p.ej. 1 M; devuelve tupla inmutable → seguro).
- **A2 `infrastructure/nvd.py`**: `_queue_*` dejan de usar
  `asyncio.Queue` temporal; funciones síncronas puras que devuelven
  `list[DatabaseCommand]` (mismos tipos, mismo orden). Firmas privadas →
  sin impacto externo. Online y offline las reutilizan.
- **A3 `infrastructure/writer.py`**: `wait_for_writer_flush` espera el
  `Event` con `asyncio.wait({event.wait(), writer_task}, FIRST_COMPLETED)`
  en vez de polling. Mismo contrato de error.
- **A4 `infrastructure/storage.py`**: inserts masivos vía Core
  (`(await session.connection()).execute(insert(Model.__table__)..., rows)`)
  en vez de ORM bulk; mismas cláusulas `ON CONFLICT`. PRAGMAs por
  conexión: `synchronous=NORMAL`, `cache_size=-262144`,
  `temp_store=MEMORY`. **No WAL** (cambia el fichero persistentemente;
  el NSE/Docker lo abre en solo lectura → riesgo de regresión).

Estimación: −50…60 % del tiempo. Cada tarea es independiente y verificable.

### Fase B — solapar parseo y escritura (pipeline ordenado)
- Offline: lectura+parseo de la página N+1 mientras el writer confirma N.
  Prefetch acotado (ventana 2) y **orden de commit preservado** → IDs
  idénticos a baseline. La lectura de disco + `validate_json` +
  construcción de comandos van a `asyncio.to_thread` (sqlite libera el GIL
  en el hilo de aiosqlite; el solape es real en la parte C).
- Online ya es concurrente (semáforo 4); solo hereda Fase A.
- Checkpoint por página sin cambios: un `NvdPageBatch` = una transacción.

### Fase C — paralelismo de CPU (condicional, YAGNI)
Solo si tras A+B el parseo sigue dominando (>50 % del wall time):
`ProcessPoolExecutor` que recibe `(path, endpoint, populate, start_index)` y
devuelve filas planas (tuplas) → el writer las convierte. Ventana acotada,
orden preservado. **No se planifica en contratos hasta medir A+B.**

### Descartado
- WAL persistente, `synchronous=OFF`, borrar/recrear índices UNIQUE
  (los `ON CONFLICT` dependen de ellos), caché en memoria de 1,7 M
  `product_id` (~350 MB), reescritura a SQL crudo sin SQLAlchemy,
  cambio de esquema/índices de consulta (otra iniciativa).

## 4. Waves (para el Orchestrator)

| Wave | Contenido | Ficheros | Paralelo |
|------|-----------|----------|----------|
| W0 | Red de seguridad: oráculo CPE + test; `db_diff.py`; `check_cpe_corpus.py`; baseline BD + tiempo | `tests/reference_cpe.py`, `tests/test_cpe_equivalence.py`, `tests/tools/*` | sí (2 contratos) |
| W1 | A1 cpe.py | `domain/cpe.py` | sí |
| W1 | A3 writer flush | `infrastructure/writer.py` | sí |
| W1 | A4 storage Core + PRAGMAs | `infrastructure/storage.py` | sí |
| W2 | A2 comandos como lista | `infrastructure/nvd.py` | tras W1 (evita conflicto con tests) |
| W3 | Medición A: build + `db_diff` vs baseline + corpus + suites | — | — |
| W4 | B pipeline ordenado offline | `infrastructure/nvd.py` (+ test en `tests/test_offline.py`) | — |
| W5 | Medición B; decidir Fase C | — | — |
| W6 | README db-manager: sección rendimiento | `db-manager/README.md` | — |

Regla: tras **cada** wave → suites verdes; tras W3 y W5 → `db_diff` = 0
diferencias y corpus CPE = 0 diferencias. Una diferencia bloquea la wave
siguiente.

## 5. Riesgos

| Riesgo | Mitigación |
|--------|------------|
| Fast path de split difiere en casos raros (`cpe:/` con `/` inicial, campos vacíos) | oráculo + corpus completo exacto |
| `lru_cache` con `ValueError` (no cachea excepciones → se relanza igual) | test explícito de error repetido |
| Core insert pierde algún default ORM | tablas sin defaults Python; `db_diff` |
| `synchronous=NORMAL` y corte de luz | atomicidad de transacción se mantiene; solo puede perderse la última página confirmada → se rehace al reanudar |
| Pipeline B rompe orden/IDs o checkpoint | orden de commit estricto + tests de resume/offline + `db_diff` |
| Fase C: pickling y memoria | solo filas planas; ventana acotada; condicional |
