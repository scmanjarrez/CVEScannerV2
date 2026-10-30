# STATE — optimización parseo/populate (ver PLAN.md)

Objetivo: reducir el tiempo de build/actualización de la BD sin cambiar
esquema ni contenido (diff por clave natural = 0 frente a baseline).
Perfil inicial (cProfile, BD nueva, offline): 384 s; split CPE 41 %.

Próximo número de contrato libre: TASK-15.

Contratos: 11 A2 nvd · 12 fix columnas multiaffected · 13 caché acotada · 06 oráculo CPE · 07 tools db_diff/corpus · 08 A1 cpe · 09 A3 writer · 10 A4 storage.

## Waves
| Wave | Contenido | Estado |
|------|-----------|--------|
| W0 | Oráculo CPE + test (TASK-06), `db_diff.py`+`check_cpe_corpus.py` (TASK-07), baseline BD + tiempo real | DONE (06,07 OK; baseline hecha; corpus-base en curso) |
| W1 | TASK-08 · TASK-09 · TASK-10 (paralelo) | DONE (08,09,10 OK; 17 tests OK) |
| W2 | TASK-11 A2 `_queue_*` → listas (nvd.py) | DONE |
| W3 | Medición Fase A (tras TASK-12/13): 156,6 s, RSS 663 MB, db_diff OK, corpus 0 dif., unittest 17 OK. Lua `tests/run.sh` NO ejecutada | DONE |
| W4 | TASK-14 B prefetch → REVERTIDO por TASK-15 (sin ganancia medible) | REVERTED |
| W5 | B: 165,2 s sin mejora; revertido. Medición final sin B: 176,2 s, RSS 649 MB, db_diff OK, corpus 0 dif., 17 tests OK. Varianza entre pasadas ~±10 %. Fase C no planificada (YAGNI) | DONE |
| W6 | README db-manager: sección Performance | DONE |

## Métricas
| Punto | Wall time | db_diff | corpus CPE |
|-------|-----------|---------|------------|
| Baseline (sin perfilador) | 227,8 s (3:47,8), RSS 339 MB | ref | ref |
| Tras A | 156,6 s (−31 %), RSS 663 MB | 0 dif. | 0 dif. (2 023 862) |
| Tras B (revertido) | 165,2 s, RSS 876 MB | 0 dif. | — |
| Final (A, sin B) | 176,2 s (2.ª pasada; 1.ª 156,6 s), RSS 649 MB | 0 dif. | 0 dif. |

