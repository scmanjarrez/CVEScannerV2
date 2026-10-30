# STATE — sondas de servicio NSE (ver PLAN.md)

Próximo número de contrato libre: TASK-11.
Nota: `load_luasql()` en el NSE lo añadió el usuario (fallback luasql). No tocar.
Regla transversal (PLAN §3.0): sonda solo con disparador (servicio
detectado por Nmap) + necesidad (versión imprecisa / CVEs con
`requires_platform` y SO desconocido). Cada contrato debe incluir tests de
"no corre".

## Backlog
- [~] F0 hecha en MS2 (ver tasks/artifacts/f0-probes.md); falta MS3 (ajp, rdp, ntlm) de campo de scripts P1/P2 en MS2/MS3 + baseline (sin código)
- [x] F5 DESCARTADA (MS3 es Ubuntu, sin RDP/NTLM)
- [x] F3 ftp STAT DESCARTADA por F0 (vsftpd ya preciso en -sV)
- [x] F6 DESCARTADA (sin 8009)
- [x] F7 DESCARTADA (sin objetivo UDP)
- [ ] F8 propuestas de catálogo HTTP (sin objetivo que lo justifique; no ejecutada)

## In Progress

## Done
- [x] F9b verify_nvd.py sobre MS2 (.131, -p- -T4, copia en results/f9v/; TASK-11 añadió unrealircd): pares producto-CVE distintos, `high`: none 615 → 90.9 % (559 CONFIRMADO, 51 DEPENDE, 5 FP); all 681 → 91.8 % (625, 51, 5 FP). Sin FP nuevos; FN=0 en unrealircd. `low`: FP 131 → 0. NO comparable con el 95.2 % de 002 (otra base de conteo: 1010/1061)
- [x] F8 artefacto tasks/artifacts/apache-server-status-probe.json (sin cargar en catálogo real)
- [x] FIX-1/2 TASK-09/10 motor HTTP: excluye no-HTTP con TLS y corta tras 5 fallos / lote vacío (216 tests OK; 3389 en .130: de >40 min a 12 s)
- [x] F4c TASK-08 smb_os ignora Samba que dice ser Windows (206 tests OK)
- [x] F9 medición MS2+MS3 y README (results/f9/, README «Service probes»)
- [x] F4b TASK-07 clave de caché con host si SO desconocido (204 tests OK; tests no verificados por mutación)
- [x] F4 TASK-06 os_context `probe` + `smb_os` bajo demanda (201 tests OK). MS2 completo: probes=all +3 CVEs Unreal, Samba range LOW→exacto, +0.65 s (17.07→17.72 s)
- [x] F2b/c TASK-04/05 irc reintento ante throttle (20 s); MS2 real: 3.2.8.1, CVE-2010-2075 HIGH, 192 tests OK
- [x] F2 sonda V `irc` + necesidad §3.0 (TASK-03, 189 tests OK verificados)
- [x] F1b TASK-02 tests despachador (180 tests OK verificados)
- [x] F1 refactor `SERVICE_PROBES` + arg `probes` (TASK-01, 172 tests OK verificados por Orchestrator). Pendiente: TASK-02 tests de `probes=none`/no-corre

## Métricas
| Punto | MS2 UnrealIRCd | MS2 high precisión | MS3 puertos con os_context | Tiempo |
|---|---|---|---|---|
| Baseline (002) | 0 CVEs | 95.2 % | SMB/IIS | — |
| Final (003) | 3 CVEs, CVE-2010-2075 HIGH (`version_source=irc`) | no medido con verify_nvd.py | MS3 es Linux: sin sonda O aplicable; Samba 4.3.11 exacto: 195 LOW → 77 CVEs (76 HIGH) | MS2 17.07→17.72 s (+4 %); MS3 213.4→212.9 s |

## Notas finales
- MS3 Windows (.130): sin cambios con `probes=all` (no hay CVEs `requires_platform`; ver tasks/artifacts/f0-probes.md).
- Bug preexistente del barrido HTTP sobre 3389: CORREGIDO (TASK-09/10).
