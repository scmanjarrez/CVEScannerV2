# STATE — limitaciones detección Nmap (ver PLAN.md)

Próximo número de contrato libre: TASK-20.

## Backlog

## In Progress

## Done
- [x] F8 (TASK-17/18/19): motor permite refinar versión de serie con sonda; sonda propuesta en tasks/artifacts/tomcat-probe.json (para catálogo upstream nmap-vulners). MS2: Tomcat 5.5 -> 5.5.25 (70 -> 52 CVEs); version_source=http; lua 172 OK
- [x] TASK-15 Dockerfile: legacy OpenSSL + platform-families.json (verificado: smb probe OK en imagen)
- [x] TASK-16 etiqueta platform_mismatch:<vendor|familia>, lua 165 OK
- [x] TASK-13 fix smb.get_os, TASK-14 fix host.os + umbral observed_range; lua 163 OK (con luasql, 0 skipped)
- [x] F9b medición MS2 (2026-10-30): high 1061 CVEs, precisión 95.2 %; FP Samba 0 (195→64); FN pg/ruby/tomcat = 0; 14 CVEs solo-Windows -> low
- [x] F9a (TASK-12) README
- [x] F7a (TASK-10) confianza/motivos; F7b (TASK-11) salida+minconf, lua 136 OK; test_database.lua (SQLite) SIN verificar (falta luasql)
- [x] F5b (TASK-09) evaluación plataforma, lua 117 OK
- [x] F5a+F6 (TASK-08) os_context + distro_backport, lua 107 OK
- [x] F3 (TASK-07) sonda SMB, lua 101 OK
- [x] F4c (TASK-05) nvd.py emite conditions, 25 tests db-manager OK (F4 completo)
- [x] data/platform-families.json creado (parte de F5)
- [x] F4b (TASK-04) tabla conditions, 23 tests db-manager OK
- [x] F2 (TASK-06) expansión serie, lua 96 OK (tocó harness.lua EXPORTS)
- [x] F4a (TASK-02) models+cpe, 6 tests nuevos OK
- [x] F0 (TASK-01) FN medidos: pg=4, ruby=11 (plan decía 17), tomcat=8; AND: windows=14, linux=4, component=3, macos=1, bsd=1
- [x] F1 L3 (TASK-03) lua tests 89 OK (texlua; lua5.4 no instalado)

## Métricas
| Punto | Precisión | FP Samba | FN ruby/tomcat/pg | CVE solo-AND reportadas |
|---|---|---|---|---|
| Baseline (v4 actual) | 84 % (945/1130) | 131 | 17 / 8 / 4 | 26 (~16 solo Windows) |
| Final (v4 + plan 002) | high 95.2 % (1010/1061) | 0 | 0 / 0 / 0 | 14 Windows marcadas low |

Notas: imagen docker mínima no carga el módulo OpenSSL (smbauth) -> sonda SMB cae a Nmap; BD regenerada con db-manager (conditions=226857 filas; affected/multiaffected idénticas). F8: la entrada de sonda debe publicarse en el catálogo upstream (nmap-vulners) para que se use por defecto.
