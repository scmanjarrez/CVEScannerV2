# TASK-16 — Etiqueta de platform_mismatch por distro
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_scoping.lua`.
Gate: `sh tests/run.sh` (≥163, 0 skipped).

## Problema
`config_status` devuelve la familia de la config; si el host es Linux/Ubuntu
y la CVE solo aplica a `redhat` o `gentoo` (misma familia, distro distinta),
`evaluate_platform` emite `platform_mismatch:linux`, confuso.
## Cambio
`config_status` debe devolver además el vendor requerido (el de la primera
fila `o` de la config). En `evaluate_platform`, el sufijo de
`platform_mismatch:` es el vendor cuando su familia == `os_ctx.family`
(desajuste de distro: `platform_mismatch:redhat`) y la familia en caso
contrario (`platform_mismatch:windows`). Nivel low como hasta ahora.
Tests: ctx linux/ubuntu + vendor redhat ⇒ `platform_mismatch:redhat`;
ctx linux + vendor microsoft ⇒ `platform_mismatch:windows`; los tests
actuales siguen verdes (actualiza solo los que esperen `:linux` en un caso
de distro). Devuelve STATUS. Actualiza si procede el README: tabla de
motivos, `platform_mismatch:<family or distro>` (solo esa línea).
