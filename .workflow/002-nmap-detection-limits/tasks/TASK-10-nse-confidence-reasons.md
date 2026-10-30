# TASK-10 — NSE: confianza y motivos por CVE (F7a)
Plan: 002-nmap-detection-limits (PLAN.md §2.C tabla de niveles). Depende de
TASK-06 (`series_expanded`) y TASK-09 (`rec.reasons` de plataforma).
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_scoping.lua`
(+ `tests/lua/harness.lua` EXPORTS). Gate: `LUA=texlua sh tests/run.sh`.
Sin cambios de salida visible (eso es TASK-11).

## Cambios
1. Cada CVE del registro interno de `vulnerabilities` obtiene
   `rec.reasons` (lista de strings, ya existe para plataforma) y
   `rec.confidence` ('high'|'medium'|'low').
2. Motivos añadidos al decidir cada coincidencia (en
   `scoped_versions` / `scoped_multi_versions` / rama de serie; pasar el
   motivo vía el resultado, mínimo cambio):
   - `exact_version` (high): fila `affected` con versión y update iguales.
   - `range_contains` (high): rango NVD contiene TODO el intervalo
     observado (from..to del escaneo; para versión exacta, from==to).
   - `range_overlap` (medium): rango NVD solapa solo parte del
     intervalo observado (L6).
   - `series_expanded` (medium): ya existe flag de TASK-06.
   - `update_unknown` (medium): la versión observada no trae update
     (`vup` '*') y la fila NVD exige update concreto (L4).
   - `nvd_unbounded` (low): fila multiaffected sin ninguna cota
     (`*` sin cotas, L5).
   - `observed_range` (low): el escaneo trae rango amplio (`range=true`
     con `from`/`to` distintos) y no es una expansión de serie (L1).
   - Plataforma (TASK-09): `requires_platform`/`requires_component`
     (medium), `platform_mismatch:<fam>` (low).
3. Nivel final = el más bajo de sus motivos (low<medium<high). Sin
   motivos explícitos ⇒ high. Función local `confidence_of(reasons)` y
   tabla `REASON_LEVEL`.
4. Aviso por servicio: `warnings` (lista) con `distro_backport` cuando
   `ctx.backport`; devolver `summary = {high=n, medium=n, low=n}` junto
   al listado (mismo valor de retorno ampliado de `vulnerabilities`, o
   campos en la tabla devuelta; los llamadores deben seguir
   funcionando). `analysis` pasa `ctx.backport` (de `distro_backport`).
5. Tests: un caso por motivo anterior y por nivel final (incluye
   combinación: `range_overlap`+`platform_mismatch` ⇒ low), y resumen.
Devuelve STATUS.
