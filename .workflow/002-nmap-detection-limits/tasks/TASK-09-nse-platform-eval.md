# TASK-09 — NSE: evaluar condiciones de plataforma por CVE (F5b)
Plan: 002-nmap-detection-limits (PLAN.md §2.B). Depende de TASK-08.
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_scoping.lua`
(+ `tests/lua/harness.lua` solo EXPORTS). Gate: `LUA=texlua sh tests/run.sh`.

## Esquema BD (TASK-04)
Tabla `conditions(cve_id, product_id, config_idx, part, vendor, product)`
— una fila por (CVE, producto vulnerable, config AND, CPE de plataforma).
Sin filas para una CVE ⇒ incondicional.

## Cambios
1. Nueva query `platform_conditions` en `query(qtype)` (mismo estilo):
   filas `cve_id, config_idx, part, vendor, product` para el
   `product_id` y CVEs dados (o por vendor/product del escaneo; elegir lo
   más simple coherente con cómo `vulnerabilities` ya consulta).
2. Detección de BD antigua: `registry.has_conditions` (nil=sin comprobar)
   comprobando `sqlite_master` una vez; si falta ⇒ omitir evaluación y
   avisar UNA vez en log.
3. Función local `evaluate_platform(rows, ctx)` → `reason|nil`:
   agrupar filas por `config_idx` de una CVE; una config es compatible si
   alguna de sus plataformas lo es:
   - `part == 'o'`: familia = `registry.platform_families[vendor]`;
     compatible si `ctx.family == familia`; incompatible si ctx.family
     conocido y distinto; si ctx.family desconocido ⇒ "desconocido".
     Vendor con familia linux y `ctx.family=='linux'` pero distro
     desconocida y vendor ∈ {suse,redhat,debian,canonical,fedoraproject,
     gentoo}: compatible solo por familia ⇒ `requires_platform`.
   - `part == 'a'`: `requires_component`.
   Resultado de la CVE: si alguna config es plenamente compatible (distro
   coincide o vendor genérico `linux`) ⇒ nil (sin motivo);
   si todas incompatibles con SO conocido ⇒ `platform_mismatch:<familia
   de la 1.ª config>`; si desconocido o solo-familia ⇒ `requires_platform`;
   si hay condición `a:` ⇒ `requires_component`. Sin filas ⇒ nil.
4. En `vulnerabilities(...)` (recibe `ctx` desde `analysis`) calcular el
   motivo por CVE y guardarlo en el registro interno de la CVE
   (`rec.reasons`, lista; sin cambiar la salida visible: F7). NO eliminar
   ninguna CVE.
5. Tests (stub de `registry.conn` como en los de TASK-06): CVE solo AND
   Windows con ctx linux ⇒ `platform_mismatch:windows`; ctx desconocido ⇒
   `requires_platform`; vendor `suse` + linux sin distro ⇒
   `requires_platform`; vendor `linux` + linux ⇒ nil; `a:` ⇒
   `requires_component`; sin filas ⇒ nil; BD sin tabla ⇒ sin motivos y un
   solo aviso. Exportar lo necesario en EXPORTS.
Devuelve STATUS.
