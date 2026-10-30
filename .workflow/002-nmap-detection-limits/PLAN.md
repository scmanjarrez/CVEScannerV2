# PLAN — limitaciones de la detección de Nmap y mitigaciones

Fecha: 2026-10-29. Autor: Tier 1 (Architect). Ámbito: `cvescannerv2.nse`,
`db-manager/` (tabla aditiva), catálogo `data/*.json`, `tests/`,
`results/compare/verify_nvd.py`, `README.md`.
Fuente: `results/compare/VERIFICACION.md` + `new.json`/`new.log` +
`data/cve.db` + `data/nvd-raw`.

## 1. Diagnóstico (medido sobre Metasploitable 2)

Datos de Nmap que el NSE usa hoy: solo `port.version.cpe[1]`,
`port.version.version` (si la CPE no trae versión) y `service_fp`.
**No usa**: resto de `cpe[]` (incl. CPE `o:`), `extrainfo`, `ostype`,
`service_dtype`, `host.os` (con `-O`), ni librerías NSE de protocolo (`smb`).

| # | Limitación | Evidencia | Impacto | ¿Resoluble con Nmap? |
|---|---|---|---|---|
| L1 | Versión por rango amplio (`Samba 3.X - 4.X`) | 131 FP | FP masivos | **Sí**: `smb.get_os(host)` → `lanmanager = "Samba 3.0.20-Debian"` |
| L2 | Versión "de serie" (`8.3`, `5.5`, `1.8`) tratada como `x.y.0` exacta | Filas NVD no reportadas: ruby 1.8.x **17**, tomcat 5.5.x **8**, postgresql 8.3.x **4** | **FN** (no medidos en VERIFICACION) | **Sí**, parcial: rango `x.y.0–x.y.∞` si la BD tiene versiones `x.y.%` |
| L3 | Versión de la CPE gana a `port.version.version` más rico | PG: Nmap `8.3.0 - 8.3.7`, CPE `8.3` | FN (los 4 de PG) | **Sí** |
| L4 | Update desconocido casa con cualquier update NVD | BIND CVE-2008-4163 (NVD solo `9.4.2:p2_w1`) | 1 FP | Mitigable: confianza |
| L5 | NVD sin cotas (`*`) | 6 SIN_COTAS | Ruido | Mitigable: confianza |
| L6 | Rango NVD solapa solo parte del rango observado | 47 DEPENDE | Ruido | Mitigable: confianza |
| L7 | Backports de distro (`8ubuntu1`, `3ubuntu5`, `(Ubuntu)`) | Todo CONFIRMADO de MS2 | FP no medibles | Mitigable: aviso |
| L8 | Patch exacto oculto (Tomcat 5.5.x, Ruby 1.8.x) | DEPENDE | — | Parcial: sondas HTTP del catálogo |
| L9 | **Configuraciones AND de NVD ignoradas**: `db-manager` (`domain/cpe.py:parse_node`) aplana nodos, descarta `vulnerable=false` y no modela `operator` | **26 CVEs** reportados en MS2 solo aplican en AND: ~16 solo Windows (p. ej. CVE-2010-0425 `mod_isapi`, CVE-2012-2376 PHP), 9 SUSE, Fedora, Gentoo, FreeBSD, macOS | FP en objetivo Linux | **Sí**: Nmap expone SO (`ostype`, CPE `o:` en `port.version.cpe[]`, `host.os` con `-O`, `Service Info: OSs`) |
| L10 | Salida opaca: no distingue coincidencia estricta de laxa | Tabla/JSON/log iguales para `exact` y para rango `3.X - 4.X` | Usuario no puede priorizar | **Sí**: reformateo (§2.C) |

No resolubles con Nmap (se documentan): explotabilidad, configuración y
módulos activos, condiciones AND sobre aplicaciones no detectadas.

## 2. Decisión de diseño

Tres ejes, sin abstracciones nuevas.

### A. Mejor versión de entrada (reduce FP/FN reales) — L1, L2, L3
Prioridad de versión (de más a menos fiable):
1. Sonda de protocolo (SMB `lanmanager`).
2. `port.version.version` si es rango o más específico que la CPE.
3. Versión de la CPE.
Se registra `version_source` (`smb|nmap_version|nmap_cpe|http`).

### B. Condiciones de plataforma de NVD (AND) — L9
**db-manager** (cambio aditivo, sin tocar tablas existentes):
- Modelar `operator` en `NvdConfiguration`/`NvdConfigurationNode`.
- Nueva tabla `conditions(cve_id, product_id, config_idx, part, vendor,
  product)`: para cada configuración `AND`, las CPE `vulnerable=false`
  (plataforma) asociadas al producto vulnerable de esa configuración.
- Sin fila para (cve, producto) en alguna config ⇒ **incondicional** (hay
  una config OR que lo afecta sin requisitos).
- `affected`/`multiaffected` siguen igual (no regresión de contenido).

**NSE**:
- Contexto de SO del host/puerto: `port.version.ostype`, CPE `o:` de
  `port.version.cpe[]`, `host.os` (clases/CPE si `-O`), distro inferida (L7).
- Mapa plataforma→familia en datos (`data/platform-families.json`:
  `microsoft→windows`, `apple→macos`, `freebsd→bsd`,
  `canonical|debian|redhat|suse|fedoraproject|gentoo|linux→linux`).
- Evaluación por CVE: incondicional → sin efecto. Condicional → la CVE
  aplica si **alguna** config tiene una plataforma compatible.
  - SO conocido e incompatible en todas las configs ⇒ `platform_mismatch`
    (confianza baja, "posible falso positivo").
  - SO desconocido, o compatible solo por familia (p. ej. `suse` en Linux
    sin distro conocida) ⇒ `requires_platform` (confianza media).
  - Condición `a:` (otra aplicación) ⇒ `requires_component` (media).
- BD sin tabla `conditions` (antigua) ⇒ se omite la evaluación y se avisa
  una vez en log.
- **No se elimina** ninguna CVE por defecto; se clasifica (§C).

### C. Salida transparente (JSON, tabla Nmap, log) — L4, L5, L6, L10
Cada CVE lleva **nivel de confianza** + **motivos**:

| Nivel | Significado | Motivos que lo producen |
|---|---|---|
| `high` (alta probabilidad) | Filtro estricto de versión | `exact_version` (fila `affected` con versión y update iguales); `range_contains` (rango NVD contiene **todo** el intervalo observado) |
| `medium` (certeza reducida) | Versión aplica, pero con supuestos | `range_overlap` (L6); `series_expanded` (L2); `update_unknown` (L4); `requires_platform` / `requires_component` (L9) |
| `low` (posible falso positivo) | Filtro laxo o contradicción | `nvd_unbounded` (L5); `observed_range` (versión observada es rango amplio, p. ej. `3.X - 4.X`, L1 sin SMB); `platform_mismatch` (L9) |

Regla: nivel final = el **más bajo** de sus motivos.
Aviso por **servicio** (no por CVE): `distro_backport` si se detecta paquete
de distro (L7) — "las CVEs pueden estar parcheadas por backport".

Formato:
- **JSON** (solo campos añadidos; claves actuales intactas):
  - Por CVE: `"confidence": "high|medium|low"`, `"reasons": [...]`
    (p. ej. `"platform_mismatch:windows"`).
  - Por servicio: `"version_source"`, `"os_context"` (familia/distro y
    origen), `"warnings": [...]`, `"summary": {"high": n, "medium": n,
    "low": n}`.
- **Tabla Nmap**: columna nueva `Conf` (`HIGH|MED|LOW`); orden por
  confianza y luego CVSS; línea de cabecera por servicio con
  `version_source` y avisos; `maxcve` se aplica tras ordenar (las `high`
  salen primero).
- **Log**: por CVE `confidence` + `reasons`; por servicio
  `version_source`, `os_context`, `warnings`; resumen por nivel.
- **Arg** `cvescannerv2.minconf=low|medium|high` (defecto `low`: mostrar
  todo). Filtra tabla y log; el JSON conserva siempre todo.
- README: leyenda de niveles y motivos.

## 3. Invariantes / no regresión

1. `db-manager`: tablas actuales con esquema y contenido idénticos
   (`db_diff` = 0 sobre ellas); solo se **añade** `conditions`.
2. NSE funciona con BD antigua (sin `conditions`).
3. JSON: solo campos añadidos.
4. Sonda SMB opcional (`cvescannerv2.smb=1` por defecto), con timeout y
   fallo silencioso → comportamiento actual.
5. Gates: `unittest` db-manager, `tests/run.sh` (Lua) verdes + casos
   nuevos por limitación y por nivel de confianza.
6. Medición MS2 + `verify_nvd.py`: precisión de `high` ≥ 95 %; FP Samba
   ≤ 10; FN L2/L3 = 0; las 16 CVEs solo-Windows marcadas `low`.

## 4. Fases

| Fase | Contenido | Archivos | Depende |
|---|---|---|---|
| F0 | `verify_nvd.py`: medir **FN** y evaluar AND (plataforma) en la verdad de referencia | `results/compare/verify_nvd.py` | — |
| F1 | L3: preferir `port.version.version` sobre CPE + `version_source` | `cvescannerv2.nse`, `tests/test_scanner.lua` | — |
| F2 | L2: expansión versión de serie si la BD tiene `x.y.%` | ídem | F1 |
| F3 | L1: sonda SMB (`smb.get_os`) → `samba:samba:<ver>`, `location='smb'` | ídem | — |
| F4 | L9-db: `operator` en modelos + tabla `conditions` + tests | `db-manager/src/db_manager/domain/{models,cpe}.py`, infra/storage | — |
| F5 | L9-nse: contexto SO (`ostype`, CPE `o:`, `host.os`) + `platform-families.json` + evaluación | `cvescannerv2.nse`, `data/platform-families.json` | F4 |
| F6 | L7: detección `distro` (regex `version/extrainfo/ostype`) | `cvescannerv2.nse` | — |
| F7 | C: niveles/motivos en `scoped_*` y salida JSON/tabla/log + `minconf` | `cvescannerv2.nse`, `tests/` | F2, F3, F5, F6 |
| F8 | L8: sondas Tomcat en catálogo HTTP (si dan patch real en MS2) | `data/http-*.json` | — |
| F9 | Medición MS2 + `verify_nvd.py` + README (leyenda y limitaciones) | `results/compare/`, `README.md` | F0–F8 |

Paralelizables: F0, F4, F8 (ficheros disjuntos). F1/F2/F3/F5/F6/F7 tocan el
mismo NSE → serializar.

## 5. Riesgos

- F2 sube recall a costa de más `medium`; aceptable porque queda marcado.
- F3: conexión SMB extra por host (~1 s); falla con SMB1 deshabilitado →
  fallback a Nmap.
- F4: NVD anida AND con hijos (`children`); `config_idx` debe referirse a
  la configuración raíz, no al nodo. Sin `operator` en datos antiguos ⇒
  tratar como OR (comportamiento actual).
- F5: `ostype` falta en muchos servicios; sin `-O` el SO puede quedar
  desconocido → `requires_platform` (media), nunca `low`.
- Heurística `distro` puede dar falsos avisos; solo informativa.
- Cambio visual de la tabla Nmap: documentar en README/CHANGELOG.
