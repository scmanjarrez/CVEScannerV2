# TASK-06 — F4: contexto de SO por sonda (`probe`) bajo demanda + SMB `os`

Plan: 003 (PLAN §3.0, §3.B, §4). Requiere TASK-01..05.

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/test_catalog.lua` (suite nueva `os probe`, al final)

No tocar `load_luasql()`. No modificar `harness.lua`: usa los exports ya
disponibles (`SERVICE_PROBES`, `registry`, `os_context`, `analysis`,
`probe_enabled`, `evaluate_platform`, `add_platform_reasons`,
`vulnerabilities`). Tests de integración mínimos con stubs; si algo no es
alcanzable sin exportar, cubrir con `os_context` + `registry` y anotarlo.

## 1. Caché compartida de `smb.get_os`
Helper `smb_get_os(host)` con caché por host (`registry.smb_info[host.ip]`,
`false` = fallo; añadir `smb_info = {}` al registry). `smb_probe` (sonda V)
pasa a usarlo ⇒ **una sola llamada** a `smb.get_os` por host aunque corran
la sonda V y la O. Los tests SMB existentes deben seguir verdes.

## 2. Sonda de SO `smb_os`
Nueva entrada de `SERVICE_PROBES` con `kind='os'`, `name='smb'` NO (nombre
`smb_os`; `probes=smb_os` la selecciona; `probes=all` la incluye; `smb=0`
también la desactiva), `services = SMB_SERVICES`, `ports = SMB_PORTS`,
`run(host)` ⇒ si `info.os` empieza por `Windows` ⇒ `{ family='windows' }`.
Cualquier otra cosa (Unix/Samba, fallo) ⇒ `nil`. **Desviación del PLAN
§2 (documentar en comentario):** Samba NO produce familia `unix`, porque
`evaluate_platform` compararía `unix ≠ linux` y marcaría falsos
`platform_mismatch` en Samba sobre Linux.

## 3. `host_probe_os(host)`
- Devuelve `{ family=..., source='probe:<name>' }` o `nil`.
- Itera los puertos abiertos TCP del host que Nmap ya identificó
  (`nmap.get_ports(host, port, 'tcp', 'open')`, patrón estándar NSE;
  proteger con `pcall`), y para cada sonda `kind='os'` habilitada cuyo
  `services`/`ports` encaje con alguno, ejecuta `run` con `pcall` (la
  primera que dé familia gana). Sin servicios detectados ⇒ no se sondea.
- Caché en `registry.host_os_probe[host.ip]` (`false` = negativo; añadir
  `host_os_probe = {}` al registry). Si `nmap.mutex` existe, envolver la
  ronda con `local m = nmap.mutex(host.ip); m 'lock' ... m 'done'` (los
  stubs de test no lo tienen: comprobar `type(nmap.mutex) == 'function'`).
- `nmap` se obtiene al llamar (como en `irc_probe`).

## 4. `os_context` — fuente `probe` de máxima prioridad
Orden final: `probe` > `cpe` > `ostype` > `host_os` > `extrainfo`.
`os_context(host, port)` SOLO lee la caché `registry.host_os_probe` (nunca
ejecuta sondas) y devuelve `{ family=, source='probe:smb_os' }` si hay
resultado positivo.

## 5. Disparo bajo demanda (PLAN §3.0)
En `vulnerabilities(...)`, tras el primer `add_platform_reasons`: si algún
CVE tiene el motivo `requires_platform` y `ctx.os.family == nil` y
`ctx.os.source` no empieza por `probe`, llamar `host_probe_os(host)`. Si
devuelve familia: sustituir el contexto (`os_ctx = {family=..., source=...}`
— conservar `distro` nil), **quitar** de cada `rec.reasons` los motivos
`requires_platform`, `requires_component` y `platform_mismatch:*`
añadidos antes, y volver a llamar a `add_platform_reasons` con el nuevo
contexto; `meta.os_context` refleja el contexto final. Sin CVEs
condicionales ⇒ no se sondea nunca. Con `ctx.os.family` ya conocida ⇒ no
se sondea.

## 6. Clave de caché (`analysis`)
La caché de `analysis` no incluye el host. Tras `vulnerabilities`, si
`meta.os_context.family ~= vctx.os.family` (la sonda cambió el contexto),
guardar el resultado bajo la clave recalculada con
`context_key({os = meta.os_context, backport = vctx.backport,
version_source = vctx.version_source})` y NO bajo la clave previa. Así un
host sin sonda con SO desconocido no hereda resultados de otro con sonda.

## 7. Tests (suite `os probe`)
1. SMB `os='Windows Server 2008 R2 ...'` ⇒ `host_probe_os` familia
   `windows`, `source='probe:smb_os'`; una sola llamada a `get_os` aunque
   se llame dos veces y aunque corra antes la sonda V.
2. `os='Unix (Samba 3.0.20-Debian)'` ⇒ `nil`, sin familia.
3. Sin puertos SMB detectados (`get_ports` stub devuelve solo http) ⇒ no
   llama a `get_os`.
4. `probes=none`, `probes=smb` (sin `smb_os`), `smb=0` ⇒ no se sondea.
5. `os_context` con caché positiva ⇒ `source='probe:smb_os'` aunque
   `info.cpe` dé otra familia; sin caché ⇒ comportamiento previo
   idéntico (no ejecuta sonda).
6. `get_os` lanza error ⇒ `nil`, cacheado negativo (1 llamada).
7. Integración de `vulnerabilities` (si es alcanzable con el montaje de
   `test_scoping.lua`/`platform_scanner`): CVE Linux-only con SO
   desconocido y sonda `windows` ⇒ motivo pasa de `requires_platform` a
   `platform_mismatch:linux`; con SO conocido o sin CVEs condicionales ⇒
   sonda no llamada. Si no es alcanzable, anotarlo en NOTES.

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
Todo verde (192 previos + nuevos). Estilo 2 espacios, ≤ 80 col. No
ejecutar nmap. Devolver SOLO el bloque de estado (`TASK: TASK-06`,
`CHECKS: lua_tests=PASS`).
