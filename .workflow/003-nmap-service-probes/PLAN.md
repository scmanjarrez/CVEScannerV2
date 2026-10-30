# PLAN — sondas de servicio con librerías NSE (generalizar la sonda SMB)

Fecha: 2026-10-30. Autor: Tier 1 (Architect). Ámbito: `cvescannerv2.nse`,
`data/platform-families.json` (+ mapa SO opcional), `tests/lua/`,
`README.md`, artefactos de catálogo HTTP (`tasks/artifacts/`).
Base: plan 002 (sonda SMB `smb.get_os`, `version_source`, `os_context`,
confianza/motivos). Nmap de referencia: 7.97 (Alpine 3.23,
`nmap-nselibs`).

## 1. Problema

Plan 002 demostró el patrón: una consulta de protocolo barata y `safe`
da una versión mejor que `-sV` (Samba `3.X - 4.X` → `3.0.20`, FP 131 → 0).
Quedan servicios donde `-sV` da versión vacía, de serie o nada, y hosts
donde el SO es desconocido (platform AND de NVD en `requires_platform`).

Dos tipos de sonda útiles:

| Tipo | Qué aporta | Limitación que ataca |
|---|---|---|
| **V** (versión) | `cpe + versión exacta` sustituye a la de Nmap | FN por versión `*`; FP por rango/serie (L1, L2, L8) |
| **O** (SO) | familia/versión de SO del host sin `-O` | `requires_platform` → resuelto; `platform_mismatch` fiable (L9) |

La BD solo contiene productos `a:` (sin `o:microsoft:windows*`, kernel
casi vacío) ⇒ las sondas de SO **no** generan CVEs nuevas; solo alimentan
`os_context`.

Evidencia actual:
- MS2 `6667/irc`: `cpe:/a:unrealircd:unrealircd`, versión `*` ⇒ **0 CVEs**
  (FN: CVE-2010-2075, backdoor 3.2.8.1). `irc-info` (comando `VERSION`,
  respuesta 351) da `Unreal3.2.8.1`.
- MS3 (Windows 2008 R2): SO solo por `-sV` de SMB/IIS; Apache 8383 y
  MySQL 3306 sin contexto de SO ⇒ CVEs solo-Linux quedan `medium`.
  `rdp-ntlm-info`/`http-ntlm-info`/`smb` dan `Product_Version 6.1.7601`.
- MS3 `9200` (Elasticsearch) clasificado como `wap-wsp?` ⇒ fuera de
  `portrule`/HTTP. (Fuera de alcance, ver §6.)

## 2. Inventario de candidatas (Nmap 7.97)

Todas en categoría `safe` salvo indicación. "Lib" = librería NSE que el NSE
reutiliza con `pcall(require, ...)`, como `smb`.

### Tipo V — versión

| Prio | Script de referencia | Lib | Puerto/servicio | Dato | Ganancia | Objetivo de medición |
|---|---|---|---|---|---|---|
| **P1** | `irc-info` | `comm` (o `irc`) | `irc` 6667 | 351 `Unreal3.2.8.1.` → `unrealircd:3.2.8.1` | FN → CVEs reales | MS2 |
| **P1** | `ftp-syst` (STAT) | `ftp` | `ftp` 21/2121 | `vsFTPd 2.3.4`, `ProFTPD x.y.z` cuando el banner está oculto o es genérico | FN banner ocultado | MS2 (control: no debe cambiar) |
| **P2** | `ajp-headers`/`ajp-request` | `ajp` | `ajp13` 8009 | cabecera/página de error `Apache Tomcat/x.y.z`; reutiliza `response_subjects` + catálogo | Tomcat sin HTTP expuesto | MS3 8009 |
| **P2** | `ntp-info` (readvar) | `comm` | `ntp` 123/udp | `ntpd 4.2.4p4` (`-sV` da `NTP v4`) + `system: Linux/2.6.24` (tipo O) | FN ntp | lab con `-sU` |
| P3 | `redis-info` | `redis` | `redis` 6379 | `redis_version` + `os` (tipo O) | `-sV` suele bastar; valor = SO | si hay objetivo |
| P3 | `mongodb-info` | `mongodb` | `mongodb` 27017 | `buildInfo.version` + `os` | ídem | si hay objetivo |
| P3 | `mqtt-subscribe` | `mqtt` | `mqtt` 1883 | `$SYS/broker/version` (mosquitto) | IoT sin versión | si hay objetivo |

### Tipo O — sistema operativo (por host, cacheado)

| Prio | Script de referencia | Lib | Puerto | Dato | Mapa |
|---|---|---|---|---|---|
| **P1** | `smb-os-discovery` | `smb` (ya llamado) | 139/445 | `os` (`Windows Server 2008 R2 ...`) / `lanmanager` Samba | Windows → `windows`; Samba → `unix` (no implica Linux) |
| **P1** | `rdp-ntlm-info` | `rdp` + `smbauth` | `ms-wbt-server` 3389 | NTLM `os_major.minor.build` (`6.1.7601`) | NTLM ⇒ `windows` |
| **P1** | `http-ntlm-info` | `http` + `smbauth` | HTTP con `WWW-Authenticate: NTLM` | ídem | ídem |
| P2 | `smtp-`/`telnet-`/`ms-sql-ntlm-info` | `smtp`/`comm`/`mssql` + `smbauth` | 25/23/1433 | ídem | ídem (mismo helper NTLM) |
| P2 | `snmp-sysdescr` | `snmp` | `snmp` 161/udp | `sysDescr` (`Linux host 2.6.24-16-server`, `Cisco IOS ...`) | regex → familia |
| P2 | `ntp-info` (`system`) | — (misma sonda V) | 123/udp | `Linux/2.6.24` | regex → familia |

### Descartadas (YAGNI, documentar en README)

| Script | Motivo |
|---|---|
| `mysql-info`, `oracle-tns-version`, `amqp-info`, `xmpp-info`, `sip-methods`, `memcached-info` | `-sV` ya extrae la misma versión |
| `ssh2-enum-algos`, `ssh-hostkey` | No revelan versión; el banner es todo |
| `pgsql` | Versión exacta requiere autenticación; queda `series_expanded` (medium) |
| `ms-sql-info` | Build exacto, pero mapear build → CPE NVD (`sql_server:2008:r2`) exige tabla de builds; `-sV` ya da versión mayor |
| `vmware-version` | ESXi es `o:` (no está en la BD); vCenter vía catálogo HTTP |
| `smb2-*` | SMB2 no expone versión de Samba; con SMB1 deshabilitado no hay sonda (límite documentado) |
| `ldap-rootdse` | OpenLDAP no da versión; AD ya se cubre con NTLM |
| `http-apache-server-status`, `http-generator` | **No es código**: son rutas/patrones HTTP ⇒ propuesta de entradas de catálogo (como Tomcat en F8 de 002) |
| `*-vuln-*`, `ssl-heartbleed`, `smb-vuln-ms17-010` (confirmación de CVE) | Ver §6 (fase futura, no en este plan) |

## 3. Decisión de diseño

### 0. Principio: sondas dirigidas, nunca a ciegas
Una sonda solo se ejecuta si se cumplen **las dos** condiciones:
1. **Disparador**: Nmap ya detectó en ese puerto el servicio/producto que
   la sonda sabe interrogar (`port.service`, producto de la CPE o
   `port.version.product`). El número de puerto no basta por sí solo.
2. **Necesidad**: el dato que aporta falta o es impreciso.
   - V: versión de Nmap vacía (`*`), de serie (`x.y`) o rango
     (`3.X - 4.X`). Con versión precisa (`cpe_has_precise_version`) la
     sonda **no** corre.
   - O: el puerto analizado tiene CVEs con condición de plataforma
     (`requires_platform`) y `os_context` es desconocido o solo de
     familia. Sin CVEs condicionales no hay sonda O.

Nada de barridos de puertos ni sondas "por si acaso": si Nmap no detectó
el servicio, no hay sonda.

### A. Generalizar el patrón SMB, sin framework
Una tabla local `SERVICE_PROBES` (lista de entradas planas) y un único
despachador que aplica §0. Cada entrada:

```
{ name = 'irc', kind = 'version'|'os',
  services = {irc=true,...},           -- disparador: servicio detectado
  products = {unrealircd=true} | nil,  -- disparador: producto Nmap/CPE
  run = function(host, port) ... end } -- devuelve {cpe=, version=} | {family=, version=} | nil
```

- `run` envuelto en `pcall`, timeout corto (`stdnse` socket timeout
  ≤ 5 s), fallo silencioso ⇒ comportamiento actual (log nivel 2).
- Caché en `registry.probes[name][host.ip .. ':' .. port.number]`
  (V) o `registry.host_os_probe[host.ip]` (O). La caché SMB actual
  (`registry.smb`) se migra a esta.
- Ubicación en `matches.data`: una sola clave nueva `'probe'`;
  `version_source` = `name` de la sonda (`smb`, `irc`, `ftp`, `ajp`,
  `ntp`). `'smb'` se mantiene como valor para no romper JSON.
- Regla V (igual que SMB): si la sonda da versión precisa para el CPE del
  puerto, **sustituye** a la de Nmap (no se suma). Si el puerto no tiene
  CPE pero la sonda identifica producto (p. ej. IRC sin CPE), se añade.
- AJP no reimplementa el motor HTTP: construye un objeto respuesta y
  reutiliza `response_subjects` + `match_subjects` + `run_targeted_probes`
  (catálogo) con `location='probe'`.

### B. Contexto de SO por host (tipo O)
- `os_context` gana una fuente nueva de máxima prioridad a nivel host:
  `probe` (antes de `cpe` `o:` del puerto, `ostype`, `host.os`,
  `extrainfo`). Orden final: `probe` > `cpe` > `ostype` > `host_os` >
  `extrainfo`.
- Disparo bajo demanda (§0): `host_probe_os(host)` se llama solo desde
  `vulnerabilities()` cuando hay CVEs con `requires_platform` y SO
  desconocido. Entonces elige, entre los puertos del host que **Nmap ya
  identificó** con un servicio que tenga sonda O (`microsoft-ds`/
  `netbios-ssn`, `ms-wbt-server`, HTTP con `WWW-Authenticate: NTLM`),
  el de mayor prioridad y ejecuta una sola sonda; si falla, la siguiente.
  Si el host no tiene ninguno de esos servicios detectados, no se sondea.
- Concurrencia: `nmap.mutex(host.ip)` + caché por host (`false` =
  negativo): como mucho una ronda O por host, compartida por todos sus
  puertos y estable aunque los `portaction` corran en paralelo.
- SMB: si la sonda V de Samba ya llamó a `smb.get_os`, su campo `os` se
  reutiliza (cero conexiones extra).
- Mapas en datos, no en código: NTLM `major.minor` → `windows` (familia
  basta; versión opcional en `os_context.version`), regex `sysDescr` /
  `system` → familia vía `data/platform-families.json` (sección nueva
  `patterns`) o tabla local mínima si son ≤ 5 patrones (decidir en
  contrato; preferir tabla local por KISS).
- Samba ⇒ familia `unix`, **no** `linux` (no inferir distro).

### C. Argumentos y salida
- Nuevo `cvescannerv2.probes=all|none|<csv>` (defecto `all`).
  `cvescannerv2.smb=0` se mantiene como alias para desactivar `smb`.
- JSON: sin claves nuevas salvo valores nuevos en `version_source` y
  `os_context.source = 'probe:<name>'`. Tabla/log: idem (cabecera ya
  imprime `version_source`).
- Confianza: sin niveles nuevos. Versión de sonda precisa ⇒ elegible para
  `exact_version`/`range_contains` (high). SO de sonda ⇒ las reglas de
  `evaluate_platform` existentes deciden.
- README: lista de sondas, puertos, si requieren `-sU`, coste (1
  conexión extra por servicio/host) y cómo desactivarlas.

## 4. Invariantes / no regresión

1. `probes=none` ⇒ salida idéntica a la actual (tests Lua existentes
   verdes sin cambios de expectativa; 172 tests a fecha de 002).
2. Sonda SMB: mismo resultado en MS2 tras la migración (Samba 3.0.20,
   `version_source=smb`).
3. Todas las sondas: categoría `safe` del script de referencia; sin
   credenciales, sin escritura, sin payloads de explotación.
4. Fallo/timeout de sonda ⇒ fallback a Nmap; nunca aborta el puerto.
5. JSON: solo valores nuevos, ninguna clave eliminada/renombrada.
6. Coste: ≤ 1 conexión extra por (sonda, puerto) y ≤ 1 ronda O por host.
7. Sonda solo con disparador (servicio detectado por Nmap) **y**
   necesidad (§3.0). Tests explícitos: versión precisa ⇒ no corre;
   servicio distinto en el puerto típico ⇒ no corre; sin CVEs
   condicionales ⇒ no hay sonda O.

## 5. Fases

| Fase | Contenido | Archivos | Depende |
|---|---|---|---|
| F0 | **Validación de campo (sin código)**: ejecutar los scripts de referencia P1/P2 contra MS2/MS3 (imagen Alpine, `-sV [-sU]`) y anotar qué devuelven. Criterio de entrada: sonda que no cambie la salida en ningún objetivo de laboratorio ⇒ se descarta. Baseline de CVEs/confianza por servicio | `tasks/artifacts/f0-probes.md` | — |
| F1 | Refactor: `SERVICE_PROBES` + despachador + arg `probes`; migrar SMB sin cambio de comportamiento | `cvescannerv2.nse`, `tests/lua/test_catalog.lua`, `harness.lua` | F0 |
| F2 | Sonda V `irc` (P1) + tests (stub socket) | ídem | F1 |
| F3 | Sonda V `ftp` STAT (P1) + tests | ídem | F1 |
| F4 | `os_context` fuente `probe` + `host_probe_os` bajo demanda (solo con `requires_platform`, solo sobre servicios ya detectados; mutex) + SMB `os` como primera sonda O + tests | ídem | F1 |
| F5 | Helper NTLM (`smbauth.get_host_info_from_security_blob`) + sondas O `rdp`, `http-ntlm` + tests | ídem | F4 |
| F6 | Sonda V `ajp` reutilizando motor HTTP (P2) | ídem | F1 |
| F7 | Sonda V+O `ntp` y O `snmp` (UDP, P2) — solo si F0 encontró objetivo | ídem | F4 |
| F8 | Propuestas de catálogo HTTP: `/server-status`, `meta generator` (artefactos JSON, como `tomcat-probe.json`) | `tasks/artifacts/` | — |
| F9 | Medición MS2 + MS3 (`probes=none` vs `all`), `verify_nvd.py`, README | `results/compare/`, `README.md` | F1–F8 |

Paralelizables: F0 y F8 (sin código). F1–F7 tocan el mismo NSE ⇒
serializar. Orden recomendado: F0 → F1 → F2 → F4 → F5 → F3 → F6 → F7 → F9.
P3 (`redis`, `mongodb`, `mqtt`) solo si F0/F9 aportan objetivo real.

## 6. Fuera de alcance (registrar, no implementar)

- **Confirmación de CVE** con scripts `vuln`+`safe` (`ssl-heartbleed`,
  `ssl-ccs-injection`, `smb-vuln-ms17-010`): aportaría un nivel
  `confirmed`, pero duplica scripts que el usuario puede lanzar en el
  mismo `nmap --script vuln`; y MS17-010 es CVE de SO (no está en la BD).
  Reevaluar tras F9.
- **Servicios mal clasificados por `-sV`** (`wap-wsp?` = Elasticsearch):
  requiere ampliar `portrule`/HTTP a servicios con `?`; cambio de
  alcance, plan aparte.
- Tabla build → CPE para `ms-sql-info` y backports por distro.

## 7. Métricas objetivo (F9)

| Métrica | Baseline (002) | Objetivo |
|---|---|---|
| MS2 UnrealIRCd | 0 CVEs (`*`) | versión `3.2.8.1`, CVE-2010-2075 `high` |
| MS2 resto | high precisión 95.2 % | ≥ 95.2 %, sin nuevos FP |
| MS3 servicios con `os_context` | solo SMB/IIS (por `-sV`) | **todos** los puertos del host, `source=probe:*` |
| MS3 CVEs solo-Linux en Apache/MySQL | `medium` (`requires_platform`) | `low` (`platform_mismatch:linux`) |
| Tiempo de escaneo MS2/MS3 | baseline F0 | ≤ +10 % |

## 8. Riesgos

- `irc-info` hace `NICK/USER` (aparece en logs del IRCd); aceptable
  (`safe`), documentar. Algunos IRCd exigen esperar PING ⇒ timeout.
- `ftp` STAT tras login anónimo no siempre disponible; sin login solo
  algunos servidores responden ⇒ fallo silencioso.
- Sondas O sobre servicios no detectados (p. ej. 3389 fuera de `-p`, o
  identificado como `ms-wbt-server?`) no corren: por diseño (§3.0). El
  SO queda desconocido y las CVEs condicionales siguen `medium`.
- La sonda O se dispara desde el análisis de otro puerto (el que tiene
  CVEs condicionales), pero solo contra un servicio que Nmap ya
  identificó en el host; no es un escaneo nuevo.
- NTLM da versión de Windows, no de aplicaciones: no inferir versiones de
  IIS/SQL Server a partir de ella.
- APIs de librerías NSE cambian entre versiones de Nmap ⇒ todo bajo
  `pcall(require)` + `pcall(run)`; tests con stubs en `harness.lua`.
- UDP (`ntp`, `snmp`) solo con `-sU`; sin él la sonda no aplica.
