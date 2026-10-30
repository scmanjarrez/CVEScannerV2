# TASK-09 — Fix: servicios no-HTTP con TLS no entran en el motor HTTP

Bug preexistente (reproducido con HEAD): `portaction` entra en
`http_match` si `shortport.ssl(host, port)`; el 3389 (`ms-wbt-server`
con TLS, MS3-Windows 192.168.251.130) pasa por ese filtro y el barrido de
rutas HTTP no termina (cada petición vence por tiempo).

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/test_catalog.lua` (suite nueva `http engine gating`)

No tocar `load_luasql()`.

## Cambio
- Tabla local `NON_HTTP_SERVICES` (conjunto) con servicios que Nmap
  identifica y que NO hablan HTTP aunque lleven TLS: `ms-wbt-server`,
  `ms-sql-s`, `mysql`, `postgresql`, `ssh`, `ftp`, `ftps`, `smtp`, `smtps`,
  `imap`, `imaps`, `pop3`, `pop3s`, `ldap`, `ldapssl`, `ldaps`, `vnc`,
  `microsoft-ds`, `netbios-ssn`, `msrpc`, `telnet`, `domain`, `ntp`, `snmp`.
- Función local `use_http_engine(host, port)`: `true` si
  `shortport.http(host, port)` o `port.service == 'upnp'`, o
  (`shortport.ssl(host, port)` y `port.service` no está en
  `NON_HTTP_SERVICES`). Servicios HTTP reales (`http`, `https`,
  `http-proxy`, `ssl/http`, `unknown`/sin servicio con TLS) siguen
  entrando como hoy.
- `portaction` usa `http_arg == '1' and use_http_engine(host, port)`.
  Exportar `use_http_engine` en `tests/lua/harness.lua` NO está
  permitido: probar a través de `portaction` o `shortport` stub.

## Tests
1. Puerto 3389 `ms-wbt-server` con `shortport.ssl` stub verdadero ⇒ no se
   llama a ningún método del stub `http` (`get`, `pipeline_add`,
   `pipeline_go`).
2. Puerto 443 `https` con ssl verdadero ⇒ sí entra (el stub `http` es
   llamado).
3. Puerto 8080 `http` (shortport.http verdadero) ⇒ sí entra.
4. `upnp` ⇒ sí entra.
5. `ssh` con ssl verdadero ⇒ no entra.

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
206 previos + nuevos en verde. No ejecutar nmap. Devolver SOLO el bloque
de estado (`TASK: TASK-09`, `CHECKS: lua_tests=PASS`).
