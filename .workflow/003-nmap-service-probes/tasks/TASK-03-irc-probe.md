# TASK-03 — F2: sonda de versión `irc` (UnrealIRCd) + necesidad §3.0

Plan: 003-nmap-service-probes (PLAN §1 evidencia MS2, §3.0, §3.A, §8).
Requiere TASK-01 y TASK-02 hechos.

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/test_catalog.lua` (suite nueva `irc probe`, al final)

(Si hace falta exportar algo nuevo en `harness.lua`, está PROHIBIDO: usa
solo lo ya exportado: `SERVICE_PROBES`, `run_version_probe`,
`add_nmap_matches`, `registry`, `probe_enabled`.)

## 1. Necesidad (PLAN §3.0) — en `version_probe_result`
Antes de ejecutar una sonda de kind `version`, saltarla si la versión de
Nmap del puerto ya es precisa: usar `is_precise_version(version)` con la
versión de `port.version.version` (vacía/`*` ⇒ no precisa ⇒ la sonda
corre). Pasar esa versión desde `add_nmap_matches`. Aplica a todas las
sondas, SMB incluida. Ajusta SOLO si algún test SMB existente se rompe
(entonces reporta BLOCKED).

## 2. Sonda `irc`
- Entrada nueva en `SERVICE_PROBES`: `name='irc'`, `kind='version'`,
  `services={irc=true, ircs=true}`, `products={unrealircd=true}`,
  `ports=nil`. Disparador: servicio detectado **y** producto CPE
  unrealircd. Caché por defecto (`ip:puerto`).
- `run(host, port)`: socket `nmap.new_socket()` (obtener `nmap` al llamar,
  no al cargar), `sock:set_timeout(5000)`, `sock:connect(host, port)`;
  enviar `NICK cvescan\r\nUSER cvescan 0 * :cvescan\r\nVERSION\r\n`; leer
  líneas (`sock:receive_lines(1)` en bucle, máx. ~10 lecturas / 5 s en
  total); responder `PONG <arg>` a cualquier `PING :<arg>`; terminar al
  ver una línea con código `351`. Siempre `sock:close()`.
- Parseo de 351: `^:%S+ 351 %S+ (%S+)`; del token, patrón
  `^Unreal(%d[%w%.]*)` y quitar el punto final ⇒ versión `3.2.8.1`.
  Devolver `{ cpe = 'cpe:/a:unrealircd:unrealircd', version = v }`.
  Cualquier otro caso (no 351, token sin `Unreal`, error de socket) ⇒
  `nil`.
- Solo lectura `safe`: sin payloads de explotación (nada de `AB;`).

## 3. Tests (`irc probe`) con socket stub
Montar `scanner.stubs.nmap.new_socket` devolviendo un objeto con
`set_timeout`, `connect`, `send`, `receive_lines`, `close` y un guion de
respuestas. Casos:
1. 351 `:irc.local 351 cvescan Unreal3.2.8.1. irc.local :FhiXOoE` ⇒
   `add_nmap_matches` añade en `matches.data.irc` el CPE unrealircd
   `3.2.8.1` y NO añade nada en `matches.data.nmap`. (Para ello
   `matches.data.irc = {}` antes, como se hace con `smb`.)
2. Nmap con versión precisa (`3.2.8.1`) ⇒ el socket no se crea
   (contador 0) y queda el CPE de Nmap.
3. Servicio `http` en 6667 con CPE unrealircd ⇒ no corre.
4. Servicio `irc` pero CPE de otro producto (`ngircd`) ⇒ no corre.
5. `probes=none` y `probes=smb` ⇒ no corre.
6. Respuesta sin 351 / error de `connect` / token sin `Unreal` ⇒ fallback
   a Nmap sin error; `close` llamado en todos.
7. PING intercalado ⇒ se envía `PONG`.
8. Caché: dos llamadas mismo `ip:puerto` ⇒ un solo `new_socket`.
9. Necesidad en SMB: puerto samba con versión Nmap precisa (`4.5.16`) ⇒
   `get_os` no se llama.

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
Todo verde. Estilo: 2 espacios, ≤ 80 col, comentarios `---`. Documentar
`irc` en la cabecera de args (`probes`). Devolver SOLO el bloque de estado
(`CHECKS: lua_tests=PASS`).
