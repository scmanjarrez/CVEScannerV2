# TASK-02 — F1: tests del despachador de sondas

Plan: 003-nmap-service-probes (PLAN §3.A, §3.C, §4 invariantes 1,4,7).

## Archivos (únicos permitidos)
1. `tests/lua/test_catalog.lua` (añadir una suite nueva tras la suite
   `smb samba probe`; no alterar los tests existentes)

NO modificar `cvescannerv2.nse` ni `harness.lua`. Si un test revela un bug
del NSE, NO lo arregles: márcalo `BLOCKED` con la descripción.

## Contexto
`cvescannerv2.nse` exporta (vía harness) `SERVICE_PROBES`,
`run_version_probe(host, port, probe)`, `probe_enabled(name)`,
`add_nmap_matches`, `smb_version`, `registry`. Usa los helpers de la suite
SMB existente (`with_smb`, `new_matches`, `samba_port`). Los args se pasan
con `t.load_scanner({ args = { probes = '...' } })`.

## Casos a cubrir (suite `service probes dispatcher`)
1. `probes=none` ⇒ `smb.get_os` no se llama y el CPE de Nmap se conserva.
2. `probes=smb` ⇒ la sonda smb corre; `probes=irc` ⇒ smb NO corre.
3. `probes=smb,irc` (csv con coma) ⇒ `probe_enabled('smb')` true.
4. `smb=0` con `probes=all` ⇒ `probe_enabled('smb')` false.
5. Sonda falsa propia: `run_version_probe(host, port, fake)` con
   `fake.run` que lanza `error()` ⇒ devuelve nil, no propaga; segunda
   llamada no vuelve a ejecutar `run` (caché negativa).
6. Sonda falsa con `run` que devuelve `{cpe=..., version=...}` ⇒ se llama
   una sola vez para la misma clave `ip:puerto` y dos veces para puertos
   distintos (sin `cache_key`).
7. Puerto con servicio distinto (p. ej. `http` en 80) con CPE `samba` ⇒
   la sonda smb no corre (ya existe; no duplicar si cubre lo mismo).
8. `analysis`: un origen de matches cualquiera distinto de `nmap`
   (p. ej. `'irc'`) produce `version_source == 'irc'` (reutilizar el
   patrón de `test_scoping.lua` «version source» solo si es sencillo; si
   requiere el montaje de scoping, omitir y anotarlo en NOTES).

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
Todo en verde; el contador de pasados sube con los casos nuevos. Estilo:
2 espacios, ≤ 80 columnas. Devolver SOLO el bloque de estado
(`CHECKS: lua_tests=PASS`).
