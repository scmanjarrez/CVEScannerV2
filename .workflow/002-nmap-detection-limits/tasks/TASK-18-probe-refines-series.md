# TASK-18 — Sonda dirigida puede refinar una versión de serie (F8, motor)
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_catalog.lua`
(+ `tests/lua/harness.lua` EXPORTS si hace falta). Gate: `sh tests/run.sh`
(≥165, 0 skipped).

## Problema
`run_targeted_probes` solo ejecuta una sonda si `not cpe_has_version(alias)`.
En MS2 Nmap aporta `tomcat 5.5` (versión de serie, 2 componentes) así que la
sonda de Tomcat (changelog => 5.5.25) nunca corre.
## Cambios
1. Nueva función local `cpe_has_precise_version(matches, cpe)`: true si
   alguna versión registrada para `cpe` NO es de serie (serie = `^%d+%.%d+$`
   o sufijo `.x`/`.*`) ni rango. `run_targeted_probes` usa esta función
   (en la condición del bucle de sondas y en la de rutas) en vez de
   `cpe_has_version`.
2. Tras `add_cpe_version(probe.alias, version, ...)` con una versión
   precisa que empiece por `<serie>.` : eliminar de `matches.data[*][alias]`
   las versiones de serie coincidentes (decrementando `matches.size` por
   cada una) para analizar solo la precisa. Si la sonda no encuentra nada,
   la versión de serie original se conserva.
3. `cpe_has_version` y su resto de usos (`sweep_catalog`, etc.) no cambian.
4. Tests: alias con versión `5.5` + sonda stub que devuelve body con
   `5.5.25` ⇒ matches finales sólo `5.5.25`; sonda sin hallazgo ⇒ sigue
   `5.5`; alias con `5.5.25` previo ⇒ la sonda no corre; sin versión ⇒ corre
   como antes.
Devuelve STATUS.
