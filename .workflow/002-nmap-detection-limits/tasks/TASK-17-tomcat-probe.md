# TASK-17 — F8: sonda Tomcat para el parche exacto (propuesta de catálogo)
Contexto: el catálogo HTTP es el de upstream (nmap-vulners, rama
catalog; fichero `probes.json` con entradas {alias, detect[], extract[],
name, paths[], source}); el NSE admite `catalog_url` para otra fuente.
En MS2 (192.168.251.128:8180, laboratorio del usuario; solo GET de lectura)
Tomcat solo muestra `Apache Tomcat/5.5` en páginas de error, pero
`/tomcat-docs/changelog.html` (200) lista como primera entrada
`<strong>Tomcat 5.5.25 (fhanik)</strong>` => el parche exacto es 5.5.25.
Archivos permitidos: SOLO crear
`.workflow/002-nmap-detection-limits/tasks/artifacts/tomcat-probe.json`
(entrada de sonda propuesta) y trabajar en el directorio temporal
`/tmp/claude-1000/-home-schica-csic-safehorizon-projects-CVEScannerV2/65d263b6-f370-4fda-85d0-7cbfccaba79f/scratchpad/catalog-test/`.
NO modificar cvescannerv2.nse ni `data/` del repo.

## Pasos
1. Lee en `cvescannerv2.nse` cómo se valida y se aplica una sonda
   (`validate_probes`, `run_targeted_probes`, `probe_version`,
   `probe_detects`) y el soporte de `catalog_url`/formato de `index.json`.
2. Crea la entrada de sonda de Tomcat: alias `cpe:/a:apache:tomcat`,
   detect (canales válidos, p. ej. cuerpo/cabecera `Apache Tomcat/5%.5`
   o `Apache%-Coyote`), paths `["/tomcat-docs/changelog.html"]`, extract
   con captura de la PRIMERA versión `5.5.N` del changelog (patrón Lua
   válido y que el validador acepte; documenta si el motor toma la
   primera coincidencia).
3. Copia el catálogo cacheado del run
   (`.../scratchpad/run/data/{index,fingerprints,paths,probes}.json`)
   al dir de prueba, añade tu sonda a `probes.json` (actualiza
   `entries` en `index.json`), sírvelo con `python3 -m http.server` en
   localhost, y ejecuta (imagen Alpine con nmap completo, como en las
   pruebas previas: `docker run --rm --network host --entrypoint sh
   alpine:3.23 -c 'apk add -q nmap nmap-scripts nmap-nselibs
   lua5.4-sql-sqlite3 openssl; nmap -sV -p 8180 --script <nse montado ro>
   --script-args "catalog_url=http://127.0.0.1:PORT/,log=...,json=..."
   192.168.251.128'`; monta una COPIA del dir de datos con cve.db en
   `/CVEScannerV2/data`, workdir `/CVEScannerV2`). Comprueba si Tomcat
   pasa a `5.5.25` y cuántas CVEs salen (antes 70 con 5.5).
4. Si funciona, deja la entrada validada en `artifacts/tomcat-probe.json`
   y en NOTES el resultado (versión detectada, nº de CVEs, confianza).
   Si el motor no permite expresarlo, documenta por qué.
Devuelve STATUS (CHECKS: probe_run=PASS|FAIL).
