# Scanner tests

Pruebas de `cvescannerv2.nse` que no necesitan Nmap. Las librerías NSE
(`http`, `nmap`, `stdnse`, `shortport`, `json`, `lfs`, `datetime`) se
sustituyen por stubs, y la base de datos es una fixture SQLite temporal.

## Ejecución en contenedor (recomendada)

```bash
docker build -f nmap/tests/Dockerfile -t cvescannerv2-tests .
```

```bash
docker run --rm cvescannerv2-tests
```

Para probar el código local sin reconstruir la imagen:

```bash
docker run --rm -v "$PWD:/src:ro" cvescannerv2-tests
```

`nmap/tests/Dockerfile.dockerignore` define el contexto de esta imagen. El
`.dockerignore` raíz no se modifica y la imagen del escáner no incluye
`nmap/tests/`.

## Ejecución local

Requiere `lua5.4`. La suite SQLite requiere además `luasql.sqlite3` y se
salta si no está instalado.

```bash
sh nmap/tests/run.sh
```

## Variables

| Variable | Efecto |
| --- | --- |
| `CVESCANNER_STRICT=1` | Los XFAIL y XPASS hacen fallar la ejecución. Úsala tras corregir los bugs conocidos. |
| `CVESCANNER_FILTER=texto` | Ejecuta solo los tests cuyo `suite :: nombre` contiene `texto`. |
| `CVESCANNER_NSE=ruta` | Script que se prueba (por defecto `nmap/src/cvescannerv2.nse`). |
| `LUA=binario` | Intérprete que usa `run.sh` (por defecto `lua5.4`). |

```bash
docker run --rm -e CVESCANNER_FILTER=openssl cvescannerv2-tests
```

## Packaging tests

Dos comprobaciones del empaquetado de la imagen del escáner:

- Estática (`lua/test_docker.lua`, suite `docker packaging`): sin Docker.
  Comprueba que cada fichero `data/` que lee el NSE está copiado o generado
  por `docker/Dockerfile`, que los `COPY data/...` existen y no los excluye
  `.dockerignore`, y que la URL por defecto de `scripts/download-catalog.sh`
  coincide con `ARG CATALOG_BASE` de `docker/Dockerfile`. Tarda
  menos de un segundo y se ejecuta dentro de `sh nmap/tests/run.sh`.
- Integración (`docker/check.sh [--fresh]`): requiere Docker y red. Construye
  las imágenes `nodb` y `db`, comprueba su contenido, valida `cve.db` con
  `python3` y escanea un `php:5.6-apache` en una red temporal. No entra en
  `run.sh`. Tarda varios minutos (la primera vez, más por la descarga de la
  base de datos y del catálogo). `--fresh` fuerza regenerar la base de datos
  y el catálogo sin caché. Imprime `PASS`/`FAIL` por comprobación y devuelve
  código distinto de cero si alguna falla. Limpia contenedores, red y
  ficheros temporales al terminar.

```bash
sh nmap/tests/run.sh                     # estática, sin Docker
sh nmap/tests/docker/check.sh            # integración
sh nmap/tests/docker/check.sh --fresh    # integración sin caché
```

## Estructura

| Fichero | Contenido | Casos |
| --- | --- | --- |
| `test_scanner.lua` | Redirecciones HTTP, lectura local del catálogo y puerto sin CVE. | - |
| `lua/harness.lua` | Mini framework (`case`, `known_bug`, `skip`) y cargador del NSE con stubs. | - |
| `lua/test_versions.lua` | `compare_version`, `parse_nmap_version`, `split_cpe`, `parse_cpe_version`, aliases. | 38 |
| `lua/test_scoping.lua` | `scoped_multi_versions`, `scoped_versions`, orden CVSS y escape SQL. | 65 |
| `lua/test_output.lua` | Salida de texto (`text_output`) y JSON (`json_report`) con tablas fijas. | 24 |
| `lua/test_catalog.lua` | Validación del catálogo de Vulners y extracción de huellas HTTP. | 107 |
| `lua/test_database.lua` | `portaction`/`postaction` de extremo a extremo sobre la fixture SQLite. | 24 |
| `lua/test_docker.lua` | Empaquetado: rutas `data/` del NSE frente a `docker/Dockerfile` y `.dockerignore`. | 6 |
| `lua/test_architecture.lua` | Estática: grafo de capas de `nmap/src/cvescannerv2/`, ciclos, dueños de E/S y globales implícitas. | 5 |
| `docker/check.sh` | Integración: construye las imágenes, valida su contenido y escanea un objetivo real. | - |
| `lua/run.lua` | Ejecuta las suites de `lua/` y devuelve el código de salida. | - |

Los recuentos son los `t.case(` de nivel superior de cada fichero. El total
de `lua5.4 nmap/tests/lua/run.lua` (308 casos) es mayor porque algunos casos
se generan en bucles (por ejemplo, `compare_version`).

## Resultados

- `PASS`/`FAIL`: el comportamiento debe mantenerse.
- `XFAIL`: un bug conocido sigue presente. El test describe el
  comportamiento correcto y muestra el motivo del fallo.
- `XPASS`: un bug conocido ya no se reproduce. Pasa el test de `known_bug` a
  `case`.

Sin `CVESCANNER_STRICT`, los `XFAIL` no hacen fallar la ejecución. Así la
suite sirve de regresión desde ahora y de checklist para las correcciones.

## Cómo funciona el cargador

`harness.load_scanner()` carga `cvescannerv2.nse` con `load()` y devuelve sus
puntos de entrada: `portaction`, `preaction`, `postaction` y `portrule`. Las
librerías NSE se sustituyen por stubs, que quedan en `scanner.stubs`.

Los módulos de `nmap/src/cvescannerv2/**.lua` se cargan con `require()` y se
acceden como `scanner.modules.<nombre>`, donde `<nombre>` es el último
componente del módulo (por ejemplo, `scanner.modules.service_cves` o
`scanner.modules.state`). El snapshot se toma al cargar, así que cada escáner
conserva sus propios módulos aunque se cargue otro después. Nada se copia a la
tabla del escáner: los tests llaman a las mismas funciones que usa Nmap, sin
alias ni exports solo de test.

`lua/test_architecture.lua` impone el grafo de capas: un módulo solo puede
hacer `require` de módulos de una capa estrictamente inferior, y no hay
ciclos. También fija los dueños de las APIs de Nmap y de E/S (`get_script_args`
solo en `config`, `luasql` solo en `db`, `io.open` solo en `util`,
`catalog.store`, `reference_files`, `log` y `json_report`). Si un módulo nuevo necesita una
de estas APIs, hay que añadirlo a la regla correspondiente en ese fichero.
