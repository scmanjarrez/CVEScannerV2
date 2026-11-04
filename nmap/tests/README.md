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
  `.dockerignore`, y que `CATALOG_BASE` coincide con el del NSE. Tarda
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

| Fichero | Contenido |
| --- | --- |
| `test_scanner.lua` | Suite original: redirecciones HTTP, caché del catálogo y puerto sin CVE. |
| `lua/harness.lua` | Mini framework (`case`, `known_bug`, `skip`) y cargador del NSE con stubs. |
| `lua/test_versions.lua` | `compare_version`, `version_parser`, `split_cpe`, `cpe_parser`, aliases. |
| `lua/test_scoping.lua` | `scoped_multi_versions`, `scoped_versions`, orden CVSS y escape SQL. |
| `lua/test_catalog.lua` | Validación del catálogo de Vulners y extracción de huellas HTTP. |
| `lua/test_database.lua` | `portaction`/`postaction` de extremo a extremo sobre la fixture SQLite. |
| `lua/test_docker.lua` | Empaquetado: rutas `data/` del NSE frente a `docker/Dockerfile` y `.dockerignore`. |
| `docker/check.sh` | Integración: construye las imágenes, valida su contenido y escanea un objetivo real. |
| `lua/run.lua` | Ejecuta las suites de `lua/` y devuelve el código de salida. |

## Resultados

- `PASS`/`FAIL`: el comportamiento debe mantenerse.
- `XFAIL`: un bug conocido sigue presente. El test describe el
  comportamiento correcto y muestra el motivo del fallo.
- `XPASS`: un bug conocido ya no se reproduce. Pasa el test de `known_bug` a
  `case`.

Sin `CVESCANNER_STRICT`, los `XFAIL` no hacen fallar la ejecución. Así la
suite sirve de regresión desde ahora y de checklist para las correcciones.

## Cómo funciona el cargador

Las funciones del NSE son `local`. `harness.load_scanner()` añade al final del
código fuente un `return { nombre = nombre, ... }` y lo carga con `load()`,
de modo que las funciones se exportan desde el mismo chunk sin tocar el
script. Si una función se renombra, hay que actualizar `EXPORTS` en
`harness.lua`.
