# Scanner tests

Pruebas de `cvescannerv2.nse` que no necesitan Nmap. Las librerías NSE
(`http`, `nmap`, `stdnse`, `shortport`, `json`, `lfs`, `datetime`) se
sustituyen por stubs, y la base de datos es una fixture SQLite temporal.

## Ejecución en contenedor (recomendada)

```bash
docker build -f tests/Dockerfile -t cvescannerv2-tests .
```

```bash
docker run --rm cvescannerv2-tests
```

Para probar el código local sin reconstruir la imagen:

```bash
docker run --rm -v "$PWD:/src:ro" cvescannerv2-tests
```

`tests/Dockerfile.dockerignore` define el contexto de esta imagen. El
`.dockerignore` raíz no se modifica y la imagen del escáner no incluye
`tests/`.

## Ejecución local

Requiere `lua5.4`. La suite SQLite requiere además `luasql.sqlite3` y se
salta si no está instalado.

```bash
sh tests/run.sh
```

## Variables

| Variable | Efecto |
| --- | --- |
| `CVESCANNER_STRICT=1` | Los XFAIL y XPASS hacen fallar la ejecución. Úsala tras corregir los bugs conocidos. |
| `CVESCANNER_FILTER=texto` | Ejecuta solo los tests cuyo `suite :: nombre` contiene `texto`. |
| `CVESCANNER_NSE=ruta` | Script que se prueba (por defecto `cvescannerv2.nse`). |
| `LUA=binario` | Intérprete que usa `run.sh` (por defecto `lua5.4`). |

```bash
docker run --rm -e CVESCANNER_FILTER=openssl cvescannerv2-tests
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
