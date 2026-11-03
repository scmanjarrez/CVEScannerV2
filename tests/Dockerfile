# syntax=docker/dockerfile:1
# Lua test runner for cvescannerv2.nse; Nmap is not installed.
#   docker build -f tests/Dockerfile -t cvescannerv2-tests .
#   docker run --rm cvescannerv2-tests
#   docker run --rm -v "$PWD:/src:ro" cvescannerv2-tests   # live sources

FROM alpine:3.23

RUN apk add --no-cache lua5.4 lua5.4-sql-sqlite3

WORKDIR /src
COPY cvescannerv2.nse ./
COPY tests/ ./tests/
COPY docker/Dockerfile ./docker/Dockerfile
COPY .dockerignore ./.dockerignore
COPY data/product-aliases.json data/vendor-aliases.json \
    data/platform-families.json data/local-catalog.json \
    data/product-cpe.json ./data/

ENV LUA=lua5.4
ENTRYPOINT ["sh", "tests/run.sh"]
