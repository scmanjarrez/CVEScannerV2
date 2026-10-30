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
COPY data/vendor-aliases.json ./data/vendor-aliases.json

ENV LUA=lua5.4
ENTRYPOINT ["sh", "tests/run.sh"]
