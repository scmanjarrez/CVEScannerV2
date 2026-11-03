# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM alpine:3.23 AS database-builder

ARG BUILDARCH
RUN --mount=type=cache,id=apk-3.23-${BUILDARCH},target=/var/cache/apk,sharing=locked \
    apk add --update-cache git sqlite
WORKDIR /src
# Invalidate only the database download/build when refreshing upstream data.
ARG DATABASE_REFRESH=latest
RUN test -n "$DATABASE_REFRESH" \
    && git clone --depth 1 --branch master \
        https://github.com/scmanjarrez/CVEScannerV2DB.git . \
    && mkdir -p /output \
    && sh build.sh --output /output/cve.db \
    && test -s /output/cve.db \
    && sqlite3 /output/cve.db 'PRAGMA quick_check;' | grep -qx ok

FROM alpine:3.23 AS catalog-fetcher

# Vulners HTTP catalogue, stored under the names the NSE reads from its cache.
# The source marker must equal the catalogue base URL, without a newline.
ARG CATALOG_BASE=https://raw.githubusercontent.com/vulnersCom/nmap-vulners/catalog/
ARG CATALOG_REFRESH=latest
RUN --mount=type=cache,id=apk-3.23-catalog,target=/var/cache/apk,sharing=locked     apk add --update-cache ca-certificates curl
RUN test -n "$CATALOG_REFRESH" \
    && mkdir -p /catalog \
    && for name in index fingerprints paths probes; do \
        curl -fsSL --retry 3 -o "/catalog/$name.json" \
            "${CATALOG_BASE}$name.json" || exit 1; \
    done \
    && printf '%s' "$CATALOG_BASE" > /catalog/.vulners-catalog-source

FROM alpine:3.23 AS nmap-builder

ARG TARGETARCH
ARG TARGETVARIANT
RUN --mount=type=cache,id=apk-3.23-${TARGETARCH}${TARGETVARIANT},target=/var/cache/apk,sharing=locked \
    apk add --update-cache \
    ca-certificates \
    lddtreepax \
    lua5.4-sql-sqlite3 \
    nmap \
    nmap-nselibs

# Shared objects have no ELF interpreter from which lddtreepax can infer
# musl's library search paths; supply them for Lua module dependencies.
RUN export LD_LIBRARY_PATH=/lib:/usr/lib \
    && mkdir -p /rootfs \
    && lddtreepax --copy-to-tree /rootfs /usr/bin/nmap \
    && find -L /usr/lib/lua -type f -name '*.so' \
        -exec lddtreepax --copy-to-tree /rootfs {} + \
    && mkdir -p /rootfs/usr/share/nmap \
    && for item in /usr/share/nmap/*; do \
        [ "${item##*/}" = scripts ] || \
            cp -a "$item" /rootfs/usr/share/nmap/; \
    done \
    && cp -a /usr/lib/lua /rootfs/usr/lib/ \
    && lddtreepax --copy-to-tree /rootfs /usr/lib/ossl-modules/legacy.so \
    && cp -a /usr/lib/ossl-modules /rootfs/usr/lib/ \
    && mkdir -p /rootfs/usr/local/lib \
    && ln -s /usr/lib/lua /rootfs/usr/local/lib/lua \
    && mkdir -p /rootfs/etc/ssl/certs \
    && cp -a /etc/ssl/cert.pem /rootfs/etc/ssl/ \
    && cp -a /etc/ssl/certs/ca-certificates.crt \
        /rootfs/etc/ssl/certs/ \
    && mkdir -p /rootfs/usr/share/ncat \
    && cp /etc/ssl/certs/ca-certificates.crt \
        /rootfs/usr/share/ncat/ca-bundle.crt \
    && mkdir -p /rootfs/CVEScannerV2/data /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

# Small source assets change independently of Nmap and the CVE database.
FROM scratch AS scanner-files

COPY --link LICENSE /usr/share/licenses/cvescannerv2/LICENSE
COPY --link data/product-aliases.json /CVEScannerV2/data/product-aliases.json
COPY --link data/vendor-aliases.json /CVEScannerV2/data/vendor-aliases.json
COPY --link data/platform-families.json /CVEScannerV2/data/platform-families.json
COPY --link data/local-catalog.json /CVEScannerV2/data/local-catalog.json
COPY --link --from=catalog-fetcher /catalog/ /CVEScannerV2/data/
COPY --link cvescannerv2.nse /usr/share/nmap/scripts/cvescannerv2.nse

FROM scratch AS runtime

COPY --link --from=nmap-builder /rootfs/ /

WORKDIR /CVEScannerV2
ENV NMAPDIR=/usr/share/nmap
ENTRYPOINT ["/usr/bin/nmap", "-sV", "--script", "/usr/share/nmap/scripts/cvescannerv2.nse"]

FROM runtime AS db

# Keep the large database layer independent of changes to scanner assets.
COPY --link --from=database-builder /output/cve.db /CVEScannerV2/data/cve.db
COPY --link --from=scanner-files / /

FROM runtime AS nodb

COPY --link --from=scanner-files / /
