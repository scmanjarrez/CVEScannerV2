# TASK-15 — Dockerfile: OpenSSL legacy provider + platform-families.json
Archivos permitidos: `docker/Dockerfile` (+ `.dockerignore` solo si excluye algo necesario).

## Problemas (hallados con MS2)
1. La sonda SMB falla en la imagen: `smbauth.lua: OpenSSL error: error:12800067:DSO support routines::could not load the shared library`.
   En Alpine el proveedor legacy está en `/usr/lib/ossl-modules/legacy.so`
   (paquete libcrypto3) y no se copia al rootfs.
2. `data/platform-families.json` no se copia a la imagen (stage
   `scanner-files`), y el NSE lo necesita junto a los alias.

## Cambios
- Stage `nmap-builder`: copiar al rootfs `/usr/lib/ossl-modules/` (usar
  `lddtreepax --copy-to-tree /rootfs /usr/lib/ossl-modules/legacy.so`
  como con los `.so` de Lua, con `LD_LIBRARY_PATH=/lib:/usr/lib`, y
  `cp -a /usr/lib/ossl-modules /rootfs/usr/lib/`).
- Stage `scanner-files`: `COPY --link data/platform-families.json
  /CVEScannerV2/data/platform-families.json`.
## Verificación
`docker build --target nodb -t cvescanner-nodb-test -f docker/Dockerfile .`
(contexto = raíz del repo) y luego, contra 192.168.251.128 (MS2, laboratorio
del usuario, accesible):
`docker run --rm --network host -v <dir con cve.db>:/CVEScannerV2/data cvescanner-nodb-test -p 445 -d1 192.168.251.128 2>&1 | grep -i "smb probe"`
NO debe aparecer `smb probe failed: ... OpenSSL`. El cve.db de prueba está
en `/tmp/claude-1000/-home-schica-csic-safehorizon-projects-CVEScannerV2/65d263b6-f370-4fda-85d0-7cbfccaba79f/scratchpad/run/data`
(copia ese directorio a otro temporal antes de montarlo para no ensuciarlo).
Devuelve STATUS (CHECKS: docker_build=PASS, smb_probe=PASS|FAIL).
