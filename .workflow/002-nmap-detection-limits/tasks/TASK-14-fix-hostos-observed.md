# TASK-14 — Corregir host.os y umbral de observed_range (hallazgos MS2)
Archivos permitidos: `cvescannerv2.nse`, `tests/lua/test_versions.lua`,
`tests/lua/test_scoping.lua`. Gate: `sh tests/run.sh` (≥160, 0 skipped).

## Hallazgos (escaneo real de Metasploitable 2 con -O)
A. `os_context` queda `{}` en ruby/vsftpd/bind/tomcat/postgresql/samba
   aunque nmap -O da `Running: Linux 2.6.X`, `OS CPE: cpe:/o:linux:linux_kernel:2.6`.
   Causa probable: en `first_host_os_family` se itera `first.osclass`, pero
   la API NSE expone `host.os[i].classes` (cada clase con `vendor`,
   `osfamily`, `osgen`, `type`, `cpe`={strings}); además `host.os[i].cpe`
   puede no existir. Iterar `classes` (mantener `osclass` por compat),
   y aceptar cpe como tabla de strings.
   Además `ostype='Unix'` NO es una familia concreta: no debe producir un
   family que choque con 'linux' (tratar 'unix' como desconocido para
   `os_context` de modo que se pase a host.os).
B. `observed_range` marca low rangos estrechos como `8.3.0 - 8.3.7`
   (PostgreSQL). Debe aplicarse solo si los extremos `from`/`to`
   difieren en sus dos primeros componentes numéricos (major.minor);
   `3.X - 4.X` ⇒ sí; `8.3.0 - 8.3.7` ⇒ no (el motivo lo darán
   range_contains/range_overlap). Ajusta la línea
   `if info.range then add_reason(vulns, 'observed_range')`.
C. Etiqueta `platform_mismatch:<fam>`: usar la familia/vendor REQUERIDO
   por la config (no la del contexto) — si ya lo hace, déjalo y anota.
## Tests
Casos: host.os stub con `classes={{osfamily='Linux',cpe={'cpe:/o:linux:linux_kernel:2.6'}}}`
⇒ family linux source host_os; ostype 'Unix' sin host.os ⇒ `{}`;
rango `8.3.0 - 8.3.7` ⇒ sin observed_range; `3.X - 4.X` ⇒ con él.
Devuelve STATUS.
