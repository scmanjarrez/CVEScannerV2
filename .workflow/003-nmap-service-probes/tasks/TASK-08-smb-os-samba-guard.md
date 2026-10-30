# TASK-08 — F4c: `smb_os` no debe tomar Samba por Windows

Evidencia (MS3 Ubuntu 14.04 real, `smb-os-discovery`):
`OS: Windows 6.1 (Samba 4.3.11-Ubuntu)`. Samba anuncia `Windows 6.1` en el
campo `os` y su versión en `lanmanager`. La sonda `smb_os` (TASK-06) daría
familia `windows` en un Linux ⇒ falsos `platform_mismatch`.

## Archivos (únicos permitidos)
1. `cvescannerv2.nse`
2. `tests/lua/test_catalog.lua` (suite `os probe`)

No tocar `load_luasql()`.

## Cambio
En la `run` de la sonda `smb_os`: devolver `nil` si
`info.lanmanager` es string y empieza por `Samba` (insensible a
mayúsculas), antes de mirar `info.os`. Comentario breve con el motivo.
Windows real (lanmanager `Windows Server 2008 R2 Standard 6.1`, o
ausente) sigue dando `{ family = 'windows' }`.

## Tests
1. `os='Windows 6.1'`, `lanmanager='Samba 4.3.11-Ubuntu'` ⇒ `nil`.
2. `os='Windows Server 2008 R2 Standard 7601 Service Pack 1'`,
   `lanmanager='Windows Server 2008 R2 Standard 6.1'` ⇒ `windows`.
3. `os='Windows Server 2008 R2 ...'` sin `lanmanager` ⇒ `windows`.
4. `os='Unix'`, `lanmanager='Samba 3.0.20-Debian'` ⇒ `nil` (ya existente;
   no duplicar si cubre lo mismo).

## Verificación
```bash
lua5.4 tests/lua/run.lua && lua5.4 tests/test_scanner.lua
```
204 previos + nuevos en verde. No ejecutar nmap. Devolver SOLO el bloque
de estado (`TASK: TASK-08`, `CHECKS: lua_tests=PASS`).
