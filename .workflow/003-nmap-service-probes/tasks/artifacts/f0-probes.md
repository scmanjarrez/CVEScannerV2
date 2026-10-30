# F0 — validación de campo (MS2 192.168.251.128, Nmap 7.993)

Fecha: 2026-10-30. Solo MS2 (MS3 no encendida).

| Script | Resultado MS2 | Veredicto |
|---|---|---|
| irc-info | `Unreal3.2.8.1.` (351) | **Mantener** (F2). `-sV`: versión `*` |
| ftp-syst | `vsFTPd 2.3.4`; `-sV` ya da `vsftpd 2.3.4` | Control: no cambia nada ⇒ **descartar F3** (la necesidad §3.0 ya impide correr) |
| ajp-headers | solo `Content-Type`, sin `Server`/Tomcat | Sin dato en MS2 ⇒ F6 pendiente de MS3 |
| smb-os-discovery | `Unix (Samba 3.0.20-Debian)` | Confirma sonda SMB; SO = `unix` |

## Hallazgos operativos
- UnrealIRCd aplica throttle de reconexión: tras `-sV` la conexión de la
  sonda recibe `ERROR ... Throttled: Reconnecting too fast`. Se levanta en
  < 10 s ⇒ TASK-04 (un reintento tras 10 s).
- Los argumentos con prefijo `cvescannerv2.x=` NO se leen (ya pasaba con
  `smb=0`); funcionan sin prefijo (`probes=none`). Preexistente; revisar
  README.

# F0 — MS3 (192.168.251.129, Ubuntu 14.04, NO Windows)

Servicios: ssh 6.6.1p1, Apache 2.4.7, Samba 4.3.11 (445), CUPS 1.7,
MySQL, `irc?` (no UnrealIRCd), Jetty 8.1.7. Sin 3389, sin 8009, sin NTLM.

| Candidata | Veredicto |
|---|---|
| rdp-ntlm-info / http-ntlm-info (F5) | **Descartada**: no hay objetivo (sin RDP/NTLM) |
| ajp (F6) | **Descartada**: sin puerto 8009 |
| smb-os-discovery | Samba anuncia `OS: Windows 6.1 (Samba 4.3.11-Ubuntu)` ⇒ guardia `lanmanager^Samba` (TASK-08) |
| ntp/snmp (F7) | Sin objetivo (no se escaneó UDP) ⇒ descartada |

# F0/F9 — MS3 Windows (192.168.251.130, 2008 R2 SP1)

| Candidata | Resultado |
|---|---|
| rdp-ntlm-info / http-ntlm-info / ms-sql-ntlm-info | Sin salida ⇒ F5 sigue descartada |
| ajp-headers (8009) | Solo `Content-Type`, sin versión ⇒ F6 descartada |
| smb-os-discovery | `Windows Server 2008 R2 Standard 7601 SP1` (sin Samba) ⇒ `smb_os` daría `windows` |
| Elasticsearch 9200 | `-sV` ya lo identifica (1.1.1) |

Medición `probes=none` vs `all` (sin 3389): 18 s vs 17 s; CVEs, confianza
y `os_context` idénticos. Motivo: ningún CVE de estos servicios tiene
`requires_platform` ⇒ por diseño (§3.0) la sonda O no se dispara.
Las sondas V no aplican (sin Samba/UnrealIRCd). El objetivo
"CVEs solo-Linux medium → low" no se pudo ejercitar: no hay CVEs
condicionales en los servicios de MS3-Windows de la BD actual.

## Problema preexistente (fuera de plan 003)
El puerto 3389 (RDP con TLS) entra por `shortport.ssl` en el motor HTTP y
el barrido de rutas legacy no termina (> 40 min, "Error creating socket"
en cada ruta). Reproducido con `HEAD:cvescannerv2.nse`.
