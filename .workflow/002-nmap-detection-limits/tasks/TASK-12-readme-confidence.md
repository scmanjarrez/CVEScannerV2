# TASK-12 — README: leyenda de confianza y limitaciones (F9, parte docs)
Plan: 002-nmap-detection-limits (PLAN.md §1, §2.C). Archivo permitido:
`README.md` (único; solo Markdown, sin gate de linters).

## Contenido (en el idioma y estilo del README actual)
1. Args nuevos en su tabla de argumentos: `cvescannerv2.smb` (defecto 1;
   sonda SMB para versión exacta de Samba, falla en silencio),
   `cvescannerv2.minconf` (low|medium|high, defecto low; filtra tabla y
   log, no el JSON).
2. Sección "Niveles de confianza": tabla high/medium/low con significado y
   motivos (`exact_version`, `range_contains`, `range_overlap`,
   `series_expanded`, `update_unknown`, `requires_platform`,
   `requires_component`, `nvd_unbounded`, `observed_range`,
   `platform_mismatch:<familia>`); regla "nivel = el más bajo".
3. Descripción de la nueva columna `Conf`, orden y cabecera por servicio
   (`version_source`, aviso `distro_backport`); campos añadidos al JSON
   (`confidence`, `reasons`, `version_source`, `os_context`, `warnings`,
   `summary`); nota de cambio visual de la tabla.
4. Sección "Limitaciones de la detección con Nmap" (resumen de L1–L10 y
   las no resolubles: explotabilidad, configuración, módulos activos,
   AND sobre aplicaciones no detectadas) y nota de que las condiciones de
   plataforma requieren una BD generada con la versión nueva de
   db-manager (BD antigua: se omite con aviso).
No inventes métricas de medición. Devuelve STATUS (CHECKS: n/a).
