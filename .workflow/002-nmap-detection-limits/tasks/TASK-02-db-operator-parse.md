# TASK-02 — db-manager: modelar `operator` y extraer condiciones (F4a)
Plan: 002-nmap-detection-limits (PLAN.md §2.B, F4, riesgo F4)
Archivos permitidos (<=2): `db-manager/src/db_manager/domain/models.py`,
`db-manager/src/db_manager/domain/cpe.py`. (Tests nuevos: ver abajo; son
un 3.º fichero explícitamente permitido: `db-manager/tests/test_conditions.py`.)

## Cambios
1. `models.py`:
   - `NvdConfigurationNode`: añadir `operator: str = Field(default="OR", ...)`.
   - `NvdConfiguration`: añadir `operator: str | None = Field(default=None, ...)`
     (datos antiguos sin operator ⇒ tratar como OR).
   - Nuevo `ImmutableModel` `ConditionRecord` con `cve_id: str`,
     `identity: CpeIdentity` (producto vulnerable), `config_idx: int`,
     `platform: CpeIdentity` (CPE `vulnerable=false`). Docstring
     `Attributes:` y `Field(description=...)` según AGENTS.md.
   - Añadir `ConditionRecord` a la unión `DatabaseCommand`.
2. `cpe.py`: nueva función pública
   `parse_conditions(config: NvdConfiguration) -> list[ParsedCondition]`
   con `ParsedCondition = tuple[CpeIdentity, CpeIdentity]`
   (producto vulnerable, plataforma). Semántica:
   - Si `config.operator == "AND"` (o algún nodo raíz/hijo con
     `operator == "AND"`): por cada CPE `vulnerable=true` de la config
     (usar `parse_node` sobre los nodos) × cada CPE `vulnerable=false`
     (no negadas) de la misma config ⇒ un par.
   - Si la config es OR pura (sin AND) ⇒ lista vacía.
   - `parse_node` NO cambia de comportamiento (no regresión).
   - Nodo `negate` ⇒ se ignora.
   El índice de configuración lo asigna el llamador (enumerate de
   `cve.configurations`), no esta función.
3. Tests `db-manager/tests/test_conditions.py` (unittest): AND con
   `a:php:php` + `o:microsoft:windows` ⇒ 1 par; OR pura ⇒ []; AND anidado
   en `children` ⇒ detectado; `operator` ausente ⇒ []; `parse_node`
   sigue devolviendo solo `vulnerable=true`.

## Verificación
Gate AGENTS.md §5 sobre los 3 ficheros .py y además
`cd db-manager && python -m unittest discover -s tests -p "test_conditions.py"`
y la suite existente `python -m unittest discover -s tests` (sin regresión).
Devuelve el bloque STATUS.
