# TASK-11 — verify_nvd.py: soportar el producto `unrealircd`

`verify_nvd.py` (copia de medición para MS2 en .131) lanza `KeyError:
'unrealircd'` porque el escaneo `probes=all` detecta ahora UnrealIRCd
3.2.8.1 (sonda `irc`).

## Archivo (único permitido)
1. `results/f9v/verify_nvd.py` (copia de medición; NO tocar
   `results/compare/verify_nvd.py`)

## Cambio
Añadir al diccionario `T` la entrada
`'unrealircd': ('unrealircd', 'unrealircd', [('3.2.8.1', '*')],
'UnrealIRCd 3.2.8.1 (real en MS2; backdoor CVE-2010-2075)')`.
Si tras eso aparece otra `KeyError` por un producto que SÍ existe en
`old.json`/`new.json` y no en `T`, NO la inventes: responde BLOCKED con el
nombre del producto y la versión real que figura en el JSON.

## Verificación (excepción documentada al gate de AGENTS.md §5)
Es un script de medición desechable que no cumple ese gate de origen;
basta:
```bash
cd results/f9v && python3 -m py_compile verify_nvd.py && python3 verify_nvd.py
```
(ejecuta en el directorio `results/f9v`, con `old.json`/`new.json` ya
presentes). Debe terminar sin excepción. Devolver SOLO el bloque de estado
(`TASK: TASK-11`, `CHECKS: py_compile=PASS, run=PASS|FAIL`) y en NOTES las
últimas 15 líneas de salida del script.
