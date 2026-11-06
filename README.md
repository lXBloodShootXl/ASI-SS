# sshook - .asi sueltos para Split/Second (Revised)

Reescritos a mano a partir del desensamblado/DWARF del mod original. **Sin probar en el juego.**

| .asi | Que hace |
|---|---|
| `sshook_borderless.asi` | Ventana sin bordes a resolucion de escritorio; modo ventana con marco si el juego pide menos resolucion; resolucion por defecto = escritorio. Variable opcional `SSHOOK_WINDOW=1600x900` para forzar el tamano de "pantalla". |
| `sshook_matfix.asi` | Parche de contencion del use-after-free de materiales: hace que `0x510860` (liberador de grupos de materiales, 11 llamadores) retorne de inmediato (`C2 04 00`). Solo parchea si los bytes coinciden (`8B 81 20 08 00 00`). Log: `sshook_matfix.log`. |
| `sshook_crashfixes.asi` | ExitProcess->TerminateProcess, watchdog de salida, parche `0x7BA19E` (jcc->jmp). |

## Compilar (sin instalar nada)
1. Crea un repo en GitHub y sube esta carpeta (con `.github/`).
2. Pestana **Actions** -> workflow **build-asi** (se lanza solo al hacer push) -> descarga el artefacto `sshook-asi`.

(Local con MinGW 32 bits: `cmake -S . -B build -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc -DCMAKE_CXX_COMPILER=i686-w64-mingw32-g++ && cmake --build build`)

## Instalar
- `dinput8.dll` = Ultimate ASI Loader (el que ya tienes) junto al .exe del juego.
- Los `.asi` en la carpeta del juego o en `scripts\`.
- **No** uses a la vez el dinput8.dll original del mod: duplicaria los hooks.

## Si algo falla
Prueba cada .asi por separado y dime cual. Los hooks al codigo del .exe (resolucion por defecto, 0x7BA19E) solo se
aplican si los bytes coinciden con los del mod original (version Steam del juego).

## v2 (diagnostico)
- Cada .asi escribe un log junto a si mismo (`sshook_borderless.log`, `sshook_crashfixes.log`) con cada paso y las
  primeras excepciones (direccion y modulo). Si el juego no arranca, envia ese log.
- El arranque ya no ocurre en DllMain: se hace en un hilo cuando el .exe esta descifrado.
- crashfixes solo parchea con el .exe descifrado, y el watchdog solo se arma si la ventana llego a mostrarse.

## v3
- Los hooks de ventana y D3D se instalan en cuanto carga el .asi (la v2 esperaba 20 s y el juego ya habia creado la ventana).
- Los logs vuelcan datos del .exe (base, timestamp, bytes en las direcciones usadas) para comprobar la version.
