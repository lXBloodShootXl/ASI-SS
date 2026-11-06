// sshook_matfix.asi - Split/Second: use-after-free de materiales
//
// 0x467855: push eax / call 0x510860  (en el destructor 0x4677E0)
// 0x510860 busca un grupo de materiales en la lista del gestor y lo borra entero (0x515DD0 -> 0x516410: Release de
// los shaders [+0x114]/[+0x118] y free del material) sin contar referencias. Los objetos de render que aun lo usan
// ([obj+0x60], leido en 0x50811A -> 0x512590) acaban leyendo materiales/shaders liberados.
// Parche de contencion: se anulan esas dos instrucciones (6 NOPs), asi ese grupo no se libera por esta ruta.
// Coste: algo de memoria no liberada. No cambia el resto de usos de 0x510860.
#include "../common/sshook_common.h"

using namespace sshook;

namespace {

constexpr uintptr_t kPatchAddr = 0x00467855;
const BYTE kOrig[6] = {0x50, 0xE8, 0x05, 0x90, 0x0A, 0x00};  // push eax / call 0x510860
const BYTE kNops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

bool PatchBytes(uintptr_t addr, const BYTE* src, size_t n) {
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(addr), n, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(reinterpret_cast<void*>(addr), src, n);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(addr), n);
    DWORD tmp = 0;
    VirtualProtect(reinterpret_cast<void*>(addr), n, old, &tmp);
    return true;
}

DWORD WINAPI PatchThread(LPVOID) {
    LogExeInfo();
    // El .exe esta protegido (.secu) y se descifra al arrancar: no tocar antes.
    bool dec = WaitForDecryptedExe(120000);
    Log("exe descifrado: %s", dec ? "si" : "no (timeout)");
    if (!dec) return 0;

    DumpBytes("antes   ", kPatchAddr, 6);
    DWORD start = GetTickCount();
    bool applied = false;
    // Vigila ~5 min: si la proteccion restaura los bytes originales, se vuelve a parchear.
    while (GetTickCount() - start < 300000) {
        if (BytesMatch(kPatchAddr, kOrig, sizeof(kOrig))) {
            bool ok = PatchBytes(kPatchAddr, kNops, sizeof(kNops));
            Log("parche 0x%08X: call 0x510860 anulado (%s)", static_cast<unsigned>(kPatchAddr), ok ? "ok" : "fallo");
            DumpBytes("despues ", kPatchAddr, 6);
            applied = applied || ok;
        } else if (BytesMatch(kPatchAddr, kNops, sizeof(kNops))) {
            if (!applied) {
                Log("bytes ya en NOP (ya parcheado)");
                applied = true;
            }
        } else if (GetTickCount() - start > 20000 && !applied) {
            DumpBytes("no coincide", kPatchAddr, 6);
            Log("los bytes no coinciden con el exe esperado; no se parchea");
            return 0;
        }
        Sleep(applied ? 1000 : 50);
    }
    return 0;
}

}  // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        LogInit(inst);
        Log("sshook_matfix attach");
        HANDLE t = CreateThread(nullptr, 0, PatchThread, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
