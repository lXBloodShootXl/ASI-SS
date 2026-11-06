// sshook_matfix.asi - Split/Second: use-after-free de materiales
//
// 0x510860 (thiscall, 1 arg, ret 4; 11 llamadores) busca un grupo de materiales en la lista del gestor y lo borra entero (0x515DD0 -> 0x516410: Release de
// los shaders [+0x114]/[+0x118] y free del material) sin contar referencias. Los objetos de render que aun lo usan
// ([obj+0x60], leido en 0x50811A -> 0x512590) acaban leyendo materiales/shaders liberados.
// Parche de contencion: 0x510860 retorna de inmediato (C2 04 00) y nunca libera grupos de materiales.
// Coste: memoria de materiales sin liberar (crece entre carreras).
#include "../common/sshook_common.h"

using namespace sshook;

namespace {

// v7: se parchea la entrada de 0x510860 (hay 11 llamadores, no solo 0x467856): mov eax,[ecx+0x820] -> ret 4
constexpr uintptr_t kPatchAddr = 0x00510860;
const BYTE kOrig[6] = {0x8B, 0x81, 0x20, 0x08, 0x00, 0x00};
const BYTE kRet4[3] = {0xC2, 0x04, 0x00};

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
    // v7: ya no se usa WaitForDecryptedExe (su patron de 0x558910 no existe en este exe y bloqueaba el parche).
    // Se sondean directamente los bytes de 0x510860.
    DumpBytes("antes   ", kPatchAddr, 6);
    DWORD start = GetTickCount();
    bool applied = false;
    // Vigila ~5 min: si la proteccion restaura los bytes originales, se vuelve a parchear.
    while (GetTickCount() - start < 300000) {
        if (BytesMatch(kPatchAddr, kOrig, sizeof(kOrig))) {
            bool ok = PatchBytes(kPatchAddr, kRet4, sizeof(kRet4));
            Log("parche 0x%08X: 0x510860 -> ret 4 (%s)", static_cast<unsigned>(kPatchAddr), ok ? "ok" : "fallo");
            DumpBytes("despues ", kPatchAddr, 6);
            applied = applied || ok;
        } else if (BytesMatch(kPatchAddr, kRet4, sizeof(kRet4))) {
            if (!applied) {
                Log("bytes ya en ret 4 (ya parcheado)");
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
