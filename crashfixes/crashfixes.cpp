// sshook_crashfixes.asi - Split/Second: Revised
//  * ExitProcess -> TerminateProcess (evita cuelgues/crashes al cerrar el juego)
//  * Watchdog: si la ventana del juego desaparece, termina el proceso 1 s despues
//  * Parche del .exe: salto condicional -> incondicional en 0x7BA19E (fix de crash del mod original)
// Reescrito a partir de crash_fixes.cpp del mod original.
#include "../common/sshook_common.h"

using namespace sshook;

namespace {

constexpr uintptr_t kCrashFixAddr = 0x007BA19E;  // original: PatchByte(0x7BA19E, 0xEB)

typedef VOID(WINAPI* ExitProcess_t)(UINT);
ExitProcess_t g_realExitProcess = nullptr;
volatile HWND g_gameHwnd = nullptr;

VOID WINAPI HookExitProcess(UINT code) {
    TerminateProcess(GetCurrentProcess(), code);
}

void OnDeviceCreated(HWND hwnd) {
    if (!g_gameHwnd) g_gameHwnd = hwnd;
}

DWORD WINAPI ExitWatchdogProc(LPVOID) {
    HWND hwnd;
    while (!(hwnd = g_gameHwnd)) Sleep(250);
    while (IsWindow(hwnd)) Sleep(250);
    Sleep(1000);
    TerminateProcess(GetCurrentProcess(), 0);
    return 0;
}

// El .exe esta protegido y se descifra durante el arranque: solo se parchea si el byte actual es un
// salto condicional corto (0x70..0x7F), y se sigue comprobando por si el descifrado lo sobrescribe.
DWORD WINAPI PatchThread(LPVOID) {
    for (int i = 0; i < 720; ++i) {  // ~3 min
        if (CanRead(kCrashFixAddr, 1)) {
            BYTE b = *reinterpret_cast<const BYTE*>(kCrashFixAddr);
            if (b >= 0x70 && b <= 0x7F) PatchByte(kCrashFixAddr, 0xEB);
        }
        Sleep(250);
    }
    return 0;
}

void Init() {
    if (MH_Initialize() != MH_OK) return;

    void* pExit = ModuleProc(L"kernel32.dll", "ExitProcess");
    if (pExit) InstallHook(pExit, HookExitProcess, &g_realExitProcess);

    D3DCallbacks cb = {};
    cb.deviceCreated = OnDeviceCreated;
    InstallD3D9Hooks(cb);

    HANDLE t = CreateThread(nullptr, 0, ExitWatchdogProc, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
    t = CreateThread(nullptr, 0, PatchThread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}

}  // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        Init();
    }
    return TRUE;
}
