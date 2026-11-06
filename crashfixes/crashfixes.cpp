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
    Log("CreateDevice ok, hwnd=%p", hwnd);
}

// El watchdog solo se "arma" cuando la ventana del dispositivo ha sido visible alguna vez (asi una ventana
// temporal/oculta no mata el proceso) y la ventana desaparece despues.
DWORD WINAPI ExitWatchdogProc(LPVOID) {
    HWND hwnd;
    while (!(hwnd = g_gameHwnd)) Sleep(250);
    while (IsWindow(hwnd) && !IsWindowVisible(hwnd)) Sleep(250);
    if (!IsWindow(hwnd)) {
        Log("watchdog: la ventana desaparecio sin llegar a mostrarse; no se arma");
        return 0;
    }
    Log("watchdog armado (hwnd=%p)", hwnd);
    while (IsWindow(hwnd)) Sleep(250);
    Log("watchdog: ventana cerrada, terminando proceso");
    Sleep(1000);
    TerminateProcess(GetCurrentProcess(), 0);
    return 0;
}

// El .exe esta protegido y se descifra durante el arranque: solo se parchea si el byte actual es un
// salto condicional corto (0x70..0x7F), y se sigue comprobando por si el descifrado lo sobrescribe.
DWORD WINAPI PatchThread(LPVOID) {
    // NUNCA tocar el .exe mientras siga cifrado: modificar el texto cifrado corrompe el descifrado.
    if (!WaitForDecryptedExe(60000)) {
        Log("exe no descifrado tras 60 s: no se aplica el parche");
        return 0;
    }
    Log("exe descifrado");
    bool logged = false;
    for (int i = 0; i < 240; ++i) {  // ~1 min comprobando por si se restaura
        if (CanRead(kCrashFixAddr, 1)) {
            BYTE b = *reinterpret_cast<const BYTE*>(kCrashFixAddr);
            if (b >= 0x70 && b <= 0x7F) {
                bool ok = PatchByte(kCrashFixAddr, 0xEB);
                Log("parche 0x%08X: %02X -> EB (%s)", static_cast<unsigned>(kCrashFixAddr), b, ok ? "ok" : "fallo");
            } else if (!logged) {
                Log("byte en 0x%08X = %02X (ya parcheado o no es un jcc corto)", static_cast<unsigned>(kCrashFixAddr), b);
                logged = true;
            }
        }
        Sleep(250);
    }
    return 0;
}

void Init() {
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK) {
        Log("MH_Initialize fallo: %s", MH_StatusToString(st));
        return;
    }

    void* pExit = ModuleProc(L"kernel32.dll", "ExitProcess");
    if (pExit) InstallHook(pExit, HookExitProcess, &g_realExitProcess);

    D3DCallbacks cb = {};
    cb.deviceCreated = OnDeviceCreated;
    InstallD3D9Hooks(cb);

    HANDLE t = CreateThread(nullptr, 0, ExitWatchdogProc, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
    t = CreateThread(nullptr, 0, PatchThread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
    Log("init terminado");
}

// Fuera de DllMain (loader lock) y tras descifrarse el .exe.
DWORD WINAPI InitThread(LPVOID) {
    bool ok = WaitForDecryptedExe(20000);
    Log("exe descifrado: %s", ok ? "si" : "no (timeout, se continua igualmente)");
    Init();
    return 0;
}

}  // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        LogInit(inst);
        Log("sshook_crashfixes attach");
        HANDLE t = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
