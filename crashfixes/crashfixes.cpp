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
    g_gameHwnd = hwnd;  // siempre la ultima: el juego crea primero un dispositivo temporal y luego el real
    Log("CreateDevice ok, hwnd=%p", hwnd);
}

// El watchdog solo se "arma" para una ventana de dispositivo que haya llegado a mostrarse. Si esa ventana
// desaparece y en 1.5 s no aparece otra (p.ej. un cambio de modo), termina el proceso.
DWORD WINAPI ExitWatchdogProc(LPVOID) {
    HWND armed = nullptr;
    for (;;) {
        HWND cur = g_gameHwnd;
        if (cur != armed) {
            armed = nullptr;
            if (cur && IsWindow(cur) && IsWindowVisible(cur)) {
                armed = cur;
                Log("watchdog armado (hwnd=%p)", cur);
            }
        } else if (armed && !IsWindow(armed)) {
            Sleep(1500);
            if (g_gameHwnd == armed) {
                Log("watchdog: ventana cerrada, terminando proceso");
                TerminateProcess(GetCurrentProcess(), 0);
                return 0;
            }
            armed = nullptr;
            continue;
        }
        Sleep(250);
    }
}

// El .exe esta protegido y se descifra al arrancar: no se toca hasta que la ventana del juego existe
// (o pasan 10 s). Solo se parchea si el byte actual es un salto condicional corto (0x70..0x7F).
DWORD WINAPI PatchThread(LPVOID) {
    DWORD start = GetTickCount();
    while (!g_gameHwnd && GetTickCount() - start < 10000) Sleep(100);
    Log("parche: iniciando comprobacion (hwnd=%p)", static_cast<void*>(g_gameHwnd));
    DumpBytes("crashfix ", kCrashFixAddr - 4, 12);
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

// Fuera de DllMain (loader lock); los hooks se instalan ya.
DWORD WINAPI InitThread(LPVOID) {
    LogExeInfo();
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
