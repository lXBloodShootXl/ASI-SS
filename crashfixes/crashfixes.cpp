// sshook_crashfixes.asi - Split/Second: Revised
//  * ExitProcess -> TerminateProcess (evita cuelgues/crashes al cerrar el juego)
//  * Watchdog: si la ventana del juego desaparece, termina el proceso 1 s despues
//  * MemcpyGuard: si memcpy del .exe (0x7577C0) lee mas alla de un bloque de memoria (AV de lectura), se
//    aborta esa copia y se retorna al llamador en vez de crashear. Registra el llamador para poder arreglarlo.
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

// ---- Guard de memcpy (CRT de MSVC del .exe, 0x007577C0..0x00757B10; marco: push ebp / push edi / push esi) ----
constexpr uintptr_t kMemcpyLo = 0x007577C0, kMemcpyHi = 0x00757B10;
volatile LONG g_memcpyFaults = 0;

LONG CALLBACK MemcpyGuard(PEXCEPTION_POINTERS ep) {
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    CONTEXT* c = ep->ContextRecord;
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    if (c->Eip < kMemcpyLo || c->Eip >= kMemcpyHi) return EXCEPTION_CONTINUE_SEARCH;
    if (er->NumberParameters < 2 || er->ExceptionInformation[0] != 0) return EXCEPTION_CONTINUE_SEARCH;  // solo lecturas

    uintptr_t ebp = c->Ebp;
    if (ebp < c->Esp || ebp - c->Esp > 0x100 || !CanRead(ebp - 8, 0x14)) return EXCEPTION_CONTINUE_SEARCH;
    const DWORD* f = reinterpret_cast<const DWORD*>(ebp);
    DWORD savedEbp = f[0], ret = f[1], dst = f[2], src = f[3], n = f[4];
    if (ret < 0x00401000 || ret >= 0x00B9B000) return EXCEPTION_CONTINUE_SEARCH;  // el retorno debe estar en .text

    LONG k = InterlockedIncrement(&g_memcpyFaults);
    if (k <= 40)
        Log("memcpy guard #%ld: llamador=%08lX dst=%08lX src=%08lX n=%lu (fallo en %08lX)", k, ret, dst, src, n,
            static_cast<unsigned long>(er->ExceptionInformation[1]));

    // Simula el "ret" de memcpy (cdecl): restaura registros guardados, eax=dst, limpia DF.
    c->Edi = f[-1];
    c->Esi = f[-2];
    c->Eax = dst;
    c->Ebp = savedEbp;
    c->Eip = ret;
    c->Esp = static_cast<DWORD>(ebp + 8);
    c->EFlags &= ~0x400u;
    return EXCEPTION_CONTINUE_EXECUTION;
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
    AddVectoredExceptionHandler(1, MemcpyGuard);
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
