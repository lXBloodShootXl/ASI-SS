// Utilidades compartidas por los .asi (reescritas a partir de core/memory.cpp y d3d_hooks.cpp del mod original).
#pragma once
#include <windows.h>
#include <d3d9.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include "MinHook.h"

namespace sshook {

inline bool CanRead(uintptr_t addr, size_t n);

// ---------------------------------------------------------------- log (junto al .asi: <nombre>.log)
namespace log_detail {
inline char g_path[MAX_PATH] = {};
inline CRITICAL_SECTION g_cs;
inline bool g_ready = false;
inline volatile LONG g_excCount = 0;
}  // namespace log_detail

inline void Log(const char* fmt, ...) {
    using namespace log_detail;
    if (!g_ready) return;
    char buf[640];
    int n = snprintf(buf, sizeof(buf), "[%8lu] ", GetTickCount());
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(buf + n, sizeof(buf) - n - 2, fmt, ap);
    va_end(ap);
    buf[n++] = '\n';
    EnterCriticalSection(&g_cs);
    HANDLE f = CreateFileA(g_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(f, buf, static_cast<DWORD>(n), &w, nullptr);
        CloseHandle(f);
    }
    LeaveCriticalSection(&g_cs);
}

// Registra las primeras excepciones (AV, etc.) con direccion y modulo: sirve para ver quien rompe el arranque.
inline LONG CALLBACK ExceptionLogger(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == 0xC0000005 || code == 0xC000001D || code == 0xC0000096 || code == 0xC00000FD || code == 0xC0000409 ||
        code == 0xC0000094 || code == 0xC000008C) {
        if (InterlockedIncrement(&log_detail::g_excCount) <= 40) {
            void* addr = ep->ExceptionRecord->ExceptionAddress;
            char mod[MAX_PATH] = "?";
            HMODULE m = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   static_cast<LPCSTR>(addr), &m) && m)
                GetModuleFileNameA(m, mod, MAX_PATH);
            Log("EXCEPCION %08lX en %p (%s +0x%lX) info0=%lu info1=%p", code, addr, mod,
                static_cast<unsigned long>(reinterpret_cast<uintptr_t>(addr) - reinterpret_cast<uintptr_t>(m)),
                ep->ExceptionRecord->NumberParameters > 0 ? ep->ExceptionRecord->ExceptionInformation[0] : 0UL,
                ep->ExceptionRecord->NumberParameters > 1 ? reinterpret_cast<void*>(ep->ExceptionRecord->ExceptionInformation[1]) : nullptr);
            // Registros y pila: la direccion de retorno del llamador esta en [esp]/[ebp+4].
            const CONTEXT* c = ep->ContextRecord;
            Log("  regs eax=%08lX ebx=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX ebp=%08lX esp=%08lX",
                c->Eax, c->Ebx, c->Ecx, c->Edx, c->Esi, c->Edi, c->Ebp, c->Esp);
            const DWORD* sp = reinterpret_cast<const DWORD*>(c->Esp);
            if (CanRead(c->Esp, 16 * 4)) {
                Log("  stack %08lX %08lX %08lX %08lX %08lX %08lX %08lX %08lX", sp[0], sp[1], sp[2], sp[3], sp[4], sp[5], sp[6], sp[7]);
                Log("        %08lX %08lX %08lX %08lX %08lX %08lX %08lX %08lX", sp[8], sp[9], sp[10], sp[11], sp[12], sp[13], sp[14], sp[15]);
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

inline void LogInit(HMODULE self) {
    using namespace log_detail;
    InitializeCriticalSection(&g_cs);
    DWORD n = GetModuleFileNameA(self, g_path, MAX_PATH);
    if (n > 4 && n < MAX_PATH) {
        strcpy(g_path + n - 4, ".log");  // .asi -> .log
        HANDLE f = CreateFileA(g_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            CloseHandle(f);
            g_ready = true;
        }
    }
    AddVectoredExceptionHandler(1, ExceptionLogger);
}

// ---------------------------------------------------------------- memoria
inline bool CanRead(uintptr_t addr, size_t n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    uintptr_t end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return addr + n <= end;
}

inline bool BytesMatch(uintptr_t addr, const void* pattern, size_t n) {
    return CanRead(addr, n) && memcmp(reinterpret_cast<const void*>(addr), pattern, n) == 0;
}

inline bool PatchByte(uintptr_t addr, BYTE value) {
    DWORD old = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(addr), 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    *reinterpret_cast<volatile BYTE*>(addr) = value;
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(addr), 1);
    DWORD tmp = 0;
    VirtualProtect(reinterpret_cast<void*>(addr), 1, old, &tmp);
    return true;
}

// ---------------------------------------------------------------- hooks (MinHook)
template <class F>
inline bool CreateHook(void* target, F detour, F* original) {
    return MH_CreateHook(target, reinterpret_cast<LPVOID>(detour), reinterpret_cast<LPVOID*>(original)) == MH_OK;
}

// Crea + habilita al momento (equivale a InstallHookRaw del original).
template <class F>
inline bool InstallHook(void* target, F detour, F* original) {
    MH_STATUS st = MH_CreateHook(target, reinterpret_cast<LPVOID>(detour), reinterpret_cast<LPVOID*>(original));
    if (st != MH_OK) {
        Log("MH_CreateHook(%p) fallo: %s", target, MH_StatusToString(st));
        return false;
    }
    st = MH_EnableHook(target);
    if (st != MH_OK) {
        Log("MH_EnableHook(%p) fallo: %s", target, MH_StatusToString(st));
        MH_RemoveHook(target);
        *original = nullptr;
        return false;
    }
    Log("hook ok en %p", target);
    return true;
}

inline void DumpBytes(const char* label, uintptr_t addr, size_t n) {
    char hex[128] = {};
    if (!CanRead(addr, n)) {
        Log("%s @0x%08X: no legible", label, static_cast<unsigned>(addr));
        return;
    }
    for (size_t i = 0; i < n && i < 32; ++i) snprintf(hex + i * 3, 4, "%02X ", reinterpret_cast<const BYTE*>(addr)[i]);
    Log("%s @0x%08X: %s", label, static_cast<unsigned>(addr), hex);
}

// Datos del .exe del juego, para saber con que version estamos tratando.
inline void LogExeInfo() {
    char path[MAX_PATH] = "?";
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    Log("exe: %s", path);
    if (!CanRead(base, 0x100)) return;
    uintptr_t pe = base + *reinterpret_cast<const DWORD*>(base + 0x3C);
    if (!CanRead(pe, 0x60)) return;
    Log("exe base=0x%08X preferredBase=0x%08X timestamp=0x%08X sizeOfImage=0x%08X entryRVA=0x%08X",
        static_cast<unsigned>(base), *reinterpret_cast<const DWORD*>(pe + 0x34), *reinterpret_cast<const DWORD*>(pe + 8),
        *reinterpret_cast<const DWORD*>(pe + 0x50), *reinterpret_cast<const DWORD*>(pe + 0x28));
}

// Espera a que el .exe (protegido) este descifrado: patron del prologue en 0x558910 (el mismo que usa el mod original).
inline bool WaitForDecryptedExe(DWORD timeoutMs) {
    static const BYTE pat[7] = {0x83, 0xEC, 0x10, 0x53, 0x55, 0x56, 0x57};
    DWORD start = GetTickCount();
    for (;;) {
        if (BytesMatch(0x00558910, pat, sizeof(pat))) return true;
        if (GetTickCount() - start > timeoutMs) return false;
        Sleep(1);
    }
}

template <class F>
inline bool InstallHookAt(uintptr_t target, F detour, F* original) {
    return InstallHook(reinterpret_cast<void*>(target), detour, original);
}

inline void* ModuleProc(const wchar_t* module, const char* name) {
    HMODULE m = GetModuleHandleW(module);
    if (!m) m = LoadLibraryW(module);
    return m ? reinterpret_cast<void*>(GetProcAddress(m, name)) : nullptr;
}

// ---------------------------------------------------------------- Direct3D9
// Engancha Direct3DCreate9 -> IDirect3D9::CreateDevice -> IDirect3DDevice9::Reset.
struct D3DCallbacks {
    void (*presentParams)(D3DPRESENT_PARAMETERS*);  // antes de CreateDevice/Reset (puede modificar los parametros)
    void (*deviceCreated)(HWND);                    // tras CreateDevice con exito
    void (*beforeCreate9)();                        // al principio de Direct3DCreate9
};

namespace d3d_detail {
typedef IDirect3D9* (WINAPI* Create9_t)(UINT);
typedef HRESULT(WINAPI* CreateDevice_t)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*, IDirect3DDevice9**);
typedef HRESULT(WINAPI* Reset_t)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);

inline D3DCallbacks g_cb = {};
inline Create9_t g_realCreate9 = nullptr;
inline CreateDevice_t g_realCreateDevice = nullptr;
inline Reset_t g_realReset = nullptr;
inline volatile LONG g_createDeviceHooked = 0;
inline volatile LONG g_resetHooked = 0;

inline HRESULT WINAPI HookReset(IDirect3DDevice9* dev, D3DPRESENT_PARAMETERS* pp) {
    if (g_cb.presentParams && pp) g_cb.presentParams(pp);
    return g_realReset(dev, pp);
}

inline HRESULT WINAPI HookCreateDevice(IDirect3D9* self, UINT adapter, D3DDEVTYPE type, HWND focus, DWORD flags,
                                       D3DPRESENT_PARAMETERS* pp, IDirect3DDevice9** out) {
    if (g_cb.presentParams && pp) g_cb.presentParams(pp);
    HRESULT hr = g_realCreateDevice(self, adapter, type, focus, flags, pp, out);
    if (SUCCEEDED(hr) && out && *out) {
        if (g_cb.deviceCreated) g_cb.deviceCreated((pp && pp->hDeviceWindow) ? pp->hDeviceWindow : focus);
        if (!InterlockedCompareExchange(&g_resetHooked, 1, 0)) {
            void** vtbl = *reinterpret_cast<void***>(*out);
            if (!InstallHook(vtbl[16], HookReset, &g_realReset)) g_resetHooked = 0;  // 16 = Reset
        }
    }
    return hr;
}

inline IDirect3D9* WINAPI HookDirect3DCreate9(UINT sdk) {
    if (g_cb.beforeCreate9) g_cb.beforeCreate9();
    IDirect3D9* d3d = g_realCreate9(sdk);
    if (d3d && !InterlockedCompareExchange(&g_createDeviceHooked, 1, 0)) {
        void** vtbl = *reinterpret_cast<void***>(d3d);
        if (!InstallHook(vtbl[16], HookCreateDevice, &g_realCreateDevice)) g_createDeviceHooked = 0;  // 16 = CreateDevice
    }
    return d3d;
}

inline bool TryHookCreate9() {
    HMODULE m = GetModuleHandleW(L"d3d9.dll");
    if (!m) return false;
    void* p = reinterpret_cast<void*>(GetProcAddress(m, "Direct3DCreate9"));
    return p && InstallHook(p, HookDirect3DCreate9, &g_realCreate9);
}

inline DWORD WINAPI WaitForD3D9(LPVOID) {
    // d3d9.dll todavia no esta cargado (no podemos hacer LoadLibrary dentro de DllMain): esperar a que aparezca.
    for (int i = 0; i < 6000; ++i) {
        if (TryHookCreate9()) return 0;
        Sleep(5);
    }
    return 0;
}
}  // namespace d3d_detail

// Requiere MH_Initialize() previo.
inline void InstallD3D9Hooks(const D3DCallbacks& cb) {
    d3d_detail::g_cb = cb;
    if (d3d_detail::TryHookCreate9()) return;
    HANDLE t = CreateThread(nullptr, 0, d3d_detail::WaitForD3D9, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}

}  // namespace sshook
