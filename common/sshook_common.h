// Utilidades compartidas por los .asi (reescritas a partir de core/memory.cpp y d3d_hooks.cpp del mod original).
#pragma once
#include <windows.h>
#include <d3d9.h>
#include <stdint.h>
#include <string.h>
#include "MinHook.h"

namespace sshook {

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
    if (MH_CreateHook(target, reinterpret_cast<LPVOID>(detour), reinterpret_cast<LPVOID*>(original)) != MH_OK)
        return false;
    if (MH_EnableHook(target) != MH_OK) {
        MH_RemoveHook(target);
        *original = nullptr;
        return false;
    }
    return true;
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
