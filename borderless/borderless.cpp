// sshook_borderless.asi - Split/Second: Revised
//  * Ventana sin bordes a la resolucion del escritorio
//  * Modo ventana (con marco, centrada) cuando el juego pide una resolucion menor que el escritorio
//  * Resolucion por defecto = escritorio
// Reescrito a partir de borderless.cpp / default_resolution.cpp / process.cpp del mod original.
//
// Variable de entorno opcional SSHOOK_WINDOW=WxH para forzar el tamano "de pantalla" (min. 320x240).
#include "../common/sshook_common.h"
#include <stdio.h>

using namespace sshook;

namespace {

constexpr DWORD kFramedStyle = 0x04CA0000;  // WS_CLIPSIBLINGS | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
constexpr DWORD kPopupStyle = 0x84000000;   // WS_POPUP | WS_CLIPSIBLINGS

int g_forcedW = 1920;  // se sustituyen por el tamano real del escritorio al arrancar
int g_forcedH = 1080;
HWND g_gameHwnd = nullptr;

typedef HWND(WINAPI* CreateWindowExA_t)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef BOOL(WINAPI* MoveWindow_t)(HWND, int, int, int, int, BOOL);
typedef BOOL(WINAPI* ShowWindow_t)(HWND, int);
typedef BOOL(WINAPI* SetWindowPos_t)(HWND, HWND, int, int, int, int, UINT);

CreateWindowExA_t g_realCreateWindowExA = nullptr;
MoveWindow_t g_realMoveWindow = nullptr;
ShowWindow_t g_realShowWindow = nullptr;
SetWindowPos_t g_realSetWindowPos = nullptr;  // no se engancha, solo se usa

// ------------------------------------------------------------ tamano del escritorio
void CaptureDesktopSize() {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    if (w > 0 && h > 0) {
        g_forcedW = w;
        g_forcedH = h;
    }
    char buf[32] = {};
    DWORD n = GetEnvironmentVariableA("SSHOOK_WINDOW", buf, sizeof(buf));
    if (n > 0 && n < sizeof(buf)) {
        int ow = 0, oh = 0;
        if (sscanf(buf, "%dx%d", &ow, &oh) == 2 && ow > 319 && oh > 239) {
            g_forcedW = ow;
            g_forcedH = oh;
        }
    }
}

// ------------------------------------------------------------ ventanas
bool IsChildStyle(DWORD style) { return (style & WS_CHILD) != 0; }

bool IsChildWindowHandle(HWND h) {
    if (!h) return false;
    return IsChildStyle(static_cast<DWORD>(GetWindowLongW(h, GWL_STYLE)));
}

void EnforceSizeArgs(DWORD style, int& w, int& h) {
    if (!IsChildStyle(style)) {
        w = g_forcedW;
        h = g_forcedH;
    }
}

// Tamano cliente pedido: menor que el escritorio (en alguna dimension) y valido => ventana con marco.
bool WantsFramedWindow(int cw, int ch) {
    if (cw <= 0 || ch <= 0) return false;
    if (cw > g_forcedW || ch > g_forcedH) return false;
    return cw < g_forcedW || ch < g_forcedH;
}

HWND WINAPI HookCreateWindowExA(DWORD exStyle, LPCSTR cls, LPCSTR title, DWORD style, int x, int y, int w, int h,
                                HWND parent, HMENU menu, HINSTANCE inst, LPVOID param) {
    EnforceSizeArgs(style, w, h);
    return g_realCreateWindowExA(exStyle, cls, title, style, x, y, w, h, parent, menu, inst, param);
}

BOOL WINAPI HookMoveWindow(HWND hWnd, int X, int Y, int W, int H, BOOL repaint) {
    if (IsChildWindowHandle(hWnd)) return g_realMoveWindow(hWnd, X, Y, W, H, repaint);

    const DWORD style = static_cast<DWORD>(GetWindowLongW(hWnd, GWL_STYLE));
    const DWORD exStyle = static_cast<DWORD>(GetWindowLongW(hWnd, GWL_EXSTYLE));
    const DWORD visible = style & WS_VISIBLE;

    // tamano cliente que pretende el juego = tamano exterior pedido - marco del estilo actual
    RECT adj = {0, 0, 0, 0};
    AdjustWindowRectEx(&adj, style, GetMenu(hWnd) != nullptr, exStyle);
    const int cw = W - (adj.right - adj.left);
    const int ch = H - (adj.bottom - adj.top);

    Log("MoveWindow(%d,%d,%d,%d) cliente=%dx%d -> %s", X, Y, W, H, cw, ch, WantsFramedWindow(cw, ch) ? "ventana" : "borderless");
    if (WantsFramedWindow(cw, ch)) {
        SetWindowLongW(hWnd, GWL_STYLE, static_cast<LONG>(visible | kFramedStyle));
        RECT r = {0, 0, cw, ch};
        AdjustWindowRectEx(&r, kFramedStyle, FALSE, exStyle);
        W = r.right - r.left;
        H = r.bottom - r.top;

        RECT wa = {0, 0, 0, 0};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
        const int sw = GetSystemMetrics(SM_CXSCREEN);
        const int sh = GetSystemMetrics(SM_CYSCREEN);
        X = wa.left + ((sw - wa.left) - W) / 2;
        Y = wa.top + ((sh - wa.top) - H) / 2;
        if (X < wa.left) X = wa.left;
        if (Y < wa.top) Y = wa.top;
    } else {
        // sin marco: si el estilo es el "de ventana normal" del juego, pasar a popup
        if ((style & 0xEFFFFFFFu) == kFramedStyle)
            SetWindowLongW(hWnd, GWL_STYLE, static_cast<LONG>(visible | kPopupStyle));
        W = g_forcedW;
        H = g_forcedH;
    }

    return g_realSetWindowPos(hWnd, nullptr, X, Y, W, H,
                              SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

// Evita que el juego oculte su ventana al perder el foco.
BOOL WINAPI HookShowWindow(HWND hWnd, int cmd) {
    if (cmd == SW_HIDE && hWnd && hWnd == g_gameHwnd) cmd = SW_SHOW;
    return g_realShowWindow(hWnd, cmd);
}

BOOL CALLBACK EnumWindowsForceProc(HWND hWnd, LPARAM pid) {
    DWORD wp = 0;
    GetWindowThreadProcessId(hWnd, &wp);
    if (wp != static_cast<DWORD>(pid)) return TRUE;
    if (IsChildWindowHandle(hWnd)) return TRUE;
    if (!g_realSetWindowPos) return TRUE;
    // SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_NOMOVE
    g_realSetWindowPos(hWnd, nullptr, 0, 0, g_forcedW, g_forcedH,
                       SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_NOMOVE);
    return TRUE;
}

void ForceExistingWindows() { EnumWindows(EnumWindowsForceProc, static_cast<LPARAM>(GetCurrentProcessId())); }

// ------------------------------------------------------------ Direct3D: forzar modo ventana
void ApplyPresentParams(D3DPRESENT_PARAMETERS* pp) {
    if (!pp) return;
    pp->Windowed = TRUE;
    pp->FullScreen_RefreshRateInHz = 0;  // obligatorio en modo ventana
}

void OnDeviceCreated(HWND hwnd) {
    if (!g_gameHwnd) g_gameHwnd = hwnd;
    Log("CreateDevice ok, hwnd=%p", hwnd);
}

// ------------------------------------------------------------ resolucion por defecto = escritorio
// El .exe esta protegido: el codigo solo se puede enganchar cuando ya esta descifrado, asi que se comprueba el patron.
typedef int(__fastcall* DisplaySettingsCtor_t)(void* thisp, void* edx);
typedef void(__fastcall* SetDisplayParams_t)(void* thisp, void* edx, const int* wh);

DisplaySettingsCtor_t g_origDisplaySettingsCtor = nullptr;
SetDisplayParams_t g_origSetDisplayParams = nullptr;

constexpr uintptr_t kAddrDisplaySettingsCtor = 0x00A13460;
constexpr uintptr_t kAddrSetDisplayParams = 0x0050DA40;
constexpr uintptr_t kAddrSettingsGlobal = 0x00D57DA8;  // puntero al bloque de ajustes del juego
const BYTE kPatDisplaySettingsCtor[12] = {0x56, 0x57, 0x8B, 0xF1, 0x68, 0x00, 0x01, 0x00, 0x00, 0x8D, 0x7E, 0x08};
const BYTE kPatSetDisplayParams[13] = {0x83, 0xEC, 0x2C, 0x53, 0x55, 0x56, 0x57, 0x8B, 0xF1, 0x6A, 0x38, 0x33, 0xED};

int __fastcall HookDisplaySettingsCtor(void* thisp, void* edx) {
    BYTE* settings = CanRead(kAddrSettingsGlobal, 4) ? *reinterpret_cast<BYTE**>(kAddrSettingsGlobal) : nullptr;
    if (settings) {
        *reinterpret_cast<int*>(settings + 0xB68) = g_forcedW;
        *reinterpret_cast<int*>(settings + 0xB6C) = g_forcedH;
    }
    int r = g_origDisplaySettingsCtor(thisp, edx);
    if (thisp) *(static_cast<BYTE*>(thisp) + 0x110) = 1;
    return r;
}

void __fastcall HookRendererSetDisplayParams(void* thisp, void* edx, const int* wh) {
    g_origSetDisplayParams(thisp, edx, wh);
    if (thisp && wh && wh[0] > 0 && wh[1] > 0) {
        *reinterpret_cast<int*>(static_cast<BYTE*>(thisp) + 0x57C) = wh[0];
        *reinterpret_cast<int*>(static_cast<BYTE*>(thisp) + 0x580) = wh[1];
    }
}

volatile LONG g_tryBusy = 0;

void DefaultResolution_TryInstallHook() {
    if (InterlockedExchange(&g_tryBusy, 1)) return;
    if (!g_origDisplaySettingsCtor && BytesMatch(kAddrDisplaySettingsCtor, kPatDisplaySettingsCtor, sizeof(kPatDisplaySettingsCtor)))
        InstallHookAt(kAddrDisplaySettingsCtor, HookDisplaySettingsCtor, &g_origDisplaySettingsCtor);
    if (!g_origSetDisplayParams && BytesMatch(kAddrSetDisplayParams, kPatSetDisplayParams, sizeof(kPatSetDisplayParams)))
        InstallHookAt(kAddrSetDisplayParams, HookRendererSetDisplayParams, &g_origSetDisplayParams);
    InterlockedExchange(&g_tryBusy, 0);
}

DWORD WINAPI PollThread(LPVOID) {
    ForceExistingWindows();
    for (int i = 0; i < 1800; ++i) {  // ~3 min
        DefaultResolution_TryInstallHook();
        if (g_origDisplaySettingsCtor && g_origSetDisplayParams) {
            Log("hooks de resolucion por defecto instalados");
            return 0;
        }
        if (i % 50 == 0) {  // cada 5 s
            Log("esperando codigo del juego: ctor=%s setparams=%s", g_origDisplaySettingsCtor ? "ok" : "no",
                g_origSetDisplayParams ? "ok" : "no");
            if (i == 0 || i == 100) {
                DumpBytes("ctor     ", kAddrDisplaySettingsCtor, 12);
                DumpBytes("setparams", kAddrSetDisplayParams, 13);
            }
        }
        Sleep(100);
    }
    Log("resolucion por defecto: no se encontraron los patrones del juego (otra version del .exe?)");
    return 0;
}

void BeforeCreate9() { DefaultResolution_TryInstallHook(); }

// ------------------------------------------------------------ arranque
void Init() {
    CaptureDesktopSize();
    Log("tamano forzado %dx%d", g_forcedW, g_forcedH);
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK) {
        Log("MH_Initialize fallo: %s", MH_StatusToString(st));
        return;
    }

    g_realSetWindowPos = reinterpret_cast<SetWindowPos_t>(ModuleProc(L"user32.dll", "SetWindowPos"));
    void* pCreate = ModuleProc(L"user32.dll", "CreateWindowExA");
    void* pMove = ModuleProc(L"user32.dll", "MoveWindow");
    void* pShow = ModuleProc(L"user32.dll", "ShowWindow");
    if (!g_realSetWindowPos || !pCreate || !pMove || !pShow) {
        Log("no se encontraron funciones de user32");
        return;
    }

    InstallHook(pCreate, HookCreateWindowExA, &g_realCreateWindowExA);
    InstallHook(pMove, HookMoveWindow, &g_realMoveWindow);
    InstallHook(pShow, HookShowWindow, &g_realShowWindow);

    D3DCallbacks cb = {};
    cb.presentParams = ApplyPresentParams;
    cb.deviceCreated = OnDeviceCreated;
    cb.beforeCreate9 = BeforeCreate9;
    InstallD3D9Hooks(cb);

    HANDLE t = CreateThread(nullptr, 0, PollThread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
    Log("init terminado");
}

// Fuera de DllMain (loader lock). Los hooks de user32/D3D se instalan YA: el juego crea la ventana muy pronto.
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
        Log("sshook_borderless attach");
        HANDLE t = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
