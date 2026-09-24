#include <windows.h>

// Keep DllMain minimal: it runs under the loader lock, so anything that can
// block (dialogs, I/O, other thread creation) risks a deadlock. Use the
// exported PhantomHello function for visible confirmation.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void __stdcall PhantomHello() {
    MessageBoxA(nullptr, "PhantomHello export called.", "Phantom", MB_OK | MB_ICONINFORMATION);
}
