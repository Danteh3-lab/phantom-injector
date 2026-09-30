#include <windows.h>

#if !defined(_M_X64) && !defined(__x86_64__)
#error PhantomDumper supports native x64 Windows only
#endif

// The CRT still performs its normal loader-managed setup. No application
// logging, locks, module walks, worker threads or cleanup run under loader lock.
BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
