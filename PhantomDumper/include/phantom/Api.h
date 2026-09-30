#pragma once
#include <windows.h>

#ifdef PHANTOM_DUMPER_BUILD
#define PHANTOM_DUMPER_API __declspec(dllexport)
#else
#define PHANTOM_DUMPER_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif
// 0=success, 1=invalid state, 2=log I/O, 3=enumeration, 4=internal, 5=invalid argument.
// Call only outside DllMain/loader lock. All operations are synchronous.
PHANTOM_DUMPER_API DWORD WINAPI PhantomDumperStart(void);
// For a native host with a valid UTF-16 path. Start() uses the process temp directory.
PHANTOM_DUMPER_API DWORD WINAPI PhantomDumperStartAt(const wchar_t* log_path);
PHANTOM_DUMPER_API DWORD WINAPI PhantomDumperSnapshot(void);
PHANTOM_DUMPER_API DWORD WINAPI PhantomDumperStop(void);
#ifdef __cplusplus
}
#endif
