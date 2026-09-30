# PhantomDumper foundation

A separate x64 Windows C++17 diagnostic DLL for development processes you own
or are authorized to inspect. Version 0.1 begins with loaded-module metadata,
plain-text logging, and an explicit synchronous lifecycle. It does not yet
discover offsets, read arbitrary memory, dump binaries, or generate an SDK.

## Build and test

Install Visual Studio 2022's Desktop development with C++ workload and CMake
3.20 or newer. From the repository root:

```powershell
cmake -S PhantomDumper -B PhantomDumper/build -A x64 -DBUILD_TESTING=ON
cmake --build PhantomDumper/build --config Release
ctest --test-dir PhantomDumper/build -C Release --output-on-failure
```

Output: `PhantomDumper/build/Release/PhantomDumper.dll` with the Visual Studio
generator. The DLL uses the compiler's default shared CRT; the matching Visual
C++ x64 runtime must be available. This project has its own CMake build and
does not participate in `Phantom.sln` or change Phantom.Core/Phantom.UI.

On Linux/macOS, the same CMake project builds only the portable core and its
tests. Native module enumeration and DLL loading require Windows. CI exercises
Windows Debug/Release plus the Linux core, with compiler warnings as errors.

## Lifecycle and Phantom integration

`DllMain` is intentionally empty. Loading the DLL alone does not start a dump.
After a normal Windows loader-managed load into your development host, call:

1. `PhantomDumperStart()` with **no arguments**. It takes the first module
   snapshot and appends it to the host process's
   `%TEMP%\PhantomDumper-<pid>.log`.
2. `PhantomDumperSnapshot()` with **no arguments** for another snapshot.
3. `PhantomDumperStop()` with **no arguments** before unloading.

Phantom's existing Execute exported functions feature can call these names;
no injector changes are required. Start reports diagnostic initialization,
independently of whether injection succeeded. This foundation is supported
with standard loader-managed loading, intact headers and normal loader lists.
Other mapping/stealth configurations have not been validated for this DLL.
The included `PhantomDumperSmoke` executable provides an independent test host
using `LoadLibraryW`/`GetProcAddress`/`FreeLibrary`.

For native hosts, `PhantomDumperStartAt(const wchar_t* log_path)` accepts a
valid UTF-16 path to an existing parent directory. Do not pass a path through
Phantom's ANSI string argument UI to this UTF-16 export. Public declarations
are in `include/phantom/Api.h`; exports use a C ABI and Windows calling convention.

| Return value | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Already started, or snapshot requested before start/after stop |
| 2 | Log open/write/flush/close or temporary-path failure |
| 3 | Module enumeration failure |
| 4 | Unexpected internal exception |
| 5 | Empty/null explicit log path |

Failed start leaves the session stopped and retryable. A failed snapshot keeps
the session started so the caller can retry or stop. Stop is idempotent. Calls
are serialized by a mutex and execute entirely on the calling thread; there
are no worker threads or pending asynchronous jobs. No exception crosses the
C ABI. Call exports outside `DllMain` and outside the loader lock. The host
must keep the DLL loaded for every call and ensure **all callers have returned**
before `FreeLibrary`; Stop cannot make an overlapping unload safe.

## Snapshot semantics and logging

`ModuleResolver` uses a Tool Help snapshot of the current process only. It
copies module names, paths, runtime base addresses and image sizes; it does not
dereference returned bases. `ERROR_BAD_LENGTH` is retried up to eight times
during loader churn; any remaining failure returns status 3. A partial module
walk is discarded. The snapshot owns an RAII handle that closes on all paths.
See Microsoft's [Tool Help snapshot documentation](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
for enumeration limitations and retry behavior.

These are point-in-time module addresses, **not verified offsets**. A module
may unload after enumeration. Manual mappings, modules removed from loader
lists and data-file loads are not a complete part of this inventory. Tool Help
paths use fixed-size buffers and may be truncated for long paths.

The append-only UTF-8 text log labels base addresses and image sizes separately.
Control characters and backslashes in names/paths are escaped to preserve row
boundaries. Each operation opens, writes and closes the log before returning;
no file handle is retained for DLL detach. I/O failure can leave a partial
record, so a failed snapshot must not be treated as a complete report. Choose
a host-controlled destination with `StartAt` when strict log isolation matters;
the default temp filename is predictable and can include earlier PID reuse.

## Components and follow-up PRs

- `ModuleResolver`: Windows module metadata snapshot.
- `Logger`: format and append a snapshot without retaining handles.
- `Runtime`: transactional initialization, serialized snapshots, stop/restart.
- `Exports`/`dllmain`: explicit C API with exception containment and minimal entry point.

Core tests cover formatting, large addresses, log escaping, initialization
failures, retry, append behavior, concurrent snapshots and shutdown/restart.
Windows smoke tests validate real module bases, Unicode output paths, named
exports and repeated load/start/snapshot/stop/unload cycles. They do not test
anti-cheat behavior or Phantom's injection methods.

Later PRs can add read-only MemoryInspector, PatternScanner,
StructureInspector, OffsetManager and JSON/C++ ExportManager independently.
