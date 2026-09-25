# Phantom Injector

A from-scratch, x64-only DLL injector for Windows 10/11 in C# (.NET 8), inspired
by [master131/ExtremeInjector](https://github.com/master131/ExtremeInjector).
The original project ships no source (only runtime ZIPs + a version file), so this
is a clean-room re-implementation of the feature set described in its README.

> **Warning:** Injectors are flagged as hack tools/riskware by antivirus engines.
> Use only on processes you own or are authorised to test. The authors are not
> responsible for how this tool is used.

## Features

- **Injection methods**
  - `Standard` – remote thread + `LoadLibraryW` (most compatible)
  - `LdrLoadDll` – direct `ntdll!LdrLoadDll` call one level below `LoadLibrary`
  - `ThreadHijack` – suspends an existing thread, redirects its RIP, no remote thread
  - `ManualMap` – reflective mapping: imports, relocations and TLS resolved by the injector;
    the module never enters the loader lists
  - `DllHollowing` – maps a signed system DLL as a file-backed image section
    (`MEM_IMAGE`), reflectively maps the payload into it, runs it via thread hijack
  - `ModuleStomping` – overwrites a non-critical loaded module with the payload
    image (no new private executable memory), runs it via thread hijack
  - `LdrpLoadDll` – intentionally disabled (undocumented, broken after Windows 10 1709)
- **Direct syscalls** – all memory/thread operations (`NtAllocateVirtualMemory`,
  `NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`,
  `NtCreateThreadEx`, `NtOpenProcess`, `NtCreateSection`, `NtMapViewOfSection`,
  contexts, suspend/resume, flush) bypass usermode hooks via Hell's/Halo's Gate
  stubs resolved from a clean on-disk `ntdll.dll`
- **Section-backed scratch memory** – all temporary remote buffers (stubs,
  slots, images) are pagefile section mappings, never private `VirtualAlloc`
  memory
- **Preflight access probe** – before injecting (and before the architecture
  check, so access failures can't hide as "not AMD64"), the granted handle
  rights are queried and compared against the exact mask the method opens with
  (single source of truth per method). Kernel protections (e.g. anti-cheat
  object callbacks) that strip rights produce one actionable failure naming the
  missing rights; an unqueryable handle fails closed as "rights unverified"
  rather than a false defense win. Only the pure-hijack path omits
  `PROCESS_CREATE_THREAD` (hollowing/stomping still create threads for imports).
  Failures carry classified NTSTATUS names (`ACCESS_DENIED`, …), and a failed
  remote-thread creation is reported distinctly from a load that returned NULL
- **Multi-DLL** queue with per-DLL enable/disable, drag & drop
- **Auto-inject** when the target process starts
- **Close on inject**
- **DLL scrambling** presets: `None`, `Basic`, `Standard`, `Extreme`
- **Post-inject**: erase PE headers, hide module from the PEB loader lists
- **Execute exported functions** after injection (uses the recorded module base
  scoped to the exact target process instance, so it also works for
  manual-mapped and PEB-hidden modules; when PE headers were erased the export
  RVA is read from the original file, with forwarded and out-of-image RVAs
  rejected)
- **Secure mode**: relaunch from a randomized `%TEMP%` path
- **Un-inject** (`FreeLibrary` remotely)
- Process/thread/window picker, dark theme, settings persistence

## Requirements

- Windows 10 21H2 / Windows 11, x64 only
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) to build
- Administrator rights to run (the app manifest requests elevation)
- Visual C++ 2015-2022 x64 runtime if the injected DLL needs it

## Build

```powershell
dotnet build Phantom.sln -c Release
```

Output: `src/Phantom.UI/bin/Release/net8.0-windows/Phantom.Injector.exe`

## Publish (single file, self-contained)

```powershell
dotnet publish src/Phantom.UI/Phantom.UI.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

## Usage

1. Run `Phantom.Injector.exe` as administrator (the manifest prompts).
2. Type a process name (e.g. `notepad.exe`) or use **Select...**.
3. **Add DLL** (or drag & drop) and tick the ones to inject.
4. Pick a method and options, then click **Inject**.

For manual map + `Erase PE` + `Hide Module`, use an unsigned test DLL first.

## Injection methods – how to use each

- `Standard` – default choice. Works with almost any DLL, including ones with
  static TLS. Use when compatibility matters more than stealth.
- `LdrLoadDll` – same payload requirements as `Standard`, one loader level
  deeper. Use to dodge naive `LoadLibraryW` hooks.
- `ThreadHijack` – no remote thread is created; needs a target thread with
  enough free stack (checked against the TEB). Use when thread-creation telemetry
  is the concern. Same payload requirements as `Standard`. The stub runs on the
  interrupted thread's own stack; call-stack spoofing is designed but dormant
  (it needs a separate guarded execution stack before it is safe to enable).
- `ManualMap` – use for loader-invisible mappings. The DLL must be relocatable
  (or match its preferred base), have resolvable imports, and must **not** use
  static TLS data (rejected up front – use a loader-based method instead).
  Combine with `Erase PE` + `Hide Module` for minimal footprint.
- `DllHollowing` – use when private executable allocations are the detection
  surface: the payload lives in a file-backed `MEM_IMAGE` view. Requirements:
  a suitable signed system DLL must already be loaded in the target **and** its
  image must be at least as large as the payload (`SizeOfImage`); same
  relocation/import/TLS rules as `ManualMap`. `DllMain` runs as
  `(hModule, DLL_PROCESS_ATTACH, NULL)` under the loader lock on the hijacked
  thread, and the reported base is the mapped view.
- `ModuleStomping` – use when even a new image section stands out: an existing
  non-critical module is overwritten in place, so no new allocation appears at
  all. Requirements: a loaded non-critical module with `SizeOfImage` and `.text`
  capacity ≥ payload; same relocation/import/TLS rules as `ManualMap`. All other
  target threads are suspended during the overwrite window. The host module is
  byte-backed-up first: clean failures restore it, but a failed restore leaves
  the target in a retain state (see below).
- `Erase PE` / `Hide Module` work on every method's reported base, including
  hollowed views and stomped modules.
- **Retain states:** if the log reports a stub/view left mapped, a thread left
  suspended (e.g. loader-lock release failure), or a failed host restore,
  **restart the target process** – resuming or freeing in those states would
  corrupt or deadlock it. These outcomes are fail-closed by design.

## Safety / known limitations

- **x64 targets only.** The target's architecture is verified with
  `IsWow64Process2` (native AMD64 only); anything else, or an undeterminable
  target, is rejected up front.
- **Incomplete remote operations never free memory.** A timeout or failed wait
  means the remote thread may still be executing, so buffers it can reach are
  intentionally left mapped rather than freed under a live thread.
- **Thread hijacking** runs its stub on the interrupted thread's own stack
  (stack margin checked against the TEB), captures the full OS-managed thread
  context including XState/AVX via `InitializeContext`, restores TEB
  `LastErrorValue`, and re-applies the saved context with `SetThreadContext`
  before resuming. The stub parks in a low-CPU `Sleep(1)` loop rather than
  spinning, and the remote region is released once the thread is restored. If
  `InitializeContext`/`SetXStateFeaturesMask` cannot establish full state
  preservation the method fails rather than proceeding without it, and a
  timed-out load leaves the thread parked with its region mapped instead of
  freeing memory under a live thread. If the initial resume fails, the original
  context is restored before any further resume attempt; if that restoration
  itself fails the thread is left suspended with its stub mapped (never resumed
  into an abandoned stub), and a region that was never started is freed.
- **Manual map** fails the whole mapping if any dependency, import, or TLS
  callback cannot be resolved/run, so `DllMain` never runs with null IAT
  entries or missing TLS initialization. Unsupported or malformed TLS is
  rejected *before* any dependency is loaded. Initialization runs under the
  target's **loader lock** on a **single** remote thread: the image's x64
  unwind metadata is registered with `RtlAddFunctionTable`, then TLS callbacks
  and `DllMain` run in array order. A failed attach is rolled back in the same
  order with `DLL_PROCESS_DETACH` and `RtlDeleteFunctionTable`, the lock is
  released, and only then is a completion flag written. The temporary attach
  result and completion flag let an abnormal exit (`ExitThread`, crash) be
  detected. Dependencies are loaded with `LoadLibraryW`, which takes an
  explicit reference even when the module is already loaded (and forwarder
  targets are referenced too); references are released in reverse if the
  mapping fails and retained on success, since there is no unmap operation yet.
  Malformed relocations, imports, TLS, or exception directories are rejected
  rather than tolerated. Images that use static TLS data (a template or
  zero-fill) are **rejected**, because reflective mapping cannot install
  per-thread TLS blocks; use a loader-based method for those DLLs.
  *Limitation:* a TLS callback or `DllMain` that calls `ExitThread`, or lets an
  unhandled exception escape (the generated stub has no unwind metadata), can
  leave the target's loader lock held and the image mapped. This is detected via
  the completion flag, reported as a failure, and nothing is freed — but the
  lock is not automatically recovered.
- **Hide module** locates the loader entry *and* unlinks it inside the target
  under the real loader lock (a stub calling `LdrLockLoaderLock`). The outcome
  status is published only after `LdrUnlockLoaderLock` succeeds, so a mapping
  is never reported as hidden while the lock could not be released. The stub
  additionally removes the entry's `LdrpHashTable` bucket linkage when it can
  be positively identified (Flink/Blink round-trip validation; skipped with a
  warning otherwise, and skipped entirely on builds that don't export the
  table) – never unlinked on a guess.
- **DLL hollowing** maps the carrier with `NtCreateSection(SEC_IMAGE)` from a
  real signed file handle (never a handle-less section), verifies the view fits
  the payload, then applies the same relocation/import/TLS/exception validation
  as manual map before `DllMain` runs. Carrier bytes are backed up first; clean
  failures restore them while the hijacked thread is still suspended, and only
  verified restores resume anything.
- **Module stomping** suspends every other target thread across the
  backup/overwrite/init window (fail-closed sweep: any unverified open/suspend
  aborts untouched) and restores the host from backup on clean failures – but
  only while no thread can execute it. Rollback is two-mode: protection-only
  failures re-apply saved page protections without rewriting bytes; byte
  rollbacks rewrite the backup and restore the full saved page map (captured via
  `VirtualQueryEx`, so gaps the section list misses are covered). A failed
  restore retains everything suspended – restart the target.
- **Hijack init stubs** (hollowing/stomping) align the stack once at entry, use
  correct shadow space on every call including the `Sleep(1)` park loop, always
  signal completion (including loader-lock failure), and never restore/resume a
  thread that may still own the loader lock.
- **Secure mode** copies the whole application output directory to `%TEMP%` and
  works for both single-file publishes and normal builds.

## Test DLL

A tiny native DLL with an export is provided to verify injection:

```powershell
# From a "x64 Native Tools Command Prompt for VS"
samples\TestDll\build.bat
```

This produces `samples\TestDll\phantest.dll`. Its exported `PhantomHello` shows a
message box and can be called from the injector's export feature; `DllMain` is
intentionally silent to avoid running UI under the loader lock.

## Project layout

```
src/Phantom.Core/        Injector engine (no UI)
  Native/                Direct syscalls (Hell's/Halo's Gate), P/Invoke, CONTEXT, structs, error helpers
  Processes/             Process/module/thread/window enumeration, privileges
  Injection/             Standard, LdrLoadDll, ThreadHijack, ManualMap,
                         DllHollowing, ModuleStomping, ReflectiveMapper, PE parser
  PostInject/            Loader-lock module hiding, uninjector, export caller
  Stealth/               Scrambler, secure mode, auto-inject watcher, dependency check
src/Phantom.UI/          WinForms front-end
samples/TestDll/         Native test DLL
```

## Credits

- Manual map concept originally by DarthTon ([Blackbone](https://github.com/DarthTon/Blackbone), MIT).
- Thread hijacking concept by Darawk.
- Feature inspiration: master131's ExtremeInjector.

## Legal

This project is provided for educational and authorised security testing only.
Do not use it to tamper with software you do not own or have permission to test.
