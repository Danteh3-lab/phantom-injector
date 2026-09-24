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
  - `Standard` – `CreateRemoteThread` + `LoadLibraryW` (most compatible)
  - `LdrLoadDll` – direct `ntdll!LdrLoadDll` call one level below `LoadLibrary`
  - `ThreadHijack` – suspends an existing thread, redirects its RIP, no `CreateRemoteThread`
  - `ManualMap` – reflective mapping: imports, relocations and TLS resolved by the injector;
    the module never enters the loader lists
  - `LdrpLoadDll` – intentionally disabled (undocumented, broken after Windows 10 1709)
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
  is never reported as hidden while the lock could not be released.
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
  Native/                P/Invoke, CONTEXT, structs, error helpers
  Processes/             Process/module/thread/window enumeration, privileges
  Injection/             Standard, LdrLoadDll, ThreadHijack, ManualMap, PE parser
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
