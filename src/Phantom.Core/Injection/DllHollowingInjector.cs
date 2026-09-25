using System.Runtime.InteropServices;
using System.Text;
using Phantom.Core.Native;
using Phantom.Core.Processes;

namespace Phantom.Core.Injection;

/// <summary>
/// Phantom DLL Hollowing (section-based image mapping).
/// Creates a file-backed MEM_IMAGE view from a legitimate signed DLL via
/// NtCreateSection(SEC_IMAGE) + NtMapViewOfSection, then reflectively maps the
/// payload into that view (headers + sections by VA, relocations, imports, TLS
/// validation, section protections) and runs DllMain(hModule, ATTACH, 0) on a
/// hijacked thread. The reported base is the mapped view base, never a
/// DllMain boolean.
/// Residual: the tiny hijack stub is a temporary private allocation (RX after
/// write, freed only after the thread is confirmed restored); dependency loads
/// still use the loader until Phase 1.2 routes them through syscalls.
/// </summary>
internal sealed unsafe class DllHollowingInjector : InjectorBase
{
    public override InjectionMethod Method => InjectionMethod.DllHollowing;

    // Process open uses InjectorBase.InjectionAccess (includes CREATE_THREAD:
    // import resolution and dependency release create remote threads).
    private const uint ThreadAccess =
        NativeConstants.THREAD_SUSPEND_RESUME |
        NativeConstants.THREAD_GET_CONTEXT |
        NativeConstants.THREAD_SET_CONTEXT |
        NativeConstants.THREAD_QUERY_INFORMATION;

    private const int MinimumStackMargin = 0x8000;
    private const int TebStackLimitOffset = 0x10;
    private const int TebLastErrorOffset = 0x68;

    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x80;

    // SECTION_INHERIT ViewUnmap: the view is private to the target process.
    private const uint ViewUnmap = 2;

    public override InjectionResult Inject(uint pid, string dllPath, InjectionOptions options)
    {
        IntPtr hProcess = IntPtr.Zero;
        IntPtr fileHandle = IntPtr.Zero;
        IntPtr sectionHandle = IntPtr.Zero;
        IntPtr remoteBase = IntPtr.Zero;
        UIntPtr viewSize = UIntPtr.Zero;
        var invalidHandle = new IntPtr(-1);

        try
        {
            DirectSyscalls.Initialize();

            byte[] payloadRaw;
            PeImage pe;
            try
            {
                payloadRaw = File.ReadAllBytes(dllPath);
                pe = new PeImage(payloadRaw);
            }
            catch (BadImageFormatException ex)
            {
                return InjectionResult.Fail(Method, dllPath, "Invalid PE image: " + ex.Message);
            }

            try
            {
                hProcess = OpenRemoteProcess(pid, InjectionAccess);
            }
            catch (Exception ex)
            {
                return InjectionResult.Fail(Method, dllPath, "OpenProcess failed: " + ex.Message);
            }

            var candidate = FindSuitableSystemDll(pid, hProcess, (long)pe.SizeOfImage);
            var carrierPath = candidate.Path;
            if (carrierPath is null)
            {
                NativeMethods.CloseHandle(hProcess);
                hProcess = IntPtr.Zero;
                return InjectionResult.Fail(Method, dllPath, "Could not find a suitable system DLL to hollow (need SizeOfImage >= payload).");
            }

            fileHandle = NativeMethods.CreateFileW(carrierPath, GenericRead,
                FileShareRead | FileShareWrite | FileShareDelete,
                IntPtr.Zero, OpenExisting, FileAttributeNormal, IntPtr.Zero);
            if (fileHandle == IntPtr.Zero || fileHandle == invalidHandle)
            {
                fileHandle = IntPtr.Zero;
                NativeMethods.CloseHandle(hProcess);
                hProcess = IntPtr.Zero;
                return InjectionResult.Fail(Method, dllPath, "Could not open carrier DLL for SEC_IMAGE section: " + Win32Error.LastError());
            }

            var createStatus = DirectSyscalls.NtCreateSection(
                out sectionHandle,
                NativeConstants.SECTION_ALL_ACCESS,
                IntPtr.Zero,
                IntPtr.Zero, // MaximumSize NULL for SEC_IMAGE
                NativeConstants.PAGE_READONLY,
                NativeConstants.SEC_IMAGE,
                fileHandle);
            // Section holds its own file reference; the file handle can go away.
            NativeMethods.CloseHandle(fileHandle);
            fileHandle = IntPtr.Zero;

            if (createStatus != 0)
            {
                sectionHandle = IntPtr.Zero;
                NativeMethods.CloseHandle(hProcess);
                hProcess = IntPtr.Zero;
                return InjectionResult.Fail(Method, dllPath, $"NtCreateSection(SEC_IMAGE) failed: 0x{createStatus:X8}");
            }

            remoteBase = IntPtr.Zero;
            var mapStatus = DirectSyscalls.NtMapViewOfSection(
                sectionHandle, hProcess, ref remoteBase, IntPtr.Zero, UIntPtr.Zero,
                IntPtr.Zero, out viewSize, ViewUnmap, 0, NativeConstants.PAGE_READONLY);
            if (mapStatus != 0 || remoteBase == IntPtr.Zero)
            {
                DirectSyscalls.NtClose(sectionHandle);
                sectionHandle = IntPtr.Zero;
                NativeMethods.CloseHandle(hProcess);
                hProcess = IntPtr.Zero;
                return InjectionResult.Fail(Method, dllPath, $"NtMapViewOfSection failed: 0x{mapStatus:X8}");
            }

            if (viewSize.ToUInt64() < pe.SizeOfImage)
            {
                DirectSyscalls.NtUnmapViewOfSection(hProcess, remoteBase);
                DirectSyscalls.NtClose(sectionHandle);
                NativeMethods.CloseHandle(hProcess);
                hProcess = IntPtr.Zero;
                sectionHandle = IntPtr.Zero;
                return InjectionResult.Fail(Method, dllPath,
                    $"Carrier image is too small (0x{viewSize.ToUInt64():X} < payload 0x{pe.SizeOfImage:X}).");
            }

            // Backup the carrier extent before any overwrite so a failed
            // attempt can restore it while the hijacked thread is suspended
            // (no thread may execute the view mid-restoration).
            var carrierBackup = new byte[pe.SizeOfImage];
            if (DirectSyscalls.NtReadVirtualMemory(hProcess, remoteBase, carrierBackup, out var cbr) != 0 ||
                cbr.ToUInt64() != (ulong)carrierBackup.Length)
            {
                DirectSyscalls.NtUnmapViewOfSection(hProcess, remoteBase);
                DirectSyscalls.NtClose(sectionHandle);
                NativeMethods.CloseHandle(hProcess);
                hProcess = IntPtr.Zero;
                sectionHandle = IntPtr.Zero;
                return InjectionResult.Fail(Method, dllPath, "Could not back up the carrier view before hollowing.");
            }

            var threads = ProcessManager.GetThreads(pid).OrderBy(t => t.ThreadId).ToList();
            if (threads.Count == 0)
            {
                DirectSyscalls.NtUnmapViewOfSection(hProcess, remoteBase);
                DirectSyscalls.NtClose(sectionHandle);
                NativeMethods.CloseHandle(hProcess);
                return InjectionResult.Fail(Method, dllPath, "The target has no threads to hijack.");
            }

            foreach (var candidateThread in threads)
            {
                if (!TrySuspendCandidate(candidateThread.ThreadId, out var hThread, out var acquireError))
                {
                    if (acquireError is not null)
                    {
                        DirectSyscalls.NtUnmapViewOfSection(hProcess, remoteBase);
                        DirectSyscalls.NtClose(sectionHandle);
                        NativeMethods.CloseHandle(hProcess);
                        return InjectionResult.Fail(Method, dllPath, acquireError);
                    }
                    continue;
                }

                var outcome = TryHijackMapAndInit(
                    pid, hProcess, hThread, candidateThread.ThreadId, dllPath,
                    pe, remoteBase, (ulong)viewSize.ToUInt64(), carrierBackup, options,
                    out var initHazard);

                NativeMethods.CloseHandle(hThread);

                if (outcome is null)
                    continue; // Unsuitable thread (stack unknown/too small).

                if (outcome.Success || initHazard)
                {
                    // Mapping persists after handle close; keep the view mapped
                    // (success) or leave intact (hazard: thread may still run).
                    DirectSyscalls.NtClose(sectionHandle);
                    NativeMethods.CloseHandle(hProcess);
                    hProcess = IntPtr.Zero;
                    sectionHandle = IntPtr.Zero;
                    return outcome;
                }

                // Clean failure: unmap so no corrupted view remains.
                DirectSyscalls.NtUnmapViewOfSection(hProcess, remoteBase);
                DirectSyscalls.NtClose(sectionHandle);
                NativeMethods.CloseHandle(hProcess);
                hProcess = IntPtr.Zero;
                sectionHandle = IntPtr.Zero;
                return outcome;
            }

            DirectSyscalls.NtUnmapViewOfSection(hProcess, remoteBase);
            DirectSyscalls.NtClose(sectionHandle);
            NativeMethods.CloseHandle(hProcess);
            hProcess = IntPtr.Zero;
            sectionHandle = IntPtr.Zero;
            return InjectionResult.Fail(Method, dllPath,
                "No hijackable thread with a known, sufficiently large stack was found.");
        }
        catch (Exception ex)
        {
            if (remoteBase != IntPtr.Zero && hProcess != IntPtr.Zero)
                DirectSyscalls.NtUnmapViewOfSection(hProcess, remoteBase);
            if (sectionHandle != IntPtr.Zero)
                DirectSyscalls.NtClose(sectionHandle);
            if (hProcess != IntPtr.Zero)
                NativeMethods.CloseHandle(hProcess);
            hProcess = IntPtr.Zero;
            return InjectionResult.Fail(Method, dllPath, ex.Message);
        }
        finally
        {
            if (fileHandle != IntPtr.Zero && fileHandle != invalidHandle)
                NativeMethods.CloseHandle(fileHandle);
        }
    }

    private static (string? Path, uint SizeOfImage) FindSuitableSystemDll(uint pid, IntPtr hProcess, long payloadSize)
    {
        var systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var candidates = new[]
        {
            "mshtml.dll", "ieframe.dll", "windows.storage.dll", "shell32.dll",
            "comctl32.dll", "oleaut32.dll", "urlmon.dll", "shdocvw.dll", "browseui.dll",
            "msvcrt.dll", "d3d11.dll", "d2d1.dll", "wininet.dll", "crypt32.dll",
        };

        string? bestPath = null;
        uint bestSize = 0;

        foreach (var dll in candidates)
        {
            var fullPath = Path.Combine(systemDir, dll);
            if (!File.Exists(fullPath))
                continue;

            var remote = ProcessManager.GetRemoteModuleBase(pid, dll);
            if (remote == IntPtr.Zero)
                continue;

            if (!NativeMethods.GetModuleInformation(hProcess, remote, out var info,
                    (uint)Marshal.SizeOf<MODULEINFO>()) || info.SizeOfImage == 0)
                continue;

            if ((long)info.SizeOfImage < payloadSize)
                continue;

            // Prefer the smallest fitting carrier to reduce footprint.
            if (bestPath is null || info.SizeOfImage < bestSize)
            {
                bestPath = fullPath;
                bestSize = info.SizeOfImage;
            }
        }

        return (bestPath, bestSize);
    }

    private static InjectionResult? TryHijackMapAndInit(
        uint pid,
        IntPtr hProcess,
        IntPtr hThread,
        uint threadId,
        string dllPath,
        PeImage pe,
        IntPtr remoteBase,
        ulong viewSize,
        byte[] carrierBackup,
        InjectionOptions options,
        out bool initHazard)
    {
        initHazard = false;
        if (viewSize < pe.SizeOfImage)
            return InjectionResult.Fail(Method, dllPath, "Carrier view is smaller than the payload image.");
        var contextBuffer = IntPtr.Zero;
        CONTEXT_X64* ctx = null;
        var originalRip = 0UL;
        var redirected = false;
        var threadRunning = false;
        var leaveSuspended = false;
        var dataRegion = IntPtr.Zero;
        var codeRegion = IntPtr.Zero;
        var dependencies = new List<IntPtr>();
        // Set BEFORE the carrier write: a partial write or a throw below must
        // restore, never report "restored" without acting.
        var carrierDirty = false;

        bool Release()
        {
            if (threadRunning)
                return true;
            threadRunning = ResumeChecked(hThread);
            return threadRunning;
        }

        bool UndoRedirect()
        {
            if (!redirected || ctx == null)
                return true;
            ctx->Rip = originalRip;
            if (DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) == 0)
                redirected = false;
            return !redirected;
        }

        string RestoredOrCorrupt(bool restored, string restoredMsg, string corruptMsg)
            => restored ? restoredMsg : corruptMsg;

        // Failure exit while the hijack thread is suspended: restore first,
        // then resume. On restore failure nothing is resumed: the thread stays
        // suspended in the stub and the view is retained for restart.
        InjectionResult FailRestoredOrRetain(string restoredMsg, string corruptMsg)
        {
            var restored = RestoreCarrier();
            ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs);
            if (!restored)
            {
                initHazard = true;
                leaveSuspended = true;
                return InjectionResult.Fail(Method, dllPath, corruptMsg +
                    " Nothing was resumed; the thread was left suspended with the view intact. The target process should be restarted.");
            }
            if (!Release())
            {
                return InjectionResult.Fail(Method, dllPath, restoredMsg +
                    " WARNING: the final thread resume did not confirm; verify the target process.");
            }
            return InjectionResult.Fail(Method, dllPath, restoredMsg);
        }

        // Restores the carrier bytes. Callers must invoke this only while the
        // hijacked thread is suspended (or never redirected): no thread may
        // execute the view mid-restoration. Re-applies read-only protection
        // to match the original image mapping.
        bool RestoreCarrier()
        {
            var rwBase = remoteBase;
            var rwSize = (UIntPtr)(uint)carrierBackup.Length;
            if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref rwBase, ref rwSize, NativeConstants.PAGE_READWRITE, out _) != 0)
                return false;
            if (DirectSyscalls.NtWriteVirtualMemory(hProcess, remoteBase, carrierBackup, out var w) != 0 ||
                w.ToUInt64() != (ulong)carrierBackup.Length)
                return false;
            try
            {
                NativeMethods.FlushInstructionCacheChecked(hProcess, remoteBase, carrierBackup.Length);
            }
            catch
            {
                return false;
            }
            var roBase = remoteBase;
            var roSize = (UIntPtr)(uint)carrierBackup.Length;
            if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref roBase, ref roSize, NativeConstants.PAGE_READONLY, out _) != 0)
                return false;
            return true;
        }


        try
        {
            contextBuffer = CreateExtendedContext(out var contextPtr);
            if (contextBuffer == IntPtr.Zero)
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, "Could not create an extended thread context (XState support unavailable).");
            }

            ctx = (CONTEXT_X64*)contextPtr;
            if (DirectSyscalls.NtGetContextThread(hThread, (IntPtr)ctx) != 0)
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, "NtGetContextThread failed.");
            }

            originalRip = ctx->Rip;
            var originalRsp = ctx->Rsp;

            if (!TryGetTebInfo(hProcess, hThread, out var teb, out var stackLimit, out var lastError))
            {
                Release();
                return null;
            }

            if (originalRsp <= stackLimit || originalRsp - stackLimit < MinimumStackMargin)
            {
                Release();
                return null;
            }

            // ---- Reflective map into the file-backed view ----
            var image = ReflectiveMapper.BuildMappedImage(pe);
            var delta = (long)remoteBase.ToInt64() - (long)pe.ImageBase;
            if (!ReflectiveMapper.TryApplyRelocations(pe, image, delta, out var relocError))
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, relocError ?? "Relocation processing failed.");
            }

            var callbacks = ReflectiveMapper.ParseTlsCallbacks(pe, image, remoteBase, out var tlsError);
            if (tlsError is not null)
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, tlsError);
            }

            if (!ReflectiveMapper.TryGetExceptionTable(pe, image, remoteBase, out var exceptionTable, out var exceptionCount, out var excError))
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, excError ?? "Exception directory validation failed.");
            }

            var imports = ReflectiveMapper.ResolveImports(pe, image, pid, hProcess, options.TimeoutMs, dependencies,
                name => RemoteLoadLibrary(hProcess, pid, name, options.TimeoutMs));
            if (!imports.Ok)
            {
                if (imports.TimedOut)
                {
                    // Dependency thread may still run: do not touch loader again.
                    Release();
                    initHazard = true;
                    return InjectionResult.Fail(Method, dllPath, imports.Error ?? "Import resolution timed out; dependency state unknown, view left mapped.");
                }
                Release();
                ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs);
                return InjectionResult.Fail(Method, dllPath, imports.Error ?? "Import resolution failed.");
            }

            // The carrier view is mapped read-only: make the payload extent
            // writable BEFORE writing (a direct NtWrite cannot span guarded
            // pages, and may fail or partially write them).
            MakeImageWritable(hProcess, remoteBase, checked((int)pe.SizeOfImage));
            carrierDirty = true;
            SyscallWrite(hProcess, remoteBase, image);
            NativeMethods.FlushInstructionCacheChecked(hProcess, remoteBase, image.Length);
            ProtectMappedImage(pe, hProcess, remoteBase);

            var entryPoint = pe.AddressOfEntryPoint == 0
                ? IntPtr.Zero
                : IntPtr.Add(remoteBase, (int)pe.AddressOfEntryPoint);

            var lockFunction = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrLockLoaderLock");
            var unlockFunction = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrUnlockLoaderLock");
            var sleepFunction = RemoteFunctionResolver.Resolve(pid, "kernel32.dll", "Sleep");
            if (lockFunction == IntPtr.Zero || unlockFunction == IntPtr.Zero || sleepFunction == IntPtr.Zero)
            {
                // Thread still suspended: restore first, resume after.
                return FailRestoredOrRetain(
                    "Could not resolve loader-lock/Sleep functions in the target; carrier view restored.",
                    "Could not resolve loader-lock/Sleep functions AND carrier rollback failed; the view may be corrupted.");
            }

            IntPtr addFunctionTable = IntPtr.Zero, deleteFunctionTable = IntPtr.Zero;
            if (exceptionTable != IntPtr.Zero)
            {
                addFunctionTable = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "RtlAddFunctionTable");
                deleteFunctionTable = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "RtlDeleteFunctionTable");
                if (addFunctionTable == IntPtr.Zero || deleteFunctionTable == IntPtr.Zero)
                {
                    return FailRestoredOrRetain(
                        "Could not resolve RtlAddFunctionTable/RtlDeleteFunctionTable; carrier view restored.",
                        "Could not resolve RtlAddFunctionTable/RtlDeleteFunctionTable AND carrier rollback failed; the view may be corrupted.");
                }
            }

            // Separate allocations: data slots stay RW, code goes RX after the
            // write. NtProtect rounds the base down to the page boundary, so a
            // shared allocation would make the slots read-only and fault the
            // stub's result/cookie writes.
            const int slotsSize = 32;
            var placeholder = ReflectiveMapper.BuildHijackInitStub(
                remoteBase, callbacks, entryPoint, exceptionTable, exceptionCount,
                lockFunction, unlockFunction, addFunctionTable, deleteFunctionTable,
                sleepFunction, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            dataRegion = SyscallAlloc(hProcess, slotsSize);
            codeRegion = SyscallAllocCode(hProcess, placeholder.Length);
            var resultAddress = dataRegion;
            var doneAddress = IntPtr.Add(dataRegion, 8);
            var cookieAddress = IntPtr.Add(dataRegion, 16);
            var stubAddress = codeRegion;

            SyscallWrite(hProcess, dataRegion, new byte[slotsSize]);
            var initStub = ReflectiveMapper.BuildHijackInitStub(
                remoteBase, callbacks, entryPoint, exceptionTable, exceptionCount,
                lockFunction, unlockFunction, addFunctionTable, deleteFunctionTable,
                sleepFunction, resultAddress, doneAddress, cookieAddress);
            SyscallWrite(hProcess, codeRegion, initStub);
            NativeMethods.FlushInstructionCacheChecked(hProcess, codeRegion, initStub.Length);
            SyscallProtect(hProcess, codeRegion, initStub.Length, NativeConstants.PAGE_EXECUTE_READ);

            ctx->Rip = (ulong)stubAddress.ToInt64();
            if (DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) != 0)
            {
                FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);
                return FailRestoredOrRetain(
                    "NtSetContextThread failed; carrier view restored.",
                    "NtSetContextThread failed AND carrier rollback failed; the view may be corrupted.");
            }

            redirected = true;
            if (!Release())
            {
                if (!UndoRedirect())
                {
                    initHazard = true;
                    return InjectionResult.Fail(Method, dllPath,
                        "ResumeThread failed after redirect and the original context could not be restored; thread left suspended with stub mapped.");
                }
                // Thread suspended with its original RIP: restore first, then
                // resume it onto the restored carrier.
                FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);
                return FailRestoredOrRetain(
                    "ResumeThread failed after redirect; original context restored and carrier view restored.",
                    "ResumeThread failed after redirect; original context restored BUT carrier rollback failed; the view may be corrupted.");
            }

            if (!WaitForDone(hProcess, doneAddress, resultAddress, options.TimeoutMs, out var initResult, out var resultReadable))
            {
                // Timeout: thread may still execute stub/view. Retain everything.
                initHazard = true;
                return InjectionResult.Fail(Method, dllPath,
                    "The hijacked thread did not finish initialization; stub and mapped view were left intact and the thread may still be running.");
            }

            if (DirectSyscalls.NtSuspendThread(hThread, out _) != 0)
            {
                // Cannot confirm suspension: thread may still execute stub.
                initHazard = true;
                return InjectionResult.Fail(Method, dllPath,
                    "Could not re-suspend the hijacked thread to restore its state; stub and view left intact.");
            }
            threadRunning = false;

            // Read the outcome BEFORE restoring: result 4 means the thread may
            // still own the loader lock, in which case it must stay suspended
            // in the park loop and neither region may be freed.
            if (!resultReadable)
            {
                initHazard = true;
                leaveSuspended = true;
                return InjectionResult.Fail(Method, dllPath,
                    "The init result could not be read; the thread was left suspended in the stub with the view intact.");
            }

            if (initResult == 4)
            {
                initHazard = true;
                leaveSuspended = true;
                return InjectionResult.Fail(Method, dllPath,
                    "The target loader lock could not be released; the thread was left suspended in the stub (it may own the lock) with the view intact. " +
                    "This is fail-closed: resuming its original context under a held loader lock would deadlock future loader activity, so the target process should be restarted.");
            }

            // Outcomes 0/2/3 are handled HERE, while the thread is still
            // suspended in the park loop: a resume-then-re-suspend cycle would
            // leave a window where original code executes carrier bytes.
            // Restore first, then join the normal resume path below.
            string? rollbackNote = null;
            if (initResult is 0 or 2 or 3)
            {
                var restored = RestoreCarrier();
                ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs);
                if (!restored)
                {
                    initHazard = true;
                    leaveSuspended = true;
                    var corruptDetail = initResult switch
                    {
                        0 => "DllMain returned FALSE and the attach was rolled back BUT carrier restore failed; the view may be corrupted.",
                        2 => "RtlAddFunctionTable failed AND carrier restore failed; the view may be corrupted.",
                        _ => "Could not acquire the target loader lock AND carrier restore failed; the view may be corrupted.",
                    };
                    return InjectionResult.Fail(Method, dllPath, corruptDetail +
                        " Nothing was resumed; the thread was left suspended with the view intact. The target process should be restarted.");
                }
                rollbackNote = initResult switch
                {
                    0 => "DllMain returned FALSE; the attach was rolled back and the carrier view was restored.",
                    2 => "RtlAddFunctionTable failed; carrier view restored.",
                    _ => "Could not acquire the target loader lock; carrier view restored.",
                };
            }

            var lastErrorRestored = SyscallWriteU32(hProcess, IntPtr.Add(teb, TebLastErrorOffset), lastError);

            ctx->Rip = originalRip;
            if (DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) != 0 &&
                DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) != 0)
            {
                if (!UndoRedirect())
                {
                    initHazard = true;
                    return InjectionResult.Fail(Method, dllPath,
                        "Failed to restore the original thread context and the redirect could not be undone; thread left suspended with stub mapped.");
                }
                Release();
                FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);
                return InjectionResult.Fail(Method, dllPath, "Failed to restore the original thread context.");
            }
            redirected = false;

            if (!Release())
            {
                initHazard = true;
                return InjectionResult.Fail(Method, dllPath,
                    "ResumeThread failed after restoring the thread context; stub left mapped.");
            }

            // Thread no longer executes the stub: safe to release both regions.
            FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);

            // Rollback outcomes were restored in the suspended window above;
            // report them now that the thread runs the restored carrier again.
            if (rollbackNote is not null)
                return InjectionResult.Fail(Method, dllPath, rollbackNote);

            switch (initResult)
            {
                case 1:
                    // Authoritative base is the mapped view, not a DllMain boolean.
                    var ok = InjectionResult.Ok(Method, dllPath, remoteBase, threadId);
                    if (!lastErrorRestored)
                        ok.Warning = "The target TEB LastErrorValue could not be restored.";
                    return ok;
                case 0:
                case 2:
                case 3:
                    // Unreachable: handled in the suspended window above.
                    return InjectionResult.Fail(Method, dllPath, "Internal error: rollback outcome reached the post-resume switch.");
                case 5:
                    initHazard = true;
                    return InjectionResult.Fail(Method, dllPath, "DllMain returned FALSE and RtlDeleteFunctionTable failed; the mapped view was left intact.");
                default:
                    initHazard = true;
                    return InjectionResult.Fail(Method, dllPath, $"Image initialization returned an unexpected result ({initResult}); the mapped view was left intact.");
            }
        }
        catch (Exception ex)
        {
            var msg = ex.Message;
            // Thread safety first: while redirected (or possibly running) the
            // hijacked thread may execute the view, so no restore underneath it.
            if (redirected || threadRunning)
            {
                initHazard = true;
                msg += " The hijacked thread may still be executing the view; no rollback was attempted and the view was left intact.";
            }
            else if (carrierDirty)
            {
                var restored = RestoreCarrier();
                if (!restored)
                {
                    initHazard = true;
                    leaveSuspended = true;
                    msg += " WARNING: carrier rollback failed; the view may be corrupted. Nothing was resumed; the target process should be restarted.";
                }
                else
                {
                    msg += " The carrier view was restored.";
                }
            }
            return InjectionResult.Fail(Method, dllPath, msg);
        }
        finally
        {
            if (!leaveSuspended && !threadRunning && UndoRedirect())
                Release();
            // Free both regions only when no thread can execute them.
            if (!redirected && !leaveSuspended && !initHazard)
                FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);
            if (contextBuffer != IntPtr.Zero)
                NativeMemory.AlignedFree((void*)contextBuffer);
        }
    }

    #region syscall-backed remote helpers

    private static IntPtr SyscallAlloc(IntPtr hProcess, int size)
        => SectionMemory.Allocate(hProcess, size, NativeConstants.PAGE_READWRITE);

    // Code regions are backed executable from creation: a view mapped from a
    // non-executable section can never transition to RX later.
    private static IntPtr SyscallAllocCode(IntPtr hProcess, int size)
        => SectionMemory.Allocate(hProcess, size, NativeConstants.PAGE_EXECUTE_READWRITE);

    private static void SyscallFree(IntPtr hProcess, IntPtr address)
        => SectionMemory.Free(hProcess, address);

    private static void SyscallWrite(IntPtr hProcess, IntPtr address, byte[] data)
    {
        if (DirectSyscalls.NtWriteVirtualMemory(hProcess, address, data, out var written) != 0 ||
            written.ToUInt64() != (ulong)data.Length)
            throw new InvalidOperationException("NtWriteVirtualMemory failed or wrote a partial buffer.");
    }

    private static bool SyscallWriteU32(IntPtr hProcess, IntPtr address, uint value)
        => DirectSyscalls.NtWriteVirtualMemory(hProcess, address, BitConverter.GetBytes(value), out _) == 0;

    private static void SyscallProtect(IntPtr hProcess, IntPtr address, int size, uint protect)
    {
        var baseAddr = address;
        var region = (UIntPtr)(uint)size;
        var status = DirectSyscalls.NtProtectVirtualMemory(hProcess, ref baseAddr, ref region, protect, out _);
        if (status != 0)
            throw new InvalidOperationException($"NtProtectVirtualMemory failed: 0x{status:X8}");
    }

    private static void FreeStubRegions(IntPtr hProcess, ref IntPtr dataRegion, ref IntPtr codeRegion)
    {
        SyscallFree(hProcess, dataRegion);
        dataRegion = IntPtr.Zero;
        SyscallFree(hProcess, codeRegion);
        codeRegion = IntPtr.Zero;
    }

    private static void MakeImageWritable(IntPtr hProcess, IntPtr baseAddress, int size)
    {
        var baseAddr = baseAddress;
        var region = (UIntPtr)(uint)size;
        var status = DirectSyscalls.NtProtectVirtualMemory(hProcess, ref baseAddr, ref region, NativeConstants.PAGE_READWRITE, out _);
        if (status != 0)
            throw new InvalidOperationException($"Could not make the carrier view writable: 0x{status:X8}");
    }

    private static void ProtectMappedImage(PeImage pe, IntPtr hProcess, IntPtr remoteBase)
    {
        foreach (var s in pe.Sections)
        {
            if (s.VirtualAddress == 0)
                continue;
            var size = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (size == 0)
                continue;
            SyscallProtect(hProcess, IntPtr.Add(remoteBase, (int)s.VirtualAddress), (int)size,
                PeImage.CharacteristicsToProtection(s.Characteristics));
        }
        SyscallProtect(hProcess, remoteBase, (int)pe.SizeOfHeaders, NativeConstants.PAGE_READONLY);
    }

    private static (IntPtr Base, bool TimedOut) RemoteLoadLibrary(IntPtr hProcess, uint pid, string moduleName, int timeoutMs)
    {
        var baseAddr = RemoteLoadLibraryResult(hProcess, pid, moduleName, timeoutMs,
            out _, out var unsafeToFree, out _, out _);
        return (baseAddr, unsafeToFree);
    }

    private static bool ReleaseDependencies(IntPtr hProcess, uint pid, IReadOnlyList<IntPtr> dependencies, int timeoutMs)
    {
        if (dependencies.Count == 0)
            return true;
        var freeLibrary = RemoteFunctionResolver.Resolve(pid, "kernel32.dll", "FreeLibrary");
        if (freeLibrary == IntPtr.Zero)
            return false;
        for (var i = dependencies.Count - 1; i >= 0; i--)
        {
            var exec = RunRemoteThread(hProcess, freeLibrary, dependencies[i], timeoutMs);
            if (exec.UnsafeToFree || !exec.Created || exec.ExitCode == 0)
                return false;
        }
        return true;
    }

    #endregion

    private static bool TrySuspendCandidate(uint threadId, out IntPtr hThread, out string? error)
    {
        hThread = IntPtr.Zero;
        error = null;
        var handle = OpenRemoteThread(threadId, ThreadAccess);
        if (handle == IntPtr.Zero)
            return false;
        if (DirectSyscalls.NtSuspendThread(handle, out var previous) != 0)
        {
            NativeMethods.CloseHandle(handle);
            return false;
        }
        if (previous > 0)
        {
            if (!ResumeChecked(handle))
            {
                error = $"Could not restore thread {threadId}, which was already suspended. Aborting to avoid changing its state. " +
                        Win32Error.LastError();
                NativeMethods.CloseHandle(handle);
                return false;
            }
            NativeMethods.CloseHandle(handle);
            return false;
        }
        hThread = handle;
        return true;
    }

    private static IntPtr CreateExtendedContext(out IntPtr context)
    {
        context = IntPtr.Zero;
        const uint flags = NativeConstants.CONTEXT_ALL_X64 | NativeConstants.CONTEXT_XSTATE;
        var size = 0x1000u;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var buffer = (IntPtr)NativeMemory.AlignedAlloc((nuint)size, 64);
            var length = size;
            if (NativeMethods.InitializeContext(buffer, flags, out var ctx, ref length))
            {
                var features = NativeMethods.GetEnabledXStateFeatures();
                if (features != 0 && !NativeMethods.SetXStateFeaturesMask(ctx, features))
                {
                    NativeMemory.AlignedFree((void*)buffer);
                    return IntPtr.Zero;
                }
                context = ctx;
                return buffer;
            }
            NativeMemory.AlignedFree((void*)buffer);
            if (attempt != 0 || length == 0 || length == size)
                return IntPtr.Zero;
            size = length;
        }
        return IntPtr.Zero;
    }

    private static bool TryGetTebInfo(IntPtr hProcess, IntPtr hThread, out IntPtr teb, out ulong stackLimit, out uint lastError)
    {
        teb = IntPtr.Zero;
        stackLimit = 0;
        lastError = 0;
        if (DirectSyscalls.NtQueryTeb(hThread, out var tebBase) != 0 || tebBase == IntPtr.Zero)
            return false;
        teb = tebBase;

        var limit = new byte[8];
        if (DirectSyscalls.NtReadVirtualMemory(hProcess, IntPtr.Add(teb, TebStackLimitOffset), limit, out var lr) != 0 ||
            lr.ToUInt64() != 8)
            return false;
        stackLimit = BitConverter.ToUInt64(limit, 0);

        var err = new byte[4];
        if (DirectSyscalls.NtReadVirtualMemory(hProcess, IntPtr.Add(teb, TebLastErrorOffset), err, out var er) != 0 ||
            er.ToUInt64() != 4)
            return false;
        lastError = BitConverter.ToUInt32(err, 0);
        return true;
    }

    private static bool ResumeChecked(IntPtr hThread)
    {
        if (DirectSyscalls.NtResumeThread(hThread, out _) == 0)
            return true;
        return DirectSyscalls.NtResumeThread(hThread, out _) == 0;
    }

    private static bool WaitForDone(IntPtr hProcess, IntPtr doneSlot, IntPtr resultSlot, int timeoutMs, out long result, out bool resultReadable)
    {
        result = 0;
        resultReadable = false;
        var buffer = new byte[8];
        var deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (DirectSyscalls.NtReadVirtualMemory(hProcess, doneSlot, buffer, out var doneRead) == 0 &&
                doneRead.ToUInt64() == 8 &&
                BitConverter.ToInt64(buffer, 0) != 0)
            {
                if (DirectSyscalls.NtReadVirtualMemory(hProcess, resultSlot, buffer, out var resultRead) == 0 &&
                    resultRead.ToUInt64() == 8)
                {
                    result = BitConverter.ToInt64(buffer, 0);
                    resultReadable = true;
                }
                return true;
            }
            Thread.Sleep(5);
        }
        return false;
    }
}
