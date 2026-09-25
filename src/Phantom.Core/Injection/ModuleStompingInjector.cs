using System.Runtime.InteropServices;
using Phantom.Core.Native;
using Phantom.Core.Processes;

namespace Phantom.Core.Injection;

/// <summary>
/// Module Stomping: overwrites a non-critical loaded module's image with a
/// reflectively mapped payload (headers + sections by VA, relocations,
/// imports, TLS validation, section protections) and runs
/// DllMain(hModule, ATTACH, 0) on a hijacked thread. Original bytes are backed
/// up before the overwrite and restored on any clean failure, so a failed
/// attempt never leaves the host module corrupted. The reported base is the
/// stomped module base, never a DllMain boolean.
/// Safety: all other target threads are suspended across the backup/overwrite/
/// init window, because a running thread could otherwise fetch mixed or
/// overwritten instructions (unrecoverable by rollback). The sweep is
/// fail-closed (any unverified open/suspend aborts before any overwrite) and
/// keeps one owned count per thread so no other owner can resume one
/// mid-window. Residuals: a thread created after the suspend sweep is not
/// covered; swept-thread resume is verified with retry and surfaced on the
/// success result (a stuck resume stays suspended: fail-closed, detectable);
/// the tiny hijack stub is a temporary private allocation (RX after write,
/// freed only after the thread is confirmed restored).
/// </summary>
internal sealed unsafe class ModuleStompingInjector : InjectorBase
{
    public override InjectionMethod Method => InjectionMethod.ModuleStomping;

    private const uint ProcessAccess =
        NativeConstants.PROCESS_CREATE_THREAD |
        NativeConstants.PROCESS_QUERY_INFORMATION |
        NativeConstants.PROCESS_VM_OPERATION |
        NativeConstants.PROCESS_VM_WRITE |
        NativeConstants.PROCESS_VM_READ;

    private const uint ThreadAccess =
        NativeConstants.THREAD_SUSPEND_RESUME |
        NativeConstants.THREAD_GET_CONTEXT |
        NativeConstants.THREAD_SET_CONTEXT |
        NativeConstants.THREAD_QUERY_INFORMATION;

    private const int MinimumStackMargin = 0x8000;
    private const int TebStackLimitOffset = 0x10;
    private const int TebLastErrorOffset = 0x68;

    public override InjectionResult Inject(uint pid, string dllPath, InjectionOptions options)
    {
        IntPtr hProcess = IntPtr.Zero;
        try
        {
            DirectSyscalls.Initialize();

            PeImage pe;
            try
            {
                pe = new PeImage(File.ReadAllBytes(dllPath));
            }
            catch (BadImageFormatException ex)
            {
                return InjectionResult.Fail(Method, dllPath, "Invalid PE image: " + ex.Message);
            }

            hProcess = NativeMethods.OpenProcess(ProcessAccess, false, pid);
            if (hProcess == IntPtr.Zero)
                return InjectionResult.Fail(Method, dllPath, "OpenProcess failed: " + Win32Error.LastError(), NativeMethods.GetLastError());

            var stompTarget = FindStompTarget(hProcess, pe);
            var stompBase = stompTarget.BaseAddress;
            var stompPe = stompTarget.PeInfo;
            if (stompBase == IntPtr.Zero || stompPe is null)
            {
                NativeMethods.CloseHandle(hProcess);
                return InjectionResult.Fail(Method, dllPath, "Could not find a suitable module to stomp (need SizeOfImage and .text capacity >= payload).");
            }

            var threads = ProcessManager.GetThreads(pid).OrderBy(t => t.ThreadId).ToList();
            if (threads.Count == 0)
            {
                NativeMethods.CloseHandle(hProcess);
                return InjectionResult.Fail(Method, dllPath, "The target has no threads to hijack.");
            }

            foreach (var candidate in threads)
            {
                if (!TrySuspendCandidate(candidate.ThreadId, out var hThread, out var acquireError))
                {
                    if (acquireError is not null)
                    {
                        NativeMethods.CloseHandle(hProcess);
                        return InjectionResult.Fail(Method, dllPath, acquireError);
                    }
                    continue;
                }

                var outcome = TryHijackAndStomp(
                    pid, hProcess, hThread, candidate.ThreadId, dllPath,
                    pe, stompBase, stompPe, options,
                    out var corrupted);

                NativeMethods.CloseHandle(hThread);

                if (outcome is null)
                    continue; // Unsuitable thread.

                // On success or hazard the process handle is still ours to close;
                // the remote state (stomped image / parked stub) stays as reported.
                NativeMethods.CloseHandle(hProcess);
                hProcess = IntPtr.Zero;
                _ = corrupted;
                return outcome;
            }

            NativeMethods.CloseHandle(hProcess);
            hProcess = IntPtr.Zero;
            return InjectionResult.Fail(Method, dllPath, "No hijackable thread with a known, sufficiently large stack was found.");
        }
        catch (Exception ex)
        {
            if (hProcess != IntPtr.Zero)
                NativeMethods.CloseHandle(hProcess);
            return InjectionResult.Fail(Method, dllPath, ex.Message);
        }
    }

    private static (IntPtr BaseAddress, PeImage? PeInfo, string ModuleName) FindStompTarget(IntPtr hProcess, PeImage payload)
    {
        var payloadTextSize = PayloadTextSize(payload);
        var modules = new IntPtr[1024];
        if (!NativeMethods.EnumProcessModulesEx(hProcess, modules, (uint)(modules.Length * IntPtr.Size), out var needed, NativeConstants.LIST_MODULES_ALL))
            return (IntPtr.Zero, null, string.Empty);

        var count = needed / (uint)IntPtr.Size;
        var sb = new System.Text.StringBuilder(260);

        (IntPtr Base, PeImage? Pe, string Name, uint Size) best = (IntPtr.Zero, null, string.Empty, uint.MaxValue);

        for (var i = 0; i < count; i++)
        {
            if (NativeMethods.GetModuleBaseNameW(hProcess, modules[i], sb, 260) == 0)
                continue;
            var moduleName = sb.ToString();
            if (IsCriticalModule(moduleName))
                continue;
            if (!NativeMethods.GetModuleInformation(hProcess, modules[i], out var info,
                    (uint)Marshal.SizeOf<MODULEINFO>()) || info.SizeOfImage == 0)
                continue;
            if (info.SizeOfImage < payload.SizeOfImage)
                continue;

            var peData = new byte[info.SizeOfImage];
            if (DirectSyscalls.NtReadVirtualMemory(hProcess, info.lpBaseOfDll, peData, out var read) != 0 ||
                read.ToUInt64() != (ulong)peData.Length)
                continue;

            PeImage targetPe;
            try
            {
                targetPe = new PeImage(peData);
            }
            catch (BadImageFormatException)
            {
                continue;
            }

            var targetText = targetPe.Sections.FirstOrDefault(s => s.Name.StartsWith(".text", StringComparison.OrdinalIgnoreCase));
            if (targetText is null)
                continue;
            var targetTextSize = (long)Math.Max(targetText.VirtualSize, targetText.SizeOfRawData);
            if (targetTextSize < payloadTextSize)
                continue;

            // Prefer the smallest fitting host to reduce blast radius.
            if (info.SizeOfImage < best.Size)
                best = (info.lpBaseOfDll, targetPe, moduleName, info.SizeOfImage);
        }

        return (best.Base, best.Pe, best.Name);
    }

    private static long PayloadTextSize(PeImage payload)
    {
        long max = 0;
        foreach (var s in payload.Sections)
        {
            if (s.Name.StartsWith(".text", StringComparison.OrdinalIgnoreCase))
                max = Math.Max(max, (long)Math.Max(s.VirtualSize, s.SizeOfRawData));
        }
        // Fall back to whole image size when no .text (unusual for DLLs).
        return max > 0 ? max : payload.SizeOfImage;
    }

    private static bool IsCriticalModule(string moduleName)
    {
        return moduleName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("kernelbase.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("user32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("win32u.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("gdi32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("gdi32full.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("advapi32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("sechost.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("rpcrt4.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("combase.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("ucrtbase.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("msvcrt.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("msvcp_win.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("bcryptprimitives.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("imm32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("ws2_32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("psapi.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("version.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("shlwapi.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("cfgmgr32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("profapi.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("powrprof.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("ole32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("oleaut32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("clbcatq.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("shell32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("windows.storage.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("shcore.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("kernel.appcore.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("comctl32.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("uxtheme.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("dwmapi.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("sxs.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("apphelp.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("ntmarta.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("winmm.dll", StringComparison.OrdinalIgnoreCase)
            || moduleName.Equals("winmmbase.dll", StringComparison.OrdinalIgnoreCase);
    }

    private static InjectionResult? TryHijackAndStomp(
        uint pid,
        IntPtr hProcess,
        IntPtr hThread,
        uint threadId,
        string dllPath,
        PeImage pe,
        IntPtr remoteBase,
        PeImage targetPe,
        InjectionOptions options,
        out bool corrupted)
    {
        corrupted = false;
        var contextBuffer = IntPtr.Zero;
        CONTEXT_X64* ctx = null;
        var originalRip = 0UL;
        var redirected = false;
        var threadRunning = false;
        var leaveSuspended = false;
        // When the host may be corrupted, nothing is resumed: the hijacked
        // thread stays suspended (leaveSuspended) AND swept threads stay
        // suspended (retainAllSuspended). Releasing any thread into a
        // possibly-corrupt image is forbidden; the target must be restarted.
        var retainAllSuspended = false;
        var dataRegion = IntPtr.Zero;
        var codeRegion = IntPtr.Zero;
        var dependencies = new List<IntPtr>();
        byte[]? backup = null;
        var backupSize = checked((int)pe.SizeOfImage);
        // Set BEFORE the mutating call they guard, so a partial write or a
        // throw mid-call still triggers restoration instead of a false
        // "restored" report.
        var imageOverwritten = false;
        var protectionsChanged = false;
        // Original per-page protections across the full backup range, captured
        // before any change: the authoritative map for rollback (covers gaps
        // the sparse section list would miss).
        var origProtections = new List<(IntPtr Base, UIntPtr Size, uint Protect)>();
        var suspendedOthers = new List<IntPtr>();

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

        // Verifiable rollback: every step is status-checked, including byte
        // counts and the cache flush. Returns false when the host may still
        // be corrupted; callers must report that instead of claiming a restore.
        // Two modes: protection-only (!imageOverwritten) re-applies the saved
        // page protections without touching a single byte; byte rollback
        // rewrites the backup first, then restores saved protections across
        // EVERY page the whole-range RW touched (origProtections covers the
        // full range contiguously, unlike the sparse per-section list).
        bool RestoreBackup()
        {
            if (backup is null || (!protectionsChanged && !imageOverwritten))
                return true;
            if (!imageOverwritten)
            {
                foreach (var (b, s, old) in origProtections)
                {
                    var rb = b;
                    var rs = s;
                    if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref rb, ref rs, old, out _) != 0)
                        return false;
                }
                protectionsChanged = false;
                return true;
            }
            var rwBase = remoteBase;
            var rwSize = (UIntPtr)(uint)backupSize;
            if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref rwBase, ref rwSize, NativeConstants.PAGE_READWRITE, out _) != 0)
                return false;
            if (DirectSyscalls.NtWriteVirtualMemory(hProcess, remoteBase, backup, out var w) != 0 ||
                w.ToUInt64() != (ulong)backupSize)
                return false;
            try
            {
                NativeMethods.FlushInstructionCacheChecked(hProcess, remoteBase, backupSize);
            }
            catch
            {
                return false;
            }
            foreach (var (b, s, old) in origProtections)
            {
                var rb = b;
                var rs = s;
                if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref rb, ref rs, old, out _) != 0)
                    return false;
            }
            imageOverwritten = false;
            protectionsChanged = false;
            return true;
        }

        string RestoredOrCorrupt(bool restored, string restoredMsg, string corruptMsg)
            => restored ? restoredMsg : corruptMsg;

        // Idempotent: safe to call before terminal returns and again from
        // finally (second call is a no-op). Returns false when a live swept
        // thread could not be verified resumed.
        bool ResumeOthers()
        {
            if (suspendedOthers.Count == 0)
                return true;
            return ResumeSuspendedOthers(suspendedOthers);
        }

        // Failure exit while the hijack thread is suspended: restore first,
        // then resume. On restore failure nothing is resumed anywhere:
        // retain-all-suspended is set and the target must be restarted.
        InjectionResult FailRestoredOrRetainAll(string restoredMsg, string corruptMsg)
        {
            var restored = RestoreBackup();
            ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs);
            if (!restored)
            {
                corrupted = true;
                leaveSuspended = true;
                retainAllSuspended = true;
                return InjectionResult.Fail(Method, dllPath, corruptMsg +
                    " Nothing was resumed; the hijacked and swept threads were left suspended. The target process should be restarted.");
            }
            if (!Release())
            {
                return InjectionResult.Fail(Method, dllPath, restoredMsg +
                    " WARNING: the final thread resume did not confirm; verify the target process.");
            }
            return InjectionResult.Fail(Method, dllPath, restoredMsg);
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

            // ---- Suspend every other thread: a running thread could otherwise
            // execute the carrier mid-overwrite (unrecoverable by rollback). ----
            if (!SuspendOtherThreads(pid, threadId, suspendedOthers, out var suspendError))
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, suspendError ?? "Could not suspend target threads; host module untouched.");
            }

            // ---- Backup host bytes before any overwrite (rollback guarantee) ----
            backup = new byte[backupSize];
            if (DirectSyscalls.NtReadVirtualMemory(hProcess, remoteBase, backup, out var br) != 0 ||
                br.ToUInt64() != (ulong)backupSize)
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, "Could not back up the host module before stomping.");
            }

            // ---- Capture the original page protections before changing any --
            try
            {
                CapturePageProtections(hProcess, remoteBase, backupSize, origProtections);
            }
            catch (Exception ex)
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, "Could not query host page protections before stomping: " + ex.Message);
            }

            // ---- Build + validate payload image locally (no remote side effects) ----
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
                    Release();
                    corrupted = false; // Nothing written yet.
                    return InjectionResult.Fail(Method, dllPath, imports.Error ?? "Import resolution timed out; host module untouched.");
                }
                Release();
                ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs);
                return InjectionResult.Fail(Method, dllPath, imports.Error ?? "Import resolution failed; host module untouched.");
            }

            // ---- Overwrite: RW headers + overlapped host sections FIRST, then
            // write the complete image. A direct NtWrite cannot span guarded
            // pages, so writing before protecting risks failure/partial write.
            {
                var headerSize = (ulong)Math.Min(pe.SizeOfHeaders, (uint)backupSize);
                if (headerSize != 0)
                {
                    var hb = remoteBase;
                    var hs = (UIntPtr)headerSize;
                    if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref hb, ref hs, NativeConstants.PAGE_READWRITE, out _) != 0)
                    {
                        Release();
                        ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs);
                        return InjectionResult.Fail(Method, dllPath, "Could not make host headers writable; host module untouched.");
                    }
                    protectionsChanged = true;
                }
            }
            foreach (var s in targetPe.Sections)
            {
                if (s.VirtualAddress >= (uint)backupSize)
                    continue;
                var secBase = IntPtr.Add(remoteBase, (int)s.VirtualAddress);
                var secSize = (UIntPtr)Math.Min((ulong)Math.Max(s.VirtualSize, s.SizeOfRawData), (ulong)backupSize - s.VirtualAddress);
                if (secSize.ToUInt64() == 0)
                    continue;
                var pb = secBase;
                var ps = secSize;
                if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref pb, ref ps, NativeConstants.PAGE_READWRITE, out _) != 0)
                {
                    return FailRestoredOrRetainAll(
                        $"Could not make host section '{s.Name}' writable; original bytes restored.",
                        $"Could not make host section '{s.Name}' writable AND rollback failed; the host module may be corrupted.");
                }
                protectionsChanged = true;
            }

            // Hazard armed BEFORE the write: a partial write or a throw below
            // must restore, never report "restored" without acting.
            imageOverwritten = true;
            if (DirectSyscalls.NtWriteVirtualMemory(hProcess, remoteBase, image, out var written) != 0 ||
                written.ToUInt64() != (ulong)image.Length)
            {
                return FailRestoredOrRetainAll(
                    "Could not write the payload image; original bytes restored.",
                    "Could not write the payload image AND rollback failed; the host module may be corrupted.");
            }
            try
            {
                NativeMethods.FlushInstructionCacheChecked(hProcess, remoteBase, image.Length);
            }
            catch (Exception ex)
            {
                return FailRestoredOrRetainAll(
                    "Could not flush the payload image: " + ex.Message + " Original bytes restored.",
                    "Could not flush the payload image AND rollback failed; the host module may be corrupted. Flush error: " + ex.Message);
            }
            imageOverwritten = true;
            try
            {
                ApplyPayloadProtections(pe, hProcess, remoteBase);
            }
            catch (Exception ex)
            {
                return FailRestoredOrRetainAll(
                    "Could not protect payload sections: " + ex.Message + " Original bytes restored.",
                    "Could not protect payload sections AND rollback failed; the host module may be corrupted. Protect error: " + ex.Message);
            }

            var entryPoint = pe.AddressOfEntryPoint == 0
                ? IntPtr.Zero
                : IntPtr.Add(remoteBase, (int)pe.AddressOfEntryPoint);

            var lockFunction = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrLockLoaderLock");
            var unlockFunction = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrUnlockLoaderLock");
            var sleepFunction = RemoteFunctionResolver.Resolve(pid, "kernel32.dll", "Sleep");
            if (lockFunction == IntPtr.Zero || unlockFunction == IntPtr.Zero || sleepFunction == IntPtr.Zero)
            {
                return FailRestoredOrRetainAll(
                    "Could not resolve loader-lock/Sleep functions in the target; host module restored.",
                    "Could not resolve loader-lock/Sleep functions AND rollback failed; the host module may be corrupted.");
            }

            IntPtr addFunctionTable = IntPtr.Zero, deleteFunctionTable = IntPtr.Zero;
            if (exceptionTable != IntPtr.Zero)
            {
                addFunctionTable = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "RtlAddFunctionTable");
                deleteFunctionTable = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "RtlDeleteFunctionTable");
                if (addFunctionTable == IntPtr.Zero || deleteFunctionTable == IntPtr.Zero)
                {
                    return FailRestoredOrRetainAll(
                        "Could not resolve RtlAddFunctionTable/RtlDeleteFunctionTable; host module restored.",
                        "Could not resolve RtlAddFunctionTable/RtlDeleteFunctionTable AND rollback failed; the host module may be corrupted.");
                }
            }

            // Separate allocations: data slots stay RW, code goes RX after the
            // write (NtProtect rounds to page boundaries; sharing would make
            // the slots read-only and fault the stub's writes).
            const int slotsSize = 32;
            var placeholder = ReflectiveMapper.BuildHijackInitStub(
                remoteBase, callbacks, entryPoint, exceptionTable, exceptionCount,
                lockFunction, unlockFunction, addFunctionTable, deleteFunctionTable,
                sleepFunction, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            dataRegion = SyscallAlloc(hProcess, slotsSize);
            codeRegion = SyscallAlloc(hProcess, placeholder.Length);
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
                return FailRestoredOrRetainAll(
                    "NtSetContextThread failed; host module restored.",
                    "NtSetContextThread failed AND rollback failed; the host module may be corrupted.");
            }

            redirected = true;
            if (!Release())
            {
                if (!UndoRedirect())
                {
                    corrupted = true;
                    return InjectionResult.Fail(Method, dllPath,
                        "ResumeThread failed after redirect and the original context could not be restored; host module overwritten and thread left suspended.");
                }
                // Thread suspended with its original RIP: restore first, then
                // resume it onto the restored host.
                FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);
                return FailRestoredOrRetainAll(
                    "ResumeThread failed after redirect; original context restored and host module restored.",
                    "ResumeThread failed after redirect; original context restored BUT rollback failed, the host module may be corrupted.");
            }

            if (!WaitForDone(hProcess, doneAddress, resultAddress, options.TimeoutMs, out var initResult, out var resultReadable))
            {
                // Timeout: thread may still execute stub/stomped image. Retain.
                corrupted = true;
                return InjectionResult.Fail(Method, dllPath,
                    "The hijacked thread did not finish initialization; stub and stomped image were left intact and the thread may still be running.");
            }

            if (DirectSyscalls.NtSuspendThread(hThread, out _) != 0)
            {
                corrupted = true;
                return InjectionResult.Fail(Method, dllPath,
                    "Could not re-suspend the hijacked thread to restore its state; stub and stomped image left intact.");
            }
            threadRunning = false;

            // Read the outcome BEFORE restoring: result 4 means the thread may
            // still own the loader lock, in which case it must stay suspended
            // in the park loop and neither region may be freed.
            if (!resultReadable)
            {
                corrupted = true;
                leaveSuspended = true;
                return InjectionResult.Fail(Method, dllPath,
                    "The init result could not be read; the thread was left suspended in the stub with the stomped image intact.");
            }

            if (initResult == 4)
            {
                corrupted = true;
                leaveSuspended = true;
                return InjectionResult.Fail(Method, dllPath,
                    "The target loader lock could not be released; the thread was left suspended in the stub (it may own the lock) with the stomped image intact. " +
                    "This is fail-closed: resuming its original context under a held loader lock would deadlock future loader activity, so the target process should be restarted.");
            }

            // Outcomes 0/2/3 are handled HERE, while the thread is still
            // suspended in the park loop: a resume-then-re-suspend cycle would
            // leave a window where original code executes carrier bytes.
            // Restore first, then join the normal resume path below.
            string? rollbackNote = null;
            if (initResult is 0 or 2 or 3)
            {
                var restored = RestoreBackup();
                ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs);
                if (!restored)
                {
                    corrupted = true;
                    leaveSuspended = true;
                    retainAllSuspended = true;
                    var corruptDetail = initResult switch
                    {
                        0 => "DllMain returned FALSE and the attach was rolled back BUT host restore failed; the host module may be corrupted.",
                        2 => "RtlAddFunctionTable failed AND host restore failed; the host module may be corrupted.",
                        _ => "Could not acquire the target loader lock AND host restore failed; the host module may be corrupted.",
                    };
                    return InjectionResult.Fail(Method, dllPath, corruptDetail +
                        " Nothing was resumed; the hijacked and swept threads were left suspended. The target process should be restarted.");
                }
                rollbackNote = initResult switch
                {
                    0 => "DllMain returned FALSE; the attach was rolled back and the host module was restored.",
                    2 => "RtlAddFunctionTable failed; host module restored.",
                    _ => "Could not acquire the target loader lock; host module restored.",
                };
            }

            var lastErrorRestored = SyscallWriteU32(hProcess, IntPtr.Add(teb, TebLastErrorOffset), lastError);

            ctx->Rip = originalRip;
            if (DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) != 0 &&
                DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) != 0)
            {
                if (!UndoRedirect())
                {
                    corrupted = true;
                    return InjectionResult.Fail(Method, dllPath,
                        "Failed to restore the original thread context and the redirect could not be undone; thread left suspended in stomped image.");
                }
                Release();
                FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);
                // DllMain already ran; do NOT restore backup (would yank live code).
                corrupted = true;
                return InjectionResult.Fail(Method, dllPath, "Failed to restore the original thread context; stomped image left intact.");
            }
            redirected = false;

            if (!Release())
            {
                corrupted = true;
                return InjectionResult.Fail(Method, dllPath,
                    "ResumeThread failed after restoring the thread context; stub left mapped in stomped image.");
            }

            FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);

            // Rollback outcomes were restored in the suspended window above;
            // report them now that the thread runs the restored host again.
            if (rollbackNote is not null)
                return InjectionResult.Fail(Method, dllPath, rollbackNote);

            switch (initResult)
            {
                case 1:
                    // Resume swept threads before reporting: a resume failure
                    // must surface on the result, not behind the safety net.
                    var othersOk = ResumeOthers();
                    var ok = InjectionResult.Ok(Method, dllPath, remoteBase, threadId);
                    if (!lastErrorRestored)
                        ok.Warning = "The target TEB LastErrorValue could not be restored.";
                    if (!othersOk)
                        ok.Warning = ((ok.Warning is null ? "" : ok.Warning + " ") +
                            "WARNING: a swept target thread could not be verified resumed; inspect the target process.");
                    return ok;
                case 0:
                case 2:
                case 3:
                    // Unreachable: handled in the suspended window above.
                    return InjectionResult.Fail(Method, dllPath, "Internal error: rollback outcome reached the post-resume switch.");
                case 5:
                    corrupted = true;
                    return InjectionResult.Fail(Method, dllPath, "DllMain returned FALSE and RtlDeleteFunctionTable failed; the stomped image was left intact.");
                default:
                    corrupted = true;
                    return InjectionResult.Fail(Method, dllPath, $"Image initialization returned an unexpected result ({initResult}); the stomped image was left intact.");
            }
        }
        catch (Exception ex)
        {
            var msg = ex.Message;
            // Thread safety first: while redirected (or possibly running) the
            // hijacked thread may execute the stomped image, so restoring the
            // original bytes underneath it is forbidden. Retain everything.
            if (redirected || threadRunning)
            {
                corrupted = true;
                leaveSuspended = true;
                retainAllSuspended = true;
                msg += " The hijacked thread may still be executing the stomped image; no rollback was attempted and nothing was resumed. The target process should be restarted.";
            }
            else if ((protectionsChanged || imageOverwritten) && !corrupted && !redirected && !threadRunning)
            {
                // E.g. ApplyPayloadProtections threw after the overwrite, while
                // the hijack thread is still suspended: roll back instead of
                // leaving the carrier corrupted. Never restores under a
                // redirected or running thread. On failure nothing is resumed.
                var restored = RestoreBackup();
                if (!restored)
                {
                    corrupted = true;
                    leaveSuspended = true;
                    retainAllSuspended = true;
                    msg += " WARNING: host rollback failed; the carrier may be corrupted. Nothing was resumed; the target process should be restarted.";
                }
                else
                {
                    msg += " The host module was restored.";
                }
            }
            return InjectionResult.Fail(Method, dllPath, msg);
        }
        finally
        {
            if (!leaveSuspended && !threadRunning && UndoRedirect())
                Release();
            // On host-corruption retain, swept threads stay suspended too:
            // releasing anything into a possibly-corrupt image is forbidden.
            if (!retainAllSuspended)
                ResumeOthers();
            if (!redirected && !leaveSuspended && !corrupted && !retainAllSuspended)
            {
                // No live thread and no retained image: safe to release stub.
                // When corrupted/hazard is set, the stub stays mapped.
                FreeStubRegions(hProcess, ref dataRegion, ref codeRegion);
            }
            if (contextBuffer != IntPtr.Zero)
                NativeMemory.AlignedFree((void*)contextBuffer);
        }
    }

    #region syscall-backed remote helpers

    private static IntPtr SyscallAlloc(IntPtr hProcess, int size)
    {
        var baseAddr = IntPtr.Zero;
        var region = (UIntPtr)(uint)size;
        var status = DirectSyscalls.NtAllocateVirtualMemory(hProcess, ref baseAddr, IntPtr.Zero,
            ref region, NativeConstants.MEM_COMMIT | NativeConstants.MEM_RESERVE, NativeConstants.PAGE_READWRITE);
        if (status != 0 || baseAddr == IntPtr.Zero)
            throw new InvalidOperationException($"NtAllocateVirtualMemory failed: 0x{status:X8}");
        return baseAddr;
    }

    private static void SyscallFree(IntPtr hProcess, IntPtr address)
    {
        if (address != IntPtr.Zero)
            NativeMethods.VirtualFreeEx(hProcess, address, UIntPtr.Zero, NativeConstants.MEM_RELEASE);
    }

    private static void FreeStubRegions(IntPtr hProcess, ref IntPtr dataRegion, ref IntPtr codeRegion)
    {
        SyscallFree(hProcess, dataRegion);
        dataRegion = IntPtr.Zero;
        SyscallFree(hProcess, codeRegion);
        codeRegion = IntPtr.Zero;
    }

    /// <summary>
    /// Fail-closed sweep: suspends every thread in the target except
    /// <paramref name="excludeTid"/> and keeps one owned suspend count on each
    /// (including already-suspended ones, so no other owner can resume them
    /// mid-overwrite). Any unverified failure aborts before any overwrite;
    /// the host is untouched in that case. Only ERROR_INVALID_PARAMETER
    /// (unknown TID: raced exit) is treated as exited; every other open or
    /// suspend failure aborts.
    /// </summary>
    private const uint ErrorInvalidParameter = 87;

    private static bool SuspendOtherThreads(uint pid, uint excludeTid, List<IntPtr> suspended, out string? error)
    {
        error = null;
        List<uint> tids;
        try
        {
            tids = ProcessManager.GetThreads(pid).Select(t => t.ThreadId).OrderBy(t => t).ToList();
        }
        catch (Exception ex)
        {
            error = "Could not enumerate target threads, refusing to stomp: " + ex.Message;
            return false;
        }

        foreach (var tid in tids)
        {
            if (tid == excludeTid)
                continue;
            var h = NativeMethods.OpenThread(ThreadAccess, false, tid);
            if (h == IntPtr.Zero)
            {
                // Verified exit only: unknown TID means it raced away.
                // Anything else (e.g. access denial on a live thread) aborts.
                if (NativeMethods.GetLastError() == ErrorInvalidParameter)
                    continue;
                error = $"Could not open target thread {tid} ({Win32Error.LastError()}); refusing to stomp.";
                if (!ResumeSuspendedOthers(suspended))
                {
                    var stuck = suspended.Count;
                    AbandonSuspendedOthers(suspended);
                    error += $" In addition, {stuck} already-swept thread(s) could not be verified resumed; inspect the target process.";
                }
                return false;
            }
            var prev = NativeMethods.SuspendThread(h);
            if (prev == unchecked((uint)-1))
            {
                // Unverified: the handle was valid a moment ago, so this is
                // not a proven exit. Abort rather than run exposed.
                var suspendError = Win32Error.LastError();
                NativeMethods.CloseHandle(h);
                error = $"Could not suspend target thread {tid} ({suspendError}); refusing to stomp.";
                if (!ResumeSuspendedOthers(suspended))
                {
                    var stuck = suspended.Count;
                    AbandonSuspendedOthers(suspended);
                    error += $" In addition, {stuck} already-swept thread(s) could not be verified resumed; inspect the target process.";
                }
                return false;
            }
            // Keep our +1 even when prev > 0: the extra count stops another
            // owner from resuming this thread during the overwrite window.
            // ResumeOthers releases exactly one count, restoring the prior state.
            suspended.Add(h);
        }
        return true;
    }

    private const uint StillActive = 259;

    /// <summary>
    /// Captures the current protection of every page in
    /// [<paramref name="baseAddress"/>, +<paramref name="size"/>) via
    /// VirtualQueryEx, clipped to the range. The walk is contiguous, so the
    /// result covers the full range including gaps between sections.
    /// Throws on any query failure (caller aborts untouched).
    /// </summary>
    private static void CapturePageProtections(IntPtr hProcess, IntPtr baseAddress, int size,
        List<(IntPtr Base, UIntPtr Size, uint Protect)> pages)
    {
        var end = baseAddress.ToInt64() + size;
        var cursor = baseAddress.ToInt64();
        var querySize = (UIntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
        while (cursor < end)
        {
            if (NativeMethods.VirtualQueryEx(hProcess, (IntPtr)cursor, out var mbi, querySize) == UIntPtr.Zero)
                throw new InvalidOperationException("VirtualQueryEx failed: " + Win32Error.LastError());
            var regionEnd = mbi.BaseAddress.ToInt64() + (long)mbi.RegionSize;
            if (regionEnd <= cursor)
                throw new InvalidOperationException("VirtualQueryEx returned a degenerate region.");
            var clipStart = Math.Max(cursor, mbi.BaseAddress.ToInt64());
            var clipEnd = Math.Min(end, regionEnd);
            if (clipEnd > clipStart)
                pages.Add(((IntPtr)clipStart, (UIntPtr)(ulong)(clipEnd - clipStart), mbi.Protect));
            cursor = regionEnd;
        }
    }

    /// <summary>
    /// Exited-thread check for resume classification. Direct NtResumeThread
    /// returns NTSTATUS (not Win32), so Win32 GetLastError must NOT be used
    /// to classify its failures; liveness is verified via the thread exit code.
    /// </summary>
    private static bool ThreadExited(IntPtr hThread)
    {
        try
        {
            return NativeMethods.GetExitCodeThread(hThread, out var code) && code != StillActive;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryResumeOnce(IntPtr hThread)
        => DirectSyscalls.NtResumeThread(hThread, out _) == 0
            || DirectSyscalls.NtResumeThread(hThread, out _) == 0;

    /// <summary>
    /// Releases one owned suspend count per swept thread (two NTSTATUS-checked
    /// attempts each). A thread proven exited via its exit code counts as done.
    /// Handles that cannot be verified resumed are KEPT in the list (not
    /// closed or cleared) so the finally safety net can retry them; returns
    /// false in that case and the caller must surface it.
    /// </summary>
    private static bool ResumeSuspendedOthers(List<IntPtr> suspended)
    {
        var ok = true;
        for (var i = suspended.Count - 1; i >= 0; i--)
        {
            var h = suspended[i];
            if (TryResumeOnce(h) || ThreadExited(h))
            {
                NativeMethods.CloseHandle(h);
                suspended.RemoveAt(i);
            }
            else
            {
                ok = false;
            }
        }
        return ok;
    }

    /// <summary>
    /// Closes leftover sweep handles without resuming (abort paths only: the
    /// host is untouched, so leaking a suspend count is worse than abandoning
    /// the handle; a thread that truly will not resume stays suspended and
    /// detectable rather than running exposed).
    /// </summary>
    private static void AbandonSuspendedOthers(List<IntPtr> suspended)
    {
        foreach (var h in suspended)
            NativeMethods.CloseHandle(h);
        suspended.Clear();
    }

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
        if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref baseAddr, ref region, protect, out _) != 0)
            throw new InvalidOperationException("NtProtectVirtualMemory failed.");
    }

    private static void ApplyPayloadProtections(PeImage pe, IntPtr hProcess, IntPtr remoteBase)
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
            out _, out var unsafeToFree, out _);
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
        var handle = NativeMethods.OpenThread(ThreadAccess, false, threadId);
        if (handle == IntPtr.Zero)
            return false;
        var previous = NativeMethods.SuspendThread(handle);
        if (previous == unchecked((uint)-1))
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
