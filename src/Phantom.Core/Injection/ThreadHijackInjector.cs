using System.Runtime.InteropServices;
using System.Text;
using Phantom.Core.Native;
using Phantom.Core.Processes;

namespace Phantom.Core.Injection;

/// <summary>
/// Injects by hijacking an existing thread. The thread is suspended, its full
/// OS-managed context (including XState such as AVX) is captured, RIP is
/// redirected to a stub that loads the module and then parks, and finally the
/// original context is re-applied so execution resumes exactly where it was.
/// No CreateRemoteThread is used, so it evades hooks on that API.
/// </summary>
internal sealed unsafe class ThreadHijackInjector : InjectorBase
{
    public override InjectionMethod Method => InjectionMethod.ThreadHijack;

    private const uint ThreadAccess =
        NativeConstants.THREAD_SUSPEND_RESUME |
        NativeConstants.THREAD_GET_CONTEXT |
        NativeConstants.THREAD_SET_CONTEXT |
        NativeConstants.THREAD_QUERY_INFORMATION;

    private const int MinimumStackMargin = 0x8000;
    private const int StubReserve = 0x200;
    private const int TebStackLimitOffset = 0x10;
    private const int TebLastErrorOffset = 0x68;

    public override InjectionResult Inject(uint pid, string dllPath, InjectionOptions options)
    {
        IntPtr hProcess = IntPtr.Zero;
        try
        {
            try
            {
                hProcess = OpenRemoteProcess(pid, InjectionAccess);
            }
            catch (Exception ex)
            {
                return InjectionResult.Fail(Method, dllPath, "OpenProcess failed: " + ex.Message);
            }

            var candidates = ProcessManager.GetThreads(pid).OrderBy(t => t.ThreadId).ToList();
            if (candidates.Count == 0)
                return InjectionResult.Fail(Method, dllPath, "The target has no threads to hijack.");

            foreach (var candidate in candidates)
            {
                if (!TrySuspendCandidate(candidate.ThreadId, out var hThread, out var acquireError))
                {
                    if (acquireError is not null)
                        return InjectionResult.Fail(Method, dllPath, acquireError);
                    continue;
                }

                var outcome = TryHijackThread(pid, hProcess, hThread, candidate.ThreadId, dllPath, options);
                NativeMethods.CloseHandle(hThread);

                if (outcome is not null)
                    return outcome;
            }

            return InjectionResult.Fail(Method, dllPath,
                "No hijackable thread with a known, sufficiently large stack was found.");
        }
        catch (Exception ex)
        {
            return InjectionResult.Fail(Method, dllPath, ex.Message);
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
                NativeMethods.CloseHandle(hProcess);
        }
    }

    /// <summary>
    /// Suspends a thread that is not already suspended. Returns false with a
    /// null error when the candidate should simply be skipped, and a non-null
    /// error when the thread's state could not be restored (fatal).
    /// </summary>
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
            // Someone else already suspended it; put it back exactly as it was.
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

    /// <summary>
    /// Attempts the hijack on an already-suspended thread. Returns null when the
    /// thread is unsuitable (stack state unknown or too small) so the caller can
    /// try the next one; otherwise a terminal result.
    /// </summary>
    private InjectionResult? TryHijackThread(uint pid, IntPtr hProcess, IntPtr hThread,
        uint threadId, string dllPath, InjectionOptions options)
    {
        IntPtr contextBuffer = IntPtr.Zero;
        var region = IntPtr.Zero;
        var threadRunning = false;
        CONTEXT_X64* ctx = null;
        var originalRip = 0UL;
        var redirected = false;

        // Releases our suspension if we still hold one.
        bool Release()
        {
            if (threadRunning)
                return true;

            threadRunning = ResumeChecked(hThread);
            return threadRunning;
        }

        // Only valid while the thread is suspended: puts the original context
        // back so a later resume cannot start an abandoned stub.
        bool UndoRedirect()
        {
            if (!redirected || ctx == null)
                return true;

            ctx->Rip = originalRip;
            if (DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) == 0)
                redirected = false;
            return !redirected;
        }

        try
        {
            contextBuffer = CreateExtendedContext(out var contextPtr);
            if (contextBuffer == IntPtr.Zero)
                return InjectionResult.Fail(Method, dllPath,
                    "Could not create an extended thread context (XState support unavailable).");

            ctx = (CONTEXT_X64*)contextPtr;
            if (DirectSyscalls.NtGetContextThread(hThread, (IntPtr)ctx) != 0)
                return InjectionResult.Fail(Method, dllPath, "NtGetContextThread failed.");

            originalRip = ctx->Rip;
            var originalRsp = ctx->Rsp;

            if (!TryGetTebInfo(hProcess, hThread, out var teb, out var stackLimit, out var lastError))
            {
                // Unknown stack limit is treated as unsuitable (fail closed).
                Release();
                return null;
            }

            if (originalRsp <= stackLimit || originalRsp - stackLimit < MinimumStackMargin)
            {
                Release();
                return null;
            }

            var pathBytes = Encoding.Unicode.GetBytes(dllPath + "\0");
            var resultOffset = Align(pathBytes.Length, 8);
            var doneOffset = resultOffset + 8;
            var stubOffset = Align(doneOffset + 8, 16);
            var regionSize = stubOffset + StubReserve;

            region = AllocateRemote(hProcess, regionSize, NativeConstants.PAGE_EXECUTE_READWRITE);
            var pathAddress = region;
            var resultAddress = IntPtr.Add(region, resultOffset);
            var doneAddress = IntPtr.Add(region, doneOffset);
            var stubAddress = IntPtr.Add(region, stubOffset);

            WriteRemote(hProcess, pathAddress, pathBytes);
            WriteRemote(hProcess, resultAddress, new byte[8]);
            WriteRemote(hProcess, doneAddress, new byte[8]);

            var loadLibrary = ResolveRemoteExport(pid, "kernel32.dll", "LoadLibraryW");
            var sleep = ResolveRemoteExport(pid, "kernel32.dll", "Sleep");
            var stub = BuildStub(loadLibrary, sleep, pathAddress, resultAddress, doneAddress);
            WriteRemote(hProcess, stubAddress, stub);
            NativeMethods.FlushInstructionCacheChecked(hProcess, stubAddress, stub.Length);

            ctx->Rip = (ulong)stubAddress.ToInt64();
            if (DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) != 0)
            {
                Release();
                return InjectionResult.Fail(Method, dllPath, "NtSetContextThread failed.");
            }

            redirected = true;
            if (!Release())
            {
                // Never resume a redirected thread unless the original context is
                // back; otherwise cleanup would start an abandoned stub.
                if (!UndoRedirect())
                    return InjectionResult.Fail(Method, dllPath,
                        "ResumeThread failed after redirecting the thread and the original context could not be restored; " +
                        "the thread was left suspended with its stub mapped.");

                Release();
                return InjectionResult.Fail(Method, dllPath,
                    "ResumeThread failed after redirecting the thread; the original context was restored. " + Win32Error.LastError());
            }

            if (!WaitForDone(hProcess, doneAddress, resultAddress, options.TimeoutMs, out var moduleBase, out var resultReadable))
                return InjectionResult.Fail(Method, dllPath,
                    "The hijacked thread did not finish loading; its stub was left intact and the thread may still be running.");

            // The stub is now parked: suspend, restore the original state, resume.
            if (DirectSyscalls.NtSuspendThread(hThread, out _) != 0)
                return InjectionResult.Fail(Method, dllPath,
                    "Could not re-suspend the hijacked thread to restore its state; it was left parked in the stub.");

            threadRunning = false;

            var lastErrorRestored = WriteUInt32(hProcess, IntPtr.Add(teb, TebLastErrorOffset), lastError);

            ctx->Rip = originalRip;
            if (DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) != 0 &&
                DirectSyscalls.NtSetContextThread(hThread, (IntPtr)ctx) != 0)
            {
                if (!UndoRedirect())
                    return InjectionResult.Fail(Method, dllPath,
                        "Failed to restore the original thread context and the redirect could not be undone; " +
                        "the thread was left suspended with its stub mapped.");

                Release();
                return InjectionResult.Fail(Method, dllPath, "Failed to restore the original thread context.");
            }

            redirected = false;
            if (!Release())
                return InjectionResult.Fail(Method, dllPath, "ResumeThread failed after restoring the thread context.");

            // The thread no longer executes the region, so it can be released.
            FreeRemote(hProcess, region);
            region = IntPtr.Zero;

            if (!resultReadable)
                return InjectionResult.Fail(Method, dllPath,
                    "The thread was restored but its recorded HMODULE could not be read; the load outcome is unknown.");

            if (moduleBase == 0)
                return InjectionResult.Fail(Method, dllPath, "LoadLibraryW returned NULL in the target.");

            // moduleBase is the full 64-bit HMODULE recorded by the stub and is
            // authoritative; a basename module-list match could return a
            // different module with the same filename.
            var baseAddress = new IntPtr(moduleBase);
            var result = InjectionResult.Ok(Method, dllPath, baseAddress, threadId);
            if (!lastErrorRestored)
                result.Warning = "The target TEB LastErrorValue could not be restored.";
            return result;
        }
        catch (Exception ex)
        {
            return InjectionResult.Fail(Method, dllPath, ex.Message);
        }
        finally
        {
            // Never resume a redirected thread without first putting the original
            // context back; if that cannot be done, leave it suspended.
            if (!threadRunning && UndoRedirect())
                Release();

            // If redirection was never installed (or was undone), no thread can
            // be executing the region, so it is safe to free it.
            if (!redirected && region != IntPtr.Zero)
            {
                FreeRemote(hProcess, region);
                region = IntPtr.Zero;
            }

            if (contextBuffer != IntPtr.Zero)
                NativeMemory.AlignedFree((void*)contextBuffer);
        }
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
                    // Cannot guarantee XState capture/restore: fail closed.
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

        var error = new byte[4];
        if (DirectSyscalls.NtReadVirtualMemory(hProcess, IntPtr.Add(teb, TebLastErrorOffset), error, out var er) != 0 ||
            er.ToUInt64() != 4)
            return false;
        lastError = BitConverter.ToUInt32(error, 0);

        return true;
    }

    private static bool ResumeChecked(IntPtr hThread)
    {
        if (DirectSyscalls.NtResumeThread(hThread, out _) == 0)
            return true;

        return DirectSyscalls.NtResumeThread(hThread, out _) == 0;
    }

    private static int Align(int value, int alignment)
        => (value + alignment - 1) & ~(alignment - 1);

    private static bool WaitForDone(IntPtr hProcess, IntPtr doneSlot, IntPtr resultSlot, int timeoutMs,
        out long result, out bool resultReadable)
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

    private static bool WriteUInt32(IntPtr hProcess, IntPtr address, uint value)
        => DirectSyscalls.NtWriteVirtualMemory(hProcess, address, BitConverter.GetBytes(value), out _) == 0;

    /// <summary>
    /// Builds the load stub. Because the full context is restored afterwards by
    /// the injector, the stub preserves nothing: it aligns the stack, calls
    /// LoadLibraryW, publishes the result and a done flag, then parks in a
    /// low-CPU Sleep(1) loop so the thread can be suspended and restored.
    /// </summary>
    private static byte[] BuildStub(IntPtr loadLibrary, IntPtr sleepFunction, IntPtr path, IntPtr resultSlot, IntPtr doneSlot)
    {
        var c = new List<byte>();

        c.AddRange(new byte[] { 0x48, 0x83, 0xE4, 0xF0 });                                    // and rsp, -16
        c.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x20 });                                    // sub rsp, 0x20
        c.Add(0x48); c.Add(0xB9); c.AddRange(BitConverter.GetBytes(path.ToInt64()));          // mov rcx, path
        c.Add(0x48); c.Add(0xB8); c.AddRange(BitConverter.GetBytes(loadLibrary.ToInt64()));   // mov rax, LoadLibraryW
        c.AddRange(new byte[] { 0xFF, 0xD0 });                                                // call rax
        c.Add(0x49); c.Add(0xBA); c.AddRange(BitConverter.GetBytes(resultSlot.ToInt64()));    // mov r10, result
        c.AddRange(new byte[] { 0x49, 0x89, 0x02 });                                          // mov [r10], rax
        c.Add(0x49); c.Add(0xBA); c.AddRange(BitConverter.GetBytes(doneSlot.ToInt64()));      // mov r10, done
        c.AddRange(new byte[] { 0x49, 0xC7, 0x02, 0x01, 0x00, 0x00, 0x00 });                  // mov qword [r10], 1

        // park: Sleep(1) loop (rbx is callee-saved, so it survives Sleep)
        c.Add(0x48); c.Add(0xBB); c.AddRange(BitConverter.GetBytes(sleepFunction.ToInt64())); // mov rbx, Sleep
        c.AddRange(new byte[] { 0xB9, 0x01, 0x00, 0x00, 0x00 });                              // mov ecx, 1
        c.AddRange(new byte[] { 0xFF, 0xD3 });                                                // call rbx
        c.AddRange(new byte[] { 0xEB, 0xF7 });                                                // jmp back to mov ecx, 1

        return c.ToArray();
    }
}
