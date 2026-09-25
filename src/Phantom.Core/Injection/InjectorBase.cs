using System.Runtime.InteropServices;
using Phantom.Core.Native;
using Phantom.Core.Processes;

namespace Phantom.Core.Injection;

/// <summary>
/// Shared low-level helpers for remote memory manipulation and export
/// resolution used by every injection method.
/// </summary>
internal abstract class InjectorBase : IInjector
{
    public abstract InjectionMethod Method { get; }

    public abstract InjectionResult Inject(uint pid, string dllPath, InjectionOptions options);

    internal const uint InjectionAccess =
        NativeConstants.PROCESS_CREATE_THREAD |
        NativeConstants.PROCESS_QUERY_INFORMATION |
        NativeConstants.PROCESS_VM_OPERATION |
        NativeConstants.PROCESS_VM_WRITE |
        NativeConstants.PROCESS_VM_READ;

    /// <summary>
    /// Open mask for the pure-hijack core path, which never creates a remote
    /// thread. Single source of truth shared by ThreadHijack's actual open
    /// and the preflight gate, so a stripped CREATE_THREAD cannot false-block
    /// a method that never uses it.
    /// </summary>
    internal const uint HijackAccess =
        NativeConstants.PROCESS_QUERY_INFORMATION |
        NativeConstants.PROCESS_VM_OPERATION |
        NativeConstants.PROCESS_VM_WRITE |
        NativeConstants.PROCESS_VM_READ;

    /// <summary>
    /// Opens a target process handle via direct syscall (no usermode hooks).
    /// </summary>
    protected static IntPtr OpenRemoteProcess(uint pid, uint access)
    {
        var status = DirectSyscalls.NtOpenProcessByPid(out var hProcess, access, pid);
        if (status != 0 || hProcess == IntPtr.Zero)
            throw new InvalidOperationException($"NtOpenProcess failed: {NtStatus.Describe(status)}");
        return hProcess;
    }

    /// <summary>
    /// Opens a target thread handle via direct syscall. Returns Zero on
    /// failure (mirrors OpenThread semantics); callers check for Zero.
    /// </summary>
    protected static IntPtr OpenRemoteThread(uint tid, uint access)
    {
        var status = DirectSyscalls.NtOpenThreadByTid(out var hThread, access, tid);
        if (status != 0 || hThread == IntPtr.Zero)
            return IntPtr.Zero;
        return hThread;
    }

    protected static IntPtr AllocateRemote(IntPtr hProcess, int size, uint protect = NativeConstants.PAGE_READWRITE)
        => SectionMemory.Allocate(hProcess, size, protect);

    protected static void WriteRemote(IntPtr hProcess, IntPtr address, byte[] data)
    {
        if (DirectSyscalls.NtWriteVirtualMemory(hProcess, address, data, out var written) != 0)
            throw new InvalidOperationException("NtWriteVirtualMemory failed.");
        if (written.ToUInt64() != (ulong)data.Length)
            throw new InvalidOperationException("NtWriteVirtualMemory wrote a partial buffer.");
    }

    /// <summary>
    /// Writes a UTF-16 path into freshly allocated remote memory and returns the address.
    /// Allocations are tracked by the caller for cleanup.
    /// </summary>
    protected static IntPtr WriteRemoteString(IntPtr hProcess, string text, out int byteLength)
    {
        var bytes = System.Text.Encoding.Unicode.GetBytes(text + "\0");
        byteLength = bytes.Length;
        var addr = AllocateRemote(hProcess, bytes.Length);
        try
        {
            WriteRemote(hProcess, addr, bytes);
        }
        catch
        {
            // The caller never sees the address if the write fails, so release it here.
            FreeRemote(hProcess, addr);
            throw;
        }

        return addr;
    }

    /// <summary>
    /// Resolves an export inside the target process, accounting for forwarded
    /// exports by rebasing against the module that owns the address.
    /// </summary>
    protected static IntPtr ResolveRemoteExport(uint pid, string moduleName, string functionName)
    {
        var resolved = RemoteFunctionResolver.Resolve(pid, moduleName, functionName);
        if (resolved == IntPtr.Zero)
            throw new InvalidOperationException($"Could not resolve '{moduleName}!{functionName}' in the target process.");
        return resolved;
    }

    protected static void FreeRemote(IntPtr hProcess, IntPtr address)
        => SectionMemory.Free(hProcess, address);

    protected static bool TryReadRemoteInt64(IntPtr hProcess, IntPtr address, out long value)
    {
        var buffer = new byte[8];
        if (DirectSyscalls.NtReadVirtualMemory(hProcess, address, buffer, out var read) != 0 ||
            read.ToUInt64() != 8)
        {
            value = 0;
            return false;
        }

        value = BitConverter.ToInt64(buffer, 0);
        return true;
    }

    /// <summary>
    /// Calls LoadLibraryW in the target through a stub that records the full
    /// 64-bit HMODULE in remote memory. This avoids both the 32-bit thread exit
    /// code and any basename-based module lookup.
    /// <paramref name="unsafeToFree"/> means the remote thread may still be
    /// executing, so its buffers must be left mapped; <paramref name="resultUnknown"/>
    /// means the thread finished but the recorded result could not be read
    /// (its buffers are safe to release). <paramref name="createStatus"/> carries
    /// the thread-creation NTSTATUS so callers can tell a failed creation apart
    /// from a completed load that returned NULL.
    /// </summary>
    protected static IntPtr RemoteLoadLibraryResult(IntPtr hProcess, uint pid, string pathOrName,
        int timeoutMs, out bool resultUnknown, out bool unsafeToFree, out uint threadId, out int createStatus)
    {
        resultUnknown = false;
        unsafeToFree = false;
        threadId = 0;
        createStatus = 0;

        var remotePath = IntPtr.Zero;
        var resultAddress = IntPtr.Zero;
        var stubAddress = IntPtr.Zero;
        try
        {
            var loadLibrary = ResolveRemoteExport(pid, "kernel32.dll", "LoadLibraryW");
            remotePath = WriteRemoteString(hProcess, pathOrName, out _);
            resultAddress = AllocateRemote(hProcess, 8);
            WriteRemote(hProcess, resultAddress, new byte[8]);

            var stub = BuildLoadLibraryStub(loadLibrary, remotePath, resultAddress);
            stubAddress = AllocateRemote(hProcess, stub.Length, NativeConstants.PAGE_EXECUTE_READWRITE);
            WriteRemote(hProcess, stubAddress, stub);
            NativeMethods.FlushInstructionCacheChecked(hProcess, stubAddress, stub.Length);

            var exec = RunRemoteThread(hProcess, stubAddress, IntPtr.Zero, timeoutMs);
            threadId = exec.ThreadId;
            createStatus = exec.Status;

            if (exec.UnsafeToFree)
            {
                unsafeToFree = true;
                return IntPtr.Zero;
            }

            if (!exec.Created)
                return IntPtr.Zero;

            if (!TryReadRemoteInt64(hProcess, resultAddress, out var result))
            {
                resultUnknown = true;
                return IntPtr.Zero;
            }

            return new IntPtr(result);
        }
        finally
        {
            // Setup exceptions and normal completion both release the buffers;
            // only a thread that may still execute keeps them mapped.
            if (!unsafeToFree)
            {
                FreeRemote(hProcess, stubAddress);
                FreeRemote(hProcess, resultAddress);
                FreeRemote(hProcess, remotePath);
            }
        }
    }

    private static byte[] BuildLoadLibraryStub(IntPtr loadLibrary, IntPtr path, IntPtr resultAddress)
    {
        var code = new List<byte>();
        code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 });                                    // sub rsp, 0x28
        code.Add(0x48); code.Add(0xB9); code.AddRange(BitConverter.GetBytes(path.ToInt64()));    // mov rcx, path
        code.Add(0x48); code.Add(0xB8); code.AddRange(BitConverter.GetBytes(loadLibrary.ToInt64()));
        code.AddRange(new byte[] { 0xFF, 0xD0 });                                                // call rax
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(resultAddress.ToInt64()));
        code.AddRange(new byte[] { 0x49, 0x89, 0x02 });                                          // mov [r10], rax
        code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 });                                    // add rsp, 0x28
        code.Add(0xC3);                                                                          // ret
        return code.ToArray();
    }

    /// <summary>
    /// Runs a remote thread at <paramref name="start"/> (created via direct
    /// NtCreateThreadEx syscall) and waits for completion.
    /// On timeout the thread handle is closed but the thread keeps running, so
    /// the caller must not free any memory that thread can still reach.
    /// </summary>
    protected static RemoteThreadResult RunRemoteThread(IntPtr hProcess, IntPtr start, IntPtr parameter, int timeoutMs)
    {
        var status = DirectSyscalls.NtCreateThreadEx(out var hThread, NativeConstants.THREAD_ALL_ACCESS,
            IntPtr.Zero, hProcess, start, parameter, 0,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (status != 0 || hThread == IntPtr.Zero)
            return new RemoteThreadResult { Created = false, Status = status };

        // NtCreateThreadEx reports no TID: query it via syscall instead of
        // falling back to a hooked Win32 lookup. Strictly informational, so a
        // throwing query (stub resolution, marshalling) must never escape and
        // let callers free the stub while this thread is running it.
        uint threadId = 0;
        try
        {
            DirectSyscalls.NtQueryThreadId(hThread, out threadId);
        }
        catch
        {
            threadId = 0;
        }

        try
        {
            var wait = NativeMethods.WaitForSingleObject(hThread, (uint)timeoutMs);
            if (wait == NativeConstants.WAIT_TIMEOUT)
                return new RemoteThreadResult { Created = true, TimedOut = true, ThreadId = threadId };

            // A failed wait means the outcome is unknown: the thread may still run.
            if (wait == NativeConstants.WAIT_FAILED)
                return new RemoteThreadResult { Created = true, WaitFailed = true, ThreadId = threadId };

            if (!NativeMethods.GetExitCodeThread(hThread, out var exitCode))
                return new RemoteThreadResult { Created = true, WaitFailed = true, ThreadId = threadId };

            return new RemoteThreadResult { Created = true, ExitCode = exitCode, ThreadId = threadId };
        }
        finally
        {
            NativeMethods.CloseHandle(hThread);
        }
    }

    protected static int SizeOfContext() => CONTEXT_X64.Size;
}
