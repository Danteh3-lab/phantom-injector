using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Pins the process instance selected for an injection and validates every
/// later PID-based reopen against that instance's creation time.
/// </summary>
internal sealed class TargetProcessIdentity : IDisposable
{
    private static readonly AsyncLocal<TargetProcessIdentity?> Active = new();
    private IntPtr _handle;

    private TargetProcessIdentity(uint pid, IntPtr handle, long creationTime)
    {
        Pid = pid;
        _handle = handle;
        CreationTime = creationTime;
    }

    public uint Pid { get; }
    public long CreationTime { get; }
    public IntPtr Handle => _handle != IntPtr.Zero
        ? _handle
        : throw new ObjectDisposedException(nameof(TargetProcessIdentity));

    public static TargetProcessIdentity TakeOwnership(uint pid, IntPtr handle, long creationTime)
        => new(pid, handle, creationTime);

    public static TargetProcessIdentity? Current => Active.Value;

    public IDisposable EnterScope()
    {
        var previous = Active.Value;
        Active.Value = this;
        return new Scope(() => Active.Value = previous);
    }

    public bool MatchesHandle(IntPtr handle, bool requireRunning, out string? error)
    {
        error = null;
        if (handle == IntPtr.Zero || NativeMethods.GetProcessId(handle) != Pid)
        {
            error = "The process handle PID could not be verified.";
            return false;
        }

        if (!NativeMethods.GetProcessTimes(handle, out var created, out _, out _, out _))
        {
            error = "The process creation time could not be verified.";
            return false;
        }

        if (created.ToInt64() != CreationTime)
        {
            error = $"PID {Pid} now refers to a different process instance.";
            return false;
        }

        if (requireRunning && NativeMethods.WaitForSingleObject(handle, 0) != NativeConstants.WAIT_TIMEOUT)
        {
            error = $"The selected process (PID {Pid}) has exited or its liveness could not be verified.";
            return false;
        }

        return true;
    }

    /// <summary>Opens the selected PID and returns it only if that exact handle
    /// still refers to this process instance.</summary>
    public IntPtr OpenVerifiedHandle(uint access)
    {
        var status = DirectSyscalls.NtOpenProcessByPid(out var handle,
            access | NativeConstants.SYNCHRONIZE, Pid);
        if (status != 0 || handle == IntPtr.Zero)
            throw new InvalidOperationException($"NtOpenProcess failed: {NtStatus.Describe(status)}");

        if (MatchesHandle(handle, requireRunning: true, out var error))
            return handle;

        NativeMethods.CloseHandle(handle);
        throw new InvalidOperationException(error ?? "The target process identity could not be verified.");
    }

    /// <summary>Validates a thread handle before it can be suspended or have its
    /// context changed. The opened thread handle pins the exact thread after the
    /// owner identity check.</summary>
    public bool MatchesThread(IntPtr threadHandle)
    {
        if (threadHandle == IntPtr.Zero || NativeMethods.GetProcessIdOfThread(threadHandle) != Pid)
            return false;

        IntPtr processHandle;
        try
        {
            processHandle = OpenVerifiedHandle(NativeConstants.PROCESS_QUERY_INFORMATION);
        }
        catch
        {
            return false;
        }

        NativeMethods.CloseHandle(processHandle);
        return true;
    }

    public void Dispose()
    {
        var handle = Interlocked.Exchange(ref _handle, IntPtr.Zero);
        if (handle != IntPtr.Zero)
            NativeMethods.CloseHandle(handle);
    }

    private sealed class Scope(Action dispose) : IDisposable
    {
        private Action? _dispose = dispose;
        public void Dispose() => Interlocked.Exchange(ref _dispose, null)?.Invoke();
    }
}
