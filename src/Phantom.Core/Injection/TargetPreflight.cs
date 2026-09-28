using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Preflight handle-access probe. Kernel protections (e.g. anti-cheat object
/// callbacks) strip dangerous rights from handles opened to the target; the
/// open itself still succeeds with a subset. Probing granted-vs-requested
/// access up front turns pages of confusing downstream failures into one
/// actionable message naming exactly which rights are missing.
/// </summary>
internal static class TargetPreflight
{
    public sealed record Result(
        bool Opened,
        int OpenStatus,
        uint Requested,
        uint Granted,
        string[] Missing,
        bool RightsQueried,
        int QueryStatus,
        string? ProbeError,
        TargetProcessIdentity? Target = null);

    public static Result Check(uint pid, uint requestedAccess, long? expectedCreationTime = null)
    {
        IntPtr hProcess = IntPtr.Zero;
        try
        {
            var openStatus = DirectSyscalls.NtOpenProcessByPid(out hProcess, requestedAccess, pid);
            if (openStatus != 0 || hProcess == IntPtr.Zero)
                return new Result(false, openStatus, requestedAccess, 0, Array.Empty<string>(), false, 0, null);

            // Preserve the original classification precedence: query granted
            // rights before calling APIs that themselves need query/sync rights.
            var queryStatus = DirectSyscalls.NtQueryGrantedAccess(hProcess, out var granted);
            // A failed rights query remains an unverified-rights result rather
            // than being misreported as a process-identity failure.
            if (queryStatus != 0)
                return new Result(true, 0, requestedAccess, 0, Array.Empty<string>(), false, queryStatus, null);

            var missing = RightsNames(requestedAccess & ~granted);
            if (missing.Length > 0)
                return new Result(true, 0, requestedAccess, granted, missing, true, 0, null);

            if (NativeMethods.GetProcessId(hProcess) != pid ||
                !NativeMethods.GetProcessTimes(hProcess, out var creationTime, out _, out _, out _))
                return new Result(false, 0, requestedAccess, 0, Array.Empty<string>(), false, 0,
                    "The target process identity could not be verified.");

            var creationFileTime = creationTime.ToInt64();
            if (NativeMethods.WaitForSingleObject(hProcess, 0) != NativeConstants.WAIT_TIMEOUT)
                return new Result(false, 0, requestedAccess, 0, Array.Empty<string>(), false, 0,
                    "The target process exited or its liveness could not be verified before preflight completed.");

            if (expectedCreationTime is long expected && creationFileTime != expected)
                return new Result(false, 0, requestedAccess, 0, Array.Empty<string>(), false, 0,
                    $"PID {pid} no longer refers to the process instance selected in the UI.");

            var target = TargetProcessIdentity.TakeOwnership(pid, hProcess, creationFileTime);
            hProcess = IntPtr.Zero;
            return new Result(true, 0, requestedAccess, granted, missing, true, 0, null, target);
        }
        catch (Exception ex)
        {
            // Syscall-stub initialization (or anything else unexpected) must
            // surface as a probe failure on the result, never as a throw out
            // of the public Inject entry point.
            return new Result(false, 0, requestedAccess, 0, Array.Empty<string>(), false, 0,
                ex.Message);
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
                NativeMethods.CloseHandle(hProcess);
        }
    }

    public static string[] RightsNames(uint mask)
    {
        if (mask == 0)
            return Array.Empty<string>();

        var names = new List<string>();
        void Add(uint bit, string name)
        {
            if ((mask & bit) != 0)
                names.Add(name);
        }

        Add(NativeConstants.PROCESS_CREATE_THREAD, nameof(NativeConstants.PROCESS_CREATE_THREAD));
        Add(NativeConstants.PROCESS_QUERY_INFORMATION, nameof(NativeConstants.PROCESS_QUERY_INFORMATION));
        Add(NativeConstants.PROCESS_QUERY_LIMITED_INFORMATION, nameof(NativeConstants.PROCESS_QUERY_LIMITED_INFORMATION));
        Add(NativeConstants.PROCESS_VM_OPERATION, nameof(NativeConstants.PROCESS_VM_OPERATION));
        Add(NativeConstants.PROCESS_VM_READ, nameof(NativeConstants.PROCESS_VM_READ));
        Add(NativeConstants.PROCESS_VM_WRITE, nameof(NativeConstants.PROCESS_VM_WRITE));
        Add(NativeConstants.PROCESS_SUSPEND_RESUME, nameof(NativeConstants.PROCESS_SUSPEND_RESUME));
        Add(NativeConstants.SYNCHRONIZE, nameof(NativeConstants.SYNCHRONIZE));

        var known = NativeConstants.PROCESS_CREATE_THREAD | NativeConstants.PROCESS_QUERY_INFORMATION |
                    NativeConstants.PROCESS_QUERY_LIMITED_INFORMATION | NativeConstants.PROCESS_VM_OPERATION |
                    NativeConstants.PROCESS_VM_READ | NativeConstants.PROCESS_VM_WRITE |
                    NativeConstants.PROCESS_SUSPEND_RESUME | NativeConstants.SYNCHRONIZE;
        var unknown = mask & ~known;
        if (unknown != 0)
            names.Add($"0x{unknown:X8}");

        return names.ToArray();
    }
}
