using Phantom.Core.Native;

namespace Phantom.Core.Processes;

/// <summary>
/// Enables SeDebugPrivilege on the current process so it may open and
/// manipulate arbitrary processes. Requires the process to be elevated.
/// </summary>
public static class Privileges
{
    public static bool EnableDebugPrivilege()
    {
        IntPtr token = IntPtr.Zero;
        if (!NativeMethods.OpenProcessToken(GetCurrentProcessPseudoHandle(),
                NativeConstants.TOKEN_ADJUST_PRIVILEGES | NativeConstants.TOKEN_QUERY, out token))
            return false;

        try
        {
            if (!NativeMethods.LookupPrivilegeValueW(null, "SeDebugPrivilege", out var luid))
                return false;

            var tp = new TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = NativeConstants.SE_PRIVILEGE_ENABLED
                }
            };

            if (!NativeMethods.AdjustTokenPrivileges(token, false, ref tp,
                    (uint)System.Runtime.InteropServices.Marshal.SizeOf<TOKEN_PRIVILEGES>(), IntPtr.Zero, IntPtr.Zero))
                return false;

            // AdjustTokenPrivileges returns TRUE even when it assigns nothing
            // (ERROR_NOT_ALL_ASSIGNED, 1300); check the captured last error.
            return System.Runtime.InteropServices.Marshal.GetLastWin32Error() == 0;
        }
        finally
        {
            NativeMethods.CloseHandle(token);
        }
    }

    private static IntPtr GetCurrentProcessPseudoHandle() => new(-1);
}
