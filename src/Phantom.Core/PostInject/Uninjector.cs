using Phantom.Core.Native;

namespace Phantom.Core.PostInject;

/// <summary>
/// Unloads a previously injected module via a remote FreeLibrary call.
/// </summary>
public static class Uninjector
{
    private const uint Access =
        NativeConstants.PROCESS_CREATE_THREAD |
        NativeConstants.PROCESS_QUERY_INFORMATION |
        NativeConstants.PROCESS_VM_OPERATION |
        NativeConstants.PROCESS_VM_WRITE |
        NativeConstants.PROCESS_VM_READ;

    public static bool Unload(uint pid, IntPtr moduleBase)
    {
        IntPtr hProcess = IntPtr.Zero;
        try
        {
            var openStatus = DirectSyscalls.NtOpenProcessByPid(out hProcess, Access, pid);
            if (openStatus != 0 || hProcess == IntPtr.Zero)
            {
                hProcess = IntPtr.Zero;
                return false;
            }

            var freeLibrary = RemoteFunctionResolver.Resolve(pid, "kernel32.dll", "FreeLibrary");
            if (freeLibrary == IntPtr.Zero)
                return false;

            // The remote thread entry takes one parameter; FreeLibrary wants
            // the module base in RCX, which is exactly the first argument.
            // Created via direct syscall (no usermode hooks).
            var createStatus = DirectSyscalls.NtCreateThreadEx(out var hThread, NativeConstants.THREAD_ALL_ACCESS,
                IntPtr.Zero, hProcess, freeLibrary, moduleBase, 0,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (createStatus != 0 || hThread == IntPtr.Zero)
                return false;

            try
            {
                // A thread that is still running reports STILL_ACTIVE (259), so a
                // timeout must not be mistaken for a successful unload.
                var wait = NativeMethods.WaitForSingleObject(hThread, 5000);
                if (wait != NativeConstants.WAIT_OBJECT_0)
                    return false;

                if (!NativeMethods.GetExitCodeThread(hThread, out var exitCode))
                    return false;

                return exitCode != 0;
            }
            finally
            {
                NativeMethods.CloseHandle(hThread);
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
                NativeMethods.CloseHandle(hProcess);
        }
    }
}
