using Phantom.Core.Injection;
using Phantom.Core.Native;

namespace Phantom.Core.PostInject;

/// <summary>
/// Applies the post-injection options (PE header erase, module hiding)
/// uniformly across every injection method.
/// </summary>
public static class PostInjectProcessor
{
    private const uint Access =
        NativeConstants.PROCESS_QUERY_INFORMATION |
        NativeConstants.PROCESS_VM_OPERATION |
        NativeConstants.PROCESS_VM_READ |
        NativeConstants.PROCESS_VM_WRITE |
        NativeConstants.PROCESS_CREATE_THREAD;

    /// <summary>
    /// Runs the requested post-injection steps. Returns <c>null</c> when every
    /// requested step succeeded, otherwise a description of what failed.
    /// </summary>
    public static string? Apply(uint pid, IntPtr moduleBase, InjectionOptions options)
    {
        if (moduleBase == IntPtr.Zero)
            return "post-inject skipped: module base unknown.";

        var hProcess = NativeMethods.OpenProcess(Access, false, pid);
        if (hProcess == IntPtr.Zero)
            return "post-inject failed: OpenProcess - " + Win32Error.LastError();

        try
        {
            var failures = new List<string>();

            if (options.ErasePeHeaders && !EraseHeaders(hProcess, moduleBase))
                failures.Add("erase PE headers");

            if (options.HideModule)
            {
                // Post-inject steps must never turn a successful injection into a
                // top-level error; convert any failure into a warning.
                try
                {
                    if (!LoaderLockUnlink.TryUnlink(pid, hProcess, moduleBase, out var hideError))
                        failures.Add("hide module (" + (hideError ?? "failed") + ")");
                }
                catch (Exception ex)
                {
                    failures.Add("hide module (" + ex.Message + ")");
                }
            }

            return failures.Count == 0 ? null : "post-inject failed: " + string.Join(", ", failures);
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    private static bool EraseHeaders(IntPtr hProcess, IntPtr moduleBase)
    {
        const int size = 0x1000;
        if (!NativeMethods.VirtualProtectEx(hProcess, moduleBase, (UIntPtr)size,
                NativeConstants.PAGE_READWRITE, out var oldProtect))
            return false;

        var ok = NativeMethods.WriteProcessMemory(hProcess, moduleBase, new byte[size], (UIntPtr)size, out _);

        NativeMethods.VirtualProtectEx(hProcess, moduleBase, (UIntPtr)size, oldProtect, out _);
        return ok;
    }
}
