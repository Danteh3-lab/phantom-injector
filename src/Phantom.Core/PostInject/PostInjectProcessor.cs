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

        IntPtr hProcess;
        {
            var openStatus = DirectSyscalls.NtOpenProcessByPid(out var opened, Access, pid);
            if (openStatus != 0 || opened == IntPtr.Zero)
                return $"post-inject failed: NtOpenProcess - 0x{openStatus:X8}";
            hProcess = opened;
        }

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
        var baseAddr = moduleBase;
        var region = (UIntPtr)size;
        if (DirectSyscalls.NtProtectVirtualMemory(hProcess, ref baseAddr, ref region,
                NativeConstants.PAGE_READWRITE, out var oldProtect) != 0)
            return false;

        var ok = DirectSyscalls.NtWriteVirtualMemory(hProcess, moduleBase, new byte[size], out var written) == 0 &&
                 written.ToUInt64() == (ulong)size;

        var restoreBase = moduleBase;
        var restoreRegion = (UIntPtr)size;
        DirectSyscalls.NtProtectVirtualMemory(hProcess, ref restoreBase, ref restoreRegion, oldProtect, out _);
        return ok;
    }
}
