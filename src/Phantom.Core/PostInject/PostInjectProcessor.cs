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
        NativeConstants.PROCESS_CREATE_THREAD |
        NativeConstants.SYNCHRONIZE;

    /// <summary>
    /// Runs the requested post-injection steps. Returns <c>null</c> when every
    /// requested step succeeded, otherwise a description of what failed.
    /// </summary>
    public static string? Apply(uint pid, IntPtr moduleBase, InjectionOptions options)
    {
        if (moduleBase == IntPtr.Zero)
            return "post-inject skipped: module base unknown.";

        var preflight = TargetPreflight.Check(pid, Access);
        if (preflight.ProbeError is not null)
            return "post-inject failed: " + preflight.ProbeError;
        if (!preflight.Opened)
            return $"post-inject failed: NtOpenProcess - {NtStatus.Describe(preflight.OpenStatus)}";
        if (!preflight.RightsQueried)
            return $"post-inject failed: handle rights could not be verified ({NtStatus.Describe(preflight.QueryStatus)}).";
        if (preflight.Missing.Length > 0)
            return $"post-inject failed: required process rights are missing ({string.Join(", ", preflight.Missing)}).";

        using var target = preflight.Target;
        if (target is null)
            return "post-inject failed: target process identity could not be retained.";

        using var targetScope = target.EnterScope();
        return Apply(target, moduleBase, options);
    }

    internal static string? Apply(TargetProcessIdentity target, IntPtr moduleBase, InjectionOptions options)
    {
        if (moduleBase == IntPtr.Zero)
            return "post-inject skipped: module base unknown.";

        IntPtr hProcess;
        {
            try
            {
                hProcess = target.OpenVerifiedHandle(Access);
            }
            catch (Exception ex)
            {
                return "post-inject failed: " + ex.Message;
            }
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
                    if (!LoaderLockUnlink.TryUnlink(target.Pid, hProcess, moduleBase, out var hideError, out var hashNote))
                    {
                        failures.Add("hide module (" + (hideError ?? "failed") + ")");
                    }
                    else if (hashNote is not null)
                    {
                        // Lists unlinked; hash-table cloaking skipped — warning only.
                        failures.Add("hide module hash (" + hashNote + ")");
                    }
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
