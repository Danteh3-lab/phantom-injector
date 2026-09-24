using Phantom.Core.Processes;

namespace Phantom.Core.Native;

/// <summary>
/// Resolves an export address inside a target process using the local module as
/// the reference image. The export may be forwarded to another image, so the
/// module that actually owns the resolved address is identified and used for
/// the remote base; rebasing against the requested module would be wrong for
/// forwarded exports.
/// </summary>
internal static class RemoteFunctionResolver
{
    private const uint GetModuleHandleExFromAddress = 0x00000004;
    private const uint GetModuleHandleExUnchangedRefCount = 0x00000002;

    public static IntPtr Resolve(uint pid, string moduleName, string functionName)
    {
        var localModule = NativeMethods.GetModuleHandleW(moduleName);
        if (localModule == IntPtr.Zero)
            return IntPtr.Zero;

        var localFunction = NativeMethods.GetProcAddress(localModule, functionName);
        if (localFunction == IntPtr.Zero)
            return IntPtr.Zero;

        // Find the module that actually contains the address (handles forwarders).
        if (!NativeMethods.GetModuleHandleExW(
                GetModuleHandleExFromAddress | GetModuleHandleExUnchangedRefCount,
                localFunction, out var ownerModule) || ownerModule == IntPtr.Zero)
            return IntPtr.Zero;

        var ownerPath = GetModuleFileName(ownerModule);
        if (string.IsNullOrEmpty(ownerPath))
            return IntPtr.Zero;

        var remoteOwner = ProcessManager.GetRemoteModuleBase(pid, Path.GetFileName(ownerPath));
        if (remoteOwner == IntPtr.Zero)
            return IntPtr.Zero;

        return new IntPtr(remoteOwner.ToInt64() + (localFunction.ToInt64() - ownerModule.ToInt64()));
    }

    private static string? GetModuleFileName(IntPtr module)
    {
        var buffer = new System.Text.StringBuilder(1024);
        var length = NativeMethods.GetModuleFileNameW(module, buffer, (uint)buffer.Capacity);
        return length == 0 ? null : buffer.ToString();
    }
}
