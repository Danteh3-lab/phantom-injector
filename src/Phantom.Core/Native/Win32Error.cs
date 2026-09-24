using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Phantom.Core.Native;

/// <summary>
/// Helpers for turning Win32 error codes into readable messages and a
/// scoped native handle wrapper.
/// </summary>
public static class Win32Error
{
    public static string GetMessage(uint error)
        => new Win32Exception((int)error).Message;

    public static string LastError()
        => GetMessage(NativeMethods.GetLastError());

    public static void ThrowIfFalse(bool result, string operation)
    {
        if (!result)
            throw new Win32Exception((int)NativeMethods.GetLastError(), operation + " failed");
    }
}

/// <summary>
/// A disposable wrapper around a native HANDLE.
/// </summary>
public sealed class SafeNativeHandle : IDisposable
{
    public IntPtr Handle { get; }

    public SafeNativeHandle(IntPtr handle)
    {
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            throw new Win32Exception((int)NativeMethods.GetLastError());
        Handle = handle;
    }

    public bool IsInvalid => Handle == IntPtr.Zero || Handle == new IntPtr(-1);

    public static SafeNativeHandle OpenProcess(uint pid, uint access)
        => new(NativeMethods.OpenProcess(access, false, pid));

    public void Dispose()
    {
        if (!IsInvalid)
            NativeMethods.CloseHandle(Handle);
    }
}
