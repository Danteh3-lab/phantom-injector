namespace Phantom.Core.Injection;

/// <summary>
/// Human-readable names for the NTSTATUS codes our syscalls actually return,
/// so test logs distinguish "blocked by the target's protection" from
/// injector bugs without a debugger attached.
/// </summary>
internal static class NtStatus
{
    public static string Describe(int status) => $"0x{status:X8} ({Name(status)})";

    public static string Name(int status) => (uint)status switch
    {
        0x00000000 => "SUCCESS",
        0xC0000008 => "INVALID_HANDLE",
        0xC000000B => "INVALID_CID",
        0xC000000D => "INVALID_PARAMETER",
        0xC0000017 => "NO_MEMORY",
        0xC0000022 => "ACCESS_DENIED",
        0xC0000023 => "BUFFER_TOO_SMALL",
        0xC000009A => "INSUFFICIENT_RESOURCES",
        0xC000010A => "PROCESS_IS_TERMINATING",
        0xC0000121 => "CANNOT_DELETE",
        0xC0000058 => "UNKNOWN_REVISION",
        0xC0000602 => "FAIL_FAST_EXCEPTION",
        _ => "UNKNOWN",
    };

    public static bool IsAccessDenied(int status) => (uint)status == 0xC0000022;
}
