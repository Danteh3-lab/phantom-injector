using System.Runtime.InteropServices;
using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Pagefile-backed section memory for all temporary remote allocations
/// (stubs, slots, images). Replaces private VirtualAlloc-style mappings so
/// short-lived buffers are section-backed rather than MEM_PRIVATE.
/// Section handles are tracked per (process, base) so allocate/free keep
/// the same signatures as the allocators they replace.
/// </summary>
internal static class SectionMemory
{
    private static readonly Dictionary<(long Process, long Base), IntPtr> Sections = new();
    private static readonly object SectionLock = new();

    // SECTION_INHERIT ViewUnmap: the view is private to the target process.
    private const uint ViewUnmap = 2;

    public static IntPtr Allocate(IntPtr hProcess, int size, uint protect)
    {
        var section = CreateBackingSection(size, IsExecutable(protect));
        var baseAddr = IntPtr.Zero;
        var mapStatus = DirectSyscalls.NtMapViewOfSection(
            section, hProcess, ref baseAddr, IntPtr.Zero, UIntPtr.Zero,
            IntPtr.Zero, out _, ViewUnmap, 0, protect);
        if (mapStatus != 0 || baseAddr == IntPtr.Zero)
        {
            DirectSyscalls.NtClose(section);
            throw new InvalidOperationException($"NtMapViewOfSection failed: 0x{mapStatus:X8}");
        }

        Track(hProcess, baseAddr, section);
        return baseAddr;
    }

    /// <summary>
    /// Section-backed allocation with a preferred base (e.g. a PE's
    /// ImageBase so relocations are unnecessary). Returns Zero when the
    /// address is unavailable instead of mapping elsewhere; the caller falls
    /// back to <see cref="Allocate"/>. No private fallback lives here, so
    /// every image stays section-backed.
    /// </summary>
    public static IntPtr AllocateAt(IntPtr hProcess, int size, uint protect, IntPtr preferredBase)
    {
        if (preferredBase == IntPtr.Zero)
            return IntPtr.Zero;

        var section = CreateBackingSection(size, IsExecutable(protect));
        var baseAddr = preferredBase;
        var mapStatus = DirectSyscalls.NtMapViewOfSection(
            section, hProcess, ref baseAddr, IntPtr.Zero, UIntPtr.Zero,
            IntPtr.Zero, out _, ViewUnmap, 0, protect);
        if (mapStatus != 0 || baseAddr == IntPtr.Zero || baseAddr != preferredBase)
        {
            if (baseAddr != IntPtr.Zero && baseAddr != preferredBase)
                DirectSyscalls.NtUnmapViewOfSection(hProcess, baseAddr);
            DirectSyscalls.NtClose(section);
            return IntPtr.Zero;
        }

        Track(hProcess, baseAddr, section);
        return baseAddr;
    }

    private static bool IsExecutable(uint protect)
    {
        // NOTE: PAGE_EXECUTE (0x10) is a standalone value, not a flag shared
        // by the other execute protections, so match values explicitly.
        var baseProtect = protect & 0xFFu;
        return baseProtect is NativeConstants.PAGE_EXECUTE
            or NativeConstants.PAGE_EXECUTE_READ
            or NativeConstants.PAGE_EXECUTE_READWRITE
            or NativeConstants.PAGE_EXECUTE_WRITECOPY;
    }

    private static IntPtr CreateBackingSection(int size, bool executable)
    {
        // A mapped view's protection must be compatible with the section's
        // page protection (and later view transitions must stay compatible
        // too): sections backing code that will execute — now or after an
        // RX transition — are created executable. Data-only sections stay RW.
        var sectionProtect = executable
            ? NativeConstants.PAGE_EXECUTE_READWRITE
            : NativeConstants.PAGE_READWRITE;

        var maxSizePtr = Marshal.AllocHGlobal(8);
        try
        {
            Marshal.WriteInt64(maxSizePtr, size);
            var createStatus = DirectSyscalls.NtCreateSection(
                out var section, NativeConstants.SECTION_ALL_ACCESS, IntPtr.Zero, maxSizePtr,
                sectionProtect, NativeConstants.SEC_COMMIT, IntPtr.Zero);
            if (createStatus != 0 || section == IntPtr.Zero)
                throw new InvalidOperationException($"NtCreateSection failed: 0x{createStatus:X8}");
            return section;
        }
        finally
        {
            Marshal.FreeHGlobal(maxSizePtr);
        }
    }

    private static void Track(IntPtr hProcess, IntPtr baseAddr, IntPtr section)
    {
        lock (SectionLock)
            Sections[(hProcess.ToInt64(), baseAddr.ToInt64())] = section;
    }

    public static void Free(IntPtr hProcess, IntPtr address)
    {
        if (address == IntPtr.Zero)
            return;

        IntPtr section;
        lock (SectionLock)
        {
            if (!Sections.TryGetValue((hProcess.ToInt64(), address.ToInt64()), out section))
            {
                // Not section-backed (legacy or foreign mapping): fall back to
                // a virtual free so cleanup never leaks.
                DirectSyscalls.NtFreeVirtualMemory(hProcess, address);
                return;
            }
            Sections.Remove((hProcess.ToInt64(), address.ToInt64()));
        }

        DirectSyscalls.NtUnmapViewOfSection(hProcess, address);
        DirectSyscalls.NtClose(section);
    }
}
