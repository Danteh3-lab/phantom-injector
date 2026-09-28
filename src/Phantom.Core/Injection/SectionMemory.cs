using System.Runtime.InteropServices;
using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Pagefile-backed section memory for all temporary remote allocations
/// (stubs, slots, images). Replaces private VirtualAlloc-style mappings so
/// short-lived buffers are section-backed rather than MEM_PRIVATE.
/// Section handles are tracked per target process identity and base address.
/// </summary>
internal static class SectionMemory
{
    private readonly record struct ProcessIdentity(uint ProcessId, long CreationTime);
    private readonly record struct ViewKey(ProcessIdentity Process, long Base);

    private sealed class SectionView
    {
        public required IntPtr ProcessHandle { get; set; }
        public required IntPtr SectionHandle { get; set; }
        public bool IsUnmapped { get; set; }
        public bool CleanupPending { get; set; }
        public int CleanupAttempts { get; set; }
        public int LastStatus { get; set; }
        public long OriginScopeId { get; set; }
    }

    private static readonly Dictionary<ViewKey, SectionView> Sections = new();
    private static readonly object SectionLock = new();
    private static long _nextCleanupScopeId;

    [ThreadStatic]
    private static CleanupScope? _activeCleanupScope;

    // SECTION_INHERIT ViewUnmap: the view is private to the target process.
    private const uint ViewUnmap = 2;
    private const uint DuplicateSameAccess = 2;
    private const int MaxCleanupAttempts = 3;

    internal sealed class CleanupScope : IDisposable
    {
        private readonly CleanupScope? _previous;
        private readonly List<string> _failures = new();
        private bool _finalized;
        private string? _failureMessage;

        internal CleanupScope()
        {
            _previous = _activeCleanupScope;
            Id = Interlocked.Increment(ref _nextCleanupScopeId);
            _activeCleanupScope = this;
        }

        internal long Id { get; }

        internal string? FailureMessage
        {
            get
            {
                if (!_finalized)
                {
                    _failures.AddRange(RetryPendingViews(Id));
                    _failureMessage = _failures.Count == 0
                        ? null
                        : "Remote memory cleanup failed: " + string.Join("; ", _failures);
                    _finalized = true;
                }

                return _failureMessage;
            }
        }

        internal void Record(FreeResult result, IntPtr address)
            => _failures.Add(result.Describe(address));

        public void Dispose()
        {
            try
            {
                _ = FailureMessage;
            }
            finally
            {
                _activeCleanupScope = _previous;
            }
        }
    }

    internal static CleanupScope BeginCleanupScope() => new();
    internal static bool IsCleanupScopeActive => _activeCleanupScope is not null;

    internal readonly record struct FreeResult(int NtStatus, bool IsSectionBacked, int Win32Error = 0)
    {
        public bool Succeeded => NtStatus == 0 && Win32Error == 0;

        public string Describe(IntPtr address)
        {
            if (Win32Error != 0)
                return $"Remote memory cleanup at 0x{address.ToInt64():X} failed with Win32 error {Win32Error}.";

            var operation = IsSectionBacked ? "NtUnmapViewOfSection/NtClose" : "NtFreeVirtualMemory";
            return $"{operation} failed for remote address 0x{address.ToInt64():X}: 0x{NtStatus:X8}.";
        }
    }

    public static IntPtr Allocate(IntPtr hProcess, int size, uint protect)
    {
        var (processIdentity, processReference) = DuplicateAndIdentifyProcess(hProcess);
        IntPtr section = IntPtr.Zero;
        var ownershipTransferred = false;
        try
        {
            section = CreateBackingSection(size, IsExecutable(protect));
            var baseAddr = IntPtr.Zero;
            var mapStatus = DirectSyscalls.NtMapViewOfSection(
                section, processReference, ref baseAddr, IntPtr.Zero, UIntPtr.Zero,
                IntPtr.Zero, out _, ViewUnmap, 0, protect);
            if (mapStatus != 0 || baseAddr == IntPtr.Zero)
            {
                if (baseAddr != IntPtr.Zero)
                {
                    var unmapStatus = UnmapWithRetries(processReference, baseAddr, out var attempts);
                    if (unmapStatus != 0)
                    {
                        Track(processIdentity, baseAddr, section, processReference,
                            cleanupPending: true, lastStatus: unmapStatus);
                        ownershipTransferred = true;
                        throw new InvalidOperationException(
                            $"NtMapViewOfSection failed: 0x{mapStatus:X8}; cleanup of partial view 0x{baseAddr.ToInt64():X} failed during {attempts} attempts: 0x{unmapStatus:X8}. The view was retained for retry.");
                    }
                }

                throw new InvalidOperationException($"NtMapViewOfSection failed: 0x{mapStatus:X8}");
            }

            Track(processIdentity, baseAddr, section, processReference);
            ownershipTransferred = true;
            return baseAddr;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                if (section != IntPtr.Zero)
                    DirectSyscalls.NtClose(section);
                NativeMethods.CloseHandle(processReference);
            }
        }
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

        var (processIdentity, processReference) = DuplicateAndIdentifyProcess(hProcess);
        IntPtr section = IntPtr.Zero;
        var ownershipTransferred = false;
        try
        {
            section = CreateBackingSection(size, IsExecutable(protect));
            var baseAddr = preferredBase;
            var mapStatus = DirectSyscalls.NtMapViewOfSection(
                section, processReference, ref baseAddr, IntPtr.Zero, UIntPtr.Zero,
                IntPtr.Zero, out _, ViewUnmap, 0, protect);
            if (mapStatus != 0 || baseAddr == IntPtr.Zero || baseAddr != preferredBase)
            {
                if (mapStatus == 0 && baseAddr != IntPtr.Zero && baseAddr != preferredBase)
                {
                    var unmapStatus = UnmapWithRetries(processReference, baseAddr, out var attempts);
                    if (unmapStatus != 0)
                    {
                        Track(processIdentity, baseAddr, section, processReference,
                            cleanupPending: true, lastStatus: unmapStatus);
                        ownershipTransferred = true;
                        throw new InvalidOperationException(
                            $"NtMapViewOfSection mapped an alternate view at 0x{baseAddr.ToInt64():X}; cleanup failed during {attempts} attempts: 0x{unmapStatus:X8}. The view was retained for retry.");
                    }
                }

                return IntPtr.Zero;
            }

            Track(processIdentity, baseAddr, section, processReference);
            ownershipTransferred = true;
            return baseAddr;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                if (section != IntPtr.Zero)
                    DirectSyscalls.NtClose(section);
                NativeMethods.CloseHandle(processReference);
            }
        }
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

    private static (ProcessIdentity Identity, IntPtr ProcessReference) DuplicateAndIdentifyProcess(IntPtr hProcess)
    {
        var currentProcess = NativeMethods.GetCurrentProcess();
        if (!NativeMethods.DuplicateHandle(currentProcess, hProcess, currentProcess, out var processReference,
                0, false, DuplicateSameAccess) || processReference == IntPtr.Zero)
        {
            var error = Marshal.GetLastWin32Error();
            throw new InvalidOperationException($"Could not retain the target process handle: Win32 error {error}.");
        }

        if (!TryGetProcessIdentity(processReference, out var identity, out var identityError))
        {
            NativeMethods.CloseHandle(processReference);
            throw new InvalidOperationException($"Could not identify the target process: Win32 error {identityError}.");
        }

        return (identity, processReference);
    }

    private static bool TryGetProcessIdentity(IntPtr hProcess, out ProcessIdentity identity, out int win32Error)
    {
        identity = default;
        var processId = NativeMethods.GetProcessId(hProcess);
        if (processId == 0)
        {
            win32Error = Marshal.GetLastWin32Error();
            return false;
        }

        if (!NativeMethods.GetProcessTimes(hProcess, out var creationTime, out _, out _, out _))
        {
            win32Error = Marshal.GetLastWin32Error();
            return false;
        }

        identity = new ProcessIdentity(processId, creationTime.ToInt64());
        win32Error = 0;
        return true;
    }

    private static void Track(ProcessIdentity process, IntPtr baseAddr, IntPtr section, IntPtr processReference,
        bool cleanupPending = false, int cleanupAttempts = 0, int lastStatus = 0)
    {
        lock (SectionLock)
        {
            Sections.Add(new ViewKey(process, baseAddr.ToInt64()), new SectionView
            {
                ProcessHandle = processReference,
                SectionHandle = section,
                CleanupPending = cleanupPending,
                CleanupAttempts = cleanupAttempts,
                LastStatus = lastStatus,
                OriginScopeId = _activeCleanupScope?.Id ?? 0
            });
        }
    }

    public static FreeResult Free(IntPtr hProcess, IntPtr address, bool captureFailure = true)
    {
        if (address == IntPtr.Zero)
            return new FreeResult(0, false);

        if (!TryGetProcessIdentity(hProcess, out var processIdentity, out var identityError))
            return ReportFailure(new FreeResult(0, false, identityError), address, captureFailure);

        var key = new ViewKey(processIdentity, address.ToInt64());
        lock (SectionLock)
        {
            if (Sections.TryGetValue(key, out var view))
            {
                var deferRetriesToScope = captureFailure && _activeCleanupScope is not null;
                var attemptsRemaining = deferRetriesToScope
                    ? Math.Max(0, MaxCleanupAttempts - view.CleanupAttempts)
                    : MaxCleanupAttempts;
                var status = deferRetriesToScope && attemptsRemaining == 0
                    ? (view.LastStatus != 0 ? view.LastStatus : unchecked((int)0xC0000001))
                    : 0;
                var attemptLimit = deferRetriesToScope ? Math.Min(1, attemptsRemaining) : MaxCleanupAttempts;
                for (var attempt = 0; attempt < attemptLimit; attempt++)
                {
                    status = TryCleanupView(view, address);
                    view.CleanupAttempts++;
                    view.LastStatus = status;
                    if (status == 0)
                    {
                        Sections.Remove(key);
                        return new FreeResult(0, true);
                    }
                }

                view.CleanupPending = true;
                if (deferRetriesToScope)
                    return new FreeResult(status, true);

                // Keep both handles and the mapping identity so a later cleanup scope can retry.
                view.CleanupAttempts = 0;
                var result = new FreeResult(status, true);
                return ReportFailure(result, address, captureFailure);
            }
        }

        // Not section-backed (legacy or foreign mapping): retry the native
        // release a bounded number of times before reporting a leak.
        var freeStatus = 0;
        for (var attempt = 0; attempt < MaxCleanupAttempts; attempt++)
        {
            freeStatus = DirectSyscalls.NtFreeVirtualMemory(hProcess, address);
            if (freeStatus == 0)
                return new FreeResult(0, false);
        }

        return ReportFailure(new FreeResult(freeStatus, false), address, captureFailure);
    }

    private static int TryCleanupView(SectionView view, IntPtr address)
    {
        if (!view.IsUnmapped && view.ProcessHandle != IntPtr.Zero &&
            NativeMethods.WaitForSingleObject(view.ProcessHandle, 0) == NativeConstants.WAIT_OBJECT_0)
        {
            // A terminated process has already discarded its address space.
            view.IsUnmapped = true;
        }

        if (!view.IsUnmapped)
        {
            var unmapStatus = DirectSyscalls.NtUnmapViewOfSection(view.ProcessHandle, address);
            if (unmapStatus != 0)
                return unmapStatus;

            view.IsUnmapped = true;
        }

        if (view.ProcessHandle != IntPtr.Zero)
        {
            var closeProcessStatus = DirectSyscalls.NtClose(view.ProcessHandle);
            if (closeProcessStatus != 0)
                return closeProcessStatus;
            view.ProcessHandle = IntPtr.Zero;
        }

        if (view.SectionHandle != IntPtr.Zero)
        {
            var closeSectionStatus = DirectSyscalls.NtClose(view.SectionHandle);
            if (closeSectionStatus != 0)
                return closeSectionStatus;
            view.SectionHandle = IntPtr.Zero;
        }

        return 0;
    }

    private static List<string> RetryPendingViews(long currentScopeId)
    {
        var failures = new List<string>();
        lock (SectionLock)
        {
            foreach (var (key, view) in Sections.Where(pair => pair.Value.CleanupPending).ToArray())
            {
                var status = view.LastStatus;
                while (view.CleanupAttempts < MaxCleanupAttempts)
                {
                    status = TryCleanupView(view, new IntPtr(key.Base));
                    view.CleanupAttempts++;
                    view.LastStatus = status;
                    if (status == 0)
                        break;
                }

                if (status == 0)
                {
                    Sections.Remove(key);
                    continue;
                }

                var effect = view.IsUnmapped
                    ? "the view was unmapped but a tracking handle may remain open"
                    : "the target view may remain mapped";
                var origin = view.OriginScopeId == currentScopeId
                    ? "Current operation cleanup remains unresolved for"
                    : "Prior pending cleanup remains unresolved for";
                var message = $"{origin} remote section view 0x{key.Base:X} in process {key.Process.ProcessId}: after {view.CleanupAttempts} attempts (NTSTATUS 0x{status:X8}), {effect}. It remains queued for a later retry.";
                failures.Add(message);
                System.Diagnostics.Trace.TraceError(message);
                // A later scope gets a fresh bounded attempt budget. Keep the view and
                // any still-owned handles so the retry remains possible.
                view.CleanupAttempts = 0;
            }
        }

        return failures;
    }

    private static int UnmapWithRetries(IntPtr processHandle, IntPtr baseAddress, out int attempts)
    {
        attempts = 0;
        var status = 0;
        while (attempts < MaxCleanupAttempts)
        {
            attempts++;
            status = DirectSyscalls.NtUnmapViewOfSection(processHandle, baseAddress);
            if (status == 0)
                break;
        }

        return status;
    }

    private static FreeResult ReportFailure(FreeResult result, IntPtr address, bool captureFailure)
    {
        System.Diagnostics.Trace.TraceError(result.Describe(address));
        if (captureFailure)
            _activeCleanupScope?.Record(result, address);
        return result;
    }
}
