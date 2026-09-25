using System.Runtime.InteropServices;

namespace Phantom.Core.Native;

/// <summary>
/// Win32 structures used across the injector. x64 only.
/// </summary>
internal static class NativeConstants
{
    public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    public const uint PROCESS_CREATE_THREAD = 0x0002;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_VM_WRITE = 0x0020;
    public const uint PROCESS_SUSPEND_RESUME = 0x0800;

    public const uint MEM_COMMIT = 0x00001000;
    public const uint MEM_RESERVE = 0x00002000;
    public const uint MEM_RELEASE = 0x00008000;
    public const uint MEM_DECOMMIT = 0x00004000;
    public const uint MEM_TOP_DOWN = 0x00100000;

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READONLY = 0x02;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_WRITECOPY = 0x08;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOCACHE = 0x200;

    public const uint INFINITE = 0xFFFFFFFF;
    public const uint WAIT_OBJECT_0 = 0x00000000;
    public const uint WAIT_TIMEOUT = 0x00000102;
    public const uint WAIT_FAILED = 0xFFFFFFFF;

    public const uint TH32CS_SNAPPROCESS = 0x00000002;
    public const uint TH32CS_SNAPTHREAD = 0x00000004;
    public const uint TH32CS_SNAPMODULE = 0x00000008;
    public const uint TH32CS_SNAPMODULE32 = 0x00000010;

    public const uint LIST_MODULES_ALL = 0x03;

    public const uint THREAD_SUSPEND_RESUME = 0x0002;
    public const uint THREAD_GET_CONTEXT = 0x0008;
    public const uint THREAD_SET_CONTEXT = 0x0010;
    public const uint THREAD_QUERY_INFORMATION = 0x0040;
    public const uint THREAD_ALL_ACCESS = 0x001FFFFF;

    public const uint CONTEXT_AMD64 = 0x00100000;
    public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
    public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
    public const uint CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004;
    public const uint CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008;
    public const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
    public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
    public const uint CONTEXT_XSTATE = CONTEXT_AMD64 | 0x00000040;
    public const uint CONTEXT_ALL_X64 =
        CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

    public const uint DLL_PROCESS_ATTACH = 1;
    public const uint DLL_PROCESS_DETACH = 0;

    public const uint MEM_IMAGE = 0x1000000;

    public const uint SEC_IMAGE = 0x1000000;
    public const uint SEC_IMAGE_NO_EXECUTE = 0x11000000;
    public const uint SEC_COMMIT = 0x8000000;
    public const uint SEC_RESERVE = 0x4000000;
    public const uint SEC_LARGE_PAGES = 0x80000000;

    public const uint SECTION_QUERY = 0x0001;
    public const uint SECTION_MAP_READ = 0x0004;
    public const uint SECTION_MAP_WRITE = 0x0002;
    public const uint SECTION_MAP_EXECUTE = 0x0008;
    public const uint SECTION_EXTEND_SIZE = 0x0010;
    public const uint SECTION_MAP_EXECUTE_EXPLICIT = 0x0020;
    public const uint SECTION_ALL_ACCESS = 0x10000000;

    public const uint OBJ_CASE_INSENSITIVE = 0x00000040;

    public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
}

[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct STARTUPINFO
{
    public uint cb;
    public IntPtr lpReserved;
    public IntPtr lpDesktop;
    public IntPtr lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public ushort wShowWindow;
    public ushort cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SECURITY_ATTRIBUTES
{
    public uint nLength;
    public IntPtr lpSecurityDescriptor;
    [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
}

[StructLayout(LayoutKind.Sequential)]
internal struct OSVERSIONINFOEX
{
    public uint dwOSVersionInfoSize;
    public uint dwMajorVersion;
    public uint dwMinorVersion;
    public uint dwBuildNumber;
    public uint dwPlatformId;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szCSDVersion;
    public ushort wServicePackMajor;
    public ushort wServicePackMinor;
    public ushort wSuiteMask;
    public byte wProductType;
    public byte wReserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct LUID
{
    public uint LowPart;
    public int HighPart;
}

[StructLayout(LayoutKind.Sequential)]
internal struct LUID_AND_ATTRIBUTES
{
    public LUID Luid;
    public uint Attributes;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TOKEN_PRIVILEGES
{
    public uint PrivilegeCount;
    public LUID_AND_ATTRIBUTES Privileges;
}

[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_BASIC_INFORMATION
{
    public IntPtr Reserved1;
    public IntPtr PebBaseAddress;
    public IntPtr Reserved2_0;
    public IntPtr Reserved2_1;
    public IntPtr UniqueProcessId;
    public IntPtr Reserved3;
}

[StructLayout(LayoutKind.Sequential)]
internal struct THREADENTRY32
{
    public uint dwSize;
    public uint cntUsage;
    public uint th32ThreadID;
    public uint th32OwnerProcessID;
    public int tpBasePri;
    public int tpDeltaPri;
    public uint dwFlags;
}

// x64 CONTEXT. Explicit offsets so the layout is provably identical to the
// native structure (total size 0x4D0). Rip occupies 0xF8..0x100, so FltSave
// starts at 0x100 with no padding.
[StructLayout(LayoutKind.Explicit, Size = 0x4D0)]
internal unsafe struct CONTEXT_X64
{
    /// <summary>Exact native size of the x64 CONTEXT structure.</summary>
    public const int Size = 0x4D0;

    [FieldOffset(0x00)] public ulong P1Home;
    [FieldOffset(0x08)] public ulong P2Home;
    [FieldOffset(0x10)] public ulong P3Home;
    [FieldOffset(0x18)] public ulong P4Home;
    [FieldOffset(0x20)] public ulong P5Home;
    [FieldOffset(0x28)] public ulong P6Home;
    [FieldOffset(0x30)] public uint ContextFlags;
    [FieldOffset(0x34)] public uint MxCsr;
    [FieldOffset(0x38)] public ushort SegCs;
    [FieldOffset(0x3A)] public ushort SegDs;
    [FieldOffset(0x3C)] public ushort SegEs;
    [FieldOffset(0x3E)] public ushort SegFs;
    [FieldOffset(0x40)] public ushort SegGs;
    [FieldOffset(0x42)] public ushort SegSs;
    [FieldOffset(0x44)] public uint EFlags;
    [FieldOffset(0x48)] public ulong Dr0;
    [FieldOffset(0x50)] public ulong Dr1;
    [FieldOffset(0x58)] public ulong Dr2;
    [FieldOffset(0x60)] public ulong Dr3;
    [FieldOffset(0x68)] public ulong Dr6;
    [FieldOffset(0x70)] public ulong Dr7;
    [FieldOffset(0x78)] public ulong Rax;
    [FieldOffset(0x80)] public ulong Rcx;
    [FieldOffset(0x88)] public ulong Rdx;
    [FieldOffset(0x90)] public ulong Rbx;
    [FieldOffset(0x98)] public ulong Rsp;
    [FieldOffset(0xA0)] public ulong Rbp;
    [FieldOffset(0xA8)] public ulong Rsi;
    [FieldOffset(0xB0)] public ulong Rdi;
    [FieldOffset(0xB8)] public ulong R8;
    [FieldOffset(0xC0)] public ulong R9;
    [FieldOffset(0xC8)] public ulong R10;
    [FieldOffset(0xD0)] public ulong R11;
    [FieldOffset(0xD8)] public ulong R12;
    [FieldOffset(0xE0)] public ulong R13;
    [FieldOffset(0xE8)] public ulong R14;
    [FieldOffset(0xF0)] public ulong R15;
    [FieldOffset(0xF8)] public ulong Rip;
    [FieldOffset(0x100)] public fixed byte FltSave[512];
    [FieldOffset(0x300)] public fixed byte VectorRegister[416];
    [FieldOffset(0x4A0)] public ulong VectorControl;
    [FieldOffset(0x4A8)] public ulong DebugControl;
    [FieldOffset(0x4B0)] public ulong LastBranchToRip;
    [FieldOffset(0x4B8)] public ulong LastBranchFromRip;
    [FieldOffset(0x4C0)] public ulong LastExceptionToRip;
    [FieldOffset(0x4C8)] public ulong LastExceptionFromRip;
}

[StructLayout(LayoutKind.Sequential)]
internal struct LIST_ENTRY
{
    public IntPtr Flink;
    public IntPtr Blink;
}

internal static class NativeMethods
{
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern UIntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern unsafe bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, void* lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenThread(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern unsafe bool GetThreadContext(IntPtr hThread, CONTEXT_X64* lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern unsafe bool SetThreadContext(IntPtr hThread, CONTEXT_X64* lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool InitializeContext(IntPtr buffer, uint contextFlags, out IntPtr context, ref uint contextLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetXStateFeaturesMask(IntPtr context, ulong featureMask);

    [DllImport("kernel32.dll")]
    internal static extern ulong GetEnabledXStateFeatures();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

    /// <summary>
    /// Flushes generated code and throws if the flush fails, so the caller never
    /// executes instructions that may not be visible to the processor.
    /// </summary>
    internal static void FlushInstructionCacheChecked(IntPtr hProcess, IntPtr address, int size)
    {
        if (!FlushInstructionCache(hProcess, address, (UIntPtr)(uint)size))
            throw new InvalidOperationException("FlushInstructionCache failed: " + Win32Error.LastError());
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr GetModuleHandleW(string? lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern IntPtr LoadLibraryW(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetModuleHandleExW(uint dwFlags, IntPtr lpModuleName, out IntPtr phModule);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern uint GetModuleFileNameW(IntPtr hModule, [Out] System.Text.StringBuilder lpFilename, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    /// <summary>
    /// Returns the error captured by the most recent P/Invoke that requested
    /// SetLastError. Using Marshal keeps the value intact (calling the Win32
    /// GetLastError export directly can clobber it).
    /// </summary>
    internal static uint GetLastError() => (uint)Marshal.GetLastWin32Error();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWow64Process(IntPtr hProcess, [MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWow64Process2(IntPtr hProcess, out ushort processMachine, out ushort nativeMachine);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint GetFileSize(IntPtr hFile, IntPtr lpFileSizeHigh);

    // ---- psapi ----
    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern uint GetModuleBaseNameW(IntPtr hProcess, IntPtr hModule, [Out] System.Text.StringBuilder lpBaseName, uint nSize);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern uint GetModuleFileNameExW(IntPtr hProcess, IntPtr hModule, [Out] System.Text.StringBuilder lpFilename, uint nSize);

    [DllImport("psapi.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

    // ---- advapi32 ----
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LookupPrivilegeValueW(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    // ---- user32 ----
    internal delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern int GetWindowTextW(IntPtr hWnd, [Out] System.Text.StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern int GetClassNameW(IntPtr hWnd, [Out] System.Text.StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWindowVisible(IntPtr hWnd);

    // ---- ntdll ----
    [DllImport("ntdll.dll")]
    internal static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

    [DllImport("ntdll.dll")]
    internal static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass, ref THREAD_BASIC_INFORMATION threadInformation, int threadInformationLength, out int returnLength);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UIntPtr RegionSize, uint NewProtect, out uint OldProtect);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UIntPtr BufferSize, out UIntPtr NumberOfBytesWritten);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UIntPtr BufferSize, out UIntPtr NumberOfBytesRead);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartRoutine, IntPtr Argument, uint CreateFlags, IntPtr ZeroBits, IntPtr StackSize, IntPtr MaximumStackSize, IntPtr AttributeList);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtOpenProcess(out IntPtr ProcessHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ClientId);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtCreateSection(out IntPtr SectionHandle, uint DesiredAccess, IntPtr ObjectAttributes, ref long MaximumSize, uint SectionPageProtection, uint AllocationAttributes, IntPtr FileHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, UIntPtr CommitSize, ref long SectionOffset, out UIntPtr ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtUnmapViewOfSection(IntPtr ProcessHandle, IntPtr BaseAddress);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtGetContextThread(IntPtr ThreadHandle, IntPtr Context);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtSetContextThread(IntPtr ThreadHandle, IntPtr Context);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtSuspendThread(IntPtr ThreadHandle, out uint PreviousSuspendCount);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtResumeThread(IntPtr ThreadHandle, out uint PreviousSuspendCount);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtClose(IntPtr Handle);
}

[StructLayout(LayoutKind.Sequential)]
internal struct THREAD_BASIC_INFORMATION
{
    public int ExitStatus;
    public IntPtr TebBaseAddress;
    public IntPtr UniqueProcess;
    public IntPtr UniqueThread;
    public IntPtr AffinityMask;
    public int Priority;
    public int BasePriority;
}

[StructLayout(LayoutKind.Sequential)]
internal struct MODULEINFO
{
    public IntPtr lpBaseOfDll;
    public uint SizeOfImage;
    public IntPtr EntryPoint;
}

/// <summary>
/// Win64 MEMORY_BASIC_INFORMATION (Windows 10+ layout with PartitionId,
/// 0x30 bytes). Only BaseAddress, RegionSize and Protect are consumed.
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public ushort PartitionId;
    public ushort AlignmentPadding;
    public ulong RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}
