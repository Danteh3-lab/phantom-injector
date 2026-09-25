using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Phantom.Core.Native;

/// <summary>
/// Hell's Gate / Halo's Gate direct-syscall resolver.
/// SSNs are extracted from a clean on-disk copy of ntdll.dll (not the
/// potentially hooked in-memory image), each candidate stub is validated as a
/// full syscall sequence, and Halo's Gate adjusts by neighbor distance.
/// </summary>
internal static class DirectSyscalls
{
    private static readonly Dictionary<string, ushort> SsnCache = new();
    private static readonly Dictionary<string, IntPtr> StubCache = new();
    private static readonly object CacheLock = new();
    private static bool Initialized;

    private static byte[]? CleanNtdll;
    private static List<NtdllSection> CleanSections = new();
    private static Dictionary<string, uint> CleanExports = new(StringComparer.Ordinal);
    private static List<(string Name, uint Rva)> ExportsByRva = new();

    private struct NtdllSection
    {
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint PointerToRawData;
        public uint SizeOfRawData;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, uint AllocationType, uint Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UIntPtr RegionSize, uint NewProtect, out uint OldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtWriteVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UIntPtr BufferSize, out UIntPtr NumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtReadVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr Buffer, UIntPtr BufferSize, out UIntPtr NumberOfBytesRead);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtCreateThreadExDelegate(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartRoutine, IntPtr Argument, uint CreateFlags, IntPtr ZeroBits, IntPtr StackSize, IntPtr MaximumStackSize, IntPtr AttributeList);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtOpenProcessDelegate(out IntPtr ProcessHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtOpenThreadDelegate(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ClientId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtFreeVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UIntPtr RegionSize, uint FreeType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtFlushInstructionCacheDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, UIntPtr Length);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtCreateSectionDelegate(out IntPtr SectionHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr MaximumSize, uint SectionPageProtection, uint AllocationAttributes, IntPtr FileHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtMapViewOfSectionDelegate(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, UIntPtr CommitSize, IntPtr SectionOffset, out UIntPtr ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtUnmapViewOfSectionDelegate(IntPtr ProcessHandle, IntPtr BaseAddress);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtGetContextThreadDelegate(IntPtr ThreadHandle, IntPtr Context);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtSetContextThreadDelegate(IntPtr ThreadHandle, IntPtr Context);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtSuspendThreadDelegate(IntPtr ThreadHandle, out uint PreviousSuspendCount);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtResumeThreadDelegate(IntPtr ThreadHandle, out uint PreviousSuspendCount);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtCloseDelegate(IntPtr Handle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtQueryInformationThreadDelegate(IntPtr ThreadHandle, int ThreadInformationClass, IntPtr ThreadInformation, int ThreadInformationLength, out int ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtQueryInformationProcessDelegate(IntPtr ProcessHandle, int ProcessInformationClass, IntPtr ProcessInformation, int ProcessInformationLength, out int ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeClientId
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    public static void Initialize()
    {
        if (Initialized)
            return;

        lock (CacheLock)
        {
            if (Initialized)
                return;

            LoadCleanNtdll();
            Initialized = true;
        }
    }

    private static void LoadCleanNtdll()
    {
        var systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var path = Path.Combine(systemDir, "ntdll.dll");
        var fileBytes = File.ReadAllBytes(path);
        if (fileBytes.Length < 0x40 || BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(0, 2)) != 0x5A4D)
            throw new InvalidOperationException("Clean ntdll.dll has no MZ header.");

        var lfanew = (int)BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(0x3C, 4));
        if (lfanew < 0 || (long)lfanew + 24 > fileBytes.Length ||
            BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(lfanew, 4)) != 0x00004550)
            throw new InvalidOperationException("Clean ntdll.dll has no PE signature.");

        var fileHeader = lfanew + 4;
        var machine = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(fileHeader, 2));
        if (machine != NativeConstants.IMAGE_FILE_MACHINE_AMD64)
            throw new InvalidOperationException("Clean ntdll.dll is not AMD64.");

        var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(fileHeader + 2, 2));
        var sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(fileHeader + 16, 2));
        var optional = fileHeader + 20;
        if (sizeOfOptionalHeader < 112 || (long)optional + sizeOfOptionalHeader > fileBytes.Length)
            throw new InvalidOperationException("Clean ntdll optional header is out of range.");
        if (BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(optional, 2)) != 0x20B)
            throw new InvalidOperationException("Clean ntdll is not PE32+.");

        var numberOfRvaAndSizes = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(optional + 108, 4));
        if (numberOfRvaAndSizes <= 0 || 112 + numberOfRvaAndSizes * 8 > (uint)sizeOfOptionalHeader)
            throw new InvalidOperationException("Clean ntdll directories exceed optional header.");

        var exportRva = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(optional + 112, 4));
        var exportSize = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(optional + 116, 4));
        if (exportRva == 0 || exportSize < 40)
            throw new InvalidOperationException("Clean ntdll has no export directory.");

        var sectionStart = optional + sizeOfOptionalHeader;
        var sections = new List<NtdllSection>(numberOfSections);
        for (var i = 0; i < numberOfSections; i++)
        {
            var off = sectionStart + i * 40;
            if ((long)off + 40 > fileBytes.Length)
                throw new InvalidOperationException("Clean ntdll section table is out of range.");
            sections.Add(new NtdllSection
            {
                VirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(off + 12, 4)),
                VirtualSize = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(off + 8, 4)),
                PointerToRawData = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(off + 20, 4)),
                SizeOfRawData = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(off + 16, 4)),
            });
        }

        int RvaToOffset(uint rva)
        {
            foreach (var s in sections)
            {
                var mapped = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && (ulong)rva - s.VirtualAddress < mapped)
                {
                    var delta = rva - s.VirtualAddress;
                    if (delta >= s.SizeOfRawData)
                        return -1;
                    var fileOff = (long)s.PointerToRawData + delta;
                    return fileOff < fileBytes.Length ? (int)fileOff : -1;
                }
            }
            return -1;
        }

        var exportOff = RvaToOffset(exportRva);
        if (exportOff < 0 || (long)exportOff + 40 > fileBytes.Length)
            throw new InvalidOperationException("Clean ntdll export directory is out of range.");

        var numberOfFunctions = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(exportOff + 20, 4));
        var numberOfNames = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(exportOff + 24, 4));
        var addressOfFunctions = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(exportOff + 28, 4));
        var addressOfNames = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(exportOff + 32, 4));
        var addressOfOrdinals = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(exportOff + 36, 4));
        if (numberOfFunctions == 0 || numberOfFunctions > 0x10000 || numberOfNames > 0x10000)
            throw new InvalidOperationException("Clean ntdll export counts are invalid.");

        var funcTableOff = RvaToOffset(addressOfFunctions);
        var nameTableOff = RvaToOffset(addressOfNames);
        var ordTableOff = RvaToOffset(addressOfNameOrdinals);
        if (funcTableOff < 0 || nameTableOff < 0 || ordTableOff < 0)
            throw new InvalidOperationException("Clean ntdll export tables are out of range.");

        var exports = new Dictionary<string, uint>(StringComparer.Ordinal);
        var byRva = new List<(string Name, uint Rva)>();
        for (uint i = 0; i < numberOfNames; i++)
        {
            var nameRvaOff = nameTableOff + (long)i * 4;
            if (nameRvaOff + 4 > fileBytes.Length)
                break;
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan((int)nameRvaOff, 4));
            var nameOff = RvaToOffset(nameRva);
            if (nameOff < 0)
                continue;
            var nameEnd = nameOff;
            while (nameEnd < fileBytes.Length && fileBytes[nameEnd] != 0 && nameEnd - nameOff < 256)
                nameEnd++;
            if (nameEnd >= fileBytes.Length || fileBytes[nameEnd] != 0)
                continue;
            var name = System.Text.Encoding.ASCII.GetString(fileBytes, nameOff, nameEnd - nameOff);

            var ordOff = ordTableOff + (long)i * 2;
            if (ordOff + 2 > fileBytes.Length)
                continue;
            var ordinal = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan((int)ordOff, 2));
            if (ordinal >= numberOfFunctions)
                continue;

            var funcRvaOff = funcTableOff + (long)ordinal * 4;
            if (funcRvaOff + 4 > fileBytes.Length)
                continue;
            var funcRva = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan((int)funcRvaOff, 4));
            if (funcRva == 0)
                continue;
            // Skip forwarders (RVA inside export directory).
            if (funcRva >= exportRva && (ulong)funcRva < (ulong)exportRva + exportSize)
                continue;

            exports[name] = funcRva;
            byRva.Add((name, funcRva));
        }

        byRva.Sort((a, b) => a.Rva.CompareTo(b.Rva));

        CleanNtdll = fileBytes;
        CleanSections = sections;
        CleanExports = exports;
        ExportsByRva = byRva;
    }

    private static int CleanRvaToOffset(uint rva)
    {
        var fileBytes = CleanNtdll!;
        foreach (var s in CleanSections)
        {
            var mapped = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && (ulong)rva - s.VirtualAddress < mapped)
            {
                var delta = rva - s.VirtualAddress;
                if (delta >= s.SizeOfRawData)
                    return -1;
                var fileOff = (long)s.PointerToRawData + delta;
                return fileOff < fileBytes.Length ? (int)fileOff : -1;
            }
        }
        return -1;
    }

    /// <summary>
    /// Validates a full syscall stub: mov r10,rcx; mov eax,SSN (zero-extended);
    /// a syscall (0F 05) within the next bytes; ret (C3) nearby.
    /// </summary>
    private static bool TryParseStubAtOffset(int fileOffset, out ushort ssn)
    {
        ssn = 0;
        var bytes = CleanNtdll!;
        if (fileOffset < 0 || fileOffset + 24 > bytes.Length)
            return false;

        if (bytes[fileOffset] != 0x4C || bytes[fileOffset + 1] != 0x8B || bytes[fileOffset + 2] != 0xD1)
            return false;
        if (bytes[fileOffset + 3] != 0xB8)
            return false;

        var candidate = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(fileOffset + 4, 2));
        if (candidate == 0 || candidate >= 0x1000)
            return false;
        // mov eax, imm32 with SSN < 0x1000 must be zero-extended.
        if (bytes[fileOffset + 6] != 0x00 || bytes[fileOffset + 7] != 0x00)
            return false;

        // syscall must appear within the stub body.
        var foundSyscall = false;
        for (var i = fileOffset + 8; i + 1 < fileOffset + 24 && i + 1 < bytes.Length; i++)
        {
            if (bytes[i] == 0x0F && bytes[i + 1] == 0x05)
            {
                foundSyscall = true;
                break;
            }
        }
        if (!foundSyscall)
            return false;

        // ret must appear nearby.
        var foundRet = false;
        for (var i = fileOffset + 8; i < fileOffset + 32 && i < bytes.Length; i++)
        {
            if (bytes[i] == 0xC3)
            {
                foundRet = true;
                break;
            }
        }
        if (!foundRet)
            return false;

        ssn = candidate;
        return true;
    }

    public static ushort GetSyscallNumber(string functionName)
    {
        Initialize();

        lock (CacheLock)
        {
            if (SsnCache.TryGetValue(functionName, out var cached))
                return cached;

            var ssn = ResolveSyscallNumber(functionName);
            if (ssn == 0)
                throw new InvalidOperationException($"Failed to resolve syscall number for {functionName}");

            SsnCache[functionName] = ssn;
            return ssn;
        }
    }

    private static ushort ResolveSyscallNumber(string functionName)
    {
        if (!CleanExports.TryGetValue(functionName, out var rva))
            return 0;

        var off = CleanRvaToOffset(rva);
        if (off >= 0 && TryParseStubAtOffset(off, out var direct))
            return direct;

        return HaloGateResolve(rva);
    }

    private const int StubStride = 0x20;
    private const int HaloMaxSteps = 16;

    private static ushort HaloGateResolve(uint targetRva)
    {
        for (var step = 1; step <= HaloMaxSteps; step++)
        {
            // Forward neighbor: higher address holds a higher SSN.
            var fwdRva = targetRva + (uint)(step * StubStride);
            var fwdOff = CleanRvaToOffset(fwdRva);
            if (fwdOff >= 0 && TryParseStubAtOffset(fwdOff, out var fwdSsn))
            {
                var candidate = (int)fwdSsn - step;
                if (candidate > 0 && candidate < 0x1000)
                    return (ushort)candidate;
            }

            // Backward neighbor: lower address holds a lower SSN.
            if (targetRva >= (uint)(step * StubStride))
            {
                var bwdRva = targetRva - (uint)(step * StubStride);
                var bwdOff = CleanRvaToOffset(bwdRva);
                if (bwdOff >= 0 && TryParseStubAtOffset(bwdOff, out var bwdSsn))
                {
                    var candidate = (int)bwdSsn + step;
                    if (candidate > 0 && candidate < 0x1000)
                        return (ushort)candidate;
                }
            }
        }

        return 0;
    }

    public static IntPtr GetSyscallStub(string functionName)
    {
        Initialize();

        lock (CacheLock)
        {
            if (StubCache.TryGetValue(functionName, out var cached) && cached != IntPtr.Zero)
                return cached;

            // Resolve inside the lock (Monitor is re-entrant on the same thread).
            if (!SsnCache.TryGetValue(functionName, out var ssn))
            {
                ssn = ResolveSyscallNumber(functionName);
                if (ssn == 0)
                    throw new InvalidOperationException($"Failed to resolve syscall number for {functionName}");
                SsnCache[functionName] = ssn;
            }

            var stub = CreateSyscallStub(ssn);
            StubCache[functionName] = stub;
            return stub;
        }
    }

    private static IntPtr CreateSyscallStub(ushort ssn)
    {
        var stub = new byte[]
        {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, SSN (placeholder)
            0x0F, 0x05,                   // syscall
            0xC3                          // ret
        };

        BitConverter.GetBytes(ssn).CopyTo(stub, 4);

        var ptr = NativeMethods.VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length,
            NativeConstants.MEM_COMMIT | NativeConstants.MEM_RESERVE, NativeConstants.PAGE_EXECUTE_READWRITE);
        if (ptr == IntPtr.Zero)
            throw new InvalidOperationException("Failed to allocate syscall stub");

        Marshal.Copy(stub, 0, ptr, stub.Length);

        // Bootstrap exception: no syscall stub exists yet at this point, so
        // self-protection must NOT go through the Nt* wrappers (each wrapper
        // calls GetSyscallStub, which re-enters this method = unbounded
        // recursion). Raw Win32 on our own process memory is used instead;
        // this is local stub setup, never a target operation.
        var selfHandle = System.Diagnostics.Process.GetCurrentProcess().Handle;
        if (!NativeMethods.VirtualProtectEx(selfHandle, ptr, (UIntPtr)stub.Length, NativeConstants.PAGE_EXECUTE_READ, out _))
            throw new InvalidOperationException("Failed to protect syscall stub");

        if (!NativeMethods.FlushInstructionCache(selfHandle, ptr, (UIntPtr)stub.Length))
            throw new InvalidOperationException("Failed to flush syscall stub");
        return ptr;
    }

    public static int NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref UIntPtr regionSize, uint allocationType, uint protect)
    {
        var stub = GetSyscallStub("NtAllocateVirtualMemory");
        var del = Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemoryDelegate>(stub);
        return del(processHandle, ref baseAddress, zeroBits, ref regionSize, allocationType, protect);
    }

    public static int NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint newProtect, out uint oldProtect)
    {
        var stub = GetSyscallStub("NtProtectVirtualMemory");
        var del = Marshal.GetDelegateForFunctionPointer<NtProtectVirtualMemoryDelegate>(stub);
        return del(processHandle, ref baseAddress, ref regionSize, newProtect, out oldProtect);
    }

    public static int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, out UIntPtr bytesWritten)
    {
        var stub = GetSyscallStub("NtWriteVirtualMemory");
        var del = Marshal.GetDelegateForFunctionPointer<NtWriteVirtualMemoryDelegate>(stub);
        var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            return del(processHandle, baseAddress, handle.AddrOfPinnedObject(), (UIntPtr)(uint)buffer.Length, out bytesWritten);
        }
        finally
        {
            handle.Free();
        }
    }

    public static int NtReadVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, out UIntPtr bytesRead)
    {
        var stub = GetSyscallStub("NtReadVirtualMemory");
        var del = Marshal.GetDelegateForFunctionPointer<NtReadVirtualMemoryDelegate>(stub);
        var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            return del(processHandle, baseAddress, handle.AddrOfPinnedObject(), (UIntPtr)(uint)buffer.Length, out bytesRead);
        }
        finally
        {
            handle.Free();
        }
    }

    public static int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startRoutine, IntPtr argument, uint createFlags, IntPtr zeroBits, IntPtr stackSize, IntPtr maximumStackSize, IntPtr attributeList)
    {
        var stub = GetSyscallStub("NtCreateThreadEx");
        var del = Marshal.GetDelegateForFunctionPointer<NtCreateThreadExDelegate>(stub);
        return del(out threadHandle, desiredAccess, objectAttributes, processHandle, startRoutine, argument, createFlags, zeroBits, stackSize, maximumStackSize, attributeList);
    }

    public static int NtOpenProcessByPid(out IntPtr processHandle, uint desiredAccess, uint pid)
    {
        var stub = GetSyscallStub("NtOpenProcess");
        var del = Marshal.GetDelegateForFunctionPointer<NtOpenProcessDelegate>(stub);
        var cidPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeClientId>());
        try
        {
            Marshal.StructureToPtr(new NativeClientId { UniqueProcess = new IntPtr(pid), UniqueThread = IntPtr.Zero }, cidPtr, false);
            return del(out processHandle, desiredAccess, IntPtr.Zero, cidPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(cidPtr);
        }
    }

    public static int NtOpenThreadByTid(out IntPtr threadHandle, uint desiredAccess, uint tid)
    {
        var stub = GetSyscallStub("NtOpenThread");
        var del = Marshal.GetDelegateForFunctionPointer<NtOpenThreadDelegate>(stub);
        var cidPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeClientId>());
        try
        {
            Marshal.StructureToPtr(new NativeClientId { UniqueProcess = IntPtr.Zero, UniqueThread = new IntPtr(tid) }, cidPtr, false);
            return del(out threadHandle, desiredAccess, IntPtr.Zero, cidPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(cidPtr);
        }
    }

    public static int NtFreeVirtualMemory(IntPtr processHandle, IntPtr baseAddress)
    {
        var stub = GetSyscallStub("NtFreeVirtualMemory");
        var del = Marshal.GetDelegateForFunctionPointer<NtFreeVirtualMemoryDelegate>(stub);
        var baseAddr = baseAddress;
        var regionSize = UIntPtr.Zero;
        return del(processHandle, ref baseAddr, ref regionSize, NativeConstants.MEM_RELEASE);
    }

    public static int NtFlushInstructionCache(IntPtr processHandle, IntPtr baseAddress, int size)
    {
        var stub = GetSyscallStub("NtFlushInstructionCache");
        var del = Marshal.GetDelegateForFunctionPointer<NtFlushInstructionCacheDelegate>(stub);
        return del(processHandle, baseAddress, (UIntPtr)(uint)size);
    }

    public static int NtCreateSection(out IntPtr sectionHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr maximumSize, uint sectionPageProtection, uint allocationAttributes, IntPtr fileHandle)
    {
        var stub = GetSyscallStub("NtCreateSection");
        var del = Marshal.GetDelegateForFunctionPointer<NtCreateSectionDelegate>(stub);
        return del(out sectionHandle, desiredAccess, objectAttributes, maximumSize, sectionPageProtection, allocationAttributes, fileHandle);
    }

    public static int NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, UIntPtr commitSize, IntPtr sectionOffset, out UIntPtr viewSize, uint inheritDisposition, uint allocationType, uint win32Protect)
    {
        var stub = GetSyscallStub("NtMapViewOfSection");
        var del = Marshal.GetDelegateForFunctionPointer<NtMapViewOfSectionDelegate>(stub);
        return del(sectionHandle, processHandle, ref baseAddress, zeroBits, commitSize, sectionOffset, out viewSize, inheritDisposition, allocationType, win32Protect);
    }

    public static int NtUnmapViewOfSection(IntPtr processHandle, IntPtr baseAddress)
    {
        var stub = GetSyscallStub("NtUnmapViewOfSection");
        var del = Marshal.GetDelegateForFunctionPointer<NtUnmapViewOfSectionDelegate>(stub);
        return del(processHandle, baseAddress);
    }

    public static int NtGetContextThread(IntPtr threadHandle, IntPtr context)
    {
        var stub = GetSyscallStub("NtGetContextThread");
        var del = Marshal.GetDelegateForFunctionPointer<NtGetContextThreadDelegate>(stub);
        return del(threadHandle, context);
    }

    public static int NtSetContextThread(IntPtr threadHandle, IntPtr context)
    {
        var stub = GetSyscallStub("NtSetContextThread");
        var del = Marshal.GetDelegateForFunctionPointer<NtSetContextThreadDelegate>(stub);
        return del(threadHandle, context);
    }

    public static int NtSuspendThread(IntPtr threadHandle, out uint previousSuspendCount)
    {
        var stub = GetSyscallStub("NtSuspendThread");
        var del = Marshal.GetDelegateForFunctionPointer<NtSuspendThreadDelegate>(stub);
        return del(threadHandle, out previousSuspendCount);
    }

    public static int NtResumeThread(IntPtr threadHandle, out uint previousSuspendCount)
    {
        var stub = GetSyscallStub("NtResumeThread");
        var del = Marshal.GetDelegateForFunctionPointer<NtResumeThreadDelegate>(stub);
        return del(threadHandle, out previousSuspendCount);
    }

    public static int NtClose(IntPtr handle)
    {
        var stub = GetSyscallStub("NtClose");
        var del = Marshal.GetDelegateForFunctionPointer<NtCloseDelegate>(stub);
        return del(handle);
    }

    public static int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass, IntPtr threadInformation, int threadInformationLength, out int returnLength)
    {
        var stub = GetSyscallStub("NtQueryInformationThread");
        var del = Marshal.GetDelegateForFunctionPointer<NtQueryInformationThreadDelegate>(stub);
        return del(threadHandle, threadInformationClass, threadInformation, threadInformationLength, out returnLength);
    }

    /// <summary>
    /// Queries ThreadBasicInformation (class 0) and returns the OS thread ID.
    /// </summary>
    public static int NtQueryThreadId(IntPtr threadHandle, out uint threadId)
    {
        threadId = 0;
        var size = Marshal.SizeOf<THREAD_BASIC_INFORMATION>();
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            var status = NtQueryInformationThread(threadHandle, 0, buf, size, out _);
            if (status != 0)
                return status;
            var info = Marshal.PtrToStructure<THREAD_BASIC_INFORMATION>(buf);
            threadId = (uint)info.UniqueThread.ToInt64();
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    public static int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, int processInformationLength, out int returnLength)
    {
        var stub = GetSyscallStub("NtQueryInformationProcess");
        var del = Marshal.GetDelegateForFunctionPointer<NtQueryInformationProcessDelegate>(stub);
        return del(processHandle, processInformationClass, processInformation, processInformationLength, out returnLength);
    }

    /// <summary>
    /// Queries ProcessBasicInformation (class 0) and returns the PEB base.
    /// </summary>
    public static int NtQueryPeb(IntPtr processHandle, out IntPtr pebBase)
    {
        pebBase = IntPtr.Zero;
        var size = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            var status = NtQueryInformationProcess(processHandle, 0, buf, size, out _);
            if (status != 0)
                return status;
            pebBase = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(buf).PebBaseAddress;
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>
    /// Queries ThreadBasicInformation (class 0) and returns the TEB base.
    /// Marshals the native struct without exposing ref/IntPtr mismatches.
    /// </summary>
    public static int NtQueryTeb(IntPtr threadHandle, out IntPtr tebBase)
    {
        tebBase = IntPtr.Zero;
        var size = Marshal.SizeOf<THREAD_BASIC_INFORMATION>();
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            var status = NtQueryInformationThread(threadHandle, 0, buf, size, out _);
            if (status != 0)
                return status;
            var info = Marshal.PtrToStructure<THREAD_BASIC_INFORMATION>(buf);
            tebBase = info.TebBaseAddress;
            return 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }
}
