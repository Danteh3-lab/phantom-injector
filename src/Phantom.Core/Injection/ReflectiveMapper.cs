using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Shared reflective-mapping helpers for section-backed injectors.
/// Builds a properly laid-out image (headers + sections by VA), applies base
/// relocations, resolves imports with explicit dependency references, validates
/// TLS, and emits a hijack-compatible init stub that calls DllMain with the
/// required (hModule, DLL_PROCESS_ATTACH, reserved) arguments.
/// </summary>
internal static class ReflectiveMapper
{
    public sealed class ImportResolution
    {
        public bool Ok { get; init; }
        public bool TimedOut { get; init; }
        public string? Error { get; init; }
    }

    public readonly struct ExportLookup
    {
        public IntPtr Address { get; init; }
        public bool TimedOut { get; init; }
    }

    public static byte[] BuildMappedImage(PeImage pe)
    {
        var image = new byte[checked((int)pe.SizeOfImage)];
        var headerBytes = (int)Math.Min(pe.SizeOfHeaders, (uint)pe.Raw.Length);
        Buffer.BlockCopy(pe.Raw, 0, image, 0, Math.Min(headerBytes, image.Length));

        foreach (var s in pe.Sections)
        {
            if (s.SizeOfRawData == 0)
                continue;
            var dest = (int)s.VirtualAddress;
            var source = checked((int)s.PointerToRawData);
            var copy = checked((int)s.SizeOfRawData);
            if ((long)dest + copy > image.Length || (long)source + copy > pe.Raw.Length)
                throw new BadImageFormatException($"Section '{s.Name}' cannot be copied without truncation.");
            Buffer.BlockCopy(pe.Raw, source, image, dest, copy);
        }

        return image;
    }

    public static bool TryApplyRelocations(PeImage pe, byte[] image, long delta, out string? error)
    {
        error = null;
        var reloc = pe.Directory(PeImage.DirectoryBaseReloc);

        if (reloc.VirtualAddress == 0 || reloc.Size == 0)
        {
            if (reloc.VirtualAddress == 0 && reloc.Size == 0)
            {
                if (delta != 0)
                {
                    error = "The image has no relocation table but was not mapped at its preferred base.";
                    return false;
                }
                return true;
            }
            error = "The relocation directory has inconsistent RVA/size fields.";
            return false;
        }

        var start = (long)reloc.VirtualAddress;
        var end = start + reloc.Size;
        if (start < 0 || end > image.Length)
        {
            error = "The relocation directory points outside the mapped image.";
            return false;
        }

        var pos = (int)start;
        var endInt = (int)end;
        while (pos < endInt)
        {
            if (pos + 8 > endInt)
            {
                error = "A relocation block header runs past the directory.";
                return false;
            }
            var pageRva = ReadU32(image, pos);
            var blockSize = ReadU32(image, pos + 4);
            if (blockSize < 8 || (blockSize & 1) != 0)
            {
                error = "A relocation block has an invalid size.";
                return false;
            }
            if (pos + blockSize > endInt)
            {
                error = "A relocation block runs past the directory.";
                return false;
            }
            var entries = (int)((blockSize - 8) / 2);
            for (var i = 0; i < entries; i++)
            {
                var entry = ReadU16(image, pos + 8 + i * 2);
                var type = entry >> 12;
                var offset = entry & 0x0FFF;
                if (type == 0)
                    continue;
                if (type != 10)
                {
                    error = $"Unsupported relocation type {type} for AMD64.";
                    return false;
                }
                var target = (long)pageRva + offset;
                if (target < 0 || target + 8 > image.Length)
                {
                    error = "A relocation target points outside the mapped image.";
                    return false;
                }
                if (delta != 0)
                {
                    var value = (long)ReadU64(image, (int)target);
                    BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan((int)target, 8), (ulong)(value + delta));
                }
            }
            pos += (int)blockSize;
        }

        if (pos != endInt)
        {
            error = "The relocation directory was not consumed exactly.";
            return false;
        }
        return true;
    }

    public static List<IntPtr> ParseTlsCallbacks(PeImage pe, byte[] image, IntPtr remoteBase, out string? error)
    {
        error = null;
        var callbacks = new List<IntPtr>();
        var tls = pe.Directory(PeImage.DirectoryTls);
        if (tls.VirtualAddress == 0)
            return callbacks;
        if (tls.Size < 40)
        {
            error = "The image has an undersized TLS directory.";
            return callbacks;
        }
        var tlsOff = (int)tls.VirtualAddress;
        if (tlsOff < 0 || tlsOff + 40 > image.Length)
        {
            error = "The TLS directory points outside the mapped image.";
            return callbacks;
        }
        var startVa = ReadU64(image, tlsOff + 0);
        var endVa = ReadU64(image, tlsOff + 8);
        var sizeOfZeroFill = ReadU32(image, tlsOff + 32);
        if (startVa != endVa || sizeOfZeroFill != 0)
        {
            error = "The image uses static TLS data, which reflective mapping does not initialize. Use Standard, LdrLoadDll or ThreadHijack for this DLL.";
            return callbacks;
        }
        var callbacksVa = ReadU64(image, tlsOff + 24);
        if (callbacksVa == 0)
            return callbacks;
        var callbacksOff = (int)((long)callbacksVa - remoteBase.ToInt64());
        if (callbacksOff < 0 || callbacksOff + 8 > image.Length)
        {
            error = "The TLS callback list points outside the mapped image.";
            return callbacks;
        }
        var terminated = false;
        for (var i = 0; i < 0x10000; i++)
        {
            var entryOff = callbacksOff + i * 8;
            if (entryOff + 8 > image.Length)
                break;
            var callbackVa = ReadU64(image, entryOff);
            if (callbackVa == 0)
            {
                terminated = true;
                break;
            }
            callbacks.Add(new IntPtr((long)callbackVa));
        }
        if (!terminated)
        {
            error = "The TLS callback array is not null-terminated.";
            return new List<IntPtr>();
        }
        return callbacks;
    }

    public static bool TryGetExceptionTable(PeImage pe, byte[] image, IntPtr remoteBase, out IntPtr table, out int count, out string? error)
    {
        table = IntPtr.Zero;
        count = 0;
        error = null;
        var exception = pe.Directory(PeImage.DirectoryException);
        if ((exception.VirtualAddress == 0) != (exception.Size == 0))
        {
            error = "The exception directory has inconsistent RVA/size fields.";
            return false;
        }
        if (exception.VirtualAddress == 0)
            return true;
        if (exception.Size < 12 || exception.Size % 12 != 0 ||
            (long)exception.VirtualAddress + exception.Size > image.Length)
        {
            error = "The image has a malformed exception directory; refusing to map without unwind registration.";
            return false;
        }
        count = (int)(exception.Size / 12);
        table = IntPtr.Add(remoteBase, (int)exception.VirtualAddress);
        return true;
    }

    public static ImportResolution ResolveImports(
        PeImage pe,
        byte[] image,
        uint pid,
        IntPtr hProcess,
        int timeoutMs,
        List<IntPtr> dependencies,
        Func<string, (IntPtr Base, bool TimedOut)> loadLibrary)
    {
        var import = pe.Directory(PeImage.DirectoryImport);
        if (import.VirtualAddress == 0 && import.Size == 0)
            return new ImportResolution { Ok = true };
        if (import.VirtualAddress == 0 || import.Size == 0)
            return new ImportResolution { Error = "The import directory has inconsistent RVA/size fields." };

        var descriptorsStart = (int)import.VirtualAddress;
        var descriptorsEnd = descriptorsStart + (int)import.Size;
        if (descriptorsStart < 0 || descriptorsEnd < descriptorsStart || descriptorsEnd > image.Length)
            return new ImportResolution { Error = "The import directory points outside the mapped image." };

        var pos = descriptorsStart;
        var descriptorTerminated = false;
        while (pos + 20 <= descriptorsEnd)
        {
            var originalFirstThunk = ReadU32(image, pos);
            var nameRva = ReadU32(image, pos + 12);
            var firstThunk = ReadU32(image, pos + 16);
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
            {
                descriptorTerminated = true;
                break;
            }
            if (nameRva == 0 || nameRva >= (uint)image.Length)
                return new ImportResolution { Error = "An import descriptor has an invalid module-name RVA." };
            var dllName = ReadString(image, (int)nameRva);
            if (string.IsNullOrEmpty(dllName))
                return new ImportResolution { Error = "An import descriptor has no module name." };
            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            if (thunkRva == 0 || thunkRva >= (uint)image.Length)
                return new ImportResolution { Error = $"The import name table for '{dllName}' points outside the mapped image." };
            if (firstThunk == 0 || firstThunk >= (uint)image.Length)
                return new ImportResolution { Error = $"The import address table for '{dllName}' points outside the mapped image." };

            var load = loadLibrary(dllName);
            if (load.TimedOut)
                return new ImportResolution { TimedOut = true, Error = $"Dependency '{dllName}' could not be loaded deterministically." };
            if (load.Base == IntPtr.Zero)
                return new ImportResolution { Error = $"Failed to load dependency '{dllName}'." };
            dependencies.Add(load.Base);

            var t = (int)thunkRva;
            var iat = (int)firstThunk;
            var thunksTerminated = false;
            while (t + 8 <= image.Length && iat + 8 <= image.Length)
            {
                var thunk = ReadU64(image, t);
                if (thunk == 0)
                {
                    thunksTerminated = true;
                    break;
                }
                ExportLookup lookup;
                string importName;
                if ((thunk & 0x8000000000000000) != 0)
                {
                    var ordinal = (ushort)(thunk & 0xFFFF);
                    importName = "#" + ordinal;
                    lookup = ResolveExportByOrdinal(hProcess, load.Base, ordinal, pid, timeoutMs, loadLibrary, dependencies, 0);
                }
                else
                {
                    importName = ReadString(image, (int)(thunk & 0x7FFFFFFF) + 2);
                    lookup = ResolveExportByName(hProcess, load.Base, importName, pid, timeoutMs, loadLibrary, dependencies, 0);
                }
                if (lookup.TimedOut)
                    return new ImportResolution { TimedOut = true, Error = $"Timed out resolving '{dllName}!{importName}'." };
                if (lookup.Address == IntPtr.Zero)
                    return new ImportResolution { Error = $"Unresolved import '{dllName}!{importName}'." };
                BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(iat, 8), (ulong)lookup.Address.ToInt64());
                t += 8;
                iat += 8;
            }
            if (!thunksTerminated)
                return new ImportResolution { Error = $"The import thunk table for '{dllName}' is not null-terminated inside the image." };
            pos += 20;
        }
        if (!descriptorTerminated)
            return new ImportResolution { Error = "The import descriptor table is not null-terminated inside its declared size." };
        return new ImportResolution { Ok = true };
    }

    private static ExportLookup ResolveExportByName(IntPtr hProcess, IntPtr moduleBase, string funcName, uint pid, int timeoutMs, Func<string, (IntPtr Base, bool TimedOut)> loadLibrary, List<IntPtr> dependencies, int depth)
    {
        var (directoryRva, directorySize, sizeOfImage) = GetExportDirectory(hProcess, moduleBase);
        if (directoryRva == 0)
            return default;
        var directory = ReadRemote(hProcess, moduleBase, 40, directoryRva);
        var numberOfFunctions = ReadU32(directory, 20);
        var numberOfNames = ReadU32(directory, 24);
        var addressOfFunctions = ReadU32(directory, 28);
        var addressOfNames = ReadU32(directory, 32);
        var addressOfNameOrdinals = ReadU32(directory, 36);
        if (numberOfFunctions == 0 || numberOfNames > 0x10000 || numberOfFunctions > 0x10000 ||
            !RangeInImage(addressOfFunctions, (ulong)numberOfFunctions * 4, sizeOfImage) ||
            !TableRangeInImage(addressOfNames, (ulong)numberOfNames * 4, sizeOfImage) ||
            !TableRangeInImage(addressOfNameOrdinals, (ulong)numberOfNames * 2, sizeOfImage))
            return default;
        if (numberOfNames == 0)
            return default;
        var names = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)addressOfNames), (int)numberOfNames * 4, 0);
        var ordinals = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)addressOfNameOrdinals), (int)numberOfNames * 2, 0);
        for (var i = 0; i < numberOfNames; i++)
        {
            var nameRva = ReadU32(names, i * 4);
            if (!RangeInImage(nameRva, 1, sizeOfImage))
                return default;
            var maxNameLength = (int)Math.Min(128UL, (ulong)sizeOfImage - nameRva);
            if (!TryReadRemoteString(hProcess, IntPtr.Add(moduleBase, (int)nameRva), maxNameLength, out var name))
                return default;
            if (!string.Equals(name, funcName, StringComparison.Ordinal))
                continue;
            var ordinal = ReadU16(ordinals, i * 2);
            if (ordinal >= numberOfFunctions)
                return default;
            var funcs = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)addressOfFunctions), ((int)ordinal + 1) * 4, 0);
            var funcRva = ReadU32(funcs, ordinal * 4);
            return ResolvePossiblyForwarded(hProcess, moduleBase, funcRva, directoryRva, directorySize, sizeOfImage, pid, timeoutMs, loadLibrary, dependencies, depth);
        }
        return default;
    }

    private static ExportLookup ResolveExportByOrdinal(IntPtr hProcess, IntPtr moduleBase, ushort ordinal, uint pid, int timeoutMs, Func<string, (IntPtr Base, bool TimedOut)> loadLibrary, List<IntPtr> dependencies, int depth)
    {
        var (directoryRva, directorySize, sizeOfImage) = GetExportDirectory(hProcess, moduleBase);
        if (directoryRva == 0)
            return default;
        var directory = ReadRemote(hProcess, moduleBase, 40, directoryRva);
        var exportBase = ReadU32(directory, 16);
        var numberOfFunctions = ReadU32(directory, 20);
        var addressOfFunctions = ReadU32(directory, 28);
        if (numberOfFunctions == 0 || numberOfFunctions > 0x10000 ||
            !RangeInImage(addressOfFunctions, (ulong)numberOfFunctions * 4, sizeOfImage))
            return default;
        if (ordinal < exportBase)
            return default;
        var index = ordinal - exportBase;
        if (index >= numberOfFunctions || index > 0x10000)
            return default;
        var funcs = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)addressOfFunctions), (int)(index + 1) * 4, 0);
        var funcRva = ReadU32(funcs, (int)index * 4);
        return ResolvePossiblyForwarded(hProcess, moduleBase, funcRva, directoryRva, directorySize, sizeOfImage, pid, timeoutMs, loadLibrary, dependencies, depth);
    }

    private static ExportLookup ResolvePossiblyForwarded(IntPtr hProcess, IntPtr moduleBase, uint funcRva,
        uint directoryRva, uint directorySize, uint sizeOfImage, uint pid, int timeoutMs,
        Func<string, (IntPtr Base, bool TimedOut)> loadLibrary, List<IntPtr> dependencies, int depth)
    {
        if (funcRva == 0 || funcRva >= sizeOfImage)
            return default;
        if (funcRva >= directoryRva && (ulong)funcRva < (ulong)directoryRva + directorySize)
        {
            if (depth >= 8)
                return default;
            var forwarderEnd = (ulong)directoryRva + directorySize;
            var maxForwarderLength = (int)Math.Min(128UL, forwarderEnd - funcRva);
            if (maxForwarderLength <= 0 ||
                !TryReadRemoteString(hProcess, IntPtr.Add(moduleBase, (int)funcRva), maxForwarderLength, out var forwarder))
                return default;
            forwarder = forwarder.Trim();
            var dot = forwarder.IndexOf('.');
            if (dot <= 0 || dot >= forwarder.Length - 1)
                return default;
            var dll = forwarder[..dot] + ".dll";
            var function = forwarder[(dot + 1)..].Trim();
            if (function.Length == 0)
                return default;
            var load = loadLibrary(dll);
            if (load.TimedOut)
                return new ExportLookup { TimedOut = true };
            if (load.Base == IntPtr.Zero)
                return default;
            dependencies.Add(load.Base);
            if (function.StartsWith('#'))
            {
                return ushort.TryParse(function.AsSpan(1), out var forwardedOrdinal)
                    ? ResolveExportByOrdinal(hProcess, load.Base, forwardedOrdinal, pid, timeoutMs, loadLibrary, dependencies, depth + 1)
                    : default;
            }
            return ResolveExportByName(hProcess, load.Base, function, pid, timeoutMs, loadLibrary, dependencies, depth + 1);
        }
        return new ExportLookup { Address = IntPtr.Add(moduleBase, (int)funcRva) };
    }

    private static (uint Rva, uint Size, uint SizeOfImage) GetExportDirectory(IntPtr hProcess, IntPtr moduleBase)
    {
        if (!NativeMethods.GetModuleInformation(hProcess, moduleBase, out var moduleInfo,
                (uint)Marshal.SizeOf<MODULEINFO>()) ||
            moduleInfo.lpBaseOfDll != moduleBase || moduleInfo.SizeOfImage == 0 ||
            moduleInfo.SizeOfImage > int.MaxValue)
            return (0, 0, 0);
        var sizeOfImage = moduleInfo.SizeOfImage;
        if (sizeOfImage < 0x40)
            return (0, 0, 0);
        var dos = ReadRemote(hProcess, moduleBase, 0x40, 0);
        if (ReadU16(dos, 0) != 0x5A4D)
            return (0, 0, 0);
        var lfanew = ReadU32(dos, 0x3C);
        const int ntBytesNeeded = 0x18 + 120;
        if ((ulong)lfanew + ntBytesNeeded > sizeOfImage)
            return (0, 0, 0);
        var nt = ReadRemoteRaw(hProcess, IntPtr.Add(moduleBase, checked((int)lfanew)), ntBytesNeeded);
        if (ReadU32(nt, 0) != 0x00004550 || ReadU16(nt, 4) != 0x8664)
            return (0, 0, 0);
        var sizeOfOptionalHeader = ReadU16(nt, 20);
        var optional = 0x18;
        if (sizeOfOptionalHeader < 120 || ReadU16(nt, optional) != 0x20B ||
            (ulong)lfanew + 24UL + sizeOfOptionalHeader > sizeOfImage ||
            ReadU32(nt, optional + 56) != sizeOfImage)
            return (0, 0, sizeOfImage);
        var directoryRva = ReadU32(nt, optional + 112);
        var directorySize = ReadU32(nt, optional + 116);
        if (sizeOfImage == 0 || directoryRva == 0 || directorySize < 40 ||
            directoryRva >= sizeOfImage || !RangeInImage(directoryRva, directorySize, sizeOfImage))
            return (0, 0, sizeOfImage);
        return (directoryRva, directorySize, sizeOfImage);
    }

    private static bool RangeInImage(uint rva, ulong length, uint sizeOfImage)
        => rva != 0 && rva < sizeOfImage && length <= (ulong)sizeOfImage - rva;

    private static bool TableRangeInImage(uint rva, ulong length, uint sizeOfImage)
        => length == 0 || RangeInImage(rva, length, sizeOfImage);

    private static byte[] ReadRemote(IntPtr hProcess, IntPtr moduleBase, int size, uint rva)
        => ReadRemoteRaw(hProcess, IntPtr.Add(moduleBase, (int)rva), size);

    private static byte[] ReadRemoteRaw(IntPtr hProcess, IntPtr address, int size)
    {
        var buffer = new byte[size];
        if (DirectSyscalls.NtReadVirtualMemory(hProcess, address, buffer, out var read) != 0 ||
            read.ToUInt64() != (ulong)size)
            throw new InvalidOperationException($"NtReadVirtualMemory at 0x{address.ToInt64():X} failed.");
        return buffer;
    }

    private static bool TryReadRemoteString(IntPtr hProcess, IntPtr address, int max, out string value)
    {
        value = string.Empty;
        if (max <= 0)
            return false;
        var buffer = new byte[max];
        if (DirectSyscalls.NtReadVirtualMemory(hProcess, address, buffer, out var read) != 0 ||
            read.ToUInt64() == 0)
            return false;
        var available = (int)Math.Min((ulong)max, read.ToUInt64());
        var end = Array.IndexOf(buffer, (byte)0, 0, available);
        if (end < 0)
            return false;
        value = Encoding.ASCII.GetString(buffer, 0, end);
        return true;
    }

    /// <summary>
    /// Builds the hijack init stub: stack-align prologue, loader lock, unwind
    /// registration, TLS callbacks and DllMain(DLL_PROCESS_ATTACH) in order,
    /// with forward-order rollback on failed attach. Result codes:
    /// 1 = attached, 0 = rolled back, 2 = RtlAddFunctionTable failed,
    /// 3 = lock not acquired (no lock held), 4 = lock not released
    /// (the thread may still own the loader lock: the caller must NOT restore
    /// or resume it; leave it suspended in the park loop), 5 = detach ok but
    /// table removal failed. Every terminal path signals done before parking
    /// in a Sleep(1) loop (never ret) so the hijacked thread can be suspended.
    /// </summary>
    public static byte[] BuildHijackInitStub(
        IntPtr moduleBase,
        IReadOnlyList<IntPtr> callbacks,
        IntPtr entryPoint,
        IntPtr exceptionTable,
        int exceptionCount,
        IntPtr lockFunction,
        IntPtr unlockFunction,
        IntPtr addFunctionTable,
        IntPtr deleteFunctionTable,
        IntPtr sleepFunction,
        IntPtr resultSlot,
        IntPtr doneSlot,
        IntPtr cookieSlot)
    {
        var code = new List<byte>();
        var patches = new List<(int Offset, string Label)>();
        var labels = new Dictionary<string, int>();

        void Mark(string label) => labels[label] = code.Count;
        void Jcc(byte[] opcode, string label)
        {
            code.AddRange(opcode);
            patches.Add((code.Count, label));
            code.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });
        }
        void Jnz(string label) => Jcc(new byte[] { 0x0F, 0x85 }, label);
        void Jz(string label) => Jcc(new byte[] { 0x0F, 0x84 }, label);
        void Jmp(string label) => Jcc(new byte[] { 0xE9 }, label);
        void MovImm64(byte[] opcode, long value)
        {
            code.AddRange(opcode);
            code.AddRange(BitConverter.GetBytes(value));
        }
        // Entry RSP is 16-aligned (see prologue), so the 32-byte shadow space
        // (0x20) keeps RSP aligned before each call. (0x28 would be correct
        // only for 8-mod-16 entry via a normal call.)
        void Call(IntPtr target, params long[] args)
        {
            if (args.Length > 0) MovImm64(new byte[] { 0x48, 0xB9 }, args[0]);
            if (args.Length > 1) MovImm64(new byte[] { 0x48, 0xBA }, args[1]);
            if (args.Length > 2) MovImm64(new byte[] { 0x49, 0xB8 }, args[2]);
            if (args.Length > 3) MovImm64(new byte[] { 0x49, 0xB9 }, args[3]);
            MovImm64(new byte[] { 0x48, 0xB8 }, target.ToInt64());
            code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x20 });
            code.AddRange(new byte[] { 0xFF, 0xD0 });
            code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x20 });
        }

        // Entered via RIP redirect, not a call: the interrupted RSP has unknown
        // alignment. Normalize once so every nested call below is aligned
        // (each Call block is balanced, preserving this alignment).
        // The injector restores the original context afterwards, so RSP need
        // not be preserved here. The 0x8000 stack-margin check covers the
        // at-most-15-byte adjustment.
        code.AddRange(new byte[] { 0x48, 0x83, 0xE4, 0xF0 }); // and rsp, -16

        Call(lockFunction, 0, 0, cookieSlot.ToInt64());
        code.AddRange(new byte[] { 0x85, 0xC0 });
        Jnz("lock_failed");

        var hasFunctionTable = exceptionTable != IntPtr.Zero;
        if (hasFunctionTable)
        {
            Call(addFunctionTable, exceptionTable.ToInt64(), exceptionCount, moduleBase.ToInt64());
            code.AddRange(new byte[] { 0x84, 0xC0 });
            Jz("add_failed");
        }

        foreach (var callback in callbacks)
            Call(callback, moduleBase.ToInt64(), 1, 0);

        if (entryPoint == IntPtr.Zero)
        {
            EmitStoreResult(code, resultSlot, 1);
            Jmp("unlock");
        }
        else
        {
            Call(entryPoint, moduleBase.ToInt64(), 1, 0);
            code.AddRange(new byte[] { 0x85, 0xC0 });
            Jnz("attach_ok");

            foreach (var callback in callbacks)
                Call(callback, moduleBase.ToInt64(), 0, 0);
            Call(entryPoint, moduleBase.ToInt64(), 0, 0);

            if (hasFunctionTable)
            {
                Call(deleteFunctionTable, exceptionTable.ToInt64());
                code.AddRange(new byte[] { 0x84, 0xC0 });
                Jz("delete_failed");
            }
            EmitStoreResult(code, resultSlot, 0);
            Jmp("unlock");

            if (hasFunctionTable)
            {
                Mark("delete_failed");
                EmitStoreResult(code, resultSlot, 5);
                Jmp("unlock");
            }
            Mark("attach_ok");
            EmitStoreResult(code, resultSlot, 1);
            Jmp("unlock");
        }

        Mark("add_failed");
        EmitStoreResult(code, resultSlot, 2);
        Jmp("unlock");

        // Lock never acquired, so no lock is held: signal completion and park.
        // Callers must still read the result before restoring the thread.
        Mark("lock_failed");
        EmitStoreResult(code, resultSlot, 3);
        Jmp("signal");

        Mark("unlock");
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(cookieSlot.ToInt64()));
        code.AddRange(new byte[] { 0x49, 0x8B, 0x12 });
        code.AddRange(new byte[] { 0x31, 0xC9 });
        MovImm64(new byte[] { 0x48, 0xB8 }, unlockFunction.ToInt64());
        code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x20 });
        code.AddRange(new byte[] { 0xFF, 0xD0 });
        code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x20 });
        code.AddRange(new byte[] { 0x85, 0xC0 });
        Jnz("unlock_failed");
        Jmp("signal");

        Mark("unlock_failed");
        EmitStoreResult(code, resultSlot, 4);

        Mark("signal");
        EmitStoreResult64(code, doneSlot, 1);

        Mark("park");
        // Win64 home space for the Sleep call, reserved once (the loop never
        // returns, so no balancing add is needed). Without it Sleep could
        // spill registers onto the hijacked thread's stack contents.
        code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x20 }); // sub rsp, 0x20
        code.Add(0x48); code.Add(0xBB); code.AddRange(BitConverter.GetBytes(sleepFunction.ToInt64())); // mov rbx, Sleep
        Mark("park_loop");
        code.AddRange(new byte[] { 0xB9, 0x01, 0x00, 0x00, 0x00 }); // mov ecx, 1
        code.AddRange(new byte[] { 0xFF, 0xD3 });                   // call rbx
        Jmp("park_loop");

        foreach (var (offset, label) in patches)
        {
            var relative = labels[label] - (offset + 4);
            var bytes = BitConverter.GetBytes(relative);
            for (var i = 0; i < 4; i++)
                code[offset + i] = bytes[i];
        }
        return code.ToArray();
    }

    private static void EmitStoreResult(List<byte> code, IntPtr slot, int value)
    {
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(slot.ToInt64()));
        code.Add(0x41); code.Add(0xC7); code.Add(0x02); code.AddRange(BitConverter.GetBytes(value));
    }

    private static void EmitStoreResult64(List<byte> code, IntPtr slot, long value)
    {
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(slot.ToInt64()));
        code.AddRange(new byte[] { 0x49, 0xC7, 0x02, 0x01, 0x00, 0x00, 0x00 });
        _ = value;
    }

    private static ushort ReadU16(byte[] b, int o) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o, 2));
    private static uint ReadU32(byte[] b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o, 4));
    private static ulong ReadU64(byte[] b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o, 8));

    private static string ReadString(byte[] b, int offset, int max = 256)
    {
        if (offset < 0 || offset >= b.Length)
            return string.Empty;
        var end = offset;
        var limit = Math.Min(b.Length, offset + max);
        while (end < limit && b[end] != 0)
            end++;
        return Encoding.ASCII.GetString(b, offset, end - offset);
    }
}
