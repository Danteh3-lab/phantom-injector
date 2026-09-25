using System.Buffers.Binary;
using System.Text;
using Phantom.Core.Injection;
using Phantom.Core.Native;

namespace Phantom.Core.PostInject;

public sealed class ExportCallResult
{
    public bool Success { get; init; }
    public IntPtr FunctionAddress { get; init; }
    public ulong ReturnValue { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// Calls an exported function inside a target process after injection.
/// Arguments may be integers (decimal or 0x-prefixed hex) or strings, which
/// are copied into the target as ANSI C strings and passed by pointer.
/// </summary>
public static class ExportCaller
{
    private const uint Access =
        NativeConstants.PROCESS_CREATE_THREAD |
        NativeConstants.PROCESS_QUERY_INFORMATION |
        NativeConstants.PROCESS_VM_OPERATION |
        NativeConstants.PROCESS_VM_WRITE |
        NativeConstants.PROCESS_VM_READ;

    /// <summary>
    /// Resolves an export through the target's GetProcAddress and calls it.
    /// Requires the module's PE headers to be intact.
    /// </summary>
    public static ExportCallResult Call(uint pid, IntPtr moduleBase, string functionName,
        IReadOnlyList<string> args, int timeoutMs = 10_000)
    {
        IntPtr hProcess = IntPtr.Zero;
        var allocations = new List<IntPtr>();
        var indeterminate = false;
        try
        {
            var openStatus = DirectSyscalls.NtOpenProcessByPid(out hProcess, Access, pid);
            if (openStatus != 0 || hProcess == IntPtr.Zero)
            {
                hProcess = IntPtr.Zero;
                return new ExportCallResult { Success = false, Error = $"OpenProcess failed: 0x{openStatus:X8}" };
            }

            var getProcAddress = ResolveRemoteExport(pid, "kernel32.dll", "GetProcAddress");
            var namePtr = AllocWrite(hProcess, Encoding.ASCII.GetBytes(functionName + "\0"), allocations);
            var resultPtr = AllocWrite(hProcess, new byte[8], allocations);
            var completionPtr = AllocWrite(hProcess, new byte[8], allocations);

            var resolveStubCode = BuildResolveStub(moduleBase, namePtr, getProcAddress, resultPtr, completionPtr);
            var resolveStub = AllocWrite(hProcess, resolveStubCode, allocations, NativeConstants.PAGE_EXECUTE_READWRITE);
            NativeMethods.FlushInstructionCacheChecked(hProcess, resolveStub, resolveStubCode.Length);

            if (!RunThread(hProcess, resolveStub, timeoutMs, out indeterminate))
            {
                return new ExportCallResult
                {
                    Success = false,
                    Error = indeterminate
                        ? "GetProcAddress remote call did not complete; remote buffers were left intact."
                        : "GetProcAddress remote call failed."
                };
            }

            if (!TryReadInt64(hProcess, completionPtr, out var completion) || completion == 0)
                return new ExportCallResult { Success = false, Error = "GetProcAddress exited abnormally before recording a result." };

            if (!TryReadInt64(hProcess, resultPtr, out var functionAddressValue))
                return new ExportCallResult { Success = false, Error = "Could not read the GetProcAddress result." };

            var functionAddress = new IntPtr(functionAddressValue);
            if (functionAddress == IntPtr.Zero)
                return new ExportCallResult { Success = false, Error = $"Export '{functionName}' not found." };

            return Invoke(hProcess, functionAddress, args, timeoutMs, allocations, ref indeterminate);
        }
        catch (Exception ex)
        {
            return new ExportCallResult { Success = false, Error = ex.Message };
        }
        finally
        {
            Cleanup(hProcess, allocations, indeterminate);
        }
    }

    /// <summary>
    /// Calls an already-resolved export address. Use this for modules whose PE
    /// headers were erased (resolve the RVA from the original file with
    /// <see cref="TryGetExportRva"/> and add the module base).
    /// </summary>
    public static ExportCallResult CallByAddress(uint pid, IntPtr functionAddress,
        IReadOnlyList<string> args, int timeoutMs = 10_000)
    {
        IntPtr hProcess = IntPtr.Zero;
        var allocations = new List<IntPtr>();
        var indeterminate = false;
        try
        {
            var openStatusByAddr = DirectSyscalls.NtOpenProcessByPid(out hProcess, Access, pid);
            if (openStatusByAddr != 0 || hProcess == IntPtr.Zero)
            {
                hProcess = IntPtr.Zero;
                return new ExportCallResult { Success = false, Error = $"OpenProcess failed: 0x{openStatusByAddr:X8}" };
            }

            if (functionAddress == IntPtr.Zero)
                return new ExportCallResult { Success = false, Error = "The export address is null." };

            return Invoke(hProcess, functionAddress, args, timeoutMs, allocations, ref indeterminate);
        }
        catch (Exception ex)
        {
            return new ExportCallResult { Success = false, Error = ex.Message };
        }
        finally
        {
            Cleanup(hProcess, allocations, indeterminate);
        }
    }

    /// <summary>
    /// Reads an export's RVA from the file on disk. This works independently of
    /// the loaded image's headers, so it is usable after PE header erasure.
    /// </summary>
    public static bool TryGetExportRva(string dllPath, string functionName, out uint rva)
    {
        rva = 0;
        try
        {
            var pe = new PeImage(File.ReadAllBytes(dllPath));
            var export = pe.Directory(PeImage.DirectoryExport);
            if (export.VirtualAddress == 0 || export.Size < 40 ||
                (ulong)export.VirtualAddress + export.Size > pe.SizeOfImage)
                return false;

            var dirOff = pe.RvaToOffset(export.VirtualAddress);
            if (!RawRangeFits(pe.Raw, dirOff, 40))
                return false;

            var numberOfFunctions = ReadU32(pe.Raw, dirOff + 20);
            var numberOfNames = ReadU32(pe.Raw, dirOff + 24);
            var addressOfFunctions = ReadU32(pe.Raw, dirOff + 28);
            var addressOfNames = ReadU32(pe.Raw, dirOff + 32);
            var addressOfNameOrdinals = ReadU32(pe.Raw, dirOff + 36);

            if (numberOfFunctions == 0 ||
                numberOfNames > 0x10000 || numberOfFunctions > 0x10000)
                return false;

            var funcsOff = pe.RvaToOffset(addressOfFunctions);
            if (!RawRangeFits(pe.Raw, funcsOff, (ulong)numberOfFunctions * 4))
                return false;

            var namesOff = pe.RvaToOffset(addressOfNames);
            var ordinalsOff = pe.RvaToOffset(addressOfNameOrdinals);
            if (numberOfNames > 0 &&
                (!RawRangeFits(pe.Raw, namesOff, (ulong)numberOfNames * 4) ||
                 !RawRangeFits(pe.Raw, ordinalsOff, (ulong)numberOfNames * 2)))
                return false;

            for (var i = 0; i < numberOfNames; i++)
            {
                var nameRva = ReadU32(pe.Raw, namesOff + i * 4);
                var nameOff = pe.RvaToOffset(nameRva);
                if (nameOff < 0)
                    continue;

                if (!string.Equals(ReadAscii(pe.Raw, nameOff), functionName, StringComparison.Ordinal))
                    continue;

                var ordinalOffset = ordinalsOff + i * 2;
                if (ordinalOffset + 2 > pe.Raw.Length)
                    return false;

                var ordinal = BinaryPrimitives.ReadUInt16LittleEndian(pe.Raw.AsSpan(ordinalOffset, 2));
                if (ordinal >= numberOfFunctions)
                    return false;

                var funcRva = ReadU32(pe.Raw, funcsOff + ordinal * 4);

                // Must be real code inside the image, and not a forwarded-export
                // string (which lives inside the export directory).
                if (funcRva == 0 || funcRva >= pe.SizeOfImage || !pe.IsRvaInImage(funcRva))
                    return false;
                if (funcRva >= export.VirtualAddress &&
                    (ulong)funcRva < (ulong)export.VirtualAddress + export.Size)
                    return false;

                rva = funcRva;
                return true;
            }
        }
        catch
        {
            // Fall through to false.
        }

        return false;
    }

    private static ExportCallResult Invoke(IntPtr hProcess, IntPtr functionAddress, IReadOnlyList<string> args,
        int timeoutMs, List<IntPtr> allocations, ref bool indeterminate)
    {
        var resultPtr = AllocWrite(hProcess, new byte[8], allocations);
        var completionPtr = AllocWrite(hProcess, new byte[8], allocations);
        var nativeArgs = BuildArguments(hProcess, args, allocations);

        var callStubCode = BuildCallStub(functionAddress, nativeArgs, resultPtr, completionPtr);
        var callStub = AllocWrite(hProcess, callStubCode, allocations, NativeConstants.PAGE_EXECUTE_READWRITE);
        NativeMethods.FlushInstructionCacheChecked(hProcess, callStub, callStubCode.Length);

        if (!RunThread(hProcess, callStub, timeoutMs, out indeterminate))
        {
            return new ExportCallResult
            {
                Success = false,
                FunctionAddress = functionAddress,
                Error = indeterminate
                    ? "Exported function did not complete; remote buffers were left intact."
                    : "Exported function call failed."
            };
        }

        if (!TryReadInt64(hProcess, completionPtr, out var completion) || completion == 0)
            return new ExportCallResult { Success = false, FunctionAddress = functionAddress, Error = "The exported function exited abnormally before recording a result." };

        if (!TryReadInt64(hProcess, resultPtr, out var returnValue))
            return new ExportCallResult { Success = false, FunctionAddress = functionAddress, Error = "Could not read the exported function's return value." };

        return new ExportCallResult { Success = true, FunctionAddress = functionAddress, ReturnValue = (ulong)returnValue };
    }

    private static void Cleanup(IntPtr hProcess, List<IntPtr> allocations, bool indeterminate)
    {
        if (hProcess == IntPtr.Zero)
            return;

        if (!indeterminate)
        {
            foreach (var alloc in allocations)
                DirectSyscalls.NtFreeVirtualMemory(hProcess, alloc);
        }

        NativeMethods.CloseHandle(hProcess);
    }

    private static ulong[] BuildArguments(IntPtr hProcess, IReadOnlyList<string> args, List<IntPtr> allocations)
    {
        var values = new ulong[4];
        for (var i = 0; i < args.Count && i < 4; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                ulong.TryParse(arg.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out var hex))
            {
                values[i] = hex;
            }
            else if (ulong.TryParse(arg, out var number))
            {
                values[i] = number;
            }
            else
            {
                var ptr = AllocWrite(hProcess, Encoding.ASCII.GetBytes(arg + "\0"), allocations);
                values[i] = (ulong)ptr.ToInt64();
            }
        }

        return values;
    }

    private static bool RunThread(IntPtr hProcess, IntPtr start, int timeoutMs, out bool indeterminate)
    {
        indeterminate = false;
        var createStatus = DirectSyscalls.NtCreateThreadEx(out var hThread, NativeConstants.THREAD_ALL_ACCESS,
            IntPtr.Zero, hProcess, start, IntPtr.Zero, 0,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (createStatus != 0 || hThread == IntPtr.Zero)
            return false;

        try
        {
            var wait = NativeMethods.WaitForSingleObject(hThread, (uint)timeoutMs);
            if (wait == NativeConstants.WAIT_TIMEOUT || wait == NativeConstants.WAIT_FAILED)
            {
                indeterminate = true;
                return false;
            }

            return true;
        }
        finally
        {
            NativeMethods.CloseHandle(hThread);
        }
    }

    private static IntPtr AllocWrite(IntPtr hProcess, byte[] data, List<IntPtr> allocations, uint protect = NativeConstants.PAGE_READWRITE)
    {
        var baseAddr = IntPtr.Zero;
        var region = (UIntPtr)(uint)data.Length;
        var allocStatus = DirectSyscalls.NtAllocateVirtualMemory(hProcess, ref baseAddr, IntPtr.Zero,
            ref region, NativeConstants.MEM_COMMIT | NativeConstants.MEM_RESERVE, protect);
        if (allocStatus != 0 || baseAddr == IntPtr.Zero)
            throw new InvalidOperationException($"NtAllocateVirtualMemory failed: 0x{allocStatus:X8}");

        allocations.Add(baseAddr);
        if (DirectSyscalls.NtWriteVirtualMemory(hProcess, baseAddr, data, out var written) != 0 ||
            written.ToUInt64() != (ulong)data.Length)
            throw new InvalidOperationException("NtWriteVirtualMemory failed.");
        return baseAddr;
    }

    private static bool TryReadInt64(IntPtr hProcess, IntPtr address, out long value)
    {
        var buffer = new byte[8];
        if (DirectSyscalls.NtReadVirtualMemory(hProcess, address, buffer, out var read) != 0 ||
            read.ToUInt64() != 8)
        {
            value = 0;
            return false;
        }

        value = BinaryPrimitives.ReadInt64LittleEndian(buffer);
        return true;
    }

    private static byte[] BuildResolveStub(IntPtr moduleBase, IntPtr name, IntPtr getProcAddress, IntPtr result, IntPtr completion)
    {
        var code = new List<byte>();
        EmitMovRcxImm64(code, moduleBase.ToInt64());
        EmitMovRdxImm64(code, name.ToInt64());
        EmitMovRaxImm64(code, getProcAddress.ToInt64());
        code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
        code.AddRange(new byte[] { 0xFF, 0xD0 });
        EmitMovR10Imm64(code, result.ToInt64());
        code.AddRange(new byte[] { 0x49, 0x89, 0x02 });                                          // mov [r10], rax
        EmitMovR10Imm64(code, completion.ToInt64());
        code.AddRange(new byte[] { 0x49, 0xC7, 0x02, 0x01, 0x00, 0x00, 0x00 });                  // mov qword [r10], 1
        code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
        code.Add(0xC3);
        return code.ToArray();
    }

    private static byte[] BuildCallStub(IntPtr function, ulong[] args, IntPtr result, IntPtr completion)
    {
        var code = new List<byte>();
        EmitMovRcxImm64(code, (long)args[0]);
        EmitMovRdxImm64(code, (long)args[1]);
        EmitMovR8Imm64(code, (long)args[2]);
        EmitMovR9Imm64(code, (long)args[3]);
        EmitMovRaxImm64(code, function.ToInt64());
        code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
        code.AddRange(new byte[] { 0xFF, 0xD0 });
        EmitMovR10Imm64(code, result.ToInt64());
        code.AddRange(new byte[] { 0x49, 0x89, 0x02 });                                          // mov [r10], rax
        EmitMovR10Imm64(code, completion.ToInt64());
        code.AddRange(new byte[] { 0x49, 0xC7, 0x02, 0x01, 0x00, 0x00, 0x00 });                  // mov qword [r10], 1
        code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
        code.Add(0xC3);
        return code.ToArray();
    }

    private static void EmitMovRcxImm64(List<byte> c, long v) { c.Add(0x48); c.Add(0xB9); c.AddRange(BitConverter.GetBytes(v)); }
    private static void EmitMovRdxImm64(List<byte> c, long v) { c.Add(0x48); c.Add(0xBA); c.AddRange(BitConverter.GetBytes(v)); }
    private static void EmitMovR8Imm64(List<byte> c, long v) { c.Add(0x49); c.Add(0xB8); c.AddRange(BitConverter.GetBytes(v)); }
    private static void EmitMovR9Imm64(List<byte> c, long v) { c.Add(0x49); c.Add(0xB9); c.AddRange(BitConverter.GetBytes(v)); }
    private static void EmitMovRaxImm64(List<byte> c, long v) { c.Add(0x48); c.Add(0xB8); c.AddRange(BitConverter.GetBytes(v)); }
    private static void EmitMovR10Imm64(List<byte> c, long v) { c.Add(0x49); c.Add(0xBA); c.AddRange(BitConverter.GetBytes(v)); }

    private static uint ReadU32(byte[] buffer, int offset)
        => offset >= 0 && offset + 4 <= buffer.Length ? BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4)) : 0;

    private static bool RawRangeFits(byte[] buffer, int offset, ulong length)
        => offset >= 0 && (ulong)offset <= (ulong)buffer.Length &&
           length <= (ulong)buffer.Length - (ulong)offset;

    private static string ReadAscii(byte[] buffer, int offset)
    {
        if (offset < 0 || offset >= buffer.Length)
            return string.Empty;

        var end = offset;
        while (end < buffer.Length && buffer[end] != 0)
            end++;
        return Encoding.ASCII.GetString(buffer, offset, end - offset);
    }

    private static IntPtr ResolveRemoteExport(uint pid, string moduleName, string functionName)
        => RemoteFunctionResolver.Resolve(pid, moduleName, functionName);
}
