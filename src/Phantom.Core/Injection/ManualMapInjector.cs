using System.Buffers.Binary;
using System.Text;
using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Reflective / manual mapping. The image is mapped and its imports and
/// relocations are resolved by the injector, then DllMain is invoked
/// directly. The module never enters the target's loader lists, so Windows
/// itself is unaware a module was mapped.
/// </summary>
internal sealed class ManualMapInjector : InjectorBase
{
    public override InjectionMethod Method => InjectionMethod.ManualMap;

    public override InjectionResult Inject(uint pid, string dllPath, InjectionOptions options)
    {
        IntPtr hProcess = IntPtr.Zero;
        var remoteBase = IntPtr.Zero;
        var remoteStub = IntPtr.Zero;
        var committed = false;

        // The mapped image / init stub may still be referenced (a thread runs the
        // stub, or a live function table points into it): keep them mapped.
        var imageHazard = false;

        // A dependency load/release thread may still be running: do not touch the
        // process's loader state again, but the image itself is unaffected.
        var dependencyHazard = false;

        var dependencies = new List<IntPtr>();
        var dependenciesReleased = false;

        // Releases already-acquired dependency references and records the
        // rollback outcome on the message, so a failure never claims cleanup
        // that did not happen.
        InjectionResult FailMapping(string message)
        {
            if (!dependencyHazard && dependencies.Count > 0)
            {
                if (!ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs, out var releaseError))
                {
                    dependencyHazard = true;
                    message += " Dependency rollback also failed (" + releaseError + ").";
                }
            }

            dependenciesReleased = true;
            return InjectionResult.Fail(Method, dllPath, message);
        }

        try
        {
            var raw = File.ReadAllBytes(dllPath);
            var pe = new PeImage(raw);

            hProcess = NativeMethods.OpenProcess(InjectionAccess, false, pid);
            if (hProcess == IntPtr.Zero)
                return InjectionResult.Fail(Method, dllPath, "OpenProcess failed: " + Win32Error.LastError(), NativeMethods.GetLastError());

            var image = BuildImage(pe);

            // Try to honour the preferred base first so relocations are unnecessary.
            remoteBase = NativeMethods.VirtualAllocEx(hProcess, (IntPtr)(long)pe.ImageBase, (UIntPtr)pe.SizeOfImage,
                NativeConstants.MEM_COMMIT | NativeConstants.MEM_RESERVE, NativeConstants.PAGE_EXECUTE_READWRITE);
            if (remoteBase == IntPtr.Zero)
                remoteBase = AllocateRemote(hProcess, (int)pe.SizeOfImage, NativeConstants.PAGE_EXECUTE_READWRITE);

            var delta = (long)remoteBase.ToInt64() - (long)pe.ImageBase;
            if (!TryProcessRelocations(pe, image, delta, out var relocError))
                return InjectionResult.Fail(Method, dllPath, relocError ?? "Relocation processing failed.");

            // Reject unsupported/malformed TLS before any dependency is loaded or
            // reference-counted, so a rejected image has no side effects.
            var callbacks = ParseTlsCallbacks(pe, image, remoteBase, out var tlsError);
            if (tlsError is not null)
                return InjectionResult.Fail(Method, dllPath, tlsError);

            // The caller owns the dependency list so exceptions during import
            // resolution still leave the acquired references releasable.
            var imports = ResolveImports(pe, image, pid, hProcess, options.TimeoutMs, dependencies);
            if (!imports.Ok)
            {
                if (imports.TimedOut)
                    dependencyHazard = true;
                return FailMapping(imports.Error ?? "Import resolution failed.");
            }

            WriteRemote(hProcess, remoteBase, image);
            NativeMethods.FlushInstructionCacheChecked(hProcess, remoteBase, (int)pe.SizeOfImage);

            ProtectSections(pe, hProcess, remoteBase);

            var entryPoint = pe.AddressOfEntryPoint == 0
                ? IntPtr.Zero
                : IntPtr.Add(remoteBase, (int)pe.AddressOfEntryPoint);

            // x64 unwind metadata lives in the exception directory and must be
            // registered dynamically because the image is outside the loader.
            // Reject present-but-invalid or inconsistent directories.
            var exception = pe.Directory(PeImage.DirectoryException);
            if ((exception.VirtualAddress == 0) != (exception.Size == 0))
                return FailMapping("The exception directory has inconsistent RVA/size fields.");

            var exceptionCount = 0;
            var exceptionTable = IntPtr.Zero;
            if (exception.VirtualAddress != 0)
            {
                if (exception.Size < 12 || exception.Size % 12 != 0 ||
                    (long)exception.VirtualAddress + exception.Size > image.Length)
                {
                    return FailMapping("The image has a malformed exception directory; refusing to map without unwind registration.");
                }

                exceptionCount = (int)(exception.Size / 12);
                exceptionTable = IntPtr.Add(remoteBase, (int)exception.VirtualAddress);
            }

            // Nothing to register or initialize.
            if (callbacks.Count == 0 && entryPoint == IntPtr.Zero && exceptionTable == IntPtr.Zero)
            {
                committed = true;
                return InjectionResult.Ok(Method, dllPath, remoteBase);
            }

            var lockFunction = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrLockLoaderLock");
            var unlockFunction = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrUnlockLoaderLock");
            if (lockFunction == IntPtr.Zero || unlockFunction == IntPtr.Zero)
                return FailMapping("Could not resolve the loader-lock functions required to initialize the mapped image.");

            var addFunctionTable = IntPtr.Zero;
            var deleteFunctionTable = IntPtr.Zero;
            if (exceptionTable != IntPtr.Zero)
            {
                addFunctionTable = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "RtlAddFunctionTable");
                deleteFunctionTable = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "RtlDeleteFunctionTable");
                if (addFunctionTable == IntPtr.Zero || deleteFunctionTable == IntPtr.Zero)
                    return FailMapping("Could not resolve RtlAddFunctionTable/RtlDeleteFunctionTable for x64 unwind metadata.");
            }

            // One stub runs everything on a single thread: loader lock, unwind
            // metadata, TLS callbacks and DllMain (all in array order), with a
            // forward-order rollback on a failed attach. The completion flag is
            // written only after every call returned normally, and the loader
            // lock is released before it is written.
            const int initSlotsSize = 32;
            var placeholder = BuildInitStub(remoteBase, callbacks, entryPoint, exceptionTable, exceptionCount,
                lockFunction, unlockFunction, addFunctionTable, deleteFunctionTable,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            remoteStub = AllocateRemote(hProcess, initSlotsSize + placeholder.Length, NativeConstants.PAGE_EXECUTE_READWRITE);
            var resultAddress = remoteStub;
            var completionAddress = IntPtr.Add(remoteStub, 8);
            var cookieAddress = IntPtr.Add(remoteStub, 16);
            var stubAddress = IntPtr.Add(remoteStub, initSlotsSize);

            WriteRemote(hProcess, resultAddress, new byte[initSlotsSize]);

            var initStub = BuildInitStub(remoteBase, callbacks, entryPoint, exceptionTable, exceptionCount,
                lockFunction, unlockFunction, addFunctionTable, deleteFunctionTable,
                resultAddress, completionAddress, cookieAddress);
            WriteRemote(hProcess, stubAddress, initStub);
            NativeMethods.FlushInstructionCacheChecked(hProcess, stubAddress, initStub.Length);

            var init = RunRemoteThread(hProcess, stubAddress, IntPtr.Zero, options.TimeoutMs);
            if (init.UnsafeToFree)
            {
                imageHazard = true;
                return FailMapping("Image initialization did not complete; the remote thread may still be running so the mapped image was left intact.");
            }

            if (!init.Created)
                return FailMapping("CreateRemoteThread failed: " + Win32Error.LastError());

            if (!TryReadRemoteInt64(hProcess, completionAddress, out var completion) || completion == 0)
            {
                // The thread exited without reaching the completion flag, so the
                // module's state is unknown and the loader lock it acquired may
                // still be held; leave the image mapped.
                imageHazard = true;
                return FailMapping("Image initialization ended abnormally (ExitThread or an unhandled exception); the target loader lock may be held and the mapped image was left intact.");
            }

            if (!TryReadRemoteInt64(hProcess, resultAddress, out var initResult))
            {
                imageHazard = true;
                return FailMapping("The initialization result could not be read; the mapped image was left intact.");
            }

            switch (initResult)
            {
                case 1:
                    committed = true;
                    return InjectionResult.Ok(Method, dllPath, remoteBase, init.ThreadId);

                case 0:
                    // The stub rolled the attach back; the image is safe to release.
                    return FailMapping("DllMain returned FALSE; the attach was rolled back.");

                case 2:
                    // RtlAddFunctionTable failed before TLS/DllMain ran; safe to release.
                    return FailMapping("RtlAddFunctionTable failed; initialization never ran.");

                case 3:
                    return FailMapping("Could not acquire the target loader lock; nothing was initialized.");

                case 4:
                    imageHazard = true;
                    return FailMapping("The target loader lock could not be released; the mapped image was left intact.");

                case 5:
                    // Attach failed and the dynamic function table is still
                    // registered, so the image must not be released.
                    imageHazard = true;
                    return FailMapping("DllMain returned FALSE and RtlDeleteFunctionTable failed; the mapped image was left intact because a live function table references it.");

                default:
                    imageHazard = true;
                    return FailMapping($"Image initialization returned an unexpected result ({initResult}); the mapped image was left intact.");
            }
        }
        catch (Exception ex)
        {
            return InjectionResult.Fail(Method, dllPath, ex.Message);
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
            {
                // A failed mapping must release the dependency references it
                // acquired; a committed one retains them (there is no unmap yet).
                // Safety net for paths that threw instead of going through
                // FailMapping: release what was acquired.
                if (!dependenciesReleased && !dependencyHazard && !committed && dependencies.Count > 0)
                {
                    if (!ReleaseDependencies(hProcess, pid, dependencies, options.TimeoutMs, out _))
                        dependencyHazard = true;
                }

                // Only release remote memory once no thread we started can still
                // be executing from it.
                if (!imageHazard)
                {
                    FreeRemote(hProcess, remoteStub);
                    if (!committed)
                        FreeRemote(hProcess, remoteBase);
                }

                NativeMethods.CloseHandle(hProcess);
            }
        }
    }

    /// <summary>
    /// Releases dependency references acquired during a failed mapping, newest
    /// first, verifying every FreeLibrary. Returns false (with a reason) if any
    /// release could not be confirmed, which includes an indeterminate remote
    /// thread; the caller must then leave the mapped image in place.
    /// </summary>
    private static bool ReleaseDependencies(IntPtr hProcess, uint pid, IReadOnlyList<IntPtr> dependencies, int timeoutMs, out string? error)
    {
        error = null;
        if (dependencies.Count == 0)
            return true;

        var freeLibrary = RemoteFunctionResolver.Resolve(pid, "kernel32.dll", "FreeLibrary");
        if (freeLibrary == IntPtr.Zero)
        {
            error = "could not resolve FreeLibrary";
            return false;
        }

        for (var i = dependencies.Count - 1; i >= 0; i--)
        {
            var exec = RunRemoteThread(hProcess, freeLibrary, dependencies[i], timeoutMs);
            if (exec.UnsafeToFree)
            {
                error = $"releasing dependency 0x{dependencies[i].ToInt64():X} did not complete";
                return false;
            }

            if (!exec.Created)
            {
                error = "CreateRemoteThread failed while releasing a dependency";
                return false;
            }

            if (exec.ExitCode == 0)
            {
                error = $"FreeLibrary returned FALSE for dependency 0x{dependencies[i].ToInt64():X}";
                return false;
            }
        }

        return true;
    }

    private static byte[] BuildImage(PeImage pe)
    {
        var image = new byte[pe.SizeOfImage];
        var headerBytes = (int)Math.Min(pe.SizeOfHeaders, (uint)pe.Raw.Length);
        Buffer.BlockCopy(pe.Raw, 0, image, 0, Math.Min(headerBytes, image.Length));

        foreach (var s in pe.Sections)
        {
            if (s.SizeOfRawData == 0 || s.VirtualAddress >= image.Length)
                continue;

            var dest = (int)s.VirtualAddress;
            var copy = (int)Math.Min(s.SizeOfRawData, (uint)(image.Length - dest));
            copy = Math.Min(copy, pe.Raw.Length - (int)s.PointerToRawData);
            if (copy > 0)
                Buffer.BlockCopy(pe.Raw, (int)s.PointerToRawData, image, dest, copy);
        }

        return image;
    }

    /// <summary>
    /// Validates and, when <paramref name="delta"/> is nonzero, applies the base
    /// relocations. Malformed tables are rejected so initialization never runs
    /// with unrelocated addresses.
    /// </summary>
    private static bool TryProcessRelocations(PeImage pe, byte[] image, long delta, out string? error)
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
                var entryOff = pos + 8 + i * 2;
                var entry = ReadU16(image, entryOff);
                var type = entry >> 12;
                var offset = entry & 0x0FFF;

                if (type == 0)
                    continue; // IMAGE_REL_BASED_ABSOLUTE padding

                if (type != 10) // only IMAGE_REL_BASED_DIR64 is valid for AMD64
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

    private sealed class ImportResolution
    {
        public bool Ok { get; init; }
        public bool TimedOut { get; init; }
        public string? Error { get; init; }
    }

    private readonly struct ExportLookup
    {
        public IntPtr Address { get; init; }
        public bool TimedOut { get; init; }
    }

    /// <summary>
    /// Resolves every import, owning an explicit reference to each dependency
    /// (LoadLibraryW increments the refcount even when already loaded) so a
    /// concurrent unload cannot leave a dangling IAT. References are appended to
    /// the caller-owned <paramref name="dependencies"/> list as they are taken,
    /// so a failure or exception still leaves the caller able to release them.
    /// </summary>
    private static ImportResolution ResolveImports(PeImage pe, byte[] image, uint pid, IntPtr hProcess, int timeoutMs, List<IntPtr> dependencies)
    {
        var import = pe.Directory(PeImage.DirectoryImport);
        if (import.VirtualAddress == 0 && import.Size == 0)
            return new ImportResolution { Ok = true };

        if (import.VirtualAddress == 0 || import.Size == 0)
            return new ImportResolution { Error = "The import directory has inconsistent RVA/size fields." };

        // Descriptors must live entirely inside the declared import directory.
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

            // Take an explicit reference and use the authoritative HMODULE.
            var load = RemoteLoadLibrary(hProcess, pid, dllName, timeoutMs);
            if (load.TimedOut)
                return new ImportResolution { TimedOut = true, Error = $"Dependency '{dllName}' could not be loaded deterministically." };
            if (load.Base == IntPtr.Zero)
                return new ImportResolution { Error = $"Failed to load dependency '{dllName}'." };

            var moduleBase = load.Base;
            dependencies.Add(moduleBase);

            var t = (int)thunkRva;
            var iat = (int)firstThunk;
            var thunksTerminated = false;

            // Every read and every IAT write must fit inside the image; the
            // array must be null-terminated before either range is exhausted.
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
                    lookup = ResolveExportByOrdinal(hProcess, moduleBase, ordinal, pid, timeoutMs, dependencies, 0);
                }
                else
                {
                    // IMAGE_IMPORT_BY_NAME starts with a 2-byte hint; the name
                    // itself begins right after it.
                    importName = ReadString(image, (int)(thunk & 0x7FFFFFFF) + 2);
                    lookup = ResolveExportByName(hProcess, moduleBase, importName, pid, timeoutMs, dependencies, 0);
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

    private static (IntPtr Base, bool TimedOut) RemoteLoadLibrary(IntPtr hProcess, uint pid, string moduleName, int timeoutMs)
    {
        // Only "thread may still execute" maps to TimedOut; that is a dependency
        // hazard, so the image itself is still safe to release.
        var baseAddress = RemoteLoadLibraryResult(hProcess, pid, moduleName, timeoutMs,
            out _, out var unsafeToFree, out _);
        return (baseAddress, unsafeToFree);
    }

    private static ExportLookup ResolveExportByName(IntPtr hProcess, IntPtr moduleBase, string funcName, uint pid, int timeoutMs, List<IntPtr> dependencies, int depth)
    {
        var (directoryRva, directorySize, sizeOfImage) = GetExportDirectory(hProcess, moduleBase);
        if (directoryRva == 0)
            return default;

        var directory = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)directoryRva), 40);
        var numberOfFunctions = ReadU32(directory, 20);
        var numberOfNames = ReadU32(directory, 24);
        var addressOfFunctions = ReadU32(directory, 28);
        var addressOfNames = ReadU32(directory, 32);
        var addressOfNameOrdinals = ReadU32(directory, 36);

        // Guard against corrupt export tables before allocating read buffers,
        // and require every table to lie inside the exporting module's image.
        if (numberOfNames > 0x10000 || numberOfFunctions > 0x10000 ||
            !RangeInImage(addressOfFunctions, (ulong)numberOfFunctions * 4, sizeOfImage) ||
            !RangeInImage(addressOfNames, (ulong)numberOfNames * 4, sizeOfImage) ||
            !RangeInImage(addressOfNameOrdinals, (ulong)numberOfNames * 2, sizeOfImage))
            return default;

        var names = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)addressOfNames), (int)numberOfNames * 4);
        var ordinals = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)addressOfNameOrdinals), (int)numberOfNames * 2);

        for (var i = 0; i < numberOfNames; i++)
        {
            var nameRva = ReadU32(names, i * 4);
            var name = ReadRemoteString(hProcess, IntPtr.Add(moduleBase, (int)nameRva), 128);
            if (!string.Equals(name, funcName, StringComparison.Ordinal))
                continue;

            var ordinal = ReadU16(ordinals, i * 2);

            // The name-ordinal entry indexes AddressOfFunctions; validate it
            // against NumberOfFunctions before using it.
            if (ordinal >= numberOfFunctions)
                return default;

            var funcs = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)addressOfFunctions), ((int)ordinal + 1) * 4);
            var funcRva = ReadU32(funcs, ordinal * 4);
            return ResolvePossiblyForwarded(hProcess, moduleBase, funcRva, directoryRva, directorySize, sizeOfImage, pid, timeoutMs, dependencies, depth);
        }

        return default;
    }

    private static ExportLookup ResolveExportByOrdinal(IntPtr hProcess, IntPtr moduleBase, ushort ordinal, uint pid, int timeoutMs, List<IntPtr> dependencies, int depth)
    {
        var (directoryRva, directorySize, sizeOfImage) = GetExportDirectory(hProcess, moduleBase);
        if (directoryRva == 0)
            return default;

        var directory = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)directoryRva), 40);
        var exportBase = ReadU32(directory, 16);
        var numberOfFunctions = ReadU32(directory, 20);
        var addressOfFunctions = ReadU32(directory, 28);

        if (numberOfFunctions > 0x10000 ||
            !RangeInImage(addressOfFunctions, (ulong)numberOfFunctions * 4, sizeOfImage))
            return default;

        if (ordinal < exportBase)
            return default;

        var index = ordinal - exportBase;

        // NumberOfFunctions is the authoritative bound for the function table.
        if (index >= numberOfFunctions || index > 0x10000)
            return default;

        var funcs = ReadRemote(hProcess, IntPtr.Add(moduleBase, (int)addressOfFunctions), (int)(index + 1) * 4);
        var funcRva = ReadU32(funcs, (int)index * 4);
        return ResolvePossiblyForwarded(hProcess, moduleBase, funcRva, directoryRva, directorySize, sizeOfImage, pid, timeoutMs, dependencies, depth);
    }

    private static ExportLookup ResolvePossiblyForwarded(IntPtr hProcess, IntPtr moduleBase, uint funcRva,
        uint directoryRva, uint directorySize, uint sizeOfImage, uint pid, int timeoutMs, List<IntPtr> dependencies, int depth)
    {
        // A zero or out-of-image function RVA is never a valid export: returning
        // moduleBase + funcRva would hand back an arbitrary remote address.
        if (funcRva == 0 || funcRva >= sizeOfImage)
            return default;

        if (funcRva >= directoryRva && (ulong)funcRva < (ulong)directoryRva + directorySize)
        {
            // Bound the forwarder chain so a cyclic forwarder cannot recurse forever.
            if (depth >= 8)
                return default;

            var forwarder = ReadRemoteString(hProcess, IntPtr.Add(moduleBase, (int)funcRva), 128).Trim();
            var dot = forwarder.IndexOf('.');

            // A malformed forwarder must NOT fall through to moduleBase + funcRva,
            // which is the address of the forwarder string itself.
            if (dot <= 0 || dot >= forwarder.Length - 1)
                return default;

            var dll = forwarder[..dot] + ".dll";
            var function = forwarder[(dot + 1)..].Trim();
            if (function.Length == 0)
                return default;

            // Own a reference to the forwarder target as well. A forwarded
            // export resolves to another image, so a reference must be held
            // for the same lifetime as the mapped module.
            var load = RemoteLoadLibrary(hProcess, pid, dll, timeoutMs);
            if (load.TimedOut)
                return new ExportLookup { TimedOut = true };
            if (load.Base == IntPtr.Zero)
                return default;

            var forwardBase = load.Base;
            dependencies.Add(forwardBase);

            // Forwarders may target a name or an ordinal ("DLL.#123").
            if (function.StartsWith('#'))
            {
                return ushort.TryParse(function.AsSpan(1), out var forwardedOrdinal)
                    ? ResolveExportByOrdinal(hProcess, forwardBase, forwardedOrdinal, pid, timeoutMs, dependencies, depth + 1)
                    : default;
            }

            return ResolveExportByName(hProcess, forwardBase, function, pid, timeoutMs, dependencies, depth + 1);
        }

        return new ExportLookup { Address = IntPtr.Add(moduleBase, (int)funcRva) };
    }

    private static (uint Rva, uint Size, uint SizeOfImage) GetExportDirectory(IntPtr hProcess, IntPtr moduleBase)
    {
        var dos = ReadRemote(hProcess, moduleBase, 0x40);
        if (ReadU16(dos, 0) != 0x5A4D)
            return (0, 0, 0);

        var lfanew = (int)ReadU32(dos, 0x3C);
        var nt = ReadRemote(hProcess, IntPtr.Add(moduleBase, lfanew), 0x108);
        if (ReadU32(nt, 0) != 0x00004550)
            return (0, 0, 0);

        var optional = 0x18;
        var sizeOfImage = ReadU32(nt, optional + 56);
        var directoryRva = ReadU32(nt, optional + 112);
        var directorySize = ReadU32(nt, optional + 116);

        // The export directory must lie inside the exporting image; otherwise no
        // export can be trusted.
        if (sizeOfImage == 0 || directoryRva == 0 || directorySize < 40 ||
            directoryRva >= sizeOfImage || !RangeInImage(directoryRva, directorySize, sizeOfImage))
            return (0, 0, sizeOfImage);

        return (directoryRva, directorySize, sizeOfImage);
    }

    /// <summary>
    /// True when <paramref name="rva"/> and <paramref name="length"/> bytes fit
    /// inside an image of <paramref name="sizeOfImage"/> (overflow-safe).
    /// </summary>
    private static bool RangeInImage(uint rva, ulong length, uint sizeOfImage)
        => rva != 0 && rva < sizeOfImage && (ulong)rva + length <= sizeOfImage;

    private static void ProtectSections(PeImage pe, IntPtr hProcess, IntPtr remoteBase)
    {
        foreach (var s in pe.Sections)
        {
            if (s.VirtualAddress == 0)
                continue;

            // Protect the full extent that was copied: max(VirtualSize, SizeOfRawData).
            var size = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (size == 0)
                continue;

            if (!NativeMethods.VirtualProtectEx(hProcess, IntPtr.Add(remoteBase, (int)s.VirtualAddress), (UIntPtr)size,
                    PeImage.CharacteristicsToProtection(s.Characteristics), out _))
                throw new InvalidOperationException($"VirtualProtectEx failed for section '{s.Name}': " + Win32Error.LastError());
        }

        if (!NativeMethods.VirtualProtectEx(hProcess, remoteBase, (UIntPtr)pe.SizeOfHeaders,
                NativeConstants.PAGE_READONLY, out _))
            throw new InvalidOperationException("VirtualProtectEx failed for the PE headers: " + Win32Error.LastError());
    }

    /// <summary>
    /// Parses the TLS directory and returns the callback list. Rejects malformed
    /// directories and images that use static TLS data, since reflective mapping
    /// cannot allocate the template/index or install per-thread TLS blocks.
    /// </summary>
    private static List<IntPtr> ParseTlsCallbacks(PeImage pe, byte[] image, IntPtr remoteBase, out string? error)
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

        // Any template data or zero-fill means the DLL depends on static TLS.
        if (startVa != endVa || sizeOfZeroFill != 0)
        {
            error = "The image uses static TLS data, which manual mapping does not fully initialize. " +
                    "Use Standard, LdrLoadDll or ThreadHijack for this DLL.";
            return callbacks;
        }

        // ApplyRelocations has already rebased every VA, so the callback list and
        // its entries are absolute addresses in the target. Index back into the
        // image buffer by subtracting remoteBase (not the preferred ImageBase).
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

    /// <summary>
    /// Builds the single initialization stub run on one remote thread. It
    /// acquires the loader lock, registers the image's x64 unwind metadata,
    /// then runs every TLS callback and DllMain (DLL_PROCESS_ATTACH) — both in
    /// array order. A failed attach is rolled back with TLS callbacks and
    /// DllMain in DLL_PROCESS_DETACH order (same forward order), then the
    /// function table is removed. The loader lock is always released (except
    /// when it could not be acquired) before the completion flag is written.
    /// Result codes: 1 = attached, 0 = attach failed and rolled back,
    /// 5 = attach failed and the function table could not be removed,
    /// 3 = loader lock not acquired, 4 = loader lock not released.
    /// </summary>
    private static byte[] BuildInitStub(
        IntPtr moduleBase,
        IReadOnlyList<IntPtr> callbacks,
        IntPtr entryPoint,
        IntPtr exceptionTable,
        int exceptionCount,
        IntPtr lockFunction,
        IntPtr unlockFunction,
        IntPtr addFunctionTable,
        IntPtr deleteFunctionTable,
        IntPtr resultSlot,
        IntPtr completionSlot,
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

        // A call block; RSP is 16-byte aligned at the call because every block
        // is balanced and the thread enters at 8 mod 16.
        void Call(IntPtr target, params long[] args)
        {
            if (args.Length > 0) MovImm64(new byte[] { 0x48, 0xB9 }, args[0]); // rcx
            if (args.Length > 1) MovImm64(new byte[] { 0x48, 0xBA }, args[1]); // rdx
            if (args.Length > 2) MovImm64(new byte[] { 0x49, 0xB8 }, args[2]); // r8
            if (args.Length > 3) MovImm64(new byte[] { 0x49, 0xB9 }, args[3]); // r9
            MovImm64(new byte[] { 0x48, 0xB8 }, target.ToInt64());             // rax
            code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 });             // sub rsp, 0x28
            code.AddRange(new byte[] { 0xFF, 0xD0 });                         // call rax
            code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 });             // add rsp, 0x28
        }

        // LdrLockLoaderLock(0, NULL, &cookie)
        Call(lockFunction, 0, 0, cookieSlot.ToInt64());
        code.AddRange(new byte[] { 0x85, 0xC0 }); // test eax, eax
        Jnz("lock_failed");

        // RtlAddFunctionTable(table, count, imageBase) — BOOLEAN, test AL.
        var hasFunctionTable = exceptionTable != IntPtr.Zero;
        if (hasFunctionTable)
        {
            Call(addFunctionTable, exceptionTable.ToInt64(), exceptionCount, moduleBase.ToInt64());
            code.AddRange(new byte[] { 0x84, 0xC0 }); // test al, al
            Jz("add_failed");
        }

        // TLS callbacks (DLL_PROCESS_ATTACH) in array order.
        foreach (var callback in callbacks)
            Call(callback, moduleBase.ToInt64(), 1, 0);

        if (entryPoint == IntPtr.Zero)
        {
            EmitStoreResult(code, resultSlot, 1);
            Jmp("unlock");
        }
        else
        {
            Call(entryPoint, moduleBase.ToInt64(), 1, 0);   // eax = DllMain result
            code.AddRange(new byte[] { 0x85, 0xC0 });       // test eax, eax
            Jnz("attach_ok");

            // Failed attach: roll back in the same forward order, then remove
            // the function table. If the table cannot be removed, the image must
            // stay mapped because the live table points into it.
            foreach (var callback in callbacks)
                Call(callback, moduleBase.ToInt64(), 0, 0);
            Call(entryPoint, moduleBase.ToInt64(), 0, 0);

            if (hasFunctionTable)
            {
                Call(deleteFunctionTable, exceptionTable.ToInt64());
                code.AddRange(new byte[] { 0x84, 0xC0 }); // test al, al (BOOLEAN)
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

        Mark("lock_failed");
        EmitStoreResult(code, resultSlot, 3);
        Jmp("completion");

        Mark("unlock");
        // LdrUnlockLoaderLock(0, cookie) with the mandatory shadow space.
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(cookieSlot.ToInt64())); // mov r10, cookie
        code.AddRange(new byte[] { 0x49, 0x8B, 0x12 });                                             // mov rdx, [r10]
        code.AddRange(new byte[] { 0x31, 0xC9 });                                                   // xor ecx, ecx
        MovImm64(new byte[] { 0x48, 0xB8 }, unlockFunction.ToInt64());                               // mov rax, unlock
        code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 });                                       // sub rsp, 0x28
        code.AddRange(new byte[] { 0xFF, 0xD0 });                                                   // call rax
        code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 });                                       // add rsp, 0x28
        code.AddRange(new byte[] { 0x85, 0xC0 });                                                   // test eax, eax (NTSTATUS)
        Jnz("unlock_failed");
        Jmp("completion");

        Mark("unlock_failed");
        EmitStoreResult(code, resultSlot, 4);
        // fall through to completion

        Mark("completion");
        EmitStoreResult(code, completionSlot, 1);
        code.Add(0xC3); // ret

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
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(slot.ToInt64()));      // mov r10, slot
        code.Add(0x41); code.Add(0xC7); code.Add(0x02); code.AddRange(BitConverter.GetBytes(value)); // mov dword [r10], imm32
    }

    // ---- local byte-buffer helpers (indexed by RVA) ----

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

    // ---- remote read helpers ----

    private static byte[] ReadRemote(IntPtr hProcess, IntPtr address, int size)
    {
        var buffer = new byte[size];
        if (!NativeMethods.ReadProcessMemory(hProcess, address, buffer, (UIntPtr)size, out _))
            throw new InvalidOperationException($"ReadProcessMemory at 0x{address.ToInt64():X} failed: " + Win32Error.LastError());
        return buffer;
    }

    private static string ReadRemoteString(IntPtr hProcess, IntPtr address, int max)
    {
        var buffer = new byte[max];
        NativeMethods.ReadProcessMemory(hProcess, address, buffer, (UIntPtr)max, out _);
        var end = Array.IndexOf(buffer, (byte)0);
        if (end < 0)
            end = buffer.Length;
        return Encoding.ASCII.GetString(buffer, 0, end);
    }
}
