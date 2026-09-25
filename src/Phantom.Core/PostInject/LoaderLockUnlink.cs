using Phantom.Core.Injection;
using Phantom.Core.Native;

namespace Phantom.Core.PostInject;

/// <summary>
/// Unlinks a module from the target's loader lists from <em>inside</em> the
/// target while holding the loader lock. The entry is located by walking the
/// list under the lock (so it cannot be unloaded between lookup and mutation),
/// and the stub reports its outcome through a status word the injector reads.
/// Best-effort extension: the entry's hash-table linkage
/// (<c>LdrpHashTable</c> bucket chain) is also removed when it can be
/// positively identified, so hash-walking scanners lose it too. Hash offsets
/// differ between Windows builds, so the stub discovers the linkage by
/// round-trip validation (Flink-&gt;Blink and Blink-&gt;Flink must both point
/// back at the entry) and skips it otherwise — never unlinks on a guess.
/// </summary>
internal static class LoaderLockUnlink
{
    private const int TimeoutMs = 10_000;
    private const int PebLdrOffset = 0x18;
    private const int LdrInLoadOrderModuleList = 0x10;
    private const int LdrEntryDllBase = 0x30;

    // Candidate HashLinks offsets: [HashScanStart, HashScanEnd), step 16.
    // The true offset is build-dependent; every candidate must round-trip.
    private const long HashScanStart = 0x40;
    private const long HashScanEnd = 0x100;
    private const long HashScanStep = 0x10;

    // Generous bounds head-filter for hash candidates (round-trip is the
    // real check). Covers a 32-bucket LIST_ENTRY table and then some.
    private const long HashTableBounds = 0x1000;

    private const long StatusUnlinked = 1;
    private const long StatusNotFound = 2;
    private const long StatusLockFailed = 3;
    private const long StatusUnlockFailed = 4;
    private const long StatusListsOnlyNoHash = 5;

    public static bool TryUnlink(uint pid, IntPtr hProcess, IntPtr moduleBase, out string? error, out string? hashNote)
    {
        error = null;
        hashNote = null;

        if (!TryGetLoaderListHead(hProcess, out var listHead))
        {
            error = "could not read the target PEB loader list";
            return false;
        }

        var lockFunction = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrLockLoaderLock");
        var unlockFunction = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrUnlockLoaderLock");
        if (lockFunction == IntPtr.Zero || unlockFunction == IntPtr.Zero)
        {
            error = "could not resolve LdrLockLoaderLock/LdrUnlockLoaderLock";
            return false;
        }

        // Exported ntdll data symbol; Zero when the build does not export it.
        var hashTable = RemoteFunctionResolver.Resolve(pid, "ntdll.dll", "LdrpHashTable");
        if (hashTable == IntPtr.Zero)
            hashNote = "LdrpHashTable not exported on this build; PEB lists unlinked only.";

        const int regionSize = 0x200;
        const int stubOffset = 16;

        IntPtr region;
        try
        {
            region = SectionMemory.Allocate(hProcess, regionSize, NativeConstants.PAGE_EXECUTE_READWRITE);
        }
        catch (Exception ex)
        {
            error = "Section allocation failed: " + ex.Message;
            return false;
        }

        var keepMapped = false;
        try
        {
            var statusAddress = region;
            var stub = BuildStub(listHead, moduleBase, lockFunction, unlockFunction, statusAddress,
                hashTable, hashTable == IntPtr.Zero ? 0 : hashTable.ToInt64() + HashTableBounds);

            if (DirectSyscalls.NtWriteVirtualMemory(hProcess, statusAddress, new byte[8], out _) != 0 ||
                DirectSyscalls.NtWriteVirtualMemory(hProcess, IntPtr.Add(region, stubOffset), stub, out _) != 0)
            {
                error = "NtWriteVirtualMemory failed.";
                return false;
            }

            try
            {
                NativeMethods.FlushInstructionCacheChecked(hProcess, IntPtr.Add(region, stubOffset), stub.Length);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }

            var createStatus = DirectSyscalls.NtCreateThreadEx(out var hThread, NativeConstants.THREAD_ALL_ACCESS,
                IntPtr.Zero, hProcess, IntPtr.Add(region, stubOffset), IntPtr.Zero, 0,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (createStatus != 0 || hThread == IntPtr.Zero)
            {
                error = $"NtCreateThreadEx failed: 0x{createStatus:X8}";
                return false;
            }

            var wait = NativeMethods.WaitForSingleObject(hThread, TimeoutMs);
            NativeMethods.CloseHandle(hThread);

            if (wait == NativeConstants.WAIT_TIMEOUT || wait == NativeConstants.WAIT_FAILED)
            {
                // The loader-lock stub may still be running; leave it mapped.
                keepMapped = true;
                error = "loader-lock operation did not complete; stub left mapped";
                return false;
            }

            var statusBuffer = new byte[8];
            var status = DirectSyscalls.NtReadVirtualMemory(hProcess, statusAddress, statusBuffer, out var read) == 0 &&
                         read.ToUInt64() == 8
                ? BitConverter.ToInt64(statusBuffer, 0)
                : 0;

            switch (status)
            {
                case StatusUnlinked:
                    return true;
                case StatusListsOnlyNoHash:
                    hashNote ??= "entry hash linkage not verified on this build; PEB lists unlinked only.";
                    return true;
                case StatusNotFound:
                    error = "module was not present in the loader list";
                    return false;
                case StatusLockFailed:
                    error = "could not acquire the target loader lock";
                    return false;
                case StatusUnlockFailed:
                    error = "the target loader lock could not be released";
                    return false;
                default:
                    error = "loader-lock stub produced no usable result";
                    return false;
            }
        }
        finally
        {
            if (!keepMapped)
                SectionMemory.Free(hProcess, region);
        }
    }

    private static bool TryGetLoaderListHead(IntPtr hProcess, out IntPtr listHead)
    {
        listHead = IntPtr.Zero;

        if (DirectSyscalls.NtQueryPeb(hProcess, out var peb) != 0 || peb == IntPtr.Zero)
            return false;

        var buffer = new byte[8];
        if (DirectSyscalls.NtReadVirtualMemory(hProcess, IntPtr.Add(peb, PebLdrOffset), buffer, out var read) != 0 ||
            read.ToUInt64() != 8)
            return false;

        var ldr = (IntPtr)BitConverter.ToInt64(buffer, 0);
        if (ldr == IntPtr.Zero)
            return false;

        listHead = IntPtr.Add(ldr, LdrInLoadOrderModuleList);
        return true;
    }

    /// <summary>
    /// Builds x64 code that locks the loader, walks the InLoadOrder list to find
    /// the entry whose DllBase matches, unlinks all three list links, then
    /// unlocks. Writes a status word (1 = unlinked, 2 = not found, 3 = lock
    /// failed) so the caller does not have to re-read the list to know what
    /// happened.
    /// </summary>
    private static byte[] BuildStub(IntPtr listHead, IntPtr moduleBase, IntPtr lockFunction,
        IntPtr unlockFunction, IntPtr statusAddress, IntPtr hashTableBase, long hashTableEnd)
    {
        var code = new List<byte>();
        var patches = new List<(int Offset, string Label)>();
        var labels = new Dictionary<string, int>();

        void Mark(string label) => labels[label] = code.Count;

        void EmitJcc(byte[] opcode, string label)
        {
            code.AddRange(opcode);
            patches.Add((code.Count, label));
            code.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00 });
        }

        void EmitJmp(string label) => EmitJcc(new byte[] { 0xE9 }, label);

        code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x48 });                                 // sub rsp, 0x48
        code.AddRange(new byte[] { 0x48, 0x89, 0x5C, 0x24, 0x28 });                           // mov [rsp+0x28], rbx (preserve nonvolatile)
        code.AddRange(new byte[] { 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00 });   // mov qword [rsp+0x20], 0

        // status = 0
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(statusAddress.ToInt64()));
        code.AddRange(new byte[] { 0x49, 0xC7, 0x02, 0x00, 0x00, 0x00, 0x00 });                // mov qword [r10], 0

        // LdrLockLoaderLock(0, NULL, &cookie)
        code.AddRange(new byte[] { 0x31, 0xC9 });                                             // xor ecx, ecx
        code.AddRange(new byte[] { 0x31, 0xD2 });                                             // xor edx, edx
        code.AddRange(new byte[] { 0x4C, 0x8D, 0x44, 0x24, 0x20 });                           // lea r8, [rsp+0x20]
        code.Add(0x48); code.Add(0xB8); code.AddRange(BitConverter.GetBytes(lockFunction.ToInt64()));
        code.AddRange(new byte[] { 0xFF, 0xD0 });                                             // call rax
        code.AddRange(new byte[] { 0x85, 0xC0 });                                             // test eax, eax
        EmitJcc(new byte[] { 0x0F, 0x85 }, "lock_failed");                                    // jnz lock_failed

        // r8 = list head; r11 = first entry; r10d = iteration budget
        code.Add(0x49); code.Add(0xB8); code.AddRange(BitConverter.GetBytes(listHead.ToInt64()));  // mov r8, listHead
        code.AddRange(new byte[] { 0x4D, 0x8B, 0x18 });                                       // mov r11, [r8]
        code.AddRange(new byte[] { 0x41, 0xBA, 0x00, 0x00, 0x01, 0x00 });                     // mov r10d, 0x10000

        Mark("loop");
        code.AddRange(new byte[] { 0x4D, 0x85, 0xDB });                                       // test r11, r11
        EmitJcc(new byte[] { 0x0F, 0x84 }, "not_found");                                      // jz not_found
        code.AddRange(new byte[] { 0x4D, 0x39, 0xC3 });                                       // cmp r11, r8
        EmitJcc(new byte[] { 0x0F, 0x84 }, "not_found");                                      // je not_found
        code.AddRange(new byte[] { 0x49, 0x8B, 0x43, 0x30 });                                 // mov rax, [r11+0x30]
        code.Add(0x49); code.Add(0xB9); code.AddRange(BitConverter.GetBytes(moduleBase.ToInt64())); // mov r9, moduleBase
        code.AddRange(new byte[] { 0x4C, 0x39, 0xC8 });                                       // cmp rax, r9
        EmitJcc(new byte[] { 0x0F, 0x84 }, "found");                                          // je found
        code.AddRange(new byte[] { 0x4D, 0x8B, 0x1B });                                       // mov r11, [r11]
        code.AddRange(new byte[] { 0x41, 0xFF, 0xCA });                                       // dec r10d
        EmitJcc(new byte[] { 0x0F, 0x85 }, "loop");                                           // jnz loop

        // Fall through to not_found.
        Mark("not_found");
        EmitMovEbxImm(code, (int)StatusNotFound);
        EmitJmp("unlock");

        Mark("found");
        for (var i = 0; i < 3; i++)
        {
            var offset = (byte)(i * 0x10);
            code.AddRange(new byte[] { 0x49, 0x8B, 0x43, offset });              // mov rax, [r11+offset]
            code.AddRange(new byte[] { 0x49, 0x8B, 0x53, (byte)(offset + 8) });  // mov rdx, [r11+offset+8]
            code.AddRange(new byte[] { 0x48, 0x89, 0x02 });                      // mov [rdx], rax
            code.AddRange(new byte[] { 0x48, 0x89, 0x50, 0x08 });                // mov [rax+8], rdx
        }

        // Default outcome from here: lists unlinked, hash skipped/failed.
        EmitMovEbxImm(code, (int)StatusListsOnlyNoHash);

        // Hash-link removal. r8/r9 are dead past the list walk; r10 scratch.
        // tableBase == 0 (unexported) skips straight to unlock.
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(hashTableBase.ToInt64())); // mov r10, tableBase
        code.AddRange(new byte[] { 0x4D, 0x85, 0xD2 });                           // test r10, r10
        EmitJcc(new byte[] { 0x0F, 0x84 }, "unlock");                             // jz unlock
        code.Add(0x49); code.Add(0xC7); code.Add(0xC1);
        code.AddRange(BitConverter.GetBytes((int)HashScanStart));                 // mov r9, HashScanStart (offset cursor)

        Mark("hash_loop");
        code.AddRange(new byte[] { 0x4D, 0x8B, 0xC3 });                           // mov r8, r11
        code.AddRange(new byte[] { 0x4D, 0x01, 0xC8 });                           // add r8, r9 (candidate link address)
        code.AddRange(new byte[] { 0x49, 0x8B, 0x08 });                           // mov rcx, [r8] (Flink: reg=RCX, base=r8 via REX.B)
        code.AddRange(new byte[] { 0x49, 0x8B, 0x50, 0x08 });                     // mov rdx, [r8+8] (Blink; REX.B for r8 base)
        // Bounds head-filter: tableBase <= x < tableEnd, for both ends.
        // Comparisons use REX.R so r10 (not rdx) is the second operand.
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(hashTableBase.ToInt64())); // mov r10, tableBase
        code.AddRange(new byte[] { 0x4C, 0x39, 0xD1 });                           // cmp rcx, r10
        EmitJcc(new byte[] { 0x0F, 0x82 }, "hash_next");                          // jb hash_next
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(hashTableEnd));            // mov r10, tableEnd
        code.AddRange(new byte[] { 0x4C, 0x39, 0xD1 });                           // cmp rcx, r10
        EmitJcc(new byte[] { 0x0F, 0x83 }, "hash_next");                          // jae hash_next
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(hashTableBase.ToInt64())); // mov r10, tableBase
        code.AddRange(new byte[] { 0x4C, 0x39, 0xD2 });                           // cmp rdx, r10 (reg=R10, not R11)
        EmitJcc(new byte[] { 0x0F, 0x82 }, "hash_next");                          // jb hash_next
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(hashTableEnd));            // mov r10, tableEnd
        code.AddRange(new byte[] { 0x4C, 0x39, 0xD2 });                           // cmp rdx, r10 (reg=R10, not R11)
        EmitJcc(new byte[] { 0x0F, 0x83 }, "hash_next");                          // jae hash_next
        // Round-trip validation: Flink->Blink and Blink->Flink must both
        // point back at this candidate. Only true membership passes.
        code.AddRange(new byte[] { 0x4C, 0x39, 0x41, 0x08 });                     // cmp [rcx+8], r8
        EmitJcc(new byte[] { 0x0F, 0x85 }, "hash_next");                          // jnz hash_next
        code.AddRange(new byte[] { 0x4C, 0x39, 0x02 });                           // cmp [rdx], r8
        EmitJcc(new byte[] { 0x0F, 0x85 }, "hash_next");                          // jnz hash_next
        // Unlink + scrub the entry's own links.
        code.AddRange(new byte[] { 0x48, 0x89, 0x51, 0x08 });                     // mov [rcx+8], rdx
        code.AddRange(new byte[] { 0x48, 0x89, 0x0A });                           // mov [rdx], rcx
        code.AddRange(new byte[] { 0x31, 0xC0 });                                 // xor eax, eax
        code.AddRange(new byte[] { 0x49, 0x89, 0x00 });                           // mov [r8], rax (REX.B: r/m is r8, not rax)
        code.AddRange(new byte[] { 0x49, 0x89, 0x40, 0x08 });                     // mov [r8+8], rax (REX.B: r/m is r8, not rax)
        EmitMovEbxImm(code, (int)StatusUnlinked);
        EmitJmp("unlock");

        Mark("hash_next");
        code.AddRange(new byte[] { 0x49, 0x83, 0xC1, (byte)HashScanStep });       // add r9, step
        code.Add(0x49); code.Add(0x81); code.Add(0xF9);
        code.AddRange(BitConverter.GetBytes((int)HashScanEnd));                   // cmp r9, HashScanEnd
        EmitJcc(new byte[] { 0x0F, 0x8C }, "hash_loop");                          // jl hash_loop
        EmitJmp("unlock");

        Mark("lock_failed");
        EmitStatus(code, statusAddress, StatusLockFailed);
        EmitJmp("done");

        // Unlock first, then publish the outcome, so success is never reported
        // while the loader lock was not released.
        Mark("unlock");
        code.AddRange(new byte[] { 0x48, 0x8B, 0x54, 0x24, 0x20 });                           // mov rdx, [rsp+0x20]
        code.AddRange(new byte[] { 0x31, 0xC9 });                                             // xor ecx, ecx
        code.Add(0x48); code.Add(0xB8); code.AddRange(BitConverter.GetBytes(unlockFunction.ToInt64()));
        code.AddRange(new byte[] { 0xFF, 0xD0 });                                             // call rax
        code.AddRange(new byte[] { 0x85, 0xC0 });                                             // test eax, eax
        EmitJcc(new byte[] { 0x0F, 0x85 }, "unlock_failed");                                  // jnz unlock_failed
        EmitStatusFromRbx(code, statusAddress);                                               // status = pending result
        EmitJmp("done");

        Mark("unlock_failed");
        EmitStatus(code, statusAddress, StatusUnlockFailed);
        EmitJmp("done");

        Mark("done");
        code.AddRange(new byte[] { 0x48, 0x8B, 0x5C, 0x24, 0x28 });                           // mov rbx, [rsp+0x28] (restore nonvolatile)
        code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x48 });                                 // add rsp, 0x48
        code.Add(0xC3);                                                                       // ret

        foreach (var (offset, label) in patches)
        {
            var relative = labels[label] - (offset + 4);
            var bytes = BitConverter.GetBytes(relative);
            for (var i = 0; i < 4; i++)
                code[offset + i] = bytes[i];
        }

        return code.ToArray();
    }

    private static void EmitStatus(List<byte> code, IntPtr statusAddress, long status)
    {
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(statusAddress.ToInt64())); // mov r10, status
        code.Add(0x49); code.Add(0xC7); code.Add(0x02); code.AddRange(BitConverter.GetBytes((int)status)); // mov qword [r10], imm32
    }

    private static void EmitMovEbxImm(List<byte> code, int status)
    {
        code.Add(0xBB);                                   // mov ebx, imm32
        code.AddRange(BitConverter.GetBytes(status));
    }

    private static void EmitStatusFromRbx(List<byte> code, IntPtr statusAddress)
    {
        code.Add(0x49); code.Add(0xBA); code.AddRange(BitConverter.GetBytes(statusAddress.ToInt64())); // mov r10, status
        code.AddRange(new byte[] { 0x49, 0x89, 0x1A });                                                // mov [r10], rbx
    }
}
