using System.Buffers.Binary;
using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Calls ntdll!LdrLoadDll directly instead of going through kernel32!LoadLibraryW.
/// One level deeper in the loader, slightly less monitored by naive hooks.
/// </summary>
internal sealed class LdrLoadDllInjector : InjectorBase
{
    public override InjectionMethod Method => InjectionMethod.LdrLoadDll;

    private const int UnicodeStringSize = 16; // USHORT, USHORT, pad, PWSTR

    public override InjectionResult Inject(uint pid, string dllPath, InjectionOptions options)
    {
        IntPtr hProcess = IntPtr.Zero;
        var remotePath = IntPtr.Zero;
        var remoteUnicodeString = IntPtr.Zero;
        var remoteHandle = IntPtr.Zero;
        var remoteStub = IntPtr.Zero;
        var remoteThread = default(RemoteThreadResult);
        try
        {
            options.ReportProgress("ldr-open", "Open target process", InjectionProgressStatus.Running);
            try
            {
                hProcess = OpenRemoteProcess(pid, InjectionAccess);
            }
            catch (Exception ex)
            {
                options.ReportProgress("ldr-open", "Open target process", InjectionProgressStatus.Failed, ex.Message);
                return InjectionResult.Fail(Method, dllPath, "OpenProcess failed: " + ex.Message);
            }
            options.ReportProgress("ldr-open", "Open target process", InjectionProgressStatus.Succeeded,
                "Verified target handle opened.");

            options.ReportProgress("ldr-prepare", "Prepare LdrLoadDll call", InjectionProgressStatus.Running,
                "Resolving the target loader and writing its arguments and stub.");
            var ldrLoadDll = ResolveRemoteExport(pid, "ntdll.dll", "LdrLoadDll");

            remotePath = WriteRemoteString(hProcess, dllPath, out var pathBytes);
            var pathChars = pathBytes - 2; // exclude null terminator for Length semantics

            remoteUnicodeString = AllocateRemote(hProcess, UnicodeStringSize);
            remoteHandle = AllocateRemote(hProcess, 8);
            WriteRemote(hProcess, remoteHandle, new byte[8]);

            var us = new byte[UnicodeStringSize];
            BinaryPrimitives.WriteUInt16LittleEndian(us.AsSpan(0, 2), (ushort)pathChars);
            BinaryPrimitives.WriteUInt16LittleEndian(us.AsSpan(2, 2), (ushort)(pathChars + 2));
            BinaryPrimitives.WriteInt64LittleEndian(us.AsSpan(8, 8), remotePath.ToInt64());
            WriteRemote(hProcess, remoteUnicodeString, us);

            var stub = BuildLdrLoadDllStub(ldrLoadDll, remoteUnicodeString, remoteHandle);
            remoteStub = AllocateRemote(hProcess, stub.Length, NativeConstants.PAGE_EXECUTE_READWRITE);
            WriteRemote(hProcess, remoteStub, stub);
            NativeMethods.FlushInstructionCacheChecked(hProcess, remoteStub, stub.Length);
            options.ReportProgress("ldr-prepare", "Prepare LdrLoadDll call", InjectionProgressStatus.Succeeded,
                "Loader arguments and executable stub are ready.");

            options.ReportProgress("ldr-run", "Run LdrLoadDll in target", InjectionProgressStatus.Running);
            remoteThread = RunRemoteThread(hProcess, remoteStub, IntPtr.Zero, options.TimeoutMs);

            if (remoteThread.UnsafeToFree)
            {
                options.ReportProgress("ldr-run", "Run LdrLoadDll in target", InjectionProgressStatus.Failed,
                    "Remote thread may still be running; its buffers were retained.");
                return InjectionResult.Fail(Method, dllPath,
                    "Injection did not complete (timeout or wait failure); the remote thread may still be running so its buffers were left intact.");
            }

            if (!remoteThread.Created)
            {
                options.ReportProgress("ldr-run", "Run LdrLoadDll in target", InjectionProgressStatus.Failed,
                    NtStatus.Describe(remoteThread.Status), $"NTSTATUS 0x{remoteThread.Status:X8}");
                return InjectionResult.Fail(Method, dllPath, $"NtCreateThreadEx failed in the target: {NtStatus.Describe(remoteThread.Status)}.");
            }

            // NTSTATUS_SUCCESS == 0
            if (remoteThread.ExitCode != 0)
            {
                options.ReportProgress("ldr-run", "Run LdrLoadDll in target", InjectionProgressStatus.Failed,
                    $"LdrLoadDll returned NTSTATUS 0x{remoteThread.ExitCode:X8}.");
                return InjectionResult.Fail(Method, dllPath,
                    $"LdrLoadDll returned NTSTATUS 0x{remoteThread.ExitCode:X8}. The target may restrict this call.", remoteThread.ExitCode);
            }
            options.ReportProgress("ldr-run", "Run LdrLoadDll in target", InjectionProgressStatus.Succeeded,
                "Remote loader thread completed successfully.", remoteThread.ThreadId == 0 ? null : $"Thread ID: {remoteThread.ThreadId}");

            options.ReportProgress("ldr-handle", "Read loaded module handle", InjectionProgressStatus.Running);
            if (!TryReadRemoteInt64(hProcess, remoteHandle, out var handleValue))
            {
                options.ReportProgress("ldr-handle", "Read loaded module handle", InjectionProgressStatus.Failed,
                    "LdrLoadDll succeeded but the module handle could not be read back.");
                return InjectionResult.Fail(Method, dllPath, "LdrLoadDll returned success but the module handle could not be read back.");
            }

            var moduleBase = new IntPtr(handleValue);
            if (moduleBase == IntPtr.Zero)
            {
                options.ReportProgress("ldr-handle", "Read loaded module handle", InjectionProgressStatus.Failed,
                    "LdrLoadDll reported a null module handle.");
                return InjectionResult.Fail(Method, dllPath, "LdrLoadDll returned success but reported a null module handle.");
            }

            options.ReportProgress("ldr-handle", "Read loaded module handle", InjectionProgressStatus.Succeeded,
                $"Module base: 0x{moduleBase.ToInt64():X}");

            return InjectionResult.Ok(Method, dllPath, moduleBase, remoteThread.ThreadId);
        }
        catch (Exception ex)
        {
            return InjectionResult.Fail(Method, dllPath, ex.Message);
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
            {
                if (!remoteThread.UnsafeToFree)
                {
                    options.ReportProgress("ldr-cleanup", "Release temporary remote buffers", InjectionProgressStatus.Running);
                    var cleanup = new[]
                    {
                        (Address: remoteStub, Result: FreeRemote(hProcess, remoteStub)),
                        (Address: remoteHandle, Result: FreeRemote(hProcess, remoteHandle)),
                        (Address: remoteUnicodeString, Result: FreeRemote(hProcess, remoteUnicodeString)),
                        (Address: remotePath, Result: FreeRemote(hProcess, remotePath))
                    };
                    var failedCleanup = cleanup.Where(item => !item.Result.Succeeded).ToArray();
                    options.ReportProgress("ldr-cleanup", "Release temporary remote buffers",
                        failedCleanup.Length == 0 ? InjectionProgressStatus.Succeeded : InjectionProgressStatus.Warning,
                        failedCleanup.Length == 0 ? "Temporary call buffers were released." : "One or more buffers remain queued for cleanup.",
                        failedCleanup.Length == 0 ? null : string.Join(Environment.NewLine, failedCleanup.Select(item => item.Result.Describe(item.Address))));
                }
                else
                    options.ReportProgress("ldr-cleanup", "Release temporary remote buffers", InjectionProgressStatus.Skipped,
                        "Buffers remain mapped because the remote thread may still be running.");

                options.ReportProgress("ldr-close", "Close target handle", InjectionProgressStatus.Running);
                var closed = NativeMethods.CloseHandle(hProcess);
                options.ReportProgress("ldr-close", "Close target handle",
                    closed ? InjectionProgressStatus.Succeeded : InjectionProgressStatus.Warning,
                    closed ? "Target handle closed." : "Target handle close reported an error.");
            }
            else
            {
                options.ReportProgress("ldr-cleanup", "Release temporary remote buffers", InjectionProgressStatus.Skipped,
                    "No remote buffers were allocated.");
                options.ReportProgress("ldr-close", "Close target handle", InjectionProgressStatus.Skipped,
                    "No target handle was acquired.");
            }
        }
    }

    /// <summary>
    /// Builds x64 code that calls LdrLoadDll(NULL, 0, &amp;unicodeString, &amp;moduleHandle).
    /// </summary>
    private static byte[] BuildLdrLoadDllStub(IntPtr ldrLoadDll, IntPtr unicodeString, IntPtr outHandle)
    {
        var code = new List<byte>();

        // xor rcx, rcx            -> PathToFile = NULL
        code.AddRange(new byte[] { 0x48, 0x31, 0xC9 });
        // xor rdx, rdx            -> Flags = 0
        code.AddRange(new byte[] { 0x48, 0x31, 0xD2 });
        // mov r8, imm64           -> &ModuleFileName
        code.Add(0x49); code.Add(0xB8);
        code.AddRange(BitConverter.GetBytes(unicodeString.ToInt64()));
        // mov r9, imm64           -> &ModuleHandle
        code.Add(0x49); code.Add(0xB9);
        code.AddRange(BitConverter.GetBytes(outHandle.ToInt64()));
        // mov rax, imm64          -> LdrLoadDll
        code.Add(0x48); code.Add(0xB8);
        code.AddRange(BitConverter.GetBytes(ldrLoadDll.ToInt64()));
        // sub rsp, 0x28
        code.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
        // call rax
        code.AddRange(new byte[] { 0xFF, 0xD0 });
        // add rsp, 0x28
        code.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
        // ret
        code.Add(0xC3);

        return code.ToArray();
    }
}
