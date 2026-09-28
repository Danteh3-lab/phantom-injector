using Phantom.Core.Native;

namespace Phantom.Core.Injection;

/// <summary>
/// Classic CreateRemoteThread + LoadLibraryW injection. Most compatible method.
/// </summary>
internal sealed class StandardInjector : InjectorBase
{
    public override InjectionMethod Method => InjectionMethod.Standard;

    public override InjectionResult Inject(uint pid, string dllPath, InjectionOptions options)
    {
        IntPtr hProcess = IntPtr.Zero;
        try
        {
            options.ReportProgress("standard-open", "Open target process", InjectionProgressStatus.Running);
            try
            {
                hProcess = OpenRemoteProcess(pid, InjectionAccess);
            }
            catch (Exception ex)
            {
                options.ReportProgress("standard-open", "Open target process", InjectionProgressStatus.Failed, ex.Message);
                return InjectionResult.Fail(Method, dllPath, "OpenProcess failed: " + ex.Message);
            }
            options.ReportProgress("standard-open", "Open target process", InjectionProgressStatus.Succeeded,
                "Verified target handle opened.");

            // The wrapper records the full 64-bit HMODULE, so success and the
            // returned base are authoritative for the exact path requested.
            options.ReportProgress("standard-load", "Run LoadLibraryW in target", InjectionProgressStatus.Running,
                "Starting a remote loader call and waiting for its completion.");
            var moduleBase = RemoteLoadLibraryResult(hProcess, pid, dllPath, options.TimeoutMs,
                out var resultUnknown, out var unsafeToFree, out var threadId, out var createStatus);

            if (unsafeToFree)
            {
                options.ReportProgress("standard-load", "Run LoadLibraryW in target", InjectionProgressStatus.Failed,
                    "Remote thread may still be running; its buffers were retained.");
                return InjectionResult.Fail(Method, dllPath,
                    "Injection did not complete; the remote thread may still be running so its buffers were left intact.");
            }

            if (resultUnknown)
            {
                options.ReportProgress("standard-load", "Run LoadLibraryW in target", InjectionProgressStatus.Failed,
                    "Remote thread completed but the recorded result could not be read.");
                return InjectionResult.Fail(Method, dllPath,
                    "The module load result could not be read; the outcome is unknown.");
            }

            options.ReportProgress("standard-base", "Verify returned module address", InjectionProgressStatus.Running);
            if (moduleBase == IntPtr.Zero)
            {
                // Creation failure and a completed load returning NULL are
                // different diagnoses: report them distinctly.
                if (createStatus != 0)
                {
                    options.ReportProgress("standard-load", "Run LoadLibraryW in target", InjectionProgressStatus.Failed,
                        "Remote thread creation failed.", $"NTSTATUS 0x{createStatus:X8}");
                    options.ReportProgress("standard-base", "Verify returned module address", InjectionProgressStatus.Failed,
                        NtStatus.Describe(createStatus), $"NTSTATUS 0x{createStatus:X8}");
                    return InjectionResult.Fail(Method, dllPath,
                        $"Remote thread creation failed: {NtStatus.Describe(createStatus)}.");
                }
                options.ReportProgress("standard-load", "Run LoadLibraryW in target", InjectionProgressStatus.Failed,
                    "LoadLibraryW returned a null module address.");
                options.ReportProgress("standard-base", "Verify returned module address", InjectionProgressStatus.Failed,
                    "LoadLibraryW returned a null module address.");
                return InjectionResult.Fail(Method, dllPath,
                    "LoadLibraryW returned NULL in the target. Check the file path and bitness.");
            }

            options.ReportProgress("standard-load", "Run LoadLibraryW in target", InjectionProgressStatus.Succeeded,
                "Remote loader thread completed with a non-null module handle.", threadId == 0 ? null : $"Thread ID: {threadId}");
            options.ReportProgress("standard-base", "Verify returned module address", InjectionProgressStatus.Succeeded,
                $"Module base: 0x{moduleBase.ToInt64():X}");

            return InjectionResult.Ok(Method, dllPath, moduleBase, threadId);
        }
        catch (Exception ex)
        {
            return InjectionResult.Fail(Method, dllPath, ex.Message);
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
            {
                options.ReportProgress("standard-close", "Close target handle", InjectionProgressStatus.Running);
                var closed = NativeMethods.CloseHandle(hProcess);
                options.ReportProgress("standard-close", "Close target handle",
                    closed ? InjectionProgressStatus.Succeeded : InjectionProgressStatus.Warning,
                    closed ? "Target handle closed." : "Target handle close reported an error.",
                    closed ? null : $"Win32 error {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}");
            }
            else
            {
                options.ReportProgress("standard-close", "Close target handle", InjectionProgressStatus.Skipped,
                    "No target handle was acquired.");
            }
        }
    }
}
