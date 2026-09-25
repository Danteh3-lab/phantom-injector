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
            try
            {
                hProcess = OpenRemoteProcess(pid, InjectionAccess);
            }
            catch (Exception ex)
            {
                return InjectionResult.Fail(Method, dllPath, "OpenProcess failed: " + ex.Message);
            }

            // The wrapper records the full 64-bit HMODULE, so success and the
            // returned base are authoritative for the exact path requested.
            var moduleBase = RemoteLoadLibraryResult(hProcess, pid, dllPath, options.TimeoutMs,
                out var resultUnknown, out var unsafeToFree, out var threadId, out var createStatus);

            if (unsafeToFree)
                return InjectionResult.Fail(Method, dllPath,
                    "Injection did not complete; the remote thread may still be running so its buffers were left intact.");

            if (resultUnknown)
                return InjectionResult.Fail(Method, dllPath,
                    "The module load result could not be read; the outcome is unknown.");

            if (moduleBase == IntPtr.Zero)
            {
                // Creation failure and a completed load returning NULL are
                // different diagnoses: report them distinctly.
                if (createStatus != 0)
                    return InjectionResult.Fail(Method, dllPath,
                        $"Remote thread creation failed: {NtStatus.Describe(createStatus)}.");
                return InjectionResult.Fail(Method, dllPath,
                    "LoadLibraryW returned NULL in the target. Check the file path and bitness.");
            }

            return InjectionResult.Ok(Method, dllPath, moduleBase, threadId);
        }
        catch (Exception ex)
        {
            return InjectionResult.Fail(Method, dllPath, ex.Message);
        }
        finally
        {
            if (hProcess != IntPtr.Zero)
                NativeMethods.CloseHandle(hProcess);
        }
    }
}
