using System.IO;
using Phantom.Core.Processes;

namespace Phantom.Core.Injection;

/// <summary>
/// Entry point for performing an injection with the requested method.
/// </summary>
public static class Injector
{
    public static InjectionResult Inject(uint pid, string dllPath, InjectionOptions options)
    {
        if (!File.Exists(dllPath))
            return InjectionResult.Fail(options.Method, dllPath, "DLL file does not exist.");

        if (options.Method == InjectionMethod.LdrpLoadDll)
            return InjectionResult.Fail(options.Method, dllPath,
                "LdrpLoadDll is not supported on modern Windows and is disabled.");

        // Access probe FIRST: the architecture query cannot distinguish a
        // denied open from a non-AMD64 target, so an access failure must be
        // reported as such instead of hiding behind "not AMD64".
        var preflight = TargetPreflight.Check(pid, RequiredAccess(options.Method));
        if (preflight.ProbeError is not null)
            return InjectionResult.Fail(options.Method, dllPath,
                "Preflight probe failed: " + preflight.ProbeError);
        if (!preflight.Opened)
            return InjectionResult.Fail(options.Method, dllPath,
                $"Preflight: target could not be opened ({NtStatus.Describe(preflight.OpenStatus)}). " +
                "It may be protected, elevated above this process, or already gone.");
        if (!preflight.RightsQueried)
            return InjectionResult.Fail(options.Method, dllPath,
                $"Preflight: handle rights could not be verified ({NtStatus.Describe(preflight.QueryStatus)}). " +
                "Failing closed rather than attributing this to target protection.");
        if (preflight.Missing.Length > 0)
            return InjectionResult.Fail(options.Method, dllPath,
                $"Preflight: handle rights stripped by the target's protection " +
                $"(missing: {string.Join(", ", preflight.Missing)}; granted: 0x{preflight.Granted:X8}). " +
                $"{options.Method} cannot proceed without them; check driver callbacks.");

        switch (ProcessManager.CheckArchitecture(pid))
        {
            case ProcessManager.ArchCheckResult.NotAmd64:
                return InjectionResult.Fail(options.Method, dllPath,
                    "The target is not a native AMD64 process. Phantom is x64-only.");
            case ProcessManager.ArchCheckResult.Unknown:
                return InjectionResult.Fail(options.Method, dllPath,
                    "The target architecture could not be queried (it may have exited). Failing closed.");
            default:
                break;
        }

        IInjector injector = options.Method switch
        {
            InjectionMethod.Standard => new StandardInjector(),
            InjectionMethod.LdrLoadDll => new LdrLoadDllInjector(),
            InjectionMethod.ThreadHijack => new ThreadHijackInjector(),
            InjectionMethod.ManualMap => new ManualMapInjector(),
            InjectionMethod.DllHollowing => new DllHollowingInjector(),
            InjectionMethod.ModuleStomping => new ModuleStompingInjector(),
            _ => new StandardInjector()
        };

        return RunInjector(injector, pid, dllPath, options);
    }

    /// <summary>
    /// Handle rights each method's actual open requests — the same masks the
    /// injectors open with (single source of truth in <see cref="InjectorBase"/>).
    /// DllHollowing/ModuleStomping resolve imports and release dependencies via
    /// remote threads, so they require CREATE_THREAD like the loader methods.
    /// Only the pure-hijack core path omits it.
    /// </summary>
    private static uint RequiredAccess(InjectionMethod method) => method switch
    {
        InjectionMethod.ThreadHijack => InjectorBase.HijackAccess,
        _ => InjectorBase.InjectionAccess,
    };

    private static InjectionResult RunInjector(IInjector injector, uint pid, string dllPath, InjectionOptions options)
    {

        var result = injector.Inject(pid, dllPath, options);

        // Defense in depth (finding 8): never run PE erasure or PEB unlinking
        // against a non-image base. A DllMain boolean (0/1) must never reach here,
        // but a low sentinel would corrupt the target if passed to post-inject.
        if (result.Success && result.ModuleBase.ToInt64() < 0x10000)
            return InjectionResult.Fail(options.Method, dllPath,
                $"Injection reported an invalid module base 0x{result.ModuleBase.ToInt64():X}; refusing post-inject steps.");

        if (result.Success && (options.ErasePeHeaders || options.HideModule))
        {
            var postError = PostInject.PostInjectProcessor.Apply(pid, result.ModuleBase, options);
            if (postError is not null)
                result.Warning = result.Warning is null ? postError : result.Warning + " " + postError;
        }

        return result;
    }
}
