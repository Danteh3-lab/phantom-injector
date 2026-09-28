using System.IO;
using Phantom.Core.Processes;

namespace Phantom.Core.Injection;

/// <summary>
/// Entry point for performing an injection with the requested method.
/// </summary>
public static class Injector
{
    public static InjectionResult Inject(uint pid, string dllPath, InjectionOptions options)
        => Inject(pid, dllPath, options, expectedCreationTime: null);

    public static InjectionResult Inject(uint pid, string dllPath, InjectionOptions options,
        long? expectedCreationTime)
        => InjectionProgressSession.Run(options,
            () => InjectCore(pid, dllPath, options, expectedCreationTime));

    private static InjectionResult InjectCore(uint pid, string dllPath, InjectionOptions options,
        long? expectedCreationTime)
    {
        options.ReportProgress("validate-dll", "Validate DLL", InjectionProgressStatus.Running,
            "Checking that the selected file is available.");
        if (!File.Exists(dllPath))
        {
            options.ReportProgress("validate-dll", "Validate DLL", InjectionProgressStatus.Failed,
                "DLL file does not exist.", dllPath);
            return InjectionResult.Fail(options.Method, dllPath, "DLL file does not exist.");
        }
        options.ReportProgress("validate-dll", "Validate DLL", InjectionProgressStatus.Succeeded,
            "DLL file is available.");

        options.ReportProgress("method-support", "Check injection method", InjectionProgressStatus.Running);
        if (options.Method == InjectionMethod.LdrpLoadDll)
        {
            options.ReportProgress("method-support", "Check injection method", InjectionProgressStatus.Failed,
                "LdrpLoadDll is disabled on modern Windows.");
            return InjectionResult.Fail(options.Method, dllPath,
                "LdrpLoadDll is not supported on modern Windows and is disabled.");
        }
        options.ReportProgress("method-support", "Check injection method", InjectionProgressStatus.Succeeded,
            options.Method.ToString());

        // Access probe FIRST: the architecture query cannot distinguish a
        // denied open from a non-AMD64 target, so an access failure must be
        // reported as such instead of hiding behind "not AMD64".
        options.ReportProgress("target-preflight", "Check target access and identity", InjectionProgressStatus.Running,
            "Verifying process identity and required access rights.");
        var preflight = TargetPreflight.Check(pid, RequiredAccess(options.Method), expectedCreationTime);
        if (preflight.ProbeError is not null)
        {
            options.ReportProgress("target-preflight", "Check target access and identity", InjectionProgressStatus.Failed,
                preflight.ProbeError);
            return InjectionResult.Fail(options.Method, dllPath,
                "Preflight probe failed: " + preflight.ProbeError);
        }
        if (!preflight.Opened)
        {
            var detail = $"Target could not be opened ({NtStatus.Describe(preflight.OpenStatus)}).";
            options.ReportProgress("target-preflight", "Check target access and identity", InjectionProgressStatus.Failed,
                detail, $"NTSTATUS 0x{preflight.OpenStatus:X8}");
            return InjectionResult.Fail(options.Method, dllPath,
                $"Preflight: target could not be opened ({NtStatus.Describe(preflight.OpenStatus)}). " +
                "It may be protected, elevated above this process, or already gone.");
        }
        if (!preflight.RightsQueried)
        {
            var detail = $"Handle rights could not be verified ({NtStatus.Describe(preflight.QueryStatus)}).";
            options.ReportProgress("target-preflight", "Check target access and identity", InjectionProgressStatus.Failed,
                detail, $"NTSTATUS 0x{preflight.QueryStatus:X8}");
            return InjectionResult.Fail(options.Method, dllPath,
                $"Preflight: handle rights could not be verified ({NtStatus.Describe(preflight.QueryStatus)}). " +
                "Failing closed rather than attributing this to target protection.");
        }
        if (preflight.Missing.Length > 0)
        {
            var detail = $"Required target rights are missing: {string.Join(", ", preflight.Missing)}.";
            options.ReportProgress("target-preflight", "Check target access and identity", InjectionProgressStatus.Failed,
                detail, $"Granted mask: 0x{preflight.Granted:X8}");
            return InjectionResult.Fail(options.Method, dllPath,
                $"Preflight: handle rights stripped by the target's protection " +
                $"(missing: {string.Join(", ", preflight.Missing)}; granted: 0x{preflight.Granted:X8}). " +
                $"{options.Method} cannot proceed without them; check driver callbacks.");
        }

        using var target = preflight.Target;
        if (target is null)
        {
            options.ReportProgress("target-preflight", "Check target access and identity", InjectionProgressStatus.Failed,
                "Target process identity could not be retained.");
            return InjectionResult.Fail(options.Method, dllPath,
                "Preflight: target process identity could not be retained. Failing closed.");
        }
        options.ReportProgress("target-preflight", "Check target access and identity",
            InjectionProgressStatus.Succeeded,
            "Required handle rights and selected process identity verified.");

        using var targetScope = target.EnterScope();

        options.ReportProgress("target-architecture", "Check target architecture", InjectionProgressStatus.Running,
            "Confirming the target is a live native AMD64 process.");
        switch (ProcessManager.CheckArchitecture(target))
        {
            case ProcessManager.ArchCheckResult.NotAmd64:
                options.ReportProgress("target-architecture", "Check target architecture", InjectionProgressStatus.Failed,
                    "The target is not a native AMD64 process.");
                return InjectionResult.Fail(options.Method, dllPath,
                    "The target is not a native AMD64 process. Phantom is x64-only.");
            case ProcessManager.ArchCheckResult.Unknown:
                options.ReportProgress("target-architecture", "Check target architecture", InjectionProgressStatus.Failed,
                    "Target architecture could not be queried; the process may have exited.");
                return InjectionResult.Fail(options.Method, dllPath,
                    "The target architecture could not be queried (it may have exited). Failing closed.");
            default:
                options.ReportProgress("target-architecture", "Check target architecture", InjectionProgressStatus.Succeeded,
                    "Native AMD64 target confirmed.");
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

        using var cleanupScope = SectionMemory.BeginCleanupScope();
        var result = RunInjector(injector, target, dllPath, options);
        options.ReportProgress("remote-cleanup", "Remote memory cleanup and recovery", InjectionProgressStatus.Running,
            "Checking for unresolved temporary remote views and retrying deferred cleanup.");
        var cleanupFailure = cleanupScope.FailureMessage;
        if (cleanupFailure is not null)
        {
            result.AddCleanupFailure(cleanupFailure);
            var currentFailure = cleanupScope.CurrentFailureMessage;
            var priorFailure = cleanupScope.PriorFailureMessage;
            options.ReportProgress("remote-cleanup", "Remote memory cleanup and recovery",
                currentFailure is not null ? InjectionProgressStatus.Failed : InjectionProgressStatus.Warning,
                currentFailure is not null
                    ? "Cleanup from this injection remains unresolved."
                    : "An earlier cleanup remains pending.",
                string.Join(Environment.NewLine, new[] { currentFailure, priorFailure }.Where(s => s is not null)));
        }
        else
        {
            options.ReportProgress("remote-cleanup", "Remote memory cleanup and recovery",
                InjectionProgressStatus.Succeeded, "Temporary remote views were released or safely retained for active work.");
        }
        return result;
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

    private static InjectionResult RunInjector(IInjector injector, TargetProcessIdentity target,
        string dllPath, InjectionOptions options)
    {

        var result = injector.Inject(target.Pid, dllPath, options);

        // Defense in depth (finding 8): never run PE erasure or PEB unlinking
        // against a non-image base. A DllMain boolean (0/1) must never reach here,
        // but a low sentinel would corrupt the target if passed to post-inject.
        if (result.Success && result.ModuleBase.ToInt64() < 0x10000)
            return InjectionResult.Fail(options.Method, dllPath,
                $"Injection reported an invalid module base 0x{result.ModuleBase.ToInt64():X}; refusing post-inject steps.");

        if (result.Success && (options.ErasePeHeaders || options.HideModule))
        {
            var postError = PostInject.PostInjectProcessor.Apply(target, result.ModuleBase, options);
            if (postError is not null)
                result.Warning = result.Warning is null ? postError : result.Warning + " " + postError;
        }
        else if (result.Success)
        {
            options.ReportProgress("postinject-erase", "Erase PE headers", InjectionProgressStatus.Skipped,
                "Erase PE was not requested.");
            options.ReportProgress("postinject-hide", "Hide module", InjectionProgressStatus.Skipped,
                "Hide Module was not requested.");
        }

        return result;
    }
}
