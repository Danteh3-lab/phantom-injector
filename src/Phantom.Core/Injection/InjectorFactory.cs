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

        if (!ProcessManager.IsAmd64Target(pid))
            return InjectionResult.Fail(options.Method, dllPath,
                "The target is not a native AMD64 process, or its architecture could not be determined. Phantom is x64-only.");

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
