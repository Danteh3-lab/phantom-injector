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
            _ => new StandardInjector()
        };

        var result = injector.Inject(pid, dllPath, options);

        if (result.Success && (options.ErasePeHeaders || options.HideModule))
        {
            var postError = PostInject.PostInjectProcessor.Apply(pid, result.ModuleBase, options);
            if (postError is not null)
                result.Warning = result.Warning is null ? postError : result.Warning + " " + postError;
        }

        return result;
    }
}
