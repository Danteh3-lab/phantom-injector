namespace Phantom.Core.Injection;

public enum InjectionMethod
{
    Standard,
    LdrLoadDll,
    LdrpLoadDll,
    ThreadHijack,
    ManualMap,
    DllHollowing,
    ModuleStomping
}

/// <summary>
/// Options controlling a single injection operation.
/// </summary>
public sealed class InjectionOptions
{
    public InjectionMethod Method { get; set; } = InjectionMethod.Standard;

    /// <summary>Zero the first page of the mapped image after injection.</summary>
    public bool ErasePeHeaders { get; set; }

    /// <summary>Unlink the module from the target PEB loader lists.</summary>
    public bool HideModule { get; set; }

    /// <summary>Free the module again immediately (test helper / unload).</summary>
    public bool UnloadAfterLoad { get; set; }

    public int TimeoutMs { get; set; } = 10_000;
}

/// <summary>
/// Result of an injection attempt, including the mapped base address when known.
/// </summary>
public sealed class InjectionResult
{
    private string? _error;

    public bool Success { get; init; }
    public InjectionMethod Method { get; init; }
    public string DllPath { get; init; } = string.Empty;
    public IntPtr ModuleBase { get; init; }
    public uint RemoteThreadId { get; init; }
    public string? Error { get => _error; init => _error = value; }
    public uint ErrorCode { get; init; }

    /// <summary>
    /// Non-fatal problem after a successful injection (e.g. a post-inject step
    /// was requested but did not complete).
    /// </summary>
    public string? Warning { get; set; }

    internal void AddCleanupFailure(string message)
    {
        if (Success)
            Warning = Warning is null ? message : Warning + " " + message;
        else
            _error = _error is null ? message : _error + " " + message;
    }

    public static InjectionResult Ok(InjectionMethod method, string dll, IntPtr baseAddr, uint tid = 0)
        => new() { Success = true, Method = method, DllPath = dll, ModuleBase = baseAddr, RemoteThreadId = tid };

    public static InjectionResult Fail(InjectionMethod method, string dll, string error, uint code = 0)
        => new() { Success = false, Method = method, DllPath = dll, Error = error, ErrorCode = code };
}

/// <summary>
/// Outcome of running a remote thread. <see cref="UnsafeToFree"/> means the
/// thread may still be executing (timeout or wait failure), so no remote memory
/// it can reach may be released.
/// </summary>
internal readonly struct RemoteThreadResult
{
    public bool Created { get; init; }
    public bool TimedOut { get; init; }
    public bool WaitFailed { get; init; }
    public uint ExitCode { get; init; }
    public uint ThreadId { get; init; }

    /// <summary>Creation NTSTATUS; meaningful when <see cref="Created"/> is false.</summary>
    public int Status { get; init; }

    public bool UnsafeToFree => TimedOut || WaitFailed;
}

public interface IInjector
{
    InjectionMethod Method { get; }

    /// <summary>
    /// Injects <paramref name="dllPath"/> (a local file path) into <paramref name="pid"/>.
    /// </summary>
    InjectionResult Inject(uint pid, string dllPath, InjectionOptions options);
}
