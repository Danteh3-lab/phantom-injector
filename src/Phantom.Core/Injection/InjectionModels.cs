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

    /// <summary>
    /// Receives structured stage updates while an injection is running. Observer
    /// exceptions are ignored so reporting can never interrupt target work.
    /// </summary>
    public Action<InjectionProgressEvent>? ProgressChanged { get; set; }

    internal void ReportProgress(string stageId, string name, InjectionProgressStatus status,
        string? details = null, string? technicalDetails = null)
    {
        var update = new InjectionProgressEvent(stageId, name, status, details, technicalDetails);
        var session = InjectionProgressSession.Current;
        if (session is not null && session.Uses(this))
        {
            session.Report(update);
            return;
        }

        try { ProgressChanged?.Invoke(update); }
        catch { /* Progress observers must not affect injection. */ }
    }
}

public enum InjectionProgressStatus
{
    Pending,
    Running,
    Succeeded,
    Failed,
    Warning,
    Skipped
}

/// <summary>A method-independent progress update with an expandable detail payload.</summary>
public sealed record InjectionProgressEvent(
    string StageId,
    string Name,
    InjectionProgressStatus Status,
    string? Details = null,
    string? TechnicalDetails = null);

/// <summary>
/// Tracks stage starts and closes any stage left active when an injector exits
/// early. Events are delivered synchronously and observer errors are contained.
/// </summary>
internal sealed class InjectionProgressSession
{
    private static readonly AsyncLocal<InjectionProgressSession?> Ambient = new();
    private readonly InjectionOptions _options;
    private readonly List<InjectionProgressEvent> _active = new();

    private InjectionProgressSession(InjectionOptions options) => _options = options;

    internal static InjectionProgressSession? Current => Ambient.Value;
    internal bool Uses(InjectionOptions options) => ReferenceEquals(_options, options);

    internal void Report(InjectionProgressEvent update)
    {
        if (update.Status == InjectionProgressStatus.Running)
        {
            _active.RemoveAll(stage => stage.StageId == update.StageId);
            _active.Add(update);
        }
        else
        {
            _active.RemoveAll(stage => stage.StageId == update.StageId);
        }

        Publish(update);
    }

    internal static InjectionResult Run(InjectionOptions options, Func<InjectionResult> operation)
    {
        var previous = Ambient.Value;
        var session = new InjectionProgressSession(options);
        Ambient.Value = session;
        try
        {
            var result = operation();
            session.Complete(result.Success, result.Error);
            return result;
        }
        catch (Exception ex)
        {
            session.Complete(false, ex.Message);
            throw;
        }
        finally
        {
            Ambient.Value = previous;
        }
    }

    private void Complete(bool succeeded, string? failure)
    {
        var activeStages = _active.ToArray();
        for (var index = 0; index < activeStages.Length; index++)
        {
            var active = activeStages[index];
            var isFailureStage = !succeeded && index == activeStages.Length - 1;
            Report(active with
            {
                Status = isFailureStage ? InjectionProgressStatus.Failed : InjectionProgressStatus.Warning,
                Details = isFailureStage
                    ? failure ?? active.Details
                    : "No verified completion was reported for this stage."
            });
        }
    }

    private void Publish(InjectionProgressEvent update)
    {
        try { _options.ProgressChanged?.Invoke(update); }
        catch { /* Progress observers must not affect injection. */ }
    }
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
