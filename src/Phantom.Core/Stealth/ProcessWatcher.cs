using Phantom.Core.Processes;

namespace Phantom.Core.Stealth;

/// <summary>
/// Watches for a process to appear and raises an event once with its PID.
/// Used by the auto-inject feature.
/// </summary>
public sealed class ProcessWatcher : IDisposable
{
    private readonly string _processName;
    private readonly Timer _timer;
    private readonly object _gate = new();
    private volatile bool _fired;

    public event Action<uint>? ProcessFound;

    public ProcessWatcher(string processName, int intervalMs = 250)
    {
        _processName = processName;
        _timer = new Timer(Poll, null, intervalMs, intervalMs);
    }

    private void Poll(object? state)
    {
        if (_fired)
            return;

        ProcessInfo? process;
        try
        {
            process = ProcessManager.GetByName(_processName);
        }
        catch
        {
            return;
        }

        if (process is null)
            return;

        lock (_gate)
        {
            if (_fired)
                return;
            _fired = true;
        }

        try
        {
            ProcessFound?.Invoke(process.Pid);
        }
        finally
        {
            Dispose();
        }
    }

    public void Dispose()
    {
        _timer.Dispose();
    }
}
