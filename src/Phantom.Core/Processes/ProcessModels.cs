namespace Phantom.Core.Processes;

public sealed class ProcessInfo
{
    public uint Pid { get; init; }
    public string Name { get; init; } = string.Empty;
    public string? Path { get; init; }
    public string? WindowTitle { get; init; }
    public bool Is64Bit { get; init; } = true;

    public override string ToString() => $"{Name} (PID {Pid})";
}

public sealed class ModuleInfo
{
    public string Name { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public IntPtr BaseAddress { get; init; }
    public uint Size { get; init; }

    public override string ToString() => $"{Name} @ 0x{BaseAddress.ToInt64():X}";
}

public sealed class ThreadInfo
{
    public uint ThreadId { get; init; }
    public int BasePriority { get; init; }

    public override string ToString() => $"TID {ThreadId}";
}

public sealed class WindowInfo
{
    public IntPtr Handle { get; init; }
    public uint Pid { get; init; }
    public string Title { get; init; } = string.Empty;
    public string ClassName { get; init; } = string.Empty;

    public override string ToString() => $"{Title} [{ClassName}] (PID {Pid})";
}
