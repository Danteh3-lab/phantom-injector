using System.Diagnostics;
using System.Runtime.InteropServices;
using Phantom.Core.Native;

namespace Phantom.Core.Processes;

/// <summary>
/// Process, module, thread and window enumeration used by the UI and the
/// auto-inject watcher.
/// </summary>
public static class ProcessManager
{
    public static IReadOnlyList<ProcessInfo> GetProcesses()
    {
        var results = new List<ProcessInfo>();
        foreach (var p in Process.GetProcesses())
        {
            string? path = null;
            string? title = null;
            try
            {
                path = p.MainModule?.FileName;
                title = string.IsNullOrWhiteSpace(p.MainWindowTitle) ? null : p.MainWindowTitle;
            }
            catch
            {
                // Access denied for protected / other-session processes.
            }

            results.Add(new ProcessInfo
            {
                Pid = (uint)p.Id,
                Name = p.ProcessName,
                Path = path,
                WindowTitle = title
            });

            p.Dispose();
        }

        return results.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static ProcessInfo? GetByName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return null;

        var wanted = name.Trim();
        if (wanted.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            wanted = wanted[..^4];

        try
        {
            var matches = Process.GetProcessesByName(wanted);
            if (matches.Length == 0)
                return null;

            var process = matches[0];
            try
            {
                string? path = null;
                string? title = null;
                try
                {
                    path = process.MainModule?.FileName;
                    title = string.IsNullOrWhiteSpace(process.MainWindowTitle) ? null : process.MainWindowTitle;
                }
                catch
                {
                    // Access denied for protected processes.
                }

                return new ProcessInfo
                {
                    Pid = (uint)process.Id,
                    Name = process.ProcessName,
                    Path = path,
                    WindowTitle = title,
                    Is64Bit = IsAmd64Target((uint)process.Id)
                };
            }
            finally
            {
                foreach (var match in matches)
                    match.Dispose();
            }
        }
        catch
        {
            return null;
        }
    }

    public static ProcessInfo? GetByPid(uint pid)
    {
        var process = GetProcesses().FirstOrDefault(p => p.Pid == pid);
        if (process is null)
            return null;

        return new ProcessInfo
        {
            Pid = process.Pid,
            Name = process.Name,
            Path = process.Path,
            WindowTitle = process.WindowTitle,
            Is64Bit = IsAmd64Target(pid)
        };
    }

    public enum ArchCheckResult
    {
        Amd64,
        NotAmd64,
        Unknown,
    }

    /// <summary>
    /// Returns true only when the target is a native AMD64 process on an AMD64
    /// host. Any other architecture, or a target whose architecture cannot be
    /// determined, returns false (fail closed).
    /// </summary>
    public static bool IsAmd64Target(uint pid) => CheckArchitecture(pid) == ArchCheckResult.Amd64;

    /// <summary>
    /// Three-way architecture check: distinguishes "definitely not AMD64"
    /// from "could not be queried" (no handle, exited target, missing APIs).
    /// The handle is opened via direct syscall so an access failure here is
    /// genuine, not a hook artifact.
    /// </summary>
    public static ArchCheckResult CheckArchitecture(uint pid)
    {
        if (DirectSyscalls.NtOpenProcessByPid(out var hProcess,
                NativeConstants.PROCESS_QUERY_LIMITED_INFORMATION, pid) != 0 ||
            hProcess == IntPtr.Zero)
            return ArchCheckResult.Unknown;

        try
        {
            // Preferred: distinguish native vs WOW64 vs emulated targets and the
            // host architecture explicitly (Windows 10 1709+). On older systems
            // the export is absent and the call throws rather than returning false.
            try
            {
                if (NativeMethods.IsWow64Process2(hProcess, out var processMachine, out var nativeMachine))
                    return processMachine == 0 && nativeMachine == NativeConstants.IMAGE_FILE_MACHINE_AMD64
                        ? ArchCheckResult.Amd64
                        : ArchCheckResult.NotAmd64;
            }
            catch (EntryPointNotFoundException)
            {
                // Fall through to the legacy check.
            }

            // Fallback for older systems: the injector itself is AMD64, so a
            // non-WOW64 target on such a system is an AMD64 process.
            if (NativeMethods.IsWow64Process(hProcess, out var wow64))
                return wow64 ? ArchCheckResult.NotAmd64 : ArchCheckResult.Amd64;

            return ArchCheckResult.Unknown;
        }
        finally
        {
            NativeMethods.CloseHandle(hProcess);
        }
    }

    public static ProcessInfo? GetByWindow(IntPtr hwnd)
    {
        NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
        return pid == 0 ? null : GetByPid(pid);
    }

    public static IReadOnlyList<ModuleInfo> GetModules(uint pid)
    {
        var modules = new List<ModuleInfo>();
        using var hProcess = SafeNativeHandle.OpenProcess(pid,
            NativeConstants.PROCESS_QUERY_INFORMATION | NativeConstants.PROCESS_VM_READ);

        var needed = 0u;
        var handles = new IntPtr[1024];
        if (!NativeMethods.EnumProcessModulesEx(hProcess.Handle, handles,
                (uint)(handles.Length * IntPtr.Size), out needed, NativeConstants.LIST_MODULES_ALL))
            return modules;

        var count = needed / (uint)IntPtr.Size;
        for (var i = 0; i < count && i < handles.Length; i++)
        {
            var name = new System.Text.StringBuilder(260);
            NativeMethods.GetModuleBaseNameW(hProcess.Handle, handles[i], name, (uint)name.Capacity);
            var path = new System.Text.StringBuilder(1024);
            NativeMethods.GetModuleFileNameExW(hProcess.Handle, handles[i], path, (uint)path.Capacity);
            NativeMethods.GetModuleInformation(hProcess.Handle, handles[i], out var info, (uint)Marshal.SizeOf<MODULEINFO>());

            modules.Add(new ModuleInfo
            {
                Name = name.ToString(),
                Path = path.ToString(),
                BaseAddress = info.lpBaseOfDll,
                Size = info.SizeOfImage
            });
        }

        return modules;
    }

    public static IntPtr GetRemoteModuleBase(uint pid, string moduleName)
        => GetModules(pid)
            .FirstOrDefault(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase))
            ?.BaseAddress ?? IntPtr.Zero;

    public static IReadOnlyList<ThreadInfo> GetThreads(uint pid)
    {
        var threads = new List<ThreadInfo>();
        var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeConstants.TH32CS_SNAPTHREAD, 0);
        if (snapshot == new IntPtr(-1))
            return threads;

        try
        {
            var entry = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
            if (NativeMethods.Thread32First(snapshot, ref entry))
            {
                do
                {
                    if (entry.th32OwnerProcessID == pid)
                    {
                        threads.Add(new ThreadInfo
                        {
                            ThreadId = entry.th32ThreadID,
                            BasePriority = entry.tpBasePri
                        });
                    }
                } while (NativeMethods.Thread32Next(snapshot, ref entry));
            }
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        return threads;
    }

    public static IReadOnlyList<WindowInfo> GetWindows()
    {
        var windows = new List<WindowInfo>();
        NativeMethods.EnumWindows((hwnd, _) =>
        {
            if (!NativeMethods.IsWindowVisible(hwnd))
                return true;

            NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
            if (pid == 0)
                return true;

            var title = new System.Text.StringBuilder(512);
            NativeMethods.GetWindowTextW(hwnd, title, title.Capacity);
            var text = title.ToString();
            if (string.IsNullOrWhiteSpace(text))
                return true;

            var cls = new System.Text.StringBuilder(256);
            NativeMethods.GetClassNameW(hwnd, cls, cls.Capacity);

            windows.Add(new WindowInfo
            {
                Handle = hwnd,
                Pid = pid,
                Title = text,
                ClassName = cls.ToString()
            });

            return true;
        }, IntPtr.Zero);

        return windows;
    }
}
