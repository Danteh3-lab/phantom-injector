using Microsoft.Win32;

namespace Phantom.Core.Stealth;

/// <summary>
/// Verifies the target machine has the Visual C++ 2015-2022 x64 runtime that
/// most injected DLLs depend on.
/// </summary>
public static class DependencyChecker
{
    private static readonly string[] RequiredModules = { "msvcp140.dll", "vcruntime140.dll" };

    public static bool HasVcRuntime()
    {
        var system32 = Environment.SystemDirectory;
        return RequiredModules.All(m => File.Exists(Path.Combine(system32, m)));
    }

    /// <summary>
    /// Reads the installed VC++ 2015-2022 x64 redistributable version, or null.
    /// </summary>
    public static string? GetVcRuntimeVersion()
    {
        const string key = @"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64";
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var subKey = baseKey.OpenSubKey(key);
        return subKey?.GetValue("Version") as string;
    }
}
