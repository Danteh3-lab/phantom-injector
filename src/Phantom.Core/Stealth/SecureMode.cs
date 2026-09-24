using System.Diagnostics;

namespace Phantom.Core.Stealth;

/// <summary>
/// Copies the application (single file or full output directory) to a
/// randomized path under %TEMP% and relaunches it there, then exits the
/// current instance. Reduces the chance of the original filename/path being
/// flagged mid-session.
/// </summary>
public static class SecureMode
{
    public static bool Relaunch(string[] originalArgs)
    {
        // The --secure argument doubles as the re-entry guard.
        if (originalArgs.Contains("--secure"))
            return false;

        var source = Environment.ProcessPath;
        if (string.IsNullOrEmpty(source) || !File.Exists(source))
            return false;

        var sourceDir = Path.GetDirectoryName(source);
        if (string.IsNullOrEmpty(sourceDir))
            return false;

        var tempDir = Path.Combine(Path.GetTempPath(), "Ph~" + Guid.NewGuid().ToString("N")[..8]);

        try
        {
            Directory.CreateDirectory(tempDir);
            foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
            {
                var relative = Path.GetRelativePath(sourceDir, file);
                var destination = Path.Combine(tempDir, relative);
                var destinationDir = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(destinationDir))
                    Directory.CreateDirectory(destinationDir);

                File.Copy(file, destination, overwrite: true);
            }
        }
        catch
        {
            TryDeleteDirectory(tempDir);
            return false;
        }

        var destinationPath = Path.Combine(tempDir, Path.GetFileName(source));

        // UseShellExecute keeps UAC elevation working. ArgumentList (not a
        // manually quoted string) preserves empty arguments, embedded quotes, and
        // trailing backslashes exactly.
        var startInfo = new ProcessStartInfo
        {
            FileName = destinationPath,
            UseShellExecute = true,
            WorkingDirectory = tempDir
        };
        startInfo.ArgumentList.Add("--secure");
        foreach (var argument in originalArgs)
            startInfo.ArgumentList.Add(argument);

        try
        {
            Process.Start(startInfo);
        }
        catch
        {
            TryDeleteDirectory(tempDir);
            return false;
        }

        Environment.Exit(0);
        return true;
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch
        {
            // Best effort.
        }
    }
}
