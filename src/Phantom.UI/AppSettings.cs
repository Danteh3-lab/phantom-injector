using System.Text.Json;
using System.Text.Json.Serialization;
using Phantom.Core.Injection;
using Phantom.Core.Stealth;

namespace Phantom.UI;

public sealed class DllEntry
{
    public string Path { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
}

public sealed class AppSettings
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public InjectionMethod Method { get; set; } = InjectionMethod.Standard;

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public ScramblePreset Scramble { get; set; } = ScramblePreset.None;

    public string ProcessName { get; set; } = string.Empty;
    public bool AutoInject { get; set; }
    public bool CloseOnInject { get; set; }
    public bool ErasePe { get; set; }
    public bool HideModule { get; set; }
    public bool DarkTheme { get; set; } = true;
    public List<DllEntry> Dlls { get; set; } = new();

    private static string SettingsPath
    {
        get
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Phantom");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "settings.json");
        }
    }

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath), Options) ?? new AppSettings();
        }
        catch
        {
            // Corrupt settings should never prevent startup.
        }

        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, Options));
        }
        catch
        {
            // Ignore persistence failures.
        }
    }
}
