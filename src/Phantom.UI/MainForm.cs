using Phantom.Core.Injection;
using Phantom.Core.Processes;
using Phantom.Core.Stealth;

namespace Phantom.UI;

public sealed class MainForm : Form
{
    private readonly AppSettings _settings;
    private readonly List<DllEntry> _dlls;

    private readonly TextBox _txtProcess = new();
    private readonly ComboBox _cmbMethod = new();
    private readonly ComboBox _cmbScramble = new();
    private readonly CheckBox _chkErasePe = new();
    private readonly CheckBox _chkHideModule = new();
    private readonly CheckBox _chkAutoInject = new();
    private readonly CheckBox _chkCloseOnInject = new();
    private readonly CheckBox _chkDarkTheme = new();
    private readonly ListView _lvDlls = new();
    private readonly TextBox _log = new();
    private readonly Button _btnInject = new();

    private ProcessWatcher? _watcher;
    private bool _injecting;
    private readonly string[] _startupArgs;

    // The exact process chosen in the picker, so a same-name instance is never
    // silently substituted. Cleared when the process text is edited.
    private uint? _targetPid;

    // Authoritative module base per (target PID, canonical DLL path), so export
    // calls work for manual-mapped and PEB-hidden modules and never reuse a base
    // that belongs to a different process. The process start time guards against
    // PID reuse.
    private readonly Dictionary<(uint Pid, string Path), InjectedModule> _injected = new();

    private readonly record struct InjectedModule(IntPtr Base, bool HeadersErased, DateTime ProcessStartTime);

    private static (uint Pid, string Path) InjectedKey(uint pid, string dllPath)
        => (pid, Path.GetFullPath(dllPath).ToLowerInvariant());

    private static DateTime GetProcessStartTime(uint pid)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById((int)pid);
            return process.StartTime;
        }
        catch
        {
            return DateTime.MinValue;
        }
    }

    public MainForm(string[] args)
    {
        _settings = AppSettings.Load();
        _dlls = _settings.Dlls;
        _startupArgs = args;

        Text = "Phantom Injector";
        Width = 860;
        Height = 640;
        MinimumSize = new Size(720, 520);
        StartPosition = FormStartPosition.CenterScreen;

        BuildUi();
        ApplySettingsToUi();
        RefreshDllList();
        Theme.Apply(this, _settings.DarkTheme);

        if (args.Contains("--secure"))
            Log("Running in secure mode from a temporary location.");

        if (Privileges.EnableDebugPrivilege())
            Log("SeDebugPrivilege enabled.");
        else
            Log("Warning: could not enable SeDebugPrivilege. Run as administrator for full access.");

        if (!DependencyChecker.HasVcRuntime())
            Log("Warning: Visual C++ 2015-2022 x64 runtime not detected. Most injected DLLs require it.");
        else
            Log("Visual C++ runtime detected: " + (DependencyChecker.GetVcRuntimeVersion() ?? "present"));

        if (_settings.AutoInject && !string.IsNullOrWhiteSpace(_settings.ProcessName))
            StartWatcher();
    }

    private void BuildUi()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(8)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 200));

        root.Controls.Add(BuildTopPanel(), 0, 0);
        root.Controls.Add(BuildCenterPanel(), 0, 1);
        root.Controls.Add(BuildBottomPanel(), 0, 2);

        Controls.Add(root);
    }

    private Control BuildTopPanel()
    {
        var top = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2
        };
        top.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        top.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));

        var processRow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        processRow.Controls.Add(new Label { Text = "Process:", AutoSize = true, Padding = new Padding(0, 8, 4, 0) });
        _txtProcess.Width = 220;
        _txtProcess.PlaceholderText = "e.g. notepad.exe";
        // Editing the name invalidates an explicit picker selection.
        _txtProcess.TextChanged += (_, _) => _targetPid = null;
        processRow.Controls.Add(_txtProcess);

        var btnSelect = new Button { Text = "Select...", Width = 90 };
        btnSelect.Click += (_, _) => ShowSelectDialog();
        processRow.Controls.Add(btnSelect);

        var btnBrowse = new Button { Text = "Browse EXE", Width = 100 };
        btnBrowse.Click += (_, _) => BrowseExecutable();
        processRow.Controls.Add(btnBrowse);

        var btnRefresh = new Button { Text = "Refresh", Width = 80 };
        btnRefresh.Click += (_, _) => Log("Process list refreshed (" + ProcessManager.GetProcesses().Count + " processes).");
        processRow.Controls.Add(btnRefresh);

        var optionsRow = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        optionsRow.Controls.Add(new Label { Text = "Method:", AutoSize = true, Padding = new Padding(0, 8, 4, 0) });

        _cmbMethod.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbMethod.Width = 150;
        _cmbMethod.Items.AddRange(Enum.GetValues<InjectionMethod>().Cast<object>().ToArray());
        optionsRow.Controls.Add(_cmbMethod);

        optionsRow.Controls.Add(new Label { Text = "Scramble:", AutoSize = true, Padding = new Padding(12, 8, 4, 0) });
        _cmbScramble.DropDownStyle = ComboBoxStyle.DropDownList;
        _cmbScramble.Width = 110;
        _cmbScramble.Items.AddRange(Enum.GetValues<ScramblePreset>().Cast<object>().ToArray());
        optionsRow.Controls.Add(_cmbScramble);

        _chkErasePe.Text = "Erase PE";
        _chkErasePe.AutoSize = true;
        _chkErasePe.Padding = new Padding(12, 6, 0, 0);
        optionsRow.Controls.Add(_chkErasePe);

        _chkHideModule.Text = "Hide Module";
        _chkHideModule.AutoSize = true;
        _chkHideModule.Padding = new Padding(12, 6, 0, 0);
        optionsRow.Controls.Add(_chkHideModule);

        _chkAutoInject.Text = "Auto-Inject";
        _chkAutoInject.AutoSize = true;
        _chkAutoInject.Padding = new Padding(12, 6, 0, 0);
        _chkAutoInject.CheckedChanged += (_, _) =>
        {
            if (_chkAutoInject.Checked)
                StartWatcher();
            else
                StopWatcher();
        };
        optionsRow.Controls.Add(_chkAutoInject);

        _chkCloseOnInject.Text = "Close on inject";
        _chkCloseOnInject.AutoSize = true;
        _chkCloseOnInject.Padding = new Padding(12, 6, 0, 0);
        optionsRow.Controls.Add(_chkCloseOnInject);

        top.Controls.Add(processRow, 0, 0);
        top.Controls.Add(optionsRow, 0, 1);
        return top;
    }

    private Control BuildCenterPanel()
    {
        var center = new Panel { Dock = DockStyle.Fill };

        _lvDlls.Dock = DockStyle.Fill;
        _lvDlls.View = View.Details;
        _lvDlls.CheckBoxes = true;
        _lvDlls.FullRowSelect = true;
        _lvDlls.AllowDrop = true;
        _lvDlls.Columns.Add("DLL", 420);
        _lvDlls.Columns.Add("Folder", 320);
        _lvDlls.ItemChecked += (_, e) =>
        {
            if (e.Item.Tag is DllEntry entry)
                entry.Enabled = e.Item.Checked;
        };
        _lvDlls.DragEnter += (_, e) =>
        {
            if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true)
                e.Effect = DragDropEffects.Copy;
        };
        _lvDlls.DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] files)
                AddDlls(files);
        };

        var side = new FlowLayoutPanel
        {
            Dock = DockStyle.Right,
            FlowDirection = FlowDirection.TopDown,
            Width = 120,
            Padding = new Padding(6)
        };
        var btnAdd = new Button { Text = "Add DLL", Width = 105 };
        btnAdd.Click += (_, _) => BrowseDlls();
        var btnRemove = new Button { Text = "Remove", Width = 105 };
        btnRemove.Click += (_, _) => RemoveSelectedDll();
        var btnClear = new Button { Text = "Clear", Width = 105 };
        btnClear.Click += (_, _) =>
        {
            _dlls.Clear();
            RefreshDllList();
        };
        side.Controls.Add(btnAdd);
        side.Controls.Add(btnRemove);
        side.Controls.Add(btnClear);

        center.Controls.Add(_lvDlls);
        center.Controls.Add(side);
        return center;
    }

    private Control BuildBottomPanel()
    {
        var bottom = new Panel { Dock = DockStyle.Fill };

        var actions = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 44, WrapContents = false };

        _btnInject.Text = "Inject";
        _btnInject.Width = 140;
        _btnInject.Height = 32;
        _btnInject.BackColor = Theme.Accent;
        _btnInject.ForeColor = Color.White;
        _btnInject.FlatStyle = FlatStyle.Flat;
        _btnInject.Click += async (_, _) => await InjectAllAsync();
        actions.Controls.Add(_btnInject);

        var btnSecure = new Button { Text = "Start Secure Mode", Width = 140, Height = 32 };
        btnSecure.Click += (_, _) => StartSecureMode();
        actions.Controls.Add(btnSecure);

        var btnExport = new Button { Text = "Call Export...", Width = 120, Height = 32 };
        btnExport.Click += (_, _) => CallExport();
        actions.Controls.Add(btnExport);

        var btnClearLog = new Button { Text = "Clear Log", Width = 90, Height = 32 };
        btnClearLog.Click += (_, _) => _log.Clear();
        actions.Controls.Add(btnClearLog);

        _chkDarkTheme.Text = "Dark theme";
        _chkDarkTheme.AutoSize = true;
        _chkDarkTheme.Padding = new Padding(12, 9, 0, 0);
        _chkDarkTheme.CheckedChanged += (_, _) =>
        {
            _settings.DarkTheme = _chkDarkTheme.Checked;
            Theme.Apply(this, _settings.DarkTheme);
        };
        actions.Controls.Add(_chkDarkTheme);

        _log.Dock = DockStyle.Fill;
        _log.Multiline = true;
        _log.ReadOnly = true;
        _log.ScrollBars = ScrollBars.Vertical;
        _log.Font = new Font("Consolas", 9f);

        bottom.Controls.Add(_log);
        bottom.Controls.Add(actions);
        return bottom;
    }

    private void ApplySettingsToUi()
    {
        _txtProcess.Text = _settings.ProcessName;
        _cmbMethod.SelectedItem = _settings.Method;
        _cmbScramble.SelectedItem = _settings.Scramble;
        _chkErasePe.Checked = _settings.ErasePe;
        _chkHideModule.Checked = _settings.HideModule;
        _chkCloseOnInject.Checked = _settings.CloseOnInject;
        _chkAutoInject.Checked = _settings.AutoInject;
        _chkDarkTheme.Checked = _settings.DarkTheme;
    }

    private void CaptureSettings()
    {
        _settings.ProcessName = _txtProcess.Text.Trim();
        _settings.Method = _cmbMethod.SelectedItem is InjectionMethod m ? m : InjectionMethod.Standard;
        _settings.Scramble = _cmbScramble.SelectedItem is ScramblePreset s ? s : ScramblePreset.None;
        _settings.ErasePe = _chkErasePe.Checked;
        _settings.HideModule = _chkHideModule.Checked;
        _settings.CloseOnInject = _chkCloseOnInject.Checked;
        _settings.AutoInject = _chkAutoInject.Checked;
        _settings.DarkTheme = _chkDarkTheme.Checked;
        _settings.Dlls = _dlls;
        _settings.Save();
    }

    private void ShowSelectDialog()
    {
        using var dialog = new SelectProcessDialog(_settings.DarkTheme);
        if (dialog.ShowDialog(this) != DialogResult.OK || dialog.SelectedProcessName.Length == 0)
            return;

        // Set the text first (which clears the PID), then record the exact PID.
        _txtProcess.Text = dialog.SelectedProcessName;
        _targetPid = dialog.SelectedPid;
        Log($"Target locked to PID {dialog.SelectedPid}.");
    }

    private void BrowseExecutable()
    {
        using var dialog = new OpenFileDialog { Filter = "Executables (*.exe)|*.exe" };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            _txtProcess.Text = Path.GetFileName(dialog.FileName);
    }

    private void BrowseDlls()
    {
        using var dialog = new OpenFileDialog { Filter = "Libraries (*.dll)|*.dll", Multiselect = true };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            AddDlls(dialog.FileNames);
    }

    private void AddDlls(IEnumerable<string> files)
    {
        foreach (var file in files)
        {
            if (!file.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                continue;
            if (_dlls.Any(d => string.Equals(d.Path, file, StringComparison.OrdinalIgnoreCase)))
                continue;

            _dlls.Add(new DllEntry { Path = file, Enabled = true });
        }

        RefreshDllList();
    }

    private void RemoveSelectedDll()
    {
        foreach (ListViewItem item in _lvDlls.SelectedItems)
        {
            if (item.Tag is DllEntry entry)
                _dlls.Remove(entry);
        }

        RefreshDllList();
    }

    private void RefreshDllList()
    {
        _lvDlls.BeginUpdate();
        _lvDlls.Items.Clear();
        foreach (var entry in _dlls)
        {
            var item = new ListViewItem(Path.GetFileName(entry.Path)) { Checked = entry.Enabled, Tag = entry };
            item.SubItems.Add(Path.GetDirectoryName(entry.Path) ?? string.Empty);
            item.ToolTipText = entry.Path;
            _lvDlls.Items.Add(item);
        }

        _lvDlls.EndUpdate();
    }

    /// <summary>
    /// Immutable snapshot of everything a background injection needs. Taken on
    /// the UI thread so worker code never touches controls.
    /// </summary>
    private sealed class InjectionJob
    {
        public string ProcessName { get; init; } = string.Empty;
        public uint Pid { get; init; }
        public InjectionMethod Method { get; init; }
        public ScramblePreset Scramble { get; init; }
        public bool ErasePe { get; init; }
        public bool HideModule { get; init; }
        public bool CloseOnInject { get; init; }
        public IReadOnlyList<(string Path, bool Enabled)> Dlls { get; init; } = Array.Empty<(string, bool)>();
    }

    private InjectionJob CaptureJob(uint pid = 0)
    {
        CaptureSettings();
        return new InjectionJob
        {
            ProcessName = _txtProcess.Text.Trim(),
            Pid = pid != 0 ? pid : (_targetPid ?? 0),
            Method = _settings.Method,
            Scramble = _settings.Scramble,
            ErasePe = _settings.ErasePe,
            HideModule = _settings.HideModule,
            CloseOnInject = _settings.CloseOnInject,
            Dlls = _dlls.Select(d => (d.Path, d.Enabled)).ToList()
        };
    }

    private async Task InjectAllAsync(uint pid = 0)
    {
        if (_injecting)
            return;

        var job = CaptureJob(pid);
        _injecting = true;
        _btnInject.Enabled = false;
        try
        {
            await Task.Run(() => InjectAll(job));
        }
        finally
        {
            _injecting = false;
            _btnInject.Enabled = true;
        }
    }

    private void InjectAll(InjectionJob job)
    {
        if (job.ProcessName.Length == 0)
        {
            Log("Enter a process name first.");
            return;
        }

        // Prefer the explicitly selected PID so a same-name instance is never
        // targeted by accident.
        var process = job.Pid != 0 ? ProcessManager.GetByPid(job.Pid) : ProcessManager.GetByName(job.ProcessName);
        if (process is null)
        {
            Log(job.Pid != 0
                ? $"Process with PID {job.Pid} no longer exists."
                : $"Process '{job.ProcessName}' not found.");
            return;
        }

        var enabled = job.Dlls.Where(d => d.Enabled && File.Exists(d.Path)).ToList();
        if (enabled.Count == 0)
        {
            Log("No enabled DLLs to inject.");
            return;
        }

        Log($"Injecting {enabled.Count} DLL(s) into {process.Name} (PID {process.Pid}) using {job.Method}...");

        // Capture the identity before opening the target for injection. If the
        // PID is reused while the operation is in flight, never associate the
        // returned base with the replacement process.
        var targetStartTime = GetProcessStartTime(process.Pid);
        var succeeded = 0;
        foreach (var (dllPath, _) in enabled)
        {
            var toInject = dllPath;
            string? scrambled = null;
            try
            {
                if (job.Scramble != ScramblePreset.None)
                {
                    scrambled = Scrambler.Scramble(dllPath, job.Scramble);
                    toInject = scrambled;
                    Log($"  Scrambled {Path.GetFileName(dllPath)} ({job.Scramble}) -> temp copy.");
                }

                var options = new InjectionOptions
                {
                    Method = job.Method,
                    ErasePeHeaders = job.ErasePe,
                    HideModule = job.HideModule
                };

                var result = Injector.Inject(process.Pid, toInject, options);
                if (result.Success)
                {
                    succeeded++;
                    // Keep the authoritative base for export calls (works for
                    // manual-mapped and hidden modules), scoped to this exact
                    // process instance so a PID later reused cannot collide.
                    var currentStartTime = GetProcessStartTime(process.Pid);
                    var injectedKey = InjectedKey(process.Pid, dllPath);
                    if (targetStartTime != DateTime.MinValue && currentStartTime == targetStartTime)
                    {
                        lock (_injected)
                            _injected[injectedKey] =
                                new InjectedModule(result.ModuleBase, job.ErasePe, targetStartTime);
                    }
                    else
                    {
                        lock (_injected)
                            _injected.Remove(injectedKey);

                        Log($"  [WARN] Could not verify that PID {process.Pid} is still the same process; its module base was not cached.");
                    }

                    Log($"  [OK] {Path.GetFileName(dllPath)} -> base 0x{result.ModuleBase.ToInt64():X}" +
                        (result.RemoteThreadId != 0 ? $", TID {result.RemoteThreadId}" : ""));

                    if (result.Warning is not null)
                        Log($"  [WARN] {Path.GetFileName(dllPath)}: {result.Warning}");
                }
                else
                {
                    Log($"  [FAIL] {Path.GetFileName(dllPath)}: {result.Error}");
                }
            }
            catch (Exception ex)
            {
                Log($"  [ERROR] {Path.GetFileName(dllPath)}: {ex.Message}");
            }
            finally
            {
                if (scrambled is not null)
                {
                    try { File.Delete(scrambled); } catch { /* best effort */ }
                }
            }
        }

        Log($"Done. {succeeded}/{enabled.Count} succeeded.");

        if (succeeded > 0 && job.CloseOnInject && IsHandleCreated && !IsDisposed)
            BeginInvoke((Action)Close);
    }

    private void StartWatcher()
    {
        var name = _txtProcess.Text.Trim();
        if (name.Length == 0)
            return;

        StopWatcher();
        _watcher = new ProcessWatcher(name);
        _watcher.ProcessFound += pid =>
        {
            // Raised on a timer thread: marshal to the UI thread before
            // capturing inputs or touching controls.
            BeginInvoke((Action)(() =>
            {
                Log($"Auto-inject: found {name} (PID {pid}).");
                // Make the auto-found instance the active target so later export
                // calls resolve against this exact process.
                _targetPid = pid;
                _ = InjectAllAsync(pid);
            }));
        };
        Log($"Watching for '{name}'...");
    }

    private void StopWatcher()
    {
        _watcher?.Dispose();
        _watcher = null;
    }

    private void StartSecureMode()
    {
        if (_startupArgs.Contains("--secure"))
        {
            Log("Already running in secure mode.");
            return;
        }

        CaptureSettings();
        Log("Relaunching from a temporary path (secure mode)...");
        if (!SecureMode.Relaunch(_startupArgs))
            Log("Secure mode relaunch failed.");
    }

    private void CallExport()
    {
        var name = _txtProcess.Text.Trim();
        if (name.Length == 0)
        {
            Log("Enter a process name first.");
            return;
        }

        var process = _targetPid is uint pid ? ProcessManager.GetByPid(pid) : ProcessManager.GetByName(name);
        if (process is null)
        {
            Log(_targetPid is uint missing ? $"Process with PID {missing} no longer exists." : $"Process '{name}' not found.");
            return;
        }

        if (_lvDlls.SelectedItems.Count == 0 || _lvDlls.SelectedItems[0].Tag is not DllEntry entry)
        {
            Log("Select an injected DLL in the list first.");
            return;
        }

        // Prefer the authoritative base recorded at injection time; it is the
        // only way to find manual-mapped or PEB-hidden modules. It is valid only
        // for the same process instance (PID + start time guard against reuse).
        var moduleBase = IntPtr.Zero;
        var headersErased = false;
        var processStartTime = GetProcessStartTime(process.Pid);
        var injectedKey = InjectedKey(process.Pid, entry.Path);
        lock (_injected)
        {
            if (_injected.TryGetValue(injectedKey, out var injected))
            {
                if (injected.Base != IntPtr.Zero && processStartTime != DateTime.MinValue &&
                    injected.ProcessStartTime == processStartTime)
                {
                    moduleBase = injected.Base;
                    headersErased = injected.HeadersErased;
                }
                else
                {
                    _injected.Remove(injectedKey);
                }
            }
        }

        if (moduleBase == IntPtr.Zero)
            moduleBase = ProcessManager.GetRemoteModuleBase(process.Pid, Path.GetFileName(entry.Path));

        if (moduleBase == IntPtr.Zero)
        {
            Log($"No known base for '{Path.GetFileName(entry.Path)}' in {process.Name}. Inject it first.");
            return;
        }

        using var dialog = new ExportCallDialog(process.Pid, moduleBase, Path.GetFileName(entry.Path), entry.Path, headersErased, _settings.DarkTheme);
        dialog.ShowDialog(this);
    }

    private void Log(string message)
    {
        if (InvokeRequired)
        {
            BeginInvoke((Action)(() => Log(message)));
            return;
        }

        _log.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        StopWatcher();
        CaptureSettings();
        base.OnFormClosing(e);
    }
}
