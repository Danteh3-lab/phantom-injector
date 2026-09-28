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
    private readonly TabControl _outputTabs = new();
    private readonly TreeView _progressTree = new();
    private readonly Label _progressSummary = new();
    private readonly Dictionary<(long Batch, string Path, string Stage), TreeNode> _progressNodes = new();
    private readonly Dictionary<(long Batch, string Path), TreeNode> _progressDllNodes = new();
    private readonly Dictionary<(long Batch, string Path), TreeNode> _progressRecoveryNodes = new();
    private readonly Dictionary<TreeNode, List<(DateTimeOffset At, InjectionProgressEvent Event)>> _progressHistory = new();
    private const int ProgressHistoryCapacity = 12;
    private long _progressBatchId;
    private InjectionMethod _progressMethod;
    private string _progressTargetContext = "Target not resolved yet";

    private ProcessWatcher? _watcher;
    private bool _injecting;
    private readonly string[] _startupArgs;

    // The exact process chosen in the picker, so a same-name instance is never
    // silently substituted. Cleared when the process text is edited.
    private uint? _targetPid;
    private long? _targetCreationTime;

    // Authoritative module base per (target PID, canonical DLL path), so export
    // calls work for manual-mapped and PEB-hidden modules and never reuse a base
    // that belongs to a different process. The process start time guards against
    // PID reuse.
    private readonly Dictionary<(uint Pid, string Path), InjectedModule> _injected = new();

    private readonly record struct InjectedModule(IntPtr Base, bool HeadersErased, DateTime ProcessStartTime);

    private sealed record ProgressStagePlan(string Id, string Name);

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
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 240));

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
        _txtProcess.TextChanged += (_, _) =>
        {
            _targetPid = null;
            _targetCreationTime = null;
        };
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

        _outputTabs.Dock = DockStyle.Fill;
        _outputTabs.Padding = new Point(12, 4);

        var logPage = new TabPage("Log") { Padding = new Padding(4) };
        logPage.Controls.Add(_log);

        var progressPage = new TabPage("Progress") { Padding = new Padding(4) };
        var progressLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(4)
        };
        progressLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        progressLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _progressSummary.Dock = DockStyle.Fill;
        _progressSummary.TextAlign = ContentAlignment.MiddleLeft;
        _progressSummary.Text = "No injection has run.";
        _progressSummary.Font = new Font("Segoe UI", 9f, FontStyle.Bold);

        _progressTree.Dock = DockStyle.Fill;
        _progressTree.HideSelection = false;
        _progressTree.FullRowSelect = true;
        _progressTree.ShowRootLines = true;
        _progressTree.ShowPlusMinus = true;
        _progressTree.ShowLines = true;
        _progressTree.BorderStyle = BorderStyle.FixedSingle;
        _progressTree.Font = new Font("Segoe UI", 9f);

        progressLayout.Controls.Add(_progressSummary, 0, 0);
        progressLayout.Controls.Add(_progressTree, 0, 1);
        progressPage.Controls.Add(progressLayout);

        _outputTabs.TabPages.Add(logPage);
        _outputTabs.TabPages.Add(progressPage);

        bottom.Controls.Add(_outputTabs);
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

        if (dialog.SelectedCreationTime is not long creationTime)
        {
            _targetPid = null;
            _targetCreationTime = null;
            Log("Could not record the selected process start time, so the PID was not locked.");
            return;
        }

        // Set the text first (which clears the PID), then record the exact PID.
        _txtProcess.Text = dialog.SelectedProcessName;
        _targetPid = dialog.SelectedPid;
        _targetCreationTime = creationTime;
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
        public long? ExpectedCreationTime { get; init; }
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
            ExpectedCreationTime = pid != 0 ? null : _targetCreationTime,
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
        var batchId = BeginProgressBatch(job, job.Dlls.Where(d => d.Enabled).ToList());
        _injecting = true;
        _btnInject.Enabled = false;
        try
        {
            await Task.Run(() => InjectAll(job, batchId));
        }
        finally
        {
            _injecting = false;
            _btnInject.Enabled = true;
        }
    }

    private long BeginProgressBatch(InjectionJob job, IReadOnlyList<(string Path, bool Enabled)> enabledDlls)
    {
        var batchId = ++_progressBatchId;
        _progressNodes.Clear();
        _progressDllNodes.Clear();
        _progressRecoveryNodes.Clear();
        _progressHistory.Clear();
        _progressMethod = job.Method;
        _progressTargetContext = $"Looking for '{job.ProcessName}' · {job.Method}";
        _progressTree.BeginUpdate();
        _progressTree.Nodes.Clear();
        foreach (var dll in enabledDlls)
        {
            var path = dll.Path;
            var pathKey = ProgressPathKey(path);
            var stages = BuildProgressPlan(job);
            var node = new TreeNode($"{Path.GetFileName(path)} · 0/{stages.Count} stages succeeded")
            {
                Tag = path,
                ToolTipText = path
            };
            _progressTree.Nodes.Add(node);
            _progressDllNodes[(batchId, pathKey)] = node;
            foreach (var plan in stages)
            {
                var pending = new InjectionProgressEvent(plan.Id, plan.Name, InjectionProgressStatus.Pending);
                var stageNode = CreateProgressNode(pending);
                node.Nodes.Add(stageNode);
                _progressNodes[(batchId, pathKey, plan.Id)] = stageNode;
            }
            var recovery = new TreeNode("Cleanup and recovery · details") { Tag = "recovery-group" };
            node.Nodes.Add(recovery);
            _progressRecoveryNodes[(batchId, pathKey)] = recovery;
            node.Expand();
        }
        _progressTree.EndUpdate();
        _progressSummary.Text = enabledDlls.Count == 0
            ? $"No enabled DLLs in this batch · {_progressTargetContext}"
            : $"Current batch · {_progressTargetContext} · {enabledDlls.Count} DLL(s) · 0/{_progressNodes.Count} stages succeeded";
        if (_outputTabs.TabPages.Count > 1)
            _outputTabs.SelectedIndex = 1;
        return batchId;
    }

    private static IReadOnlyList<ProgressStagePlan> BuildProgressPlan(InjectionJob job)
    {
        var stages = new List<ProgressStagePlan>
        {
            new("input-check", "Validate selected DLL")
        };
        if (job.Scramble != ScramblePreset.None)
            stages.Add(new ProgressStagePlan("scramble", "Prepare optional scrambled copy"));
        stages.Add(new ProgressStagePlan("preflight", "Check method, target access, and architecture"));

        stages.AddRange(job.Method switch
        {
            InjectionMethod.Standard => new[]
            {
                new ProgressStagePlan("method-open", "Open target process"),
                new ProgressStagePlan("method-run", "Run LoadLibraryW in target"),
                new ProgressStagePlan("method-base", "Verify returned module address")
            },
            InjectionMethod.LdrLoadDll => new[]
            {
                new ProgressStagePlan("method-open", "Open target process"),
                new ProgressStagePlan("method-prepare", "Prepare LdrLoadDll call"),
                new ProgressStagePlan("method-run", "Run LdrLoadDll in target"),
                new ProgressStagePlan("method-result", "Verify loaded module handle")
            },
            InjectionMethod.ThreadHijack => new[]
            {
                new ProgressStagePlan("method-thread", "Find a suitable target thread"),
                new ProgressStagePlan("method-prepare", "Prepare loader stub"),
                new ProgressStagePlan("method-run", "Wait for loader stub completion"),
                new ProgressStagePlan("method-restore", "Restore original thread state"),
                new ProgressStagePlan("method-result", "Verify loader result")
            },
            InjectionMethod.ManualMap => new[]
            {
                new ProgressStagePlan("method-map", "Validate and map payload image"),
                new ProgressStagePlan("method-layout", "Apply relocations and validate metadata"),
                new ProgressStagePlan("method-imports", "Resolve image imports"),
                new ProgressStagePlan("method-write", "Write and protect image sections"),
                new ProgressStagePlan("method-unwind", "Validate unwind metadata"),
                new ProgressStagePlan("method-init", "Initialize mapped image")
            },
            InjectionMethod.DllHollowing => new[]
            {
                new ProgressStagePlan("method-carrier", "Prepare carrier image and backup"),
                new ProgressStagePlan("method-thread", "Find a suitable target thread"),
                new ProgressStagePlan("method-layout", "Prepare payload and resolve imports"),
                new ProgressStagePlan("method-write", "Write and protect payload image"),
                new ProgressStagePlan("method-init", "Initialize payload and verify result")
            },
            InjectionMethod.ModuleStomping => new[]
            {
                new ProgressStagePlan("method-payload", "Validate payload and open target"),
                new ProgressStagePlan("method-host", "Find a suitable host module"),
                new ProgressStagePlan("method-thread", "Find a suitable target thread"),
                new ProgressStagePlan("method-backup", "Suspend peers and back up host image"),
                new ProgressStagePlan("method-layout", "Prepare payload and resolve imports"),
                new ProgressStagePlan("method-write", "Overwrite and protect host image"),
                new ProgressStagePlan("method-init", "Initialize payload and restore thread state")
            },
            _ => new[] { new ProgressStagePlan("method-run", "Run selected injection method") }
        });

        if (job.ErasePe)
            stages.Add(new ProgressStagePlan("postinject-erase", "Erase PE headers"));
        if (job.HideModule)
            stages.Add(new ProgressStagePlan("postinject-hide", "Hide module from loader lists"));
        return stages;
    }

    private static string ProgressPathKey(string path)
    {
        try { return Path.GetFullPath(path).ToLowerInvariant(); }
        catch { return path.ToLowerInvariant(); }
    }

    private void SetProgressTargetContext(string target, uint pid, long batchId)
    {
        try
        {
            if (InvokeRequired)
            {
                if (IsDisposed || !IsHandleCreated) return;
                BeginInvoke((Action)(() => SetProgressTargetContext(target, pid, batchId)));
                return;
            }
            if (IsDisposed || batchId != _progressBatchId) return;
            _progressTargetContext = $"Injecting into {target} (PID {pid}) · {_progressMethod}";
            UpdateProgressSummary();
        }
        catch (ObjectDisposedException) { }
        catch (InvalidOperationException) { }
        catch (Exception) { }
    }

    private void ReportProgress(string dllPath, InjectionProgressEvent progress, long batchId)
    {
        try
        {
            if (InvokeRequired)
            {
                if (IsDisposed || !IsHandleCreated)
                    return;
                BeginInvoke((Action)(() => ReportProgress(dllPath, progress, batchId)));
                return;
            }
            if (IsDisposed || batchId != _progressBatchId)
                return;

            var pathKey = ProgressPathKey(dllPath);
            if (!_progressDllNodes.TryGetValue((batchId, pathKey), out var dllNode))
                return;

            var plannedId = ResolveProgressStage(_progressMethod, progress.StageId);
            if (plannedId is not null && _progressNodes.TryGetValue((batchId, pathKey, plannedId), out var stageNode))
            {
                var planned = (InjectionProgressEvent)stageNode.Tag!;
                var status = NormalizeProgressStatus(_progressMethod, plannedId, progress);
                ApplyProgress(stageNode, progress with { StageId = plannedId, Name = planned.Name, Status = status }, progress);
                stageNode.EnsureVisible();
            }
            else if (progress.StageId is "scramble-dll" or "postinject-erase" or "postinject-hide")
            {
                // Optional work that was not requested has no planned row.
            }
            else
            {
                if (!_progressRecoveryNodes.TryGetValue((batchId, pathKey), out var recovery))
                    return;
                var nodeKey = (batchId, pathKey, "recovery:" + progress.StageId);
                if (!_progressNodes.TryGetValue(nodeKey, out var detailNode))
                {
                    detailNode = CreateProgressNode(progress);
                    recovery.Nodes.Add(detailNode);
                    _progressNodes[nodeKey] = detailNode;
                }
                ApplyProgress(detailNode, progress);
                if (progress.Status is InjectionProgressStatus.Running or InjectionProgressStatus.Failed or InjectionProgressStatus.Warning)
                    recovery.Expand();
            }

            UpdateProgressSummary();
        }
        catch (ObjectDisposedException) { }
        catch (InvalidOperationException) { }
        catch (Exception) { /* UI reporting must never interfere with an injection attempt. */ }
    }

    private static string? ResolveProgressStage(InjectionMethod method, string stageId)
    {
        if (stageId == "input-check") return "input-check";
        if (stageId is "validate-dll" or "method-support" or "target-preflight" or "target-architecture")
            return "preflight";
        if (stageId == "scramble-dll") return "scramble";
        if (stageId is "postinject-erase" or "postinject-hide") return stageId;

        return method switch
        {
            InjectionMethod.Standard => stageId switch
            {
                "standard-open" => "method-open",
                "standard-load" => "method-run",
                "standard-base" => "method-base",
                _ => null
            },
            InjectionMethod.LdrLoadDll => stageId switch
            {
                "ldr-open" => "method-open",
                "ldr-prepare" => "method-prepare",
                "ldr-run" => "method-run",
                "ldr-handle" => "method-result",
                _ => null
            },
            InjectionMethod.ThreadHijack => stageId switch
            {
                "hijack-open" or "hijack-enumerate" or "hijack-context" or "hijack-select" => "method-thread",
                "hijack-stub" => "method-prepare",
                "hijack-run" => "method-run",
                "hijack-restore" => "method-restore",
                "hijack-result" => "method-result",
                _ => null
            },
            InjectionMethod.ManualMap => stageId switch
            {
                "manual-parse" or "manual-open" or "manual-map" => "method-map",
                "manual-layout" => "method-layout",
                "manual-imports" => "method-imports",
                "manual-write" => "method-write",
                "manual-unwind" => "method-unwind",
                "manual-initialize" or "manual-run-init" => "method-init",
                _ => null
            },
            InjectionMethod.DllHollowing => stageId switch
            {
                "hollow-parse" or "hollow-open" or "hollow-carrier" or "hollow-section" or "hollow-backup" => "method-carrier",
                "hollow-threads" or "hollow-context" or "hollow-thread-select" => "method-thread",
                "hollow-layout" or "hollow-imports" => "method-layout",
                "hollow-write" => "method-write",
                "hollow-init-prepare" or "hollow-init-wait" or "hollow-thread-restore" or "hollow-init-result" => "method-init",
                _ => null
            },
            InjectionMethod.ModuleStomping => stageId switch
            {
                "stomp-parse" or "stomp-open" => "method-payload",
                "stomp-host" => "method-host",
                "stomp-threads" or "stomp-thread-select" => "method-thread",
                "stomp-backup" => "method-backup",
                "stomp-layout" => "method-layout",
                "stomp-write" => "method-write",
                "stomp-init" => "method-init",
                _ => null
            },
            _ => null
        };
    }

    private static InjectionProgressStatus NormalizeProgressStatus(InjectionMethod method, string plannedId,
        InjectionProgressEvent progress)
    {
        if (progress.Status == InjectionProgressStatus.Succeeded && !IsVerifiedGroupCompletion(method, plannedId, progress.StageId))
            return InjectionProgressStatus.Running;

        if (method == InjectionMethod.ManualMap && plannedId == "method-init" &&
            progress.StageId == "manual-initialize" && progress.Status == InjectionProgressStatus.Skipped)
            return InjectionProgressStatus.Succeeded;

        return progress.Status;
    }

    private static bool IsVerifiedGroupCompletion(InjectionMethod method, string plannedId, string eventId)
    {
        if (plannedId == "preflight")
            return eventId == "target-architecture";

        return method switch
        {
            InjectionMethod.ManualMap => plannedId switch
            {
                "method-map" => eventId == "manual-map",
                "method-layout" => eventId == "manual-layout",
                "method-imports" => eventId == "manual-imports",
                "method-write" => eventId == "manual-write",
                "method-unwind" => eventId == "manual-unwind",
                "method-init" => eventId == "manual-run-init",
                _ => true
            },
            InjectionMethod.ThreadHijack => plannedId == "method-thread"
                ? eventId == "hijack-select"
                : true,
            InjectionMethod.DllHollowing => plannedId switch
            {
                "method-carrier" => eventId == "hollow-backup",
                "method-thread" => eventId == "hollow-thread-select",
                "method-layout" => eventId == "hollow-imports",
                "method-write" => eventId == "hollow-write",
                "method-init" => eventId == "hollow-init-result",
                _ => true
            },
            InjectionMethod.ModuleStomping => plannedId switch
            {
                "method-payload" => eventId == "stomp-open",
                "method-host" => eventId == "stomp-host",
                "method-thread" => eventId == "stomp-thread-select",
                "method-backup" => eventId == "stomp-backup",
                "method-layout" => eventId == "stomp-layout",
                "method-write" => eventId == "stomp-write",
                "method-init" => eventId == "stomp-init",
                _ => true
            },
            _ => true
        };
    }

    private static TreeNode CreateProgressNode(InjectionProgressEvent progress)
        => new() { Tag = progress, Text = $"{ProgressGlyph(progress.Status)} {progress.Name} — {ProgressStatusLabel(progress.Status)}", ForeColor = ProgressColor(progress.Status) };

    private void ApplyProgress(TreeNode stageNode, InjectionProgressEvent progress,
        InjectionProgressEvent? historyEvent = null)
    {
        stageNode.Tag = progress;
        stageNode.Text = $"{ProgressGlyph(progress.Status)} {progress.Name} — {ProgressStatusLabel(progress.Status)}";
        stageNode.ForeColor = ProgressColor(progress.Status);
        stageNode.ToolTipText = string.Join(Environment.NewLine,
            new[] { progress.Details, progress.TechnicalDetails }.Where(value => !string.IsNullOrWhiteSpace(value)));

        if (!_progressHistory.TryGetValue(stageNode, out var history))
        {
            history = new List<(DateTimeOffset At, InjectionProgressEvent Event)>();
            _progressHistory[stageNode] = history;
        }
        history.Add((DateTimeOffset.Now, historyEvent ?? progress));
        if (history.Count > ProgressHistoryCapacity)
            history.RemoveRange(0, history.Count - ProgressHistoryCapacity);

        stageNode.Nodes.Clear();
        foreach (var entry in history)
        {
            var update = entry.Event;
            var eventNode = new TreeNode($"{entry.At:HH:mm:ss.fff} · {ProgressGlyph(update.Status)} {update.Name} — {ProgressStatusLabel(update.Status)}")
            {
                ForeColor = ProgressColor(update.Status),
                ToolTipText = string.Join(Environment.NewLine,
                    new[] { update.Details, update.TechnicalDetails }.Where(value => !string.IsNullOrWhiteSpace(value)))
            };
            if (!string.IsNullOrWhiteSpace(update.Details))
                eventNode.Nodes.Add(new TreeNode("Details: " + update.Details));
            if (!string.IsNullOrWhiteSpace(update.TechnicalDetails))
                eventNode.Nodes.Add(new TreeNode("Technical: " + update.TechnicalDetails));
            stageNode.Nodes.Add(eventNode);
        }
    }

    private void CompleteProgressDll(string dllPath, long batchId)
    {
        try
        {
            if (InvokeRequired)
            {
                if (IsDisposed || !IsHandleCreated) return;
                BeginInvoke((Action)(() => CompleteProgressDll(dllPath, batchId)));
                return;
            }
            if (IsDisposed || batchId != _progressBatchId) return;
            var pathKey = ProgressPathKey(dllPath);
            if (!_progressDllNodes.TryGetValue((batchId, pathKey), out var dllNode)) return;
            foreach (TreeNode stageNode in dllNode.Nodes)
            {
                if (stageNode.Tag is not InjectionProgressEvent current || current.Status != InjectionProgressStatus.Pending)
                    continue;
                ApplyProgress(stageNode, current with
                {
                    Status = InjectionProgressStatus.Skipped,
                    Details = "Not reached before this DLL operation finished."
                });
            }
            UpdateProgressSummary();
        }
        catch (ObjectDisposedException) { }
        catch (InvalidOperationException) { }
        catch (Exception) { }
    }

    private void FailProgressBatch(long batchId, string reason)
    {
        try
        {
            if (InvokeRequired)
            {
                if (IsDisposed || !IsHandleCreated) return;
                BeginInvoke((Action)(() => FailProgressBatch(batchId, reason)));
                return;
            }
            if (IsDisposed || batchId != _progressBatchId) return;
            foreach (var entry in _progressDllNodes.Where(pair => pair.Key.Batch == batchId))
            {
                var pathKey = entry.Key.Path;
                foreach (TreeNode stageNode in entry.Value.Nodes)
                {
                    if (stageNode.Tag is not InjectionProgressEvent current || current.Status != InjectionProgressStatus.Pending)
                        continue;
                    var isPreflight = current.StageId == "preflight";
                    ApplyProgress(stageNode, current with
                    {
                        Status = isPreflight ? InjectionProgressStatus.Failed : InjectionProgressStatus.Skipped,
                        Details = reason
                    });
                }
                var planned = _progressNodes.Where(pair => pair.Key.Batch == batchId && pair.Key.Path == pathKey &&
                    !pair.Key.Stage.StartsWith("recovery:", StringComparison.Ordinal)).ToArray();
                entry.Value.Text = $"{Path.GetFileName((string)entry.Value.Tag!)} · {planned.Count(pair => pair.Value.Tag is InjectionProgressEvent update && update.Status == InjectionProgressStatus.Succeeded)}/{planned.Length} stages succeeded";
            }
            UpdateProgressSummary(reason);
        }
        catch (ObjectDisposedException) { }
        catch (InvalidOperationException) { }
        catch (Exception) { }
    }

    private void UpdateProgressSummary(string? batchReason = null)
    {
        var nodes = _progressNodes.Where(pair => pair.Key.Batch == _progressBatchId && !pair.Key.Stage.StartsWith("recovery:", StringComparison.Ordinal))
            .Select(pair => pair.Value).Where(node => node.Tag is InjectionProgressEvent).ToArray();
        var updates = nodes.Select(node => (InjectionProgressEvent)node.Tag!).ToArray();
        var succeeded = updates.Count(update => update.Status == InjectionProgressStatus.Succeeded);
        var total = updates.Length;
        var running = updates.Count(update => update.Status == InjectionProgressStatus.Running);
        var failed = updates.Count(update => update.Status == InjectionProgressStatus.Failed);
        var warnings = updates.Count(update => update.Status == InjectionProgressStatus.Warning);
        var skipped = updates.Count(update => update.Status == InjectionProgressStatus.Skipped);
        _progressSummary.Text = string.IsNullOrWhiteSpace(batchReason)
            ? $"Current batch · {_progressTargetContext} · {succeeded}/{total} stages succeeded · {running} running · {failed} failed · {warnings} warnings · {skipped} skipped"
            : $"Batch stopped · {_progressTargetContext} · {batchReason} · {succeeded}/{total} stages succeeded";

        foreach (var entry in _progressDllNodes.Where(pair => pair.Key.Batch == _progressBatchId))
        {
            var planned = _progressNodes.Where(pair => pair.Key.Batch == entry.Key.Batch && pair.Key.Path == entry.Key.Path &&
                    !pair.Key.Stage.StartsWith("recovery:", StringComparison.Ordinal))
                .Select(pair => pair.Value.Tag).OfType<InjectionProgressEvent>().ToArray();
            var dllSucceeded = planned.Count(update => update.Status == InjectionProgressStatus.Succeeded);
            entry.Value.Text = $"{Path.GetFileName((string)entry.Value.Tag!)} · {dllSucceeded}/{planned.Length} stages succeeded";
        }
    }

    private static string ProgressGlyph(InjectionProgressStatus status) => status switch
    {
        InjectionProgressStatus.Running => "…",
        InjectionProgressStatus.Pending => "·",
        InjectionProgressStatus.Succeeded => "✓",
        InjectionProgressStatus.Failed => "×",
        InjectionProgressStatus.Warning => "!",
        InjectionProgressStatus.Skipped => "–",
        _ => "·"
    };

    private static string ProgressStatusLabel(InjectionProgressStatus status) => status switch
    {
        InjectionProgressStatus.Running => "running",
        InjectionProgressStatus.Pending => "pending",
        InjectionProgressStatus.Succeeded => "succeeded",
        InjectionProgressStatus.Failed => "failed",
        InjectionProgressStatus.Warning => "warning",
        InjectionProgressStatus.Skipped => "skipped",
        _ => "pending"
    };

    private static Color ProgressColor(InjectionProgressStatus status) => status switch
    {
        InjectionProgressStatus.Running => Color.FromArgb(0, 122, 204),
        InjectionProgressStatus.Pending => SystemColors.GrayText,
        InjectionProgressStatus.Succeeded => Color.FromArgb(0, 145, 90),
        InjectionProgressStatus.Failed => Color.FromArgb(205, 70, 70),
        InjectionProgressStatus.Warning => Color.FromArgb(180, 125, 25),
        InjectionProgressStatus.Skipped => SystemColors.GrayText,
        _ => SystemColors.ControlText
    };

    private void InjectAll(InjectionJob job, long batchId)
    {
        if (job.ProcessName.Length == 0)
        {
            FailProgressBatch(batchId, "Enter a process name first.");
            Log("Enter a process name first.");
            return;
        }

        // Prefer the explicitly selected PID so a same-name instance is never
        // targeted by accident.
        var process = job.Pid != 0 ? ProcessManager.GetByPid(job.Pid) : ProcessManager.GetByName(job.ProcessName);
        if (process is null)
        {
            var reason = job.Pid != 0
                ? $"Process with PID {job.Pid} no longer exists."
                : $"Process '{job.ProcessName}' not found.";
            FailProgressBatch(batchId, reason);
            Log(job.Pid != 0
                ? $"Process with PID {job.Pid} no longer exists."
                : $"Process '{job.ProcessName}' not found.");
            return;
        }

        var enabled = job.Dlls.Where(d => d.Enabled).ToList();
        if (enabled.Count == 0)
        {
            Log("No enabled DLLs to inject.");
            return;
        }

        Log($"Injecting {enabled.Count} DLL(s) into {process.Name} (PID {process.Pid}) using {job.Method}...");

        var expectedCreationTime = job.ExpectedCreationTime ?? process.CreationTime;
        if (expectedCreationTime is not long expected)
        {
            FailProgressBatch(batchId, $"Could not verify the start time for PID {process.Pid}; injection was stopped.");
            Log($"Could not verify the start time for PID {process.Pid}; injection was stopped.");
            return;
        }

        if (job.ExpectedCreationTime is long selected && process.CreationTime != selected)
        {
            FailProgressBatch(batchId, $"PID {process.Pid} no longer refers to the process instance selected in the picker.");
            Log($"PID {process.Pid} no longer refers to the process instance selected in the picker.");
            return;
        }

        SetProgressTargetContext(process.Name, process.Pid, batchId);

        // Keep the selected creation time as the expected identity for every
        // DLL in this batch. Injector reopens must match this exact timestamp.
        var targetStartTime = DateTime.FromFileTimeUtc(expected).ToLocalTime();
        var succeeded = 0;
        foreach (var (dllPath, _) in enabled)
        {
            var toInject = dllPath;
            string? scrambled = null;
            Action<InjectionProgressEvent> reportProgress = progress => ReportProgress(dllPath, progress, batchId);
            try
            {
                if (!File.Exists(dllPath))
                {
                    reportProgress(new InjectionProgressEvent("input-check", "Validate selected DLL",
                        InjectionProgressStatus.Failed, "DLL file does not exist.", dllPath));
                    Log($"  [FAIL] {Path.GetFileName(dllPath)}: DLL file does not exist.");
                    continue;
                }

                reportProgress(new InjectionProgressEvent("input-check", "Validate selected DLL",
                    InjectionProgressStatus.Succeeded, "Enabled DLL file exists and can be passed to the selected method.", dllPath));

                if (job.Scramble != ScramblePreset.None)
                {
                    reportProgress(new InjectionProgressEvent("scramble-dll", "Scramble DLL",
                        InjectionProgressStatus.Running, $"Applying the {job.Scramble} preset."));
                    try
                    {
                        scrambled = Scrambler.Scramble(dllPath, job.Scramble);
                    }
                    catch (Exception ex)
                    {
                        reportProgress(new InjectionProgressEvent("scramble-dll", "Scramble DLL",
                            InjectionProgressStatus.Failed, "Could not create the temporary scrambled copy.", ex.Message));
                        throw;
                    }
                    toInject = scrambled;
                    reportProgress(new InjectionProgressEvent("scramble-dll", "Scramble DLL",
                        InjectionProgressStatus.Succeeded, $"Temporary {job.Scramble} copy is ready."));
                    Log($"  Scrambled {Path.GetFileName(dllPath)} ({job.Scramble}) -> temp copy.");
                }
                else
                {
                    reportProgress(new InjectionProgressEvent("scramble-dll", "Scramble DLL",
                        InjectionProgressStatus.Skipped, "Scrambling was not requested."));
                }

                var options = new InjectionOptions
                {
                    Method = job.Method,
                    ErasePeHeaders = job.ErasePe,
                    HideModule = job.HideModule,
                    ProgressChanged = reportProgress
                };

                var result = Injector.Inject(process.Pid, toInject, options, expected);
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
                    reportProgress(new InjectionProgressEvent("scramble-cleanup", "Remove scrambled temporary copy",
                        InjectionProgressStatus.Running));
                    try
                    {
                        File.Delete(scrambled);
                        var removed = !File.Exists(scrambled);
                        reportProgress(new InjectionProgressEvent("scramble-cleanup", "Remove scrambled temporary copy",
                            removed ? InjectionProgressStatus.Succeeded : InjectionProgressStatus.Warning,
                            removed ? "Temporary copy removed." : "Temporary copy still exists.", scrambled));
                    }
                    catch (Exception ex)
                    {
                        reportProgress(new InjectionProgressEvent("scramble-cleanup", "Remove scrambled temporary copy",
                            InjectionProgressStatus.Warning, "Temporary copy could not be removed.", ex.Message));
                    }
                }
                CompleteProgressDll(dllPath, batchId);
            }
        }

        Log($"Done. {succeeded}/{enabled.Count} succeeded.");

        if (succeeded > 0 && job.CloseOnInject && IsHandleCreated && !IsDisposed)
        {
            try { BeginInvoke((Action)Close); }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }
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
                _targetCreationTime = null;
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
