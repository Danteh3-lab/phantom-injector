using Phantom.Core.Processes;

namespace Phantom.UI;

/// <summary>
/// Dialog for picking a target by process, thread or window.
/// </summary>
public sealed class SelectProcessDialog : Form
{
    private readonly ListView _processList = new();
    private readonly ListView _threadList = new();
    private readonly ListView _windowList = new();
    private readonly TextBox _filter = new();

    public uint SelectedPid { get; private set; }
    public string SelectedProcessName { get; private set; } = string.Empty;

    public SelectProcessDialog(bool dark)
    {
        Text = "Select Process";
        Width = 720;
        Height = 520;
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        MaximizeBox = false;

        var tabs = new TabControl { Dock = DockStyle.Fill };

        _processList.View = View.Details;
        _processList.FullRowSelect = true;
        _processList.MultiSelect = false;
        _processList.Dock = DockStyle.Fill;
        _processList.Columns.Add("PID", 70);
        _processList.Columns.Add("Name", 180);
        _processList.Columns.Add("Window", 200);
        _processList.Columns.Add("Path", 240);
        _processList.DoubleClick += (_, _) => Accept(_processList);

        var processTab = new TabPage("Processes");
        var filterPanel = new Panel { Dock = DockStyle.Top, Height = 30 };
        _filter.Dock = DockStyle.Fill;
        _filter.PlaceholderText = "Filter by name...";
        _filter.TextChanged += (_, _) => LoadProcesses();
        filterPanel.Controls.Add(_filter);
        processTab.Controls.Add(_processList);
        processTab.Controls.Add(filterPanel);

        _threadList.View = View.Details;
        _threadList.FullRowSelect = true;
        _threadList.Dock = DockStyle.Fill;
        _threadList.Columns.Add("TID", 100);
        _threadList.Columns.Add("Base Priority", 100);
        _threadList.DoubleClick += (_, _) => AcceptThread();
        var threadTab = new TabPage("Threads");
        threadTab.Controls.Add(_threadList);

        _windowList.View = View.Details;
        _windowList.FullRowSelect = true;
        _windowList.Dock = DockStyle.Fill;
        _windowList.Columns.Add("PID", 70);
        _windowList.Columns.Add("Title", 260);
        _windowList.Columns.Add("Class", 200);
        _windowList.DoubleClick += (_, _) => AcceptWindow();
        var windowTab = new TabPage("Windows");
        windowTab.Controls.Add(_windowList);

        tabs.TabPages.Add(processTab);
        tabs.TabPages.Add(threadTab);
        tabs.TabPages.Add(windowTab);
        tabs.SelectedIndexChanged += (_, _) => Reload(tabs.SelectedIndex);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            Height = 40,
            Padding = new Padding(6)
        };
        var cancel = new Button { Text = "Cancel", Width = 90, DialogResult = DialogResult.Cancel };
        var select = new Button { Text = "Select", Width = 90 };
        select.Click += (_, _) => AcceptCurrent(tabs.SelectedIndex);
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(select);

        Controls.Add(tabs);
        Controls.Add(buttons);

        Load += (_, _) => Reload(0);
        Theme.Apply(this, dark);
    }

    private void Reload(int tab)
    {
        switch (tab)
        {
            case 0:
                LoadProcesses();
                break;
            case 1:
                LoadThreads();
                break;
            case 2:
                LoadWindows();
                break;
        }
    }

    private void LoadProcesses()
    {
        var filter = _filter.Text.Trim();
        _processList.BeginUpdate();
        _processList.Items.Clear();
        foreach (var p in ProcessManager.GetProcesses())
        {
            if (filter.Length > 0 && !p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
                continue;

            var item = new ListViewItem(p.Pid.ToString());
            item.SubItems.Add(p.Name);
            item.SubItems.Add(p.WindowTitle ?? string.Empty);
            item.SubItems.Add(p.Path ?? string.Empty);
            item.Tag = p;
            _processList.Items.Add(item);
        }

        _processList.EndUpdate();
    }

    private void LoadThreads()
    {
        if (SelectedPid == 0)
            return;

        _threadList.BeginUpdate();
        _threadList.Items.Clear();
        foreach (var t in ProcessManager.GetThreads(SelectedPid))
        {
            var item = new ListViewItem(t.ThreadId.ToString());
            item.SubItems.Add(t.BasePriority.ToString());
            _threadList.Items.Add(item);
        }

        _threadList.EndUpdate();
    }

    private void LoadWindows()
    {
        _windowList.BeginUpdate();
        _windowList.Items.Clear();
        foreach (var w in ProcessManager.GetWindows())
        {
            var item = new ListViewItem(w.Pid.ToString());
            item.SubItems.Add(w.Title);
            item.SubItems.Add(w.ClassName);
            item.Tag = w;
            _windowList.Items.Add(item);
        }

        _windowList.EndUpdate();
    }

    private void AcceptCurrent(int tab)
    {
        switch (tab)
        {
            case 0:
                Accept(_processList);
                break;
            case 1:
                AcceptThread();
                break;
            case 2:
                AcceptWindow();
                break;
        }
    }

    private void Accept(ListView list)
    {
        if (list.SelectedItems.Count == 0)
            return;

        if (list.SelectedItems[0].Tag is ProcessInfo p)
        {
            SelectedPid = p.Pid;
            SelectedProcessName = p.Name + ".exe";
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    private void AcceptThread()
    {
        if (_threadList.SelectedItems.Count > 0 && SelectedPid != 0)
        {
            SelectedProcessName = ProcessManager.GetByPid(SelectedPid)?.Name + ".exe";
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    private void AcceptWindow()
    {
        if (_windowList.SelectedItems.Count > 0 && _windowList.SelectedItems[0].Tag is WindowInfo w)
        {
            SelectedPid = w.Pid;
            SelectedProcessName = ProcessManager.GetByPid(w.Pid)?.Name + ".exe" ?? string.Empty;
            DialogResult = DialogResult.OK;
            Close();
        }
    }
}
