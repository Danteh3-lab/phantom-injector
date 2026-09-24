using Phantom.Core.PostInject;

namespace Phantom.UI;

/// <summary>
/// Small dialog for invoking an exported function inside a target process.
/// Arguments are comma separated and may be decimal, 0x-prefixed hex, or
/// strings (passed as ANSI pointers).
/// </summary>
public sealed class ExportCallDialog : Form
{
    private readonly uint _pid;
    private readonly IntPtr _moduleBase;
    private readonly string _dllPath;
    private readonly bool _headersErased;
    private readonly TextBox _function = new();
    private readonly TextBox _args = new();
    private readonly TextBox _result = new();

    public ExportCallDialog(uint pid, IntPtr moduleBase, string moduleName, string dllPath, bool headersErased, bool dark)
    {
        _pid = pid;
        _moduleBase = moduleBase;
        _dllPath = dllPath;
        _headersErased = headersErased;

        Text = "Call Exported Function";
        Width = 520;
        Height = 320;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MinimizeBox = false;
        MaximizeBox = false;

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 5,
            Padding = new Padding(10)
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 40));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        layout.Controls.Add(new Label { Text = "Module:", TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill }, 0, 0);
        layout.Controls.Add(new Label { Text = moduleName, TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill }, 1, 0);

        layout.Controls.Add(new Label { Text = "Function:", TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill }, 0, 1);
        _function.Dock = DockStyle.Fill;
        _function.PlaceholderText = "e.g. PhantomHello";
        layout.Controls.Add(_function, 1, 1);

        layout.Controls.Add(new Label { Text = "Arguments:", TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill }, 0, 2);
        _args.Dock = DockStyle.Fill;
        _args.PlaceholderText = "comma separated, e.g. 123, 0x1F, \"hello\"";
        layout.Controls.Add(_args, 1, 2);

        var call = new Button { Text = "Call", Width = 100, Height = 28 };
        call.Click += (_, _) => CallFunction();
        layout.Controls.Add(call, 1, 3);

        _result.Dock = DockStyle.Fill;
        _result.Multiline = true;
        _result.ReadOnly = true;
        _result.ScrollBars = ScrollBars.Vertical;
        layout.Controls.Add(_result, 0, 4);
        layout.SetColumnSpan(_result, 2);

        Controls.Add(layout);
        Theme.Apply(this, dark);
    }

    private void CallFunction()
    {
        var name = _function.Text.Trim();
        if (name.Length == 0)
        {
            _result.Text = "Enter a function name.";
            return;
        }

        var args = _args.Text
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(a => a.Trim().Trim('"'))
            .ToList();

        ExportCallResult outcome;

        // With erased PE headers GetProcAddress cannot work; resolve the export
        // RVA from the original file and call the absolute address instead.
        if (_headersErased)
        {
            if (!ExportCaller.TryGetExportRva(_dllPath, name, out var rva))
            {
                _result.Text = "Failed: the export RVA could not be resolved from the original file " +
                               "(PE headers were erased for this module).";
                return;
            }

            var address = new IntPtr(_moduleBase.ToInt64() + rva);
            outcome = ExportCaller.CallByAddress(_pid, address, args);
        }
        else
        {
            outcome = ExportCaller.Call(_pid, _moduleBase, name, args);
        }

        _result.Text = outcome.Success
            ? $"OK. Address: 0x{outcome.FunctionAddress.ToInt64():X}{Environment.NewLine}Return value: 0x{outcome.ReturnValue:X} ({outcome.ReturnValue})"
            : "Failed: " + outcome.Error;
    }
}
