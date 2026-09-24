namespace Phantom.UI;

/// <summary>
/// Simple dark/light palette applied recursively to a form's controls.
/// </summary>
public static class Theme
{
    public static readonly Color DarkBackground = Color.FromArgb(30, 30, 34);
    public static readonly Color DarkSurface = Color.FromArgb(42, 42, 48);
    public static readonly Color DarkBorder = Color.FromArgb(64, 64, 72);
    public static readonly Color DarkText = Color.FromArgb(230, 230, 235);
    public static readonly Color Accent = Color.FromArgb(0, 122, 204);

    public static void Apply(Control root, bool dark)
    {
        var back = dark ? DarkBackground : SystemColors.Control;
        var surface = dark ? DarkSurface : SystemColors.Window;
        var text = dark ? DarkText : SystemColors.ControlText;

        if (root is Form form)
        {
            form.BackColor = back;
            form.ForeColor = text;
        }

        foreach (Control control in root.Controls)
        {
            switch (control)
            {
                case TextBox:
                case ListBox:
                case ListView:
                case ComboBox:
                case RichTextBox:
                    control.BackColor = surface;
                    control.ForeColor = text;
                    break;
                case Button button:
                    button.BackColor = dark ? DarkSurface : SystemColors.Control;
                    button.ForeColor = text;
                    button.FlatStyle = dark ? FlatStyle.Flat : FlatStyle.Standard;
                    button.FlatAppearance.BorderColor = dark ? DarkBorder : SystemColors.ControlDark;
                    break;
                case CheckBox:
                case RadioButton:
                case Label:
                    control.BackColor = Color.Transparent;
                    control.ForeColor = text;
                    break;
                default:
                    control.BackColor = back;
                    control.ForeColor = text;
                    break;
            }

            Apply(control, dark);
        }
    }
}
