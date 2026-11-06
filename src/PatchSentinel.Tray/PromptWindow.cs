using System.Windows;
using System.Windows.Controls;

namespace PatchSentinel.Tray;

/// <summary>A small "add a note" dialog. Returns the text (possibly empty), or null if cancelled.</summary>
public sealed class PromptWindow : Window
{
    private readonly TextBox _box;
    private readonly bool _required;

    private PromptWindow(string title, string message, bool required)
    {
        _required = required;
        Title = title;
        Width = 520;
        SizeToContent = SizeToContent.Height;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        FontFamily = new System.Windows.Media.FontFamily("Segoe UI");
        FontSize = 13;
        SetResourceReference(BackgroundProperty, "WindowBg");

        var panel = new StackPanel { Margin = new Thickness(16) };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) });
        _box = new TextBox { MinHeight = 60, MaxLength = 500, TextWrapping = TextWrapping.Wrap, AcceptsReturn = false, Padding = new Thickness(4) };
        panel.Children.Add(_box);
        var hint = new TextBlock { Text = required ? "A note is required." : "Your Windows user name and the time are recorded automatically.", Margin = new Thickness(0, 6, 0, 0), FontSize = 12 };
        hint.SetResourceReference(TextBlock.ForegroundProperty, "Muted");
        panel.Children.Add(hint);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 14, 0, 0) };
        var ok = new Button { Content = "Save", IsDefault = true, MinWidth = 90, Margin = new Thickness(0, 0, 8, 0) };
        ok.SetResourceReference(StyleProperty, "Primary");
        ok.Click += (_, _) =>
        {
            if (_required && string.IsNullOrWhiteSpace(_box.Text)) { _box.Focus(); return; }
            DialogResult = true;
        };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 90 };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        panel.Children.Add(buttons);
        Content = panel;
        Loaded += (_, _) => _box.Focus();
    }

    public static string? Ask(Window owner, string title, string message, bool required = false)
    {
        var w = new PromptWindow(title, message, required) { Owner = owner };
        return w.ShowDialog() == true ? w._box.Text.Trim() : null;
    }
}
