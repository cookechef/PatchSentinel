using System;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PatchSentinel.Core;

namespace PatchSentinel.Tray;

public partial class RemediationWindow : Window
{
    private readonly Finding _finding;
    private readonly TrayController _tray;
    private readonly bool _agentAvailable;
    private readonly bool _allowRemediation;
    private CancellationTokenSource? _cts;

    public bool Changed { get; private set; }

    public RemediationWindow(Finding finding, TrayController tray, bool agentAvailable, bool allowRemediation)
    {
        InitializeComponent();
        _finding = finding;
        _tray = tray;
        _agentAvailable = agentAvailable;
        _allowRemediation = allowRemediation;
        Render();
        Closing += (_, e) =>
        {
            if (_cts is not null && !_cts.IsCancellationRequested)
            {
                e.Cancel = MessageBox.Show(this, "The fix is still running in the background. Close this window anyway?", "Fix in progress",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes;
            }
        };
    }

    private void Render()
    {
        var f = _finding;
        var today = DateOnly.FromDateTime(DateTime.Now);
        TitleText.Text = f.Title;
        StatusText.Text = f.StatusText(today);
        StatusText.Foreground = f.Kind == FindingKind.EndOfLife ? (Brush)FindResource("Critical") : (Brush)FindResource("Warning");
        SummaryText.Text = f.Summary;
        ItemsList.ItemsSource = f.Items.Select(i => i.Describe()).ToList();

        var critical = (Brush)FindResource("Critical");
        var normal = (Brush)FindResource("Muted");
        if (f.Dependents.Count == 0)
        {
            DependentsList.ItemsSource = new[]
            {
                new { Text = f.Items.Any(i => i.Source == ItemSource.DotNetSharedFramework)
                    ? "No installed applications were found that need this runtime."
                    : "PatchSentinel cannot tell which applications use this. Check with the vendor of any app that installed it.", Brush = normal },
            };
        }
        else
        {
            DependentsList.ItemsSource = f.Dependents.Select(d => new
            {
                Text = d.WouldBreak
                    ? $"{d.AppPath}  - would stop working (targets {d.Framework} {d.RequestedVersion}, roll-forward {d.RollForward})"
                    : $"{d.AppPath}  - will keep working on a newer runtime",
                Brush = d.WouldBreak ? critical : normal,
            }).ToList();
        }

        AdviceText.Text = string.IsNullOrWhiteSpace(f.Advice) ? (f.Replacement is null ? "Remove it if it is no longer needed." : $"Replace it with {f.Replacement}.") : f.Advice;
        ReferencesText.Text = f.References.Count == 0 ? "" : "More information: " + string.Join("  ", f.References);

        ActionsPanel.Children.Clear();
        if (f.Actions.Count == 0)
        {
            ActionsHeader.Text = "Fix";
            ActionsPanel.Children.Add(new TextBlock { Text = "This needs to be fixed by hand (see advice above).", TextWrapping = TextWrapping.Wrap });
            ApplyButton.IsEnabled = false;
            return;
        }

        foreach (var a in f.Actions)
        {
            var label = new TextBlock { TextWrapping = TextWrapping.Wrap };
            label.Inlines.Add(new System.Windows.Documents.Run(a.Label) { FontWeight = a.Recommended ? FontWeights.SemiBold : FontWeights.Normal });
            if (a.Recommended) label.Inlines.Add(new System.Windows.Documents.Run("  (recommended)") { Foreground = (Brush)FindResource("Accent") });
            if (!string.IsNullOrEmpty(a.Description)) label.Inlines.Add(new System.Windows.Documents.Run(Environment.NewLine + a.Description) { Foreground = normal, FontSize = 12 });
            var rb = new RadioButton { Content = label, GroupName = "actions", Tag = a, Margin = new Thickness(0, 4, 0, 4), IsChecked = a.Recommended };
            rb.Checked += (_, _) => ShowAction(a);
            ActionsPanel.Children.Add(rb);
        }
        var initial = f.Actions.FirstOrDefault(x => x.Recommended) ?? f.Actions[0];
        foreach (var rb in ActionsPanel.Children.OfType<RadioButton>()) rb.IsChecked = ReferenceEquals(rb.Tag, initial);
        ShowAction(initial);

        if (!_allowRemediation)
        {
            ApplyButton.IsEnabled = false;
            WarningText.Text = "Your administrator has turned off fixes from this device. Share this information with IT.";
        }
    }

    /// <summary>
    /// Lists and read-only text boxes inside a scrolling page swallow the mouse wheel, so the page would not scroll
    /// while the pointer is over them. The page handles the wheel first instead.
    /// </summary>
    private void PageScroll_PreviewMouseWheel(object sender, System.Windows.Input.MouseWheelEventArgs e)
    {
        if (sender is not ScrollViewer sv || e.Handled) return;
        sv.ScrollToVerticalOffset(sv.VerticalOffset - e.Delta / 3.0);
        e.Handled = true;
    }

    private RemediationAction? Selected =>
        ActionsPanel.Children.OfType<RadioButton>().FirstOrDefault(r => r.IsChecked == true)?.Tag as RemediationAction;

    private void ShowAction(RemediationAction a)
    {
        StepsText.Text = "Steps: " + Environment.NewLine + string.Join(Environment.NewLine, a.Steps.Select((s, i) =>
            $"{i + 1}. {s.Description}{(s.RequiresUserContext ? " (runs in your account)" : "")}"));
        WarningText.Text = a.Warning ?? "";
        if (!_agentAvailable && a.HasMachineSteps)
        {
            WarningText.Text = "The PatchSentinel agent service is not running, so machine-wide changes cannot be made. " + WarningText.Text;
            ApplyButton.IsEnabled = false;
        }
        else ApplyButton.IsEnabled = _allowRemediation;
    }

    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        var a = Selected;
        if (a is null) return;
        var msg = $"{a.Label}?{Environment.NewLine}{Environment.NewLine}" +
                  (a.Warning is null ? "" : $"Warning: {a.Warning}{Environment.NewLine}{Environment.NewLine}") +
                  "Save your work and close apps that may use this software before continuing.";
        if (MessageBox.Show(this, msg, "Confirm fix", MessageBoxButton.OKCancel,
                a.Warning is null ? MessageBoxImage.Question : MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        ApplyButton.IsEnabled = false;
        foreach (var rb in ActionsPanel.Children.OfType<RadioButton>()) rb.IsEnabled = false;
        ResultText.Text = "Working... this can take several minutes.";
        _cts = new CancellationTokenSource();
        try
        {
            var (ok, lines) = await _tray.RemediateAsync(_finding, a, _cts.Token);
            Changed = true;
            ResultText.Text = string.Join(Environment.NewLine, lines);
            ResultText.Foreground = ok ? (Brush)FindResource("OkText") : (Brush)FindResource("Critical");
            if (ok) CloseButton.Content = "Done";
        }
        catch (Exception ex)
        {
            ResultText.Text = ex.Message;
            ResultText.Foreground = (Brush)FindResource("Critical");
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            foreach (var rb in ActionsPanel.Children.OfType<RadioButton>()) rb.IsEnabled = true;
            ApplyButton.IsEnabled = true;
        }
    }
}
