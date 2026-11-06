using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using PatchSentinel.Core;
using PatchSentinel.Core.Config;
using PatchSentinel.Core.Ipc;
using PatchSentinel.Core.Reporting;
using PatchSentinel.Core.Updates;

namespace PatchSentinel.Tray;

public sealed class FindingRow
{
    public Finding Finding { get; init; } = new();
    public string Severity { get; init; } = "";
    public int SeverityRank => (int)Finding.Severity;
    public string Kind => Finding.Kind.ToString();
    public string Title { get; init; } = "";
    public string Status { get; init; } = "";
    public string Versions { get; init; } = "";
    public string Dependents { get; init; } = "";
}

public sealed class AppRow : INotifyPropertyChanged
{
    private bool _selected;
    public InstalledItem Item { get; init; } = new();
    public string Name => Item.Name;
    public string Version => Item.Version ?? "";
    public string Publisher => Item.Publisher ?? "";
    public string InstallDate => Item.InstallDate?.ToString("dd MMM yyyy") ?? "";
    public int InstallDateSort => Item.InstallDate?.DayNumber ?? 0;
    public string Size => Item.SizeMB?.ToString("0.#") ?? "";
    public double SizeSort => Item.SizeMB ?? 0;
    public string Scope { get; init; } = "";
    public string Arch => Item.Architecture ?? "";
    public string UninstallMethod { get; init; } = "";
    public string UninstallCommand => Item.QuietUninstallString ?? Item.UninstallString ?? "";
    public string? VendorUrl => Item.VendorUrl;
    public string Category => Item.Classification?.Category ?? "";
    public string Concern => Item.Classification?.Concern.ToString() ?? "";
    public int ConcernRank => Item.Classification is { } c ? (int)c.Concern + 1 : 0;
    public string Purpose => Item.Classification?.Purpose ?? "";
    public string Advisory => Item.Classification is { } c ? (c.Concern == Core.Rules.Concern.Info ? c.Purpose : c.Advisory) : "";
    public string AdvisoryText => Item.Classification is { } c ? $"{Name}: {c.Category} ({Core.Reporting.InventoryExporter.ConcernText(c.Concern)}). {c.Purpose} {c.Advisory}" : "";
    public Visibility CategoryVisibility => Item.Classification is null ? Visibility.Collapsed : Visibility.Visible;
    public bool CanUninstall { get; init; }

    public bool Selected
    {
        get => _selected;
        set
        {
            if (value && !CanUninstall) value = false;
            if (_selected == value) return;
            _selected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Selected)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

public sealed class ChecklistRow
{
    public Core.Device.BuildCheckResult Result { get; init; } = new();
    public int Step => Result.Step;
    public string Title => Result.Title;
    public string Status => Result.Status.ToString();
    public string StatusLabel => Core.Reporting.DeviceReport.StatusText(Result.Status);
    public string Detail => Result.Detail;
    public string CopyText => $"{Step}. {Title} - {StatusLabel}: {Detail}";
}

public sealed class HistoryRow
{
    public HistoryEntry Entry { get; init; } = new();
    public string When => Entry.At.LocalDateTime.ToString("dd MMM yyyy HH:mm");
    public string Kind => Entry.Kind;
    public string Name => Entry.Name;
    public string? Id => Entry.Id;
    public string From => Entry.From ?? "";
    public string To => Entry.To ?? "";
    public string Result => Entry.Success ? "OK" : "Failed";
    public string Message => Entry.Message;
    public string Trigger => Entry.Trigger;
}

public sealed class UpdateRow : INotifyPropertyChanged
{
    private bool _excluded;
    private bool _selected;
    private bool _exclusionsAllowed = true;
    public UpdateCandidate Candidate { get; init; } = new();
    public string Name => Candidate.Name;
    public string Id => Candidate.Id;
    public string Installed => Candidate.InstalledVersion;
    public string Available => Candidate.AvailableVersion;
    public bool PolicyLocked => Candidate.ExcludedByPolicy;
    public string? VendorUrl => Candidate.VendorUrl;
    public string? InstallerUrl => Candidate.InstallerUrl;
    /// <summary>The Download page link is shown for apps that need a manual update.</summary>
    public Visibility LinkVisibility => Candidate.NeedsManualUpdate || Candidate.VendorUrl is not null || Candidate.LastAttempt is not null
        ? Visibility.Visible : Visibility.Collapsed;
    public string Note { get; set; } = "";

    public bool Excluded
    {
        get => _excluded;
        set
        {
            if (PolicyLocked || Candidate.ManagedByWindows) value = true; // cannot be cleared here
            if (_excluded == value) return;
            _excluded = value;
            if (value) Selected = false;
            OnChanged();
            OnChanged(nameof(CanSelect));
        }
    }

    /// <summary>Ticked for "Install ticked".</summary>
    public bool Selected
    {
        get => _selected;
        set
        {
            if (value && !CanSelect) value = false;
            if (_selected == value) return;
            _selected = value;
            OnChanged();
        }
    }

    public bool CanSelect => !Excluded && !Candidate.IdTruncated && !Candidate.RequiresExplicit;
    public bool CanExclude => _exclusionsAllowed && !PolicyLocked && !Candidate.ManagedByWindows;

    public bool ExclusionsAllowed
    {
        set { _exclusionsAllowed = value; OnChanged(nameof(CanExclude)); }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnChanged([CallerMemberName] string? p = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
}

public partial class MainWindow : Window
{
    private readonly TrayController _tray;
    private readonly ObservableCollection<UpdateRow> _updates = new();
    private ScanResult? _scan;
    private SettingsView? _settings;
    private bool _localMode;
    private bool _loadingScan;
    private HistoryView? _history;
    private List<InstalledItem> _inventory = [];
    private List<AppRow> _appRows = [];
    private bool _inventoryLoaded;
    private bool _themeLoading;
    private string? _lastSeenJob;

    public MainWindow(TrayController tray)
    {
        InitializeComponent();
        _tray = tray;
        UpdatesGrid.ItemsSource = _updates;
        _tray.StatusChanged += OnStatusChanged;
        Closed += (_, _) => _tray.StatusChanged -= OnStatusChanged;
        Loaded += async (_, _) => await RefreshAllAsync();
        _themeLoading = true;
        ThemeBox.SelectedIndex = (int)ThemeManager.Current switch { 1 => 1, 2 => 2, _ => 0 };
        _themeLoading = false;
        Tabs.SelectionChanged += async (_, e) =>
        {
            if (e.OriginalSource == Tabs && Tabs.SelectedItem == AppsTab && !_inventoryLoaded) await LoadInventoryAsync();
        };
    }

    private CheckBox[] DayBoxes => [DaySun, DayMon, DayTue, DayWed, DayThu, DayFri, DaySat]; // index == DayOfWeek

    public void SelectTab(string tab) => Tabs.SelectedItem = tab switch
    {
        "findings" => FindingsTab,
        "updates" => UpdatesTab,
        "schedule" => ScheduleTab,
        "history" => HistoryTab,
        "apps" => AppsTab,
        "device" => DeviceTab,
        _ => OverviewTab,
    };

    private async Task RefreshAllAsync()
    {
        await _tray.PollAsync();
        await LoadScanAsync();
        await LoadSettingsAsync();
        await LoadHistoryAsync();
    }

    private async void OnStatusChanged(object? sender, EventArgs e)
    {
        RenderStatus();
        var st = _tray.Status;
        if (st?.LastScanAt is { } last && (_scan is null || _localMode || last != _scan.ScannedAt))
            await LoadScanAsync();
        if (st?.LastJob?.Id is { } jobId && jobId != _lastSeenJob)
        {
            _lastSeenJob = jobId;
            await LoadHistoryAsync();
        }
    }

    // ---------------- loading ----------------

    private async Task LoadScanAsync()
    {
        if (_loadingScan || !_tray.AgentReachable) return;
        _loadingScan = true;
        try
        {
            var scan = await _tray.Client.GetAsync<ScanResult>(Commands.GetScan, timeout: TimeSpan.FromSeconds(30));
            if (scan is not null)
            {
                _scan = scan;
                _localMode = false;
                RenderScan();
            }
        }
        catch (Exception ex) { StatusBarText.Text = $"Could not load results from the agent: {ex.Message}"; }
        finally { _loadingScan = false; }
    }

    private async Task LoadSettingsAsync()
    {
        if (!_tray.AgentReachable) { SetScheduleEditable(false); return; }
        try
        {
            _settings = await _tray.Client.GetAsync<SettingsView>(Commands.GetSettings);
            RenderSettings();
        }
        catch (Exception ex) { ScheduleResultText.Text = $"Could not load settings: {ex.Message}"; }
    }

    // ---------------- rendering ----------------

    private void RenderStatus()
    {
        var st = _tray.Status;
        var busy = st?.BusyWith is not null;
        ScanButton.IsEnabled = !busy;
        UpdateAllButton.IsEnabled = !busy && _tray.AgentReachable;
        InstallSelectedButton.IsEnabled = !busy && _tray.AgentReachable;

        if (!_tray.AgentReachable || st is null)
        {
            HeadlineText.Text = "The PatchSentinel agent is not running";
            SubheadText.Text = "Start the 'PatchSentinel Agent' Windows service (or reinstall). You can still click Scan now for a read-only check of this device.";
            StatusBarText.Text = _localMode && _scan is not null ? $"Local read-only scan at {_scan.ScannedAt.LocalDateTime:HH:mm}" : "Agent not reachable";
            ScheduleSummaryText.Text = "";
            DeferButton.IsEnabled = false;
            CheckSelfUpdateButton.IsEnabled = false;
            InstallSelfUpdateButton.Visibility = Visibility.Collapsed;
            SelfUpdateText.Text = $"You have version {AppPaths.Version}. Update checks need the PatchSentinel Agent service.";
            if (_localMode && _scan is not null) RenderCounts(_scan.Counts);
            return;
        }

        RenderCounts(st.Counts);
        RenderLastUpdateRun(st);
        RenderSelfUpdate(st);
        var c = st.Counts;
        if (busy)
        {
            HeadlineText.Text = $"{st.BusyWith}...";
            SubheadText.Text = "This runs in the background; you can close this window.";
        }
        else if (c.EndOfLife > 0)
        {
            HeadlineText.Text = $"{c.EndOfLife} piece(s) of legacy software need removing";
            SubheadText.Text = "End-of-life software no longer gets security fixes and fails vulnerability scans such as Cyber Essentials Plus. Open 'Legacy & end-of-life' to fix it.";
        }
        else if (c.NearingEndOfLife + c.OutdatedPatch > 0)
        {
            HeadlineText.Text = "Some runtimes need attention soon";
            SubheadText.Text = $"{c.NearingEndOfLife} approaching end of life, {c.OutdatedPatch} missing security patches.";
        }
        else if (c.UpdatesAvailable > 0)
        {
            HeadlineText.Text = $"{c.UpdatesAvailable} app update(s) available";
            SubheadText.Text = "They will be installed at the next scheduled time, or you can install them now.";
        }
        else if (st.LastScanAt is null)
        {
            HeadlineText.Text = "Waiting for the first scan";
            SubheadText.Text = "The first scan starts a couple of minutes after the agent starts, or click Scan now.";
        }
        else
        {
            HeadlineText.Text = "This device is up to date";
            SubheadText.Text = "No legacy software or pending updates were found.";
        }

        var parts = new List<string>();
        if (st.NextUpdateAt is { } next)
        {
            parts.Add($"Next automatic update: {next.LocalDateTime:dddd d MMMM 'at' HH:mm}.");
            if (st.DeferredUntil is not null) parts.Add("(postponed)");
            if (st.CanDefer) parts.Add($"You can postpone {st.DeferralsLeft} more time(s).");
        }
        else parts.Add("Automatic app updates are switched off.");
        ScheduleSummaryText.Text = string.Join(" ", parts);
        DeviceSummaryText.Text = c.BuildChecksFailed + c.BuildChecksWarn == 0 ? ""
            : $"Device build checklist: {c.BuildChecksFailed} need action, {c.BuildChecksWarn} to check - see the Device tab.";
        DeviceSummaryText.Foreground = (System.Windows.Media.Brush)FindResource(c.BuildChecksFailed > 0 ? "Critical" : "Warning");
        DeferButton.IsEnabled = st.CanDefer && st.NextUpdateAt is not null && !busy;

        StatusBarText.Text = string.Join("  ·  ", new[]
        {
            st.LastScanAt is { } l ? $"Last scan {l.LocalDateTime:dd MMM HH:mm}" : "Not scanned yet",
            st.NextScanAt is { } n ? $"next scan {n.LocalDateTime:dd MMM HH:mm}" : null,
            st.LastJob is { } j ? $"last task: {j.Name} - {j.Message}" : null,
            st.AvailableVersion is { } av ? $"agent {st.Version} (version {av} will install automatically)" : $"agent {st.Version}",
        }.Where(s => s is not null));
    }

    private void RenderLastUpdateRun(AgentStatus st)
    {
        if (st.LastJob is not { Kind: "updates" } job || job.FinishedAt is null) return;
        UpdateResultsExpander.Visibility = Visibility.Visible;
        UpdateResultsExpander.Header = $"Last update run ({job.FinishedAt.Value.LocalDateTime:dd MMM HH:mm}): {job.Message}";
        var text = string.Join(Environment.NewLine, job.Details);
        if (UpdateResultsText.Text != text)
        {
            UpdateResultsText.Text = text;
            if (!job.Success) UpdateResultsExpander.IsExpanded = true;
        }
    }

    private void RenderSelfUpdate(AgentStatus st)
    {
        var busy = st.BusyWith is not null;
        var off = st.SelfUpdateMode == "Off";
        CheckSelfUpdateButton.IsEnabled = !busy && !off;
        InstallSelfUpdateButton.Visibility = st.AvailableVersion is not null && !off ? Visibility.Visible : Visibility.Collapsed;
        InstallSelfUpdateButton.IsEnabled = !busy;
        InstallSelfUpdateButton.Content = st.AvailableVersion is { } v ? $"Install {v} now" : "Install update now";

        var checkedAt = st.LastSelfUpdateCheckAt is { } c ? $" Last checked {c.LocalDateTime:dd MMM HH:mm}." : "";
        SelfUpdateText.Text = off ? $"You have version {st.Version}. Automatic updates of PatchSentinel are turned off by your administrator."
            : st.BusyWith?.StartsWith("Updating PatchSentinel", StringComparison.Ordinal) == true ? $"{st.BusyWith}... PatchSentinel will restart by itself."
            : st.AvailableVersion is { } av
                ? $"Version {av} is available (you have {st.Version}). " + (st.SelfUpdateInstallsAt is { } at
                    ? $"It will install automatically at {at.LocalDateTime:HH:mm}, or click Install now."
                    : "Click Install now to update.") + checkedAt
            : st.SelfUpdateError is { } err ? $"You have version {st.Version}. The last update check failed: {err}"
            : $"You have the latest version ({st.Version}).{checkedAt}";
    }

    private async void CheckSelfUpdate_Click(object sender, RoutedEventArgs e)
    {
        CheckSelfUpdateButton.IsEnabled = false;
        SelfUpdateText.Text = "Checking GitHub for a newer version...";
        try
        {
            var r = await _tray.Client.SendAsync(Commands.CheckSelfUpdate, timeout: TimeSpan.FromSeconds(40));
            var res = r.As<SelfUpdateCheckResult>();
            await _tray.PollAsync();
            SelfUpdateText.Text = r.Ok ? res?.Message ?? "" : r.Error ?? "The check failed.";
        }
        catch (Exception ex) { SelfUpdateText.Text = $"Could not reach the PatchSentinel agent: {ex.Message}"; }
        finally { CheckSelfUpdateButton.IsEnabled = true; }
    }

    private async void InstallSelfUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Install the new version of PatchSentinel now? It takes a minute; the app will close and reopen by itself.",
                "Update PatchSentinel", MessageBoxButton.OKCancel, MessageBoxImage.Question) != MessageBoxResult.OK) return;
        await _tray.InstallSelfUpdateAsync();
    }

    private void RenderCounts(ScanCounts c)
    {
        EolCount.Text = c.EndOfLife.ToString();
        NearingCount.Text = c.NearingEndOfLife.ToString();
        OutdatedCount.Text = c.OutdatedPatch.ToString();
        UpdatesCount.Text = c.UpdatesAvailable.ToString();
    }

    private void RenderScan()
    {
        if (_scan is null) return;
        var today = DateOnly.FromDateTime(DateTime.Now);
        FindingsGrid.ItemsSource = _scan.Findings.Select(f => new FindingRow
        {
            Finding = f,
            Severity = f.Severity.ToString(),
            Title = f.Title,
            Status = f.StatusText(today),
            Versions = string.Join(", ", f.Items.Select(i => $"{i.Version}{(i.Architecture is null ? "" : $" ({i.Architecture})")}").Distinct()),
            Dependents = f.Dependents.Count == 0 ? "None found"
                : f.BreakingDependents > 0 ? $"{f.Dependents.Count} ({f.BreakingDependents} would break)"
                : f.Dependents.Count.ToString(),
        }).ToList();
        FindingsTab.Header = _scan.Counts.EndOfLife > 0 ? $"Legacy & end-of-life ({_scan.Findings.Count})" : "Legacy & end-of-life";

        _updates.Clear();
        var showWindows = ShowWindowsManaged.IsChecked == true;
        foreach (var u in _scan.Updates.Where(x => showWindows || !x.ManagedByWindows))
        {
            var pattern = _settings?.ExcludedPackageIds.FirstOrDefault(p => p.Contains('*') && ExclusionMatcher.IsMatch([p], u.Id, u.Name));
            _updates.Add(new UpdateRow
            {
                Candidate = u,
                Excluded = u.Excluded,
                ExclusionsAllowed = _settings?.AllowUserExclusions ?? true,
                Note = u.ManagedByWindows ? "Updated by Windows / Microsoft Store"
                    : u.NeedsManualUpdate ? $"Update manually - {u.LastAttempt}"
                    : u.LastAttempt is not null ? u.LastAttempt
                    : u.ExcludedByPolicy ? "Excluded by your administrator"
                    : pattern is not null ? $"Excluded by pattern {pattern}"
                    : u.RequiresExplicit ? "Pinned - update manually"
                    : u.IdTruncated ? "ID shortened by winget - update manually"
                    : "",
            });
        }
        var manual = _scan.Updates.Where(u => u.NeedsManualUpdate).ToList();
        ManualBanner.Visibility = manual.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        ManualBannerText.Text = manual.Count == 0 ? "" :
            $"{manual.Count} app(s) need updating by hand because automatic updates keep failing: {string.Join(", ", manual.Select(m => m.Name))}. " +
            "Use the Download page link to get the vendor's installer, or tick Update to retry. Scheduled runs skip them until they are up to date.";
        UpdatesTab.Header = _scan.Counts.UpdatesAvailable > 0 ? $"App updates ({_scan.Counts.UpdatesAvailable})" : "App updates";
        UpdatesIntro.Text = _scan.WingetAvailable
            ? "Updates found by winget. Tick Exclude for apps that must not be updated automatically, then Save exclusions."
            : "winget (App Installer) is not installed on this device, so app updates cannot be checked.";
        WarningsText.Text = _scan.Warnings.Count == 0 ? "" : "Notes: " + string.Join(" ", _scan.Warnings.Take(4));
        RenderDevice();
        if (_localMode) StatusBarText.Text = $"Local read-only scan at {_scan.ScannedAt.LocalDateTime:HH:mm} (agent not running)";
    }

    private void RenderSettings()
    {
        if (_settings is null) return;
        var s = _settings.Schedule;
        ScheduleEnabled.IsChecked = s.Enabled;
        FrequencyBox.SelectedIndex = s.Frequency == ScheduleFrequency.Daily ? 0 : 1;
        for (var i = 0; i < 7; i++) DayBoxes[i].IsChecked = s.Days.Contains((DayOfWeek)i);
        TimeBox.Text = s.Time;
        NotifyBox.Text = s.NotifyMinutesBefore.ToString();
        RunIfMissedBox.IsChecked = s.RunIfMissed;
        ScheduleLockText.Visibility = _settings.ScheduleLocked ? Visibility.Visible : Visibility.Collapsed;
        SetScheduleEditable(!_settings.ScheduleLocked);

        var canExclude = _settings.AllowUserExclusions;
        SaveExclusionsButton.IsEnabled = canExclude;
        SaveExclusionsButton.ToolTip = canExclude ? null : "Exclusions are managed by your administrator";
        RenderScan(); // refresh pattern notes
    }

    private void SetScheduleEditable(bool editable)
    {
        foreach (var c in new Control[] { ScheduleEnabled, FrequencyBox, TimeBox, NotifyBox, RunIfMissedBox, SaveScheduleButton }) c.IsEnabled = editable;
        foreach (var d in DayBoxes) d.IsEnabled = editable;
    }

    // ---------------- overview actions ----------------

    private async void ScanNow_Click(object sender, RoutedEventArgs e)
    {
        if (_tray.AgentReachable)
        {
            await _tray.RunCommandAsync(Commands.Scan, null, "Scanning this device...");
            return;
        }

        // Agent not running: read-only scan in this user's context.
        ScanButton.IsEnabled = false;
        HeadlineText.Text = "Scanning (read-only, agent not running)...";
        try
        {
            _scan = await Task.Run(() => Scanner.ScanAsync(new EffectiveSettings(), new ScanOptions(), CancellationToken.None));
            _localMode = true;
            RenderScan();
            RenderStatus();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Scan failed", MessageBoxButton.OK, MessageBoxImage.Warning); }
        finally { ScanButton.IsEnabled = true; }
    }

    private async void UpdateAll_Click(object sender, RoutedEventArgs e)
    {
        var n = _scan?.Counts.UpdatesAvailable ?? 0;
        if (MessageBox.Show(this, $"Install {n} app update(s) now? Apps being updated may close.", "Install updates",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await _tray.RunCommandAsync(Commands.InstallUpdates, new InstallUpdatesRequest(null), "Installing app updates in the background.");
    }

    private async void Defer_Click(object sender, RoutedEventArgs e) => await _tray.DeferAsync(60);

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_scan is null) { MessageBox.Show(this, "Run a scan first.", "Export report"); return; }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            FileName = $"PatchSentinel-{_scan.ComputerName}-{_scan.ScannedAt:yyyyMMdd-HHmm}",
            Filter = "HTML report (*.html)|*.html|CSV for Excel (*.csv)|*.csv|JSON (*.json)|*.json",
        };
        if (dlg.ShowDialog(this) != true) return;
        var report = _scan;
        if (_inventory.Count > 0) { report = _scan.WithoutInventory(); report.Inventory = _inventory; } // adds the security review section
        var content = Path.GetExtension(dlg.FileName).ToLowerInvariant() switch
        {
            ".csv" => ReportWriter.ToCsv(report),
            ".json" => ReportWriter.ToJson(report),
            _ => ReportWriter.ToHtml(report),
        };
        File.WriteAllText(dlg.FileName, content);
        StatusBarText.Text = $"Report saved to {dlg.FileName}";
    }

    // ---------------- device ----------------

    private void RenderDevice()
    {
        var d = _scan?.Device;
        DeviceSections.Children.Clear();
        if (d is null)
        {
            DeviceHeadline.Text = "No device information yet";
            DeviceSubhead.Text = "Device details are collected by the PatchSentinel agent during a scan (version 0.1.11 or later). Click Refresh (scan now).";
            ChecklistGrid.ItemsSource = null;
            ChecklistSummary.Text = "";
            return;
        }
        DeviceHeadline.Text = $"{d.ComputerName} - {d.MakeModel}";
        DeviceSubhead.Text = string.Join("  ·  ", new[]
        {
            string.IsNullOrEmpty(d.SerialNumber) ? null : $"Serial {d.SerialNumber}",
            d.AgeEstimate is null ? null : $"Estimated age {d.AgeEstimate}",
            $"collected {d.CollectedAt.LocalDateTime:dd MMM HH:mm}",
        }.Where(x => x is not null));

        var checks = _scan!.BuildChecks;
        ChecklistGrid.ItemsSource = checks.Select(c => new ChecklistRow { Result = c }).ToList();
        var fail = checks.Count(c => c.Status == Core.Device.CheckStatus.Fail);
        var warn = checks.Count(c => c.Status == Core.Device.CheckStatus.Warn);
        var pass = checks.Count(c => c.Status == Core.Device.CheckStatus.Pass);
        ChecklistSummary.Text = checks.Count == 0 ? "No checklist in the rules catalogue."
            : $"{pass} OK, {fail} need action, {warn} to check, {checks.Count(c => c.Status is Core.Device.CheckStatus.Manual)} to confirm by hand. Steps follow your device build sheet.";

        foreach (var group in Core.Reporting.DeviceReport.Rows(d).GroupBy(r => r.Section))
        {
            var grid = new Grid { Margin = new Thickness(0, 6, 0, 0) };
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(150) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var row = 0;
            foreach (var r in group)
            {
                grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                var label = new TextBlock { Text = r.Field, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 8, 3) };
                label.SetResourceReference(TextBlock.ForegroundProperty, "Muted");
                var value = new TextBox
                {
                    Text = r.Value, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, BorderThickness = new Thickness(0),
                    Background = System.Windows.Media.Brushes.Transparent, Padding = new Thickness(0), MinHeight = 0, Margin = new Thickness(0, 3, 6, 3),
                };
                Grid.SetRow(label, row); Grid.SetRow(value, row); Grid.SetColumn(value, 1);
                grid.Children.Add(label); grid.Children.Add(value);
                if (r.Status is { } st)
                {
                    var pill = StatusPill(st);
                    Grid.SetRow(pill, row); Grid.SetColumn(pill, 2);
                    grid.Children.Add(pill);
                }
                row++;
            }
            var panel = new StackPanel();
            panel.Children.Add(new TextBlock { Text = group.Key, FontWeight = FontWeights.SemiBold, FontSize = 14 });
            panel.Children.Add(grid);
            var card = new Border { Child = panel, Width = 480, Margin = new Thickness(0, 0, 12, 12) };
            card.SetResourceReference(StyleProperty, "Card");
            DeviceSections.Children.Add(card);
        }
    }

    private static Border StatusPill(Core.Device.CheckStatus s)
    {
        var (bg, fg) = s switch
        {
            Core.Device.CheckStatus.Pass => ("#12B76A", "#FFFFFF"),
            Core.Device.CheckStatus.Warn => ("#F79009", "#FFFFFF"),
            Core.Device.CheckStatus.Fail => ("#D92D20", "#FFFFFF"),
            Core.Device.CheckStatus.Manual => ("#E4E7EC", "#344054"),
            _ => ("#D1E9FF", "#175CD3"),
        };
        var conv = new System.Windows.Media.BrushConverter();
        return new Border
        {
            CornerRadius = new CornerRadius(9), Padding = new Thickness(8, 1, 8, 1), VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 3, 0, 3),
            Background = (System.Windows.Media.Brush)conv.ConvertFromString(bg)!,
            Child = new TextBlock { Text = Core.Reporting.DeviceReport.StatusText(s), FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = (System.Windows.Media.Brush)conv.ConvertFromString(fg)! },
        };
    }

    private async void ExportDevice_Click(object sender, RoutedEventArgs e)
    {
        if (_scan?.Device is not { } device) { MessageBox.Show(this, "Run a scan first (Refresh).", "Export device report"); return; }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            FileName = $"PatchSentinel-device-{device.ComputerName}-{DateTime.Now:yyyyMMdd}",
            Filter = "Excel workbook - device, checklist and apps (*.xlsx)|*.xlsx|HTML report (*.html)|*.html|CSV - device and checklist (*.csv)|*.csv",
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            if (!_inventoryLoaded) await LoadInventoryAsync();
            var apps = _inventory.Where(i => !i.IsSystemComponent).ToList();
            switch (Path.GetExtension(dlg.FileName).ToLowerInvariant())
            {
                case ".html":
                    File.WriteAllText(dlg.FileName, Core.Reporting.InventoryExporter.ToHtml(apps, device.ComputerName, device, _scan.BuildChecks));
                    break;
                case ".csv":
                    File.WriteAllText(dlg.FileName, Core.Reporting.DeviceReport.ToCsv(device, _scan.BuildChecks), new System.Text.UTF8Encoding(true));
                    break;
                default:
                    using (var f = File.Create(dlg.FileName)) Core.Reporting.InventoryExporter.WriteXlsx(apps, device.ComputerName, f, device, _scan.BuildChecks);
                    break;
            }
            StatusBarText.Text = $"Device report saved to {dlg.FileName}";
            if (MessageBox.Show(this, "Device report saved. Open it now?", "Export device report", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed"); }
    }

    private void CopyDeviceSummary_Click(object sender, RoutedEventArgs e)
    {
        if (_scan?.Device is not { } d) return;
        var lines = Core.Reporting.DeviceReport.Rows(d).Select(r => $"{r.Section} - {r.Field}: {r.Value}").ToList();
        lines.Add("");
        lines.AddRange(_scan.BuildChecks.Select(c => $"{c.Step}. {c.Title} - {Core.Reporting.DeviceReport.StatusText(c.Status)}: {c.Detail}"));
        SetClipboard(string.Join(Environment.NewLine, lines));
        StatusBarText.Text = "Device summary copied to the clipboard.";
    }

    // ---------------- installed apps ----------------

    private async Task LoadInventoryAsync()
    {
        AppsCountText.Text = "Loading...";
        try
        {
            if (_tray.AgentReachable)
                _inventory = await _tray.Client.GetAsync<List<InstalledItem>>(Commands.GetInventory, timeout: TimeSpan.FromSeconds(30)) ?? new List<InstalledItem>();
            if (_inventory.Count > 0 && _inventory.All(i => i.Classification is null))
                _inventory = await Task.Run(() => ClassifyLocally(_inventory)); // agent's results pre-date categories
            if (_inventory.Count == 0)
            {
                // Agent not running or no scan yet: read this user's view of the registry directly.
                _inventory = await Task.Run(() => ClassifyLocally(Core.Inventory.RegistryInventory.Collect(false, Platform.CurrentUserSid, new List<string>())));
            }
            _inventoryLoaded = true;
            RenderInventory();
        }
        catch (Exception ex) { AppsCountText.Text = $"Could not load apps: {ex.Message}"; }
    }

    private void RenderInventory()
    {
        var sid = Platform.CurrentUserSid;
        var showSystem = AppsShowSystem.IsChecked == true;
        var q = AppsSearch.Text.Trim();
        var reviewOnly = AppsReviewOnly.IsChecked == true;
        _appRows = _inventory
            .Where(i => showSystem || !i.IsSystemComponent)
            .Where(i => !reviewOnly || i.Classification?.Concern is Core.Rules.Concern.Review or Core.Rules.Concern.High)
            .Where(i => q.Length == 0 || i.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                        || (i.Publisher?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false) || (i.Version?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false))
            .GroupBy(i => (i.Name, i.Version, i.Scope, i.UserSid)).Select(g => g.First())
            .OrderBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
            .Select(i =>
            {
                var steps = Core.Remediation.RemediationPlanner.RegistryUninstallSteps(i);
                var otherUser = i.Scope == InstallScope.User && i.UserSid is not null && i.UserSid != sid;
                var method = otherUser ? "Other user (sign in as them)"
                    : steps.Count == 0 ? "No uninstaller"
                    : steps[0].Kind == StepKind.InteractiveUninstall ? "Opens its uninstaller"
                    : "Silent";
                return new AppRow
                {
                    Item = i,
                    Scope = i.Scope == InstallScope.Machine ? "All users" : otherUser ? "Another user" : "You",
                    UninstallMethod = method,
                    CanUninstall = steps.Count > 0 && !otherUser,
                };
            }).ToList();
        AppsGrid.ItemsSource = _appRows;
        var review = _inventory.Where(i => !i.IsSystemComponent && i.Classification?.Concern is Core.Rules.Concern.Review or Core.Rules.Concern.High)
                               .GroupBy(i => i.Name).Select(g => g.First()).ToList();
        ReviewBanner.Visibility = review.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        ReviewBannerText.Text = review.Count == 0 ? "" :
            $"{review.Count} app(s) can monitor users, allow remote control or are otherwise worth checking: " +
            string.Join(", ", review.Take(8).Select(i => i.Name)) + (review.Count > 8 ? ", ..." : "") +
            ". Check each one is approved; tick 'Only apps that need a security review' to see the advice.";
        AppsCountText.Text = $"{_appRows.Count} app(s){(q.Length > 0 ? " matching" : "")}";
    }

    private static List<InstalledItem> ClassifyLocally(List<InstalledItem> items)
    {
        try
        {
            var catalog = Core.Rules.RuleCatalogLoader.Load(AppPaths.RulesDir, new List<string>());
            return new Core.Rules.SoftwareClassifier(catalog.Categories).Apply(items);
        }
        catch { return items; }
    }

    private void AppsSearch_TextChanged(object sender, TextChangedEventArgs e) { if (_inventoryLoaded) RenderInventory(); }
    private void AppsFilter_Click(object sender, RoutedEventArgs e) { if (_inventoryLoaded) RenderInventory(); }
    private async void RefreshApps_Click(object sender, RoutedEventArgs e) => await LoadInventoryAsync();

    private async void UninstallApps_Click(object sender, RoutedEventArgs e) =>
        await UninstallRowsAsync(_appRows.Where(r => r.Selected).ToList());

    private async void UninstallSelectedApps_Click(object sender, RoutedEventArgs e) =>
        await UninstallRowsAsync(AppsGrid.SelectedItems.OfType<AppRow>().Where(r => r.CanUninstall).ToList());

    private async Task UninstallRowsAsync(List<AppRow> rows)
    {
        if (rows.Count == 0) { MessageBox.Show(this, "Tick (or select) the apps you want to uninstall.", "Uninstall"); return; }
        var list = string.Join(Environment.NewLine, rows.Take(15).Select(r => $"  - {r.Name} {r.Version}")) + (rows.Count > 15 ? $"{Environment.NewLine}  ...and {rows.Count - 15} more" : "");
        var interactive = rows.Count(r => r.UninstallMethod.StartsWith("Opens", StringComparison.Ordinal));
        if (MessageBox.Show(this, $"Uninstall {rows.Count} app(s)?{Environment.NewLine}{Environment.NewLine}{list}{Environment.NewLine}{Environment.NewLine}" +
                "Windows will ask for administrator approval for apps installed for all users." +
                (interactive > 0 ? $" {interactive} app(s) will open their own uninstaller for you to complete." : ""),
                "Confirm uninstall", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;

        UninstallAppsButton.IsEnabled = false;
        AppsResultText.Text = "Uninstalling...";
        try
        {
            var (ok, lines) = await _tray.UninstallAsync(rows.Select(r => r.Item).ToList(), new List<string>());
            AppsResultText.Text = ok ? $"Removed {rows.Count} app(s)." : "Some apps were not removed - see details.";
            MessageBox.Show(this, string.Join(Environment.NewLine, lines), "Uninstall results", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
            await Task.Delay(1500);
            _inventoryLoaded = false;
            _inventory = await Task.Run(() => ClassifyLocally(Core.Inventory.RegistryInventory.Collect(false, Platform.CurrentUserSid, new List<string>())));
            // Prefer the agent's all-users view once its rescan finishes; meanwhile show what this user can see.
            _inventoryLoaded = true;
            RenderInventory();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Uninstall"); }
        finally { UninstallAppsButton.IsEnabled = true; }
    }

    private void ExportApps_Click(object sender, RoutedEventArgs e)
    {
        if (_inventory.Count == 0) { MessageBox.Show(this, "Open the list first.", "Export apps"); return; }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            FileName = $"PatchSentinel-installed-apps-{Environment.MachineName}-{DateTime.Now:yyyyMMdd}",
            Filter = "Excel workbook (*.xlsx)|*.xlsx|HTML report (*.html)|*.html|CSV (*.csv)|*.csv",
        };
        if (dlg.ShowDialog(this) != true) return;
        // Export what is shown (search and filters applied), including hidden components only if they are shown.
        var items = _appRows.Select(r => r.Item).ToList();
        try
        {
            switch (Path.GetExtension(dlg.FileName).ToLowerInvariant())
            {
                case ".html":
                    File.WriteAllText(dlg.FileName, Core.Reporting.InventoryExporter.ToHtml(items, Environment.MachineName, _scan?.Device, _scan?.BuildChecks));
                    break;
                case ".csv":
                    File.WriteAllText(dlg.FileName, Core.Reporting.InventoryExporter.ToCsv(items, Environment.MachineName, _scan?.Device), new System.Text.UTF8Encoding(true));
                    break;
                default:
                    using (var f = File.Create(dlg.FileName)) Core.Reporting.InventoryExporter.WriteXlsx(items, Environment.MachineName, f, _scan?.Device, _scan?.BuildChecks);
                    break;
            }
            StatusBarText.Text = $"Exported {items.Count} apps to {dlg.FileName}";
            if (MessageBox.Show(this, $"Exported {items.Count} apps. Open the file now?", "Export apps", MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Export failed"); }
    }

    // ---------------- uninstall from App updates ----------------

    private async void UninstallTickedUpdates_Click(object sender, RoutedEventArgs e) =>
        await UninstallUpdateRowsAsync(_updates.Where(r => r.Selected).ToList());

    private async void UninstallSelectedUpdates_Click(object sender, RoutedEventArgs e) =>
        await UninstallUpdateRowsAsync(UpdatesGrid.SelectedItems.OfType<UpdateRow>().ToList());

    private async Task UninstallUpdateRowsAsync(List<UpdateRow> rows)
    {
        rows = rows.Where(r => !r.Candidate.ManagedByWindows && WingetClient.IsValidId(r.Id)).ToList();
        if (rows.Count == 0) { MessageBox.Show(this, "Tick (or right-click) the apps you want to uninstall.", "Uninstall"); return; }
        if (MessageBox.Show(this, $"Uninstall these app(s) with winget?{Environment.NewLine}{Environment.NewLine}" +
                string.Join(Environment.NewLine, rows.Select(r => $"  - {r.Name} {r.Installed}")) +
                $"{Environment.NewLine}{Environment.NewLine}Windows will ask for administrator approval.", "Confirm uninstall",
                MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        try
        {
            var (ok, lines) = await _tray.UninstallAsync(new List<InstalledItem>(), rows.Select(r => r.Id).ToList());
            MessageBox.Show(this, string.Join(Environment.NewLine, lines), "Uninstall results", MessageBoxButton.OK, ok ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Uninstall"); }
    }

    // ---------------- history ----------------

    private async Task LoadHistoryAsync()
    {
        if (!_tray.AgentReachable) return;
        try
        {
            _history = await _tray.Client.GetAsync<HistoryView>(Commands.GetHistory, timeout: TimeSpan.FromSeconds(15));
            if (_history is null) return;
            HistoryGrid.ItemsSource = _history.Entries.Select(e => new HistoryRow { Entry = e }).ToList();
            ManualGrid.ItemsSource = _history.ManualUpdates;
            ManualPanel.Visibility = _history.ManualUpdates.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        }
        catch (Exception ex) { StatusBarText.Text = $"Could not load history: {ex.Message}"; }
    }

    private async void RefreshHistory_Click(object sender, RoutedEventArgs e) => await LoadHistoryAsync();

    private void ExportHistory_Click(object sender, RoutedEventArgs e)
    {
        if (_history is null || _history.Entries.Count == 0) { MessageBox.Show(this, "There is no history yet.", "Export history"); return; }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            FileName = $"PatchSentinel-history-{Environment.MachineName}-{DateTime.Now:yyyyMMdd}",
            Filter = "CSV for Excel (*.csv)|*.csv",
        };
        if (dlg.ShowDialog(this) != true) return;
        static string Csv(string? v) => v is null ? "" : "\"" + v.Replace("\"", "\"\"") + "\"";
        var lines = new List<string> { "When,Type,Name,Package ID,From,To,Result,Details,Started by" };
        lines.AddRange(_history.Entries.Select(h => string.Join(',', Csv(h.At.LocalDateTime.ToString("yyyy-MM-dd HH:mm")), Csv(h.Kind), Csv(h.Name), Csv(h.Id),
            Csv(h.From), Csv(h.To), Csv(h.Success ? "OK" : "Failed"), Csv(h.Message), Csv(h.Trigger))));
        File.WriteAllLines(dlg.FileName, lines);
        StatusBarText.Text = $"History saved to {dlg.FileName}";
    }

    // ---------------- copy / context menus ----------------

    private static DataGrid? GridFor(object sender) =>
        (sender as MenuItem)?.Parent is ContextMenu menu ? menu.PlacementTarget as DataGrid : null;

    private static void SetClipboard(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        for (var i = 0; i < 5; i++)
        {
            try { Clipboard.SetText(text); return; }
            catch (System.Runtime.InteropServices.COMException) { Thread.Sleep(50); } // clipboard briefly locked by another app
        }
    }

    private void CopyRows_Click(object sender, RoutedEventArgs e)
    {
        var grid = GridFor(sender);
        if (grid is null) return;
        if (grid.SelectedItems.Count == 0) grid.SelectAll();
        ApplicationCommands.Copy.Execute(null, grid);
    }

    private void CopyColumn_Click(object sender, RoutedEventArgs e)
    {
        var grid = GridFor(sender);
        var prop = (sender as MenuItem)?.Tag as string;
        if (grid is null || prop is null) return;
        var items = grid.SelectedItems.Count > 0 ? grid.SelectedItems.Cast<object>() : grid.Items.Cast<object>();
        var values = items.Select(i => i.GetType().GetProperty(prop)?.GetValue(i)?.ToString())
                          .Where(v => !string.IsNullOrWhiteSpace(v)).Distinct();
        SetClipboard(string.Join(Environment.NewLine, values));
        StatusBarText.Text = "Copied to the clipboard.";
    }

    private async void ClearManual_Click(object sender, RoutedEventArgs e)
    {
        var grid = GridFor(sender);
        if (grid is null) return;
        var ids = grid.SelectedItems.Cast<object>()
            .Select(i => i switch { UpdateRow u when u.Candidate.NeedsManualUpdate => u.Id, ManualUpdateEntry m => m.Id, _ => null })
            .Where(i => i is not null).Cast<string>().Distinct().ToList();
        if (ids.Count == 0) { MessageBox.Show(this, "Select apps that are on the manual updates list.", "Manual updates"); return; }
        try
        {
            foreach (var id in ids) await _tray.Client.SendAsync(Commands.ClearManual, new ClearManualRequest(id));
            await LoadScanAsync();
            await LoadHistoryAsync();
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Manual updates"); }
    }

    private void ShowWindowsManaged_Click(object sender, RoutedEventArgs e) => RenderScan();

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


    private void Theme_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (_themeLoading || ThemeBox.SelectedItem is not ComboBoxItem { Tag: string tag } || !Enum.TryParse<AppTheme>(tag, out var theme)) return;
        ThemeManager.Set(Application.Current, theme);
    }

    // ---------------- vendor links ----------------

    private void VendorLink_Click(object sender, RoutedEventArgs e)
    {
        var tag = (sender as FrameworkContentElement)?.Tag;
        _ = OpenVendorPageAsync(tag);
    }

    private void OpenVendorPage_Click(object sender, RoutedEventArgs e)
    {
        var grid = GridFor(sender);
        if (grid?.SelectedItem is { } item) _ = OpenVendorPageAsync(item);
        else MessageBox.Show(this, "Select an app first.", "Vendor download page");
    }

    private async void CopyVendorLink_Click(object sender, RoutedEventArgs e)
    {
        var grid = GridFor(sender);
        if (grid?.SelectedItem is not { } item) return;
        var url = await ResolveVendorUrlAsync(item);
        if (url is null) { StatusBarText.Text = "No vendor link is listed for this app."; return; }
        SetClipboard(url);
        StatusBarText.Text = $"Copied {url}";
    }

    /// <summary>Uses the stored link, otherwise asks winget for the package's homepage, otherwise searches the web.</summary>
    private async Task OpenVendorPageAsync(object? item)
    {
        var url = await ResolveVendorUrlAsync(item);
        if (url is null)
        {
            var name = item switch { UpdateRow u => u.Name, ManualUpdateEntry m => m.Name, AppRow a => a.Name, _ => null };
            if (name is null) return;
            url = "https://www.bing.com/search?q=" + Uri.EscapeDataString($"{name} download");
            StatusBarText.Text = "No vendor page is listed for this app, so a web search was opened instead.";
        }
        OpenUrl(url);
    }

    private async Task<string?> ResolveVendorUrlAsync(object? item)
    {
        var (url, id) = item switch
        {
            UpdateRow u => (u.VendorUrl, u.Id),
            ManualUpdateEntry m => (m.VendorUrl, m.Id),
            AppRow a => (a.VendorUrl, (string?)null),
            _ => ((string?)null, (string?)null),
        };
        if (url is not null || id is null) return url;
        var winget = WingetClient.TryCreate(isSystem: false);
        if (winget is null) return null;
        StatusBarText.Text = "Looking up the vendor page...";
        try { return (await winget.ShowLinksAsync(id, CancellationToken.None))?.VendorPage; }
        catch { return null; }
    }

    private void OpenUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || (u.Scheme != Uri.UriSchemeHttps && u.Scheme != Uri.UriSchemeHttp))
        {
            MessageBox.Show(this, "That link is not a web address.", "Vendor download page");
            return;
        }
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(u.AbsoluteUri) { UseShellExecute = true }); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Could not open the browser"); }
    }

    // ---------------- findings ----------------

    private async void Fix_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not FindingRow row) return;
        var allow = _tray.Status?.AllowUserRemediation ?? false;
        var win = new RemediationWindow(row.Finding, _tray, agentAvailable: _tray.AgentReachable && !_localMode, allowRemediation: allow) { Owner = this };
        win.ShowDialog();
        if (win.Changed) await RefreshAllAsync();
    }

    // ---------------- updates ----------------

    private async void InstallSelected_Click(object sender, RoutedEventArgs e)
    {
        var rows = _updates.Where(r => r.Selected).ToList();
        if (rows.Count == 0) rows = UpdatesGrid.SelectedItems.OfType<UpdateRow>().ToList(); // highlighted rows also work
        var ids = rows.Where(r => !r.Excluded && r.Candidate.Installable).Select(r => r.Id).ToList();
        if (ids.Count == 0)
        {
            MessageBox.Show(this, rows.Count > 0
                    ? "The apps you chose are excluded. Untick Exclude first (and Save exclusions) if you want to update them."
                    : "Tick Update next to the apps you want to install.", "Install ticked");
            return;
        }
        await _tray.RunCommandAsync(Commands.InstallUpdates, new InstallUpdatesRequest(ids), $"Installing {ids.Count} update(s) in the background.");
    }

    private async void SaveExclusions_Click(object sender, RoutedEventArgs e)
    {
        if (_settings is null) return;
        var visible = _updates.Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // Keep wildcard patterns and exclusions for apps that have no update showing right now.
        var keep = _settings.ExcludedPackageIds.Where(p => p.Contains('*') || !visible.Contains(p));
        var ticked = _updates.Where(r => r.Excluded && !r.PolicyLocked && !r.Candidate.ManagedByWindows && !r.Note.StartsWith("Excluded by pattern", StringComparison.Ordinal)).Select(r => r.Id);
        var ids = keep.Concat(ticked).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        try
        {
            var r = await _tray.Client.SendAsync(Commands.SetExclusions, new ExclusionsRequest(ids));
            if (!r.Ok) { MessageBox.Show(this, r.Error, "Exclusions"); return; }
            _settings = r.As<SettingsView>();
            await LoadScanAsync();
            StatusBarText.Text = $"Saved {ids.Count} exclusion(s).";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Exclusions"); }
    }

    private async void UserUpdates_Click(object sender, RoutedEventArgs e)
    {
        var winget = WingetClient.TryCreate(isSystem: false);
        if (winget is null) { MessageBox.Show(this, "winget (App Installer) is not available for your account.", "Per-user updates"); return; }
        UserUpdatesButton.IsEnabled = false;
        try
        {
            StatusBarText.Text = "Checking apps installed just for you...";
            var excluded = (_settings?.ExcludedPackageIds ?? new List<string>()).ToList();
            var policy = (_settings?.PolicyExcludedPackageIds ?? new List<string>()).ToList();
            var machine = (_scan?.Updates ?? new List<UpdateCandidate>()).Select(u => u.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var mine = ExclusionMatcher.Apply(await winget.ListUpgradesAsync(CancellationToken.None), excluded, policy)
                .Where(u => u.Installable && !machine.Contains(u.Id)).ToList();
            if (mine.Count == 0) { MessageBox.Show(this, "Your per-user apps are up to date.", "Per-user updates"); return; }

            var lines = new List<string>();
            foreach (var u in mine)
            {
                StatusBarText.Text = $"Updating {u.Name}...";
                var r = await winget.UpgradeAsync(u.Id, u.Name, CancellationToken.None);
                lines.Add($"{(r.Success ? "Updated" : "Failed")}: {u.Name} - {r.Message}");
            }
            MessageBox.Show(this, string.Join(Environment.NewLine, lines), "Per-user updates");
            StatusBarText.Text = "Per-user updates finished.";
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Per-user updates"); }
        finally { UserUpdatesButton.IsEnabled = true; }
    }

    // ---------------- schedule ----------------

    private void Frequency_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (DaysPanel is null) return;
        DaysPanel.Visibility = FrequencyBox.SelectedIndex == 0 ? Visibility.Collapsed : Visibility.Visible;
    }

    private async void SaveSchedule_Click(object sender, RoutedEventArgs e)
    {
        if (_settings is null) return;
        var current = _settings.Schedule;
        var sch = new UpdateSchedule
        {
            Enabled = ScheduleEnabled.IsChecked == true,
            Frequency = FrequencyBox.SelectedIndex == 0 ? ScheduleFrequency.Daily : ScheduleFrequency.Weekly,
            Days = Enumerable.Range(0, 7).Where(i => DayBoxes[i].IsChecked == true).Select(i => (DayOfWeek)i).ToList(),
            Time = TimeBox.Text.Trim(),
            NotifyMinutesBefore = int.TryParse(NotifyBox.Text, out var n) ? n : -1,
            RunIfMissed = RunIfMissedBox.IsChecked == true,
            RandomDelayMinutes = current.RandomDelayMinutes,
            MaxDeferrals = current.MaxDeferrals,
        };
        if (sch.Validate() is { } err) { ScheduleResultText.Text = err; return; }
        try
        {
            var r = await _tray.Client.SendAsync(Commands.SetSchedule, sch);
            if (!r.Ok) { ScheduleResultText.Text = r.Error; return; }
            _settings = r.As<SettingsView>();
            ScheduleResultText.Text = "Schedule saved.";
            await _tray.PollAsync();
        }
        catch (Exception ex) { ScheduleResultText.Text = ex.Message; }
    }
}
