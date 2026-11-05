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
    public string Title { get; init; } = "";
    public string Status { get; init; } = "";
    public string Versions { get; init; } = "";
    public string Dependents { get; init; } = "";
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
    private string? _lastSeenJob;

    public MainWindow(TrayController tray)
    {
        InitializeComponent();
        _tray = tray;
        UpdatesGrid.ItemsSource = _updates;
        _tray.StatusChanged += OnStatusChanged;
        Closed += (_, _) => _tray.StatusChanged -= OnStatusChanged;
        Loaded += async (_, _) => await RefreshAllAsync();
    }

    private CheckBox[] DayBoxes => [DaySun, DayMon, DayTue, DayWed, DayThu, DayFri, DaySat]; // index == DayOfWeek

    public void SelectTab(string tab) => Tabs.SelectedItem = tab switch
    {
        "findings" => FindingsTab,
        "updates" => UpdatesTab,
        "schedule" => ScheduleTab,
        "history" => HistoryTab,
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
            if (_localMode && _scan is not null) RenderCounts(_scan.Counts);
            return;
        }

        RenderCounts(st.Counts);
        RenderLastUpdateRun(st);
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
                    : u.NeedsManualUpdate ? $"Update manually - automatic update keeps failing ({u.ManualReason})"
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
            "Scheduled runs skip them; tick Update to retry, or see the History tab for the error.";
        UpdatesTab.Header = _scan.Counts.UpdatesAvailable > 0 ? $"App updates ({_scan.Counts.UpdatesAvailable})" : "App updates";
        UpdatesIntro.Text = _scan.WingetAvailable
            ? "Updates found by winget. Tick Exclude for apps that must not be updated automatically, then Save exclusions."
            : "winget (App Installer) is not installed on this device, so app updates cannot be checked.";
        WarningsText.Text = _scan.Warnings.Count == 0 ? "" : "Notes: " + string.Join(" ", _scan.Warnings.Take(4));
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
        var content = Path.GetExtension(dlg.FileName).ToLowerInvariant() switch
        {
            ".csv" => ReportWriter.ToCsv(_scan),
            ".json" => ReportWriter.ToJson(_scan),
            _ => ReportWriter.ToHtml(_scan),
        };
        File.WriteAllText(dlg.FileName, content);
        StatusBarText.Text = $"Report saved to {dlg.FileName}";
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
