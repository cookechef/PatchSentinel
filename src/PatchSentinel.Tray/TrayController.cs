using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using PatchSentinel.Core;
using PatchSentinel.Core.Ipc;
using PatchSentinel.Core.Remediation;
using PatchSentinel.Core.Updates;
using Forms = System.Windows.Forms;

namespace PatchSentinel.Tray;

/// <summary>Tray icon, notifications and the bridge to the SYSTEM agent service.</summary>
public sealed class TrayController : IDisposable
{
    private readonly App _app;
    private readonly Forms.NotifyIcon _icon;
    private readonly DispatcherTimer _timer;
    private MainWindow? _window;
    private string? _balloonTarget;
    private DateTimeOffset? _remindedFor;
    private string? _lastAnnouncedJob;
    private (int Count, DateTime At) _lastEolAlert = (-1, DateTime.MinValue);
    private bool _polling;
    private int _lastManualAlert;
    private string? _notifiedVersion;

    public AgentPipeClient Client { get; } = new();
    public AgentStatus? Status { get; private set; }
    public bool AgentReachable { get; private set; }
    public event EventHandler? StatusChanged;

    public TrayController(App app)
    {
        _app = app;
        _icon = new Forms.NotifyIcon
        {
            Icon = LoadIcon(),
            Text = "PatchSentinel",
            Visible = false,
            ContextMenuStrip = BuildMenu(),
        };
        _icon.DoubleClick += (_, _) => ShowMainWindow(null);
        _icon.BalloonTipClicked += (_, _) => ShowMainWindow(_balloonTarget == "self-update" ? "overview" : _balloonTarget);
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(60) };
        _timer.Tick += async (_, _) => await PollAsync();
    }

    public void Start()
    {
        _icon.Visible = true;
        _timer.Start();
        _ = PollAsync();
    }

    private static Icon LoadIcon()
    {
        try
        {
            var path = Environment.ProcessPath;
            if (path is not null && Icon.ExtractAssociatedIcon(path) is { } icon) return icon;
        }
        catch { /* fall back */ }
        return SystemIcons.Shield;
    }

    private Forms.ContextMenuStrip BuildMenu()
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Open PatchSentinel", null, (_, _) => ShowMainWindow(null));
        menu.Items.Add("Scan now", null, async (_, _) => await RunCommandAsync(Commands.Scan, null, "Scan started."));
        menu.Items.Add("Install app updates now", null, async (_, _) => await RunCommandAsync(Commands.InstallUpdates, new InstallUpdatesRequest(null), "Installing updates in the background."));
        menu.Items.Add("Postpone scheduled updates by 1 hour", null, async (_, _) => await DeferAsync(60));
        menu.Items.Add("Check for PatchSentinel updates", null, async (_, _) => await CheckSelfUpdateAsync());
        var appearance = new Forms.ToolStripMenuItem("Appearance");
        foreach (var t in new[] { AppTheme.System, AppTheme.Light, AppTheme.Dark })
        {
            var item = new Forms.ToolStripMenuItem(t == AppTheme.System ? "Match Windows" : t.ToString()) { Tag = t };
            item.Click += (_, _) => ThemeManager.Set(_app, t);
            appearance.DropDownItems.Add(item);
        }
        appearance.DropDownOpening += (_, _) =>
        {
            foreach (Forms.ToolStripMenuItem i in appearance.DropDownItems) i.Checked = (AppTheme)i.Tag! == ThemeManager.Current;
        };
        menu.Items.Add(appearance);
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => _app.Shutdown());
        return menu;
    }

    public void ShowMainWindow(string? tab)
    {
        if (_window is null)
        {
            _window = new MainWindow(this);
            _window.Closed += (_, _) => _window = null;
            _window.Show();
        }
        if (_window.WindowState == System.Windows.WindowState.Minimized) _window.WindowState = System.Windows.WindowState.Normal;
        _window.Activate();
        if (tab is not null) _window.SelectTab(tab);
    }

    public void Notify(string title, string text, Forms.ToolTipIcon icon = Forms.ToolTipIcon.Info, string? target = null)
    {
        _balloonTarget = target;
        _icon.ShowBalloonTip(10000, title, text, icon);
    }

    public async Task PollAsync()
    {
        if (_polling) return;
        _polling = true;
        try
        {
            Status = await Client.GetAsync<AgentStatus>(Commands.Status, timeout: TimeSpan.FromSeconds(5));
            AgentReachable = Status is not null;
        }
        catch
        {
            AgentReachable = false;
            Status = null;
        }
        finally { _polling = false; }

        UpdateTooltip();
        RaiseNotifications();
        StatusChanged?.Invoke(this, EventArgs.Empty);
        RestartIfUpdated();
    }

    private bool _restartAttempted;

    /// <summary>
    /// A silent self-update replaces this exe while it is running. When the agent reports a newer version and the
    /// file on disk is newer than this process, restart into it (once, so a pending-reboot replacement cannot loop).
    /// </summary>
    private void RestartIfUpdated()
    {
        if (_restartAttempted || Status is null || VersionUtil.Compare(Status.Version, AppPaths.Version) <= 0) return;
        try
        {
            var path = Environment.ProcessPath;
            if (path is null) return;
            var onDisk = System.Diagnostics.FileVersionInfo.GetVersionInfo(path).ProductVersion;
            if (VersionUtil.Compare(onDisk, AppPaths.Version) <= 0) return;
            _restartAttempted = true;
            AppLog.Info($"Tray restarting into PatchSentinel {onDisk}.");
            _app.RestartIntoNewVersion();
        }
        catch (Exception ex) { AppLog.Warn($"Update restart check failed: {ex.Message}"); }
    }

    private void UpdateTooltip()
    {
        string text;
        if (!AgentReachable || Status is null) text = "PatchSentinel - agent not running";
        else if (Status.BusyWith is { } busy) text = $"PatchSentinel - {busy}...";
        else
        {
            var c = Status.Counts;
            text = c.EndOfLife > 0 ? $"PatchSentinel - {c.EndOfLife} end-of-life item(s)" :
                   c.UpdatesAvailable > 0 ? $"PatchSentinel - {c.UpdatesAvailable} update(s) pending" :
                   "PatchSentinel - this device is up to date";
        }
        _icon.Text = text.Length > 63 ? text[..63] : text;
    }

    private void RaiseNotifications()
    {
        if (Status is null) return;
        var s = Status;

        // Legacy / EOL software: when the count changes, and at most once a day otherwise.
        var eol = s.Counts.EndOfLife;
        if (eol > 0 && s.LastScanAt is not null && (eol != _lastEolAlert.Count || DateTime.Now - _lastEolAlert.At > TimeSpan.FromHours(24)))
        {
            _lastEolAlert = (eol, DateTime.Now);
            Notify("Legacy software needs removing",
                $"{eol} end-of-life item(s) were found that no longer get security fixes. Click to review and fix.",
                Forms.ToolTipIcon.Warning, "findings");
            return;
        }

        // Reminder before scheduled updates.
        if (s.NextUpdateAt is { } next && s.Counts.UpdatesAvailable > 0 && _remindedFor != next)
        {
            var until = next - DateTimeOffset.Now;
            if (until > TimeSpan.Zero && until <= TimeSpan.FromMinutes(Math.Max(1, s.NotifyMinutesBefore)))
            {
                _remindedFor = next;
                Notify("App updates are scheduled",
                    $"{s.Counts.UpdatesAvailable} update(s) will install at {next.LocalDateTime:HH:mm}." +
                    (s.CanDefer ? " Right-click the PatchSentinel icon to postpone." : ""),
                    Forms.ToolTipIcon.Info, "overview");
                return;
            }
        }

        // A new version of PatchSentinel itself.
        if (s.AvailableVersion is { } av && av != _notifiedVersion)
        {
            _notifiedVersion = av;
            Notify($"PatchSentinel {av} is available",
                s.SelfUpdateInstallsAt is { } at
                    ? $"It will install automatically at {at.LocalDateTime:HH:mm}. Click to install it now."
                    : "Click to open PatchSentinel and install the update.",
                Forms.ToolTipIcon.Info, "self-update");
            return;
        }

        // Apps whose automatic updates keep failing.
        if (s.ManualUpdatesNeeded > _lastManualAlert)
        {
            _lastManualAlert = s.ManualUpdatesNeeded;
            Notify("Some apps need a manual update",
                $"{s.ManualUpdatesNeeded} app(s) could not be updated automatically. Click to see which and why.",
                Forms.ToolTipIcon.Warning, "updates");
            return;
        }
        _lastManualAlert = s.ManualUpdatesNeeded;

        // Completed jobs (except routine scans).
        if (s.LastJob is { } job && job.Id != _lastAnnouncedJob && job.FinishedAt is not null)
        {
            var first = _lastAnnouncedJob is null;
            _lastAnnouncedJob = job.Id;
            if (!first && job.Kind != "scan")
                Notify(job.Success ? $"{job.Name} - done" : $"{job.Name} - needs attention", job.Message,
                    job.Success ? Forms.ToolTipIcon.Info : Forms.ToolTipIcon.Warning, job.Kind == "updates" ? "updates" : "findings");
        }
    }

    // ---------- commands used by the window and menu ----------

    public async Task<string?> RunCommandAsync(string command, object? payload, string? startedMessage)
    {
        try
        {
            var r = await Client.SendAsync(command, payload);
            if (!r.Ok)
            {
                Notify("PatchSentinel", r.Error ?? "The agent refused the request.", Forms.ToolTipIcon.Warning);
                return null;
            }
            if (startedMessage is not null) Notify("PatchSentinel", startedMessage);
            await PollAsync();
            return r.As<JobStarted>()?.JobId;
        }
        catch (Exception ex)
        {
            Notify("PatchSentinel agent not reachable", $"Is the 'PatchSentinel Agent' service running? ({ex.Message})", Forms.ToolTipIcon.Error);
            return null;
        }
    }

    /// <summary>
    /// Uninstalls apps. Per-user apps of the signed-in user are removed here; machine-wide apps and winget packages
    /// are removed by "psentinel uninstall" started elevated, so Windows asks for administrator approval (UAC).
    /// </summary>
    public async Task<(bool Success, List<string> Lines)> UninstallAsync(IReadOnlyList<InstalledItem> items, IReadOnlyList<string> wingetIds, CancellationToken ct = default)
    {
        var lines = new List<string>();
        var records = new List<UninstallRecord>();
        var sid = Platform.CurrentUserSid;

        // 1. This user's own per-user apps: no elevation needed.
        var mine = items.Where(i => i.Scope == InstallScope.User && (i.UserSid is null || i.UserSid == sid)).ToList();
        var executor = new RemediationExecutor(WingetClient.TryCreate(isSystem: false), runningAsSystem: false);
        foreach (var i in mine)
        {
            var steps = RemediationPlanner.RegistryUninstallSteps(i);
            if (steps.Count == 0) { records.Add(new UninstallRecord(i.Name, i.Version, false, "No uninstaller registered")); continue; }
            var res = await executor.ExecuteAsync(new Finding { Id = "uninstall", Title = i.Name },
                new RemediationAction { Id = "uninstall", Label = i.Name, Steps = steps }, _ => true, ct);
            records.Add(new UninstallRecord(i.Name, i.Version, res.Success, res.Success ? "Uninstalled" : string.Join("; ", res.Steps.Select(s => s.Message))));
        }
        foreach (var other in items.Where(i => i.Scope == InstallScope.User && i.UserSid is not null && i.UserSid != sid))
            lines.Add($"SKIP {other.Name}: installed for another user - they need to remove it while signed in.");

        // 2. Machine-wide apps and winget packages: elevated helper.
        var machine = items.Where(i => i.Scope == InstallScope.Machine && i.RegistryKey is not null).ToList();
        if (machine.Count > 0 || wingetIds.Count > 0)
        {
            var exe = System.IO.Path.Combine(AppContext.BaseDirectory, "psentinel.exe");
            if (!System.IO.File.Exists(exe)) return (false, new List<string> { "psentinel.exe was not found next to the tray app." });
            var resultFile = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"patchsentinel-uninstall-{Guid.NewGuid():N}.json");
            var args = "uninstall --yes --result \"" + resultFile + "\"" +
                       string.Concat(machine.Select(m => $" --key \"{m.RegistryKey}\"")) +
                       string.Concat(wingetIds.Where(WingetClient.IsValidId).Select(id => $" --winget-id {id}"));
            try
            {
                using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe, args)
                {
                    UseShellExecute = true, Verb = "runas", WindowStyle = System.Diagnostics.ProcessWindowStyle.Minimized,
                });
                if (p is not null) await p.WaitForExitAsync(ct);
                if (System.IO.File.Exists(resultFile))
                {
                    var outcome = System.Text.Json.JsonSerializer.Deserialize<UninstallResultFile>(System.IO.File.ReadAllText(resultFile), Json.Options);
                    if (outcome is not null)
                    {
                        records.AddRange(outcome.Results);
                        if (outcome.RebootRequired) lines.Add("A restart is needed to finish removing some apps.");
                    }
                    System.IO.File.Delete(resultFile);
                }
                else lines.Add("The uninstaller did not report back; check the list after it refreshes.");
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                lines.Add("Cancelled: administrator approval was not given, so machine-wide apps were left installed.");
            }
        }

        lines.InsertRange(0, records.Select(r => $"{(r.Success ? "OK  " : "FAIL")} {r.Name} {r.Version}: {r.Message}"));
        if (records.Count > 0)
        {
            try { await Client.SendAsync(Commands.RecordUninstall, records, ct: ct); } catch { /* history is best effort */ }
            _ = RunCommandAsync(Commands.Scan, null, null);
        }
        return (records.Count > 0 && records.All(r => r.Success), lines);
    }

    public async Task CheckSelfUpdateAsync()
    {
        try
        {
            var r = await Client.SendAsync(Commands.CheckSelfUpdate, timeout: TimeSpan.FromSeconds(40));
            if (!r.Ok) { Notify("PatchSentinel", r.Error ?? "The update check failed.", Forms.ToolTipIcon.Warning); return; }
            var res = r.As<SelfUpdateCheckResult>();
            await PollAsync(); // raises the "available" notification if there is one
            if (res is { UpdateAvailable: false }) Notify("PatchSentinel", res.Message);
        }
        catch (Exception ex) { Notify("PatchSentinel agent not reachable", ex.Message, Forms.ToolTipIcon.Error); }
    }

    public async Task InstallSelfUpdateAsync()
    {
        try
        {
            var r = await Client.SendAsync(Commands.InstallSelfUpdate);
            if (!r.Ok && (r.Error ?? "").Contains("Check for", StringComparison.Ordinal))
            {
                // The agent restarted and forgot the release: check again, then install.
                await Client.SendAsync(Commands.CheckSelfUpdate, timeout: TimeSpan.FromSeconds(40));
                r = await Client.SendAsync(Commands.InstallSelfUpdate);
            }
            if (!r.Ok) { Notify("Could not update PatchSentinel", r.Error ?? "", Forms.ToolTipIcon.Warning); return; }
            Notify("Updating PatchSentinel", "Downloading and installing the new version. This icon will disappear for a minute and come back on the new version.");
            await PollAsync();
        }
        catch (Exception ex) { Notify("PatchSentinel agent not reachable", ex.Message, Forms.ToolTipIcon.Error); }
    }

    public async Task<bool> DeferAsync(int minutes)
    {
        try
        {
            var r = await Client.SendAsync(Commands.Defer, new DeferRequest(minutes));
            if (!r.Ok) { Notify("Could not postpone", r.Error ?? "", Forms.ToolTipIcon.Warning); return false; }
            var st = r.As<AgentStatus>();
            Notify("Updates postponed", st?.DeferredUntil is { } d ? $"Updates will now install after {d.LocalDateTime:HH:mm}." : "Updates postponed.");
            await PollAsync();
            return true;
        }
        catch (Exception ex)
        {
            Notify("PatchSentinel agent not reachable", ex.Message, Forms.ToolTipIcon.Error);
            return false;
        }
    }

    /// <summary>Polls until the agent reports the given job as finished.</summary>
    public async Task<JobInfo?> WaitForJobAsync(string jobId, TimeSpan timeout, CancellationToken ct = default)
    {
        var until = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < until)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var st = await Client.GetAsync<AgentStatus>(Commands.Status, timeout: TimeSpan.FromSeconds(5), ct: ct);
                if (st?.LastJob is { } j && j.Id == jobId && j.FinishedAt is not null)
                {
                    await PollAsync();
                    return j;
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { /* agent busy or restarting */ }
            await Task.Delay(2000, ct);
        }
        return null;
    }

    /// <summary>
    /// Applies a fix: machine-wide steps run in the SYSTEM service; per-user steps for the current user run here.
    /// </summary>
    public async Task<(bool Success, List<string> Lines)> RemediateAsync(Finding finding, RemediationAction action, CancellationToken ct)
    {
        var lines = new List<string>();
        var ok = true;

        if (action.HasMachineSteps)
        {
            var r = await Client.SendAsync(Commands.Remediate, new RemediateRequest(finding.Id, action.Id), ct: ct);
            if (!r.Ok) return (false, new List<string> { r.Error ?? "The agent refused the request." });
            var jobId = r.As<JobStarted>()?.JobId;
            if (jobId is null) return (false, new List<string> { "The agent did not start the fix." });
            lines.Add("Working... (machine-wide changes are made by the PatchSentinel service)");
            var job = await WaitForJobAsync(jobId, TimeSpan.FromMinutes(90), ct);
            lines.Clear();
            if (job is null) return (false, new List<string> { "Timed out waiting for the agent. Check the agent log in C:\\ProgramData\\PatchSentinel\\logs." });
            lines.AddRange(job.Details);
            lines.Add(job.Message);
            ok = job.Success;
        }

        var sid = Platform.CurrentUserSid;
        var mine = action.Steps.Where(s => s.RequiresUserContext && (s.UserSid is null || s.UserSid == sid)).ToList();
        if (ok && mine.Count > 0)
        {
            var executor = new RemediationExecutor(WingetClient.TryCreate(isSystem: false), runningAsSystem: false);
            var res = await executor.ExecuteAsync(finding, action, s => mine.Contains(s), ct);
            lines.AddRange(res.Steps.Select(s => $"{(s.Success ? "OK  " : "FAIL")} {s.Description}: {s.Message}"));
            ok &= res.Success;
            _ = RunCommandAsync(Commands.Scan, null, null);
        }

        var others = action.Steps.Count(s => s.RequiresUserContext && s.UserSid is not null && s.UserSid != sid);
        if (others > 0) lines.Add($"{others} step(s) belong to other users on this PC; they will be offered when those users sign in.");
        return (ok, lines);
    }

    public void Dispose()
    {
        _timer.Stop();
        _icon.Visible = false;
        _icon.Dispose();
    }
}
