using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using PatchSentinel.Core;
using PatchSentinel.Core.Config;
using PatchSentinel.Core.Ipc;
using PatchSentinel.Core.Remediation;
using PatchSentinel.Core.Rules;
using PatchSentinel.Core.Updates;

namespace PatchSentinel.Agent;

internal sealed class AgentState
{
    public DateTimeOffset? LastScanAt { get; set; }
    public DateTimeOffset? LastUpdateRunAt { get; set; }
    public DateTimeOffset? LastRulesCheckAt { get; set; }
    public DateTimeOffset? LastSelfUpdateCheckAt { get; set; }
    public string? AvailableVersion { get; set; }
    public string? LastSelfUpdateAttemptVersion { get; set; }
    public DateTimeOffset? LastSelfUpdateAttemptAt { get; set; }
    public DateTimeOffset? DeferredUntil { get; set; }
    public int DeferralsUsed { get; set; }
    /// <summary>Anchor for the schedule: runs due after this time are executed.</summary>
    public DateTimeOffset ScheduleAnchor { get; set; } = DateTimeOffset.Now;
}

/// <summary>Background engine hosted by the Windows service: scheduler, job runner and named-pipe API for the tray app.</summary>
internal sealed class AgentEngine
{
    private readonly SemaphoreSlim _jobLock = new(1, 1);
    private readonly object _gate = new();
    private EffectiveSettings _settings = new();
    private AgentState _state = new();
    private ScanResult? _lastScan;
    private string? _busyWith;
    private JobInfo? _lastJob;
    private CancellationToken _stopping;
    private readonly DateTimeOffset _startedAt = DateTimeOffset.Now;
    private UpdateTracker _tracker = null!;

    public async Task RunAsync(CancellationToken ct)
    {
        _stopping = ct;
        DataDirSecurity.Prepare(AppPaths.DataRoot);
        foreach (var d in new[] { AppPaths.StateDir, AppPaths.CacheDir, AppPaths.LogDir, AppPaths.RulesDir }) Directory.CreateDirectory(d);
        AppLog.Initialize(AppPaths.LogDir);
        AppLog.Info($"PatchSentinel agent {AppPaths.Version} starting.");

        _settings = SettingsStore.LoadEffective(AppPaths.SettingsFile);
        _state = Load<AgentState>(AppPaths.AgentStateFile) ?? new AgentState();
        _lastScan = Load<ScanResult>(AppPaths.LastScanFile);
        _tracker = new UpdateTracker();
        SaveState();

        var pipe = new PipeServer(HandleAsync);
        var pipeTask = pipe.RunAsync(ct);

        while (!ct.IsCancellationRequested)
        {
            try { await TickAsync(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { AppLog.Error("Scheduler tick failed", ex); }
            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); } catch (OperationCanceledException) { break; }
        }

        try { await pipeTask; } catch { /* stopping */ }
        AppLog.Info("PatchSentinel agent stopped.");
    }

    // ---------------- scheduling ----------------

    private async Task TickAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.Now;
        _settings = SettingsStore.LoadEffective(AppPaths.SettingsFile); // pick up policy changes

        if (_settings.Settings.AutoUpdateRules && _settings.EffectiveRulesUrl is { } url
            && (_state.LastRulesCheckAt is null || now - _state.LastRulesCheckAt > TimeSpan.FromHours(24)))
        {
            _state.LastRulesCheckAt = now;
            SaveState();
            try { AppLog.Info(await RuleCatalogLoader.UpdateFromUrlAsync(url, AppPaths.RulesDir, ct)); }
            catch (Exception ex) when (ex is not OperationCanceledException) { AppLog.Warn($"Rules update from {url} failed: {ex.Message}"); }
        }

        if (await CheckSelfUpdateAsync(now, ct)) return;

        if (NextUpdateAt(now) is { } due && now >= due)
        {
            await RunJobAsync("Installing scheduled updates", "updates", c => InstallUpdatesAsync(null, scheduled: true, c), ct);
            return;
        }

        if (NextScanAt(now) is { } scanDue && now >= scanDue)
            await RunJobAsync("Scanning", "scan", ScanAsync, ct);
    }

    /// <summary>Daily check of GitHub Releases; installs a newer version when the agent is idle. Returns true if an update was started.</summary>
    private async Task<bool> CheckSelfUpdateAsync(DateTimeOffset now, CancellationToken ct)
    {
        var repo = _settings.EffectiveUpdateRepo;
        if (!_settings.Settings.AutoUpdateAgent || !SelfUpdater.IsValidRepo(repo)) return false;
        if (now - _startedAt < TimeSpan.FromMinutes(10)) return false; // let a freshly started agent settle first
        if (_state.LastSelfUpdateCheckAt is { } last && now - last < TimeSpan.FromHours(24)) return false;
        _state.LastSelfUpdateCheckAt = now;
        SaveState();

        ReleaseInfo? latest;
        try { latest = await SelfUpdater.GetLatestAsync(repo!, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { AppLog.Warn($"Self-update check against {repo} failed: {ex.Message}"); return false; }

        if (latest is null || !SelfUpdater.IsNewer(latest.Version, AppPaths.Version))
        {
            _state.AvailableVersion = null;
            SaveState();
            return false;
        }
        _state.AvailableVersion = latest.Version;
        SaveState();
        AppLog.Info($"PatchSentinel {latest.Version} is available ({latest.PageUrl}).");

        // Do not retry a version that failed to install within the last day (the next daily check retries it).
        if (_state.LastSelfUpdateAttemptVersion == latest.Version && _state.LastSelfUpdateAttemptAt is { } at && now - at < TimeSpan.FromHours(23)) return false;
        return await RunJobAsync($"Updating PatchSentinel to {latest.Version}", "self-update", c => SelfUpdateAsync(latest, c), ct);
    }

    private async Task<JobInfo> SelfUpdateAsync(ReleaseInfo latest, CancellationToken ct)
    {
        _state.LastSelfUpdateAttemptVersion = latest.Version;
        _state.LastSelfUpdateAttemptAt = DateTimeOffset.Now;
        SaveState();
        var msi = await SelfUpdater.DownloadAndVerifyAsync(latest, ct);
        AppLog.Info($"Downloaded and verified {latest.MsiName} (sha256 {latest.Sha256}); starting silent upgrade. The service will restart.");
        _tracker.RecordEvent(new HistoryEntry { At = DateTimeOffset.Now, Kind = "Self-update", Name = "PatchSentinel", From = AppPaths.Version, To = latest.Version, Success = true, Message = "Verified installer downloaded; upgrade started", Trigger = "Automatic" });
        SelfUpdater.LaunchInstaller(msi);
        return new JobInfo { Success = true, Message = $"Installing PatchSentinel {latest.Version}; the agent will restart." };
    }

    private DateTimeOffset? NextScanAt(DateTimeOffset now)
    {
        if (_state.LastScanAt is null) return _startedAt.AddMinutes(2); // let the machine settle after boot
        return _state.LastScanAt.Value.AddHours(Math.Max(1, _settings.Settings.ScanIntervalHours));
    }

    private DateTimeOffset? NextUpdateAt(DateTimeOffset now)
    {
        var sch = _settings.Settings.Schedule;
        if (!sch.Enabled) return null;
        if (_state.DeferredUntil is { } deferred && deferred > now) return deferred;

        var anchor = _state.LastUpdateRunAt is { } last && last > _state.ScheduleAnchor ? last : _state.ScheduleAnchor;
        var next = sch.NextOccurrence(anchor.LocalDateTime);
        if (next is null) return null;
        var nextOffset = new DateTimeOffset(next.Value);
        if (nextOffset <= now)
        {
            // A run was missed (device off/asleep). Either catch up shortly after start, or wait for the next slot.
            if (sch.RunIfMissed) return Max(nextOffset, _startedAt.AddMinutes(10));
            var upcoming = sch.NextOccurrence(now.LocalDateTime);
            return upcoming is null ? null : new DateTimeOffset(upcoming.Value);
        }
        return nextOffset;
    }

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a > b ? a : b;

    // ---------------- jobs ----------------

    private async Task<bool> RunJobAsync(string name, string kind, Func<CancellationToken, Task<JobInfo>> work, CancellationToken ct, string? jobId = null)
    {
        if (!await _jobLock.WaitAsync(0, ct)) return false;
        var started = DateTimeOffset.Now;
        lock (_gate) _busyWith = name;
        JobInfo job;
        try
        {
            AppLog.Info($"Job started: {name}");
            job = await work(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            job = new JobInfo { Success = false, Message = "Cancelled because the agent is stopping." };
        }
        catch (Exception ex)
        {
            AppLog.Error($"Job failed: {name}", ex);
            job = new JobInfo { Success = false, Message = $"{ex.GetType().Name}: {ex.Message}", Details = [ex.ToString()] };
        }
        finally
        {
            lock (_gate) _busyWith = null;
            _jobLock.Release();
        }
        job.Id = jobId ?? Guid.NewGuid().ToString("N");
        job.Name = name;
        job.Kind = kind;
        job.StartedAt = started;
        job.FinishedAt = DateTimeOffset.Now;
        lock (_gate) _lastJob = job;
        AppLog.Info($"Job finished: {name} - {(job.Success ? "OK" : "FAILED")} - {job.Message}");
        foreach (var line in job.Details) AppLog.Info($"  {line}");
        return true;
    }

    /// <summary>Starts a job in the background for a pipe request; returns the job id or null when busy.</summary>
    private string? StartBackgroundJob(string name, string kind, Func<CancellationToken, Task<JobInfo>> work)
    {
        if (_jobLock.CurrentCount == 0) return null;
        var id = Guid.NewGuid().ToString("N");
        // Start the job with a clean execution context so nothing from the pipe request flows into it.
        using (ExecutionContext.SuppressFlow())
            _ = Task.Run(() => RunJobAsync(name, kind, work, _stopping, id));
        return id;
    }

    private async Task<JobInfo> ScanAsync(CancellationToken ct)
    {
        var result = await Scanner.ScanAsync(_settings, new ScanOptions(), ct);
        if (result.WingetAvailable && !result.Warnings.Any(w => w.StartsWith("winget update check failed", StringComparison.Ordinal)))
            _tracker.Reconcile(result.Updates);
        result.Updates = _tracker.Annotate(result.Updates);
        lock (_gate) _lastScan = result;
        _state.LastScanAt = result.ScannedAt;
        SaveState();
        FileUtil.WriteAllTextAtomic(AppPaths.LastScanFile, JsonSerializer.Serialize(result, Json.Options));
        var c = result.Counts;
        return new JobInfo
        {
            Success = true,
            Message = $"{c.EndOfLife} end-of-life, {c.NearingEndOfLife} nearing end of life, {c.OutdatedPatch} unpatched, {c.UpdatesAvailable} app update(s).",
            Details = result.Warnings,
        };
    }

    private async Task<JobInfo> InstallUpdatesAsync(IReadOnlyCollection<string>? ids, bool scheduled, CancellationToken ct, string trigger = "Manual")
    {
        var winget = WingetClient.TryCreate(isSystem: Platform.IsSystem);
        if (winget is null) return new JobInfo { Success = false, Message = "winget (App Installer) is not available on this device." };
        if (scheduled) trigger = "Scheduled";

        var available = _tracker.Annotate(ExclusionMatcher.Apply(await winget.ListUpgradesAsync(ct), _settings.Settings.ExcludedPackageIds, _settings.PolicyExcludedPackageIds));
        bool Requested(UpdateCandidate u) => ids is null || ids.Contains(u.Id, StringComparer.OrdinalIgnoreCase);
        // "Install all" and scheduled runs skip apps flagged for manual updating; ticking one explicitly retries it.
        var targets = available.Where(u => u.Installable && Requested(u) && (ids is not null || !u.NeedsManualUpdate)).ToList();

        var details = new List<string>();
        var results = new Dictionary<string, UpdateResult>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in targets)
        {
            ct.ThrowIfCancellationRequested();
            var r = await winget.UpgradeAsync(u.Id, u.Name, ct);
            results[u.Id] = r;
            details.Add($"{(r.Success ? "OK  " : "FAIL")} {u.Name} {u.InstalledVersion} -> {u.AvailableVersion}: {r.Message}");
        }
        foreach (var skipped in available.Where(u => Requested(u) && !targets.Contains(u)))
            details.Add($"SKIP {skipped.Name}: " + (skipped.ManagedByWindows ? "updated by Windows"
                : skipped.Excluded ? "excluded"
                : skipped.NeedsManualUpdate ? "needs a manual update (tick it to retry)"
                : skipped.RequiresExplicit ? "pinned/explicit only" : "id truncated by winget"));

        if (scheduled)
        {
            _state.LastUpdateRunAt = DateTimeOffset.Now;
            _state.DeferredUntil = null;
            _state.DeferralsUsed = 0;
            SaveState();
        }

        await ScanAsync(ct);

        // Confirm each result against a fresh list: winget sometimes reports success while the old version remains.
        List<UpdateCandidate> still;
        lock (_gate) still = _lastScan?.Updates ?? [];
        int ok = 0, failed = 0, notApplied = 0;
        var newlyManual = new List<string>();
        foreach (var u in targets)
        {
            var r = results[u.Id];
            var after = still.FirstOrDefault(x => x.Id.Equals(u.Id, StringComparison.OrdinalIgnoreCase));
            string? error = null;
            if (!r.Success) { failed++; error = r.Message; }
            else if (after is not null && VersionUtil.Compare(after.InstalledVersion, u.InstalledVersion) <= 0)
            {
                notApplied++;
                error = $"winget reported success but {u.InstalledVersion} is still installed";
                details.Add($"WARN {u.Name}: {error}. The app may need closing or a restart, or it only updates from its own installer.");
            }

            if (error is null) { ok++; _tracker.RecordSuccess(u, trigger); }
            else if (_tracker.RecordFailure(u, error, trigger)) newlyManual.Add(u.Name);
        }
        foreach (var name in newlyManual)
            details.Add($"MANUAL {name}: failed {UpdateTracker.FailuresBeforeManual} times, so it has been added to the manual updates list and will be skipped by scheduled runs.");

        lock (_gate) if (_lastScan is not null) _lastScan.Updates = _tracker.Annotate(_lastScan.Updates);

        return new JobInfo
        {
            Success = failed == 0 && notApplied == 0,
            Message = targets.Count == 0 ? "No updates to install."
                : $"Updated {ok} of {targets.Count} app(s)" + (failed > 0 ? $", {failed} failed" : "") + (notApplied > 0 ? $", {notApplied} still showing as outdated" : "")
                  + (newlyManual.Count > 0 ? $"; {string.Join(", ", newlyManual)} now need a manual update" : "") + ".",
            Details = details,
        };
    }

    private async Task<JobInfo> RemediateAsync(Finding finding, RemediationAction action, string caller, CancellationToken ct)
    {
        AppLog.Info($"Remediation requested by {caller}: {finding.Id} / {action.Id}");
        var executor = new RemediationExecutor(WingetClient.TryCreate(Platform.IsSystem), Platform.IsSystem);
        var result = await executor.ExecuteAsync(finding, action, s => !s.RequiresUserContext, ct);
        _tracker.RecordEvent(new HistoryEntry
        {
            At = DateTimeOffset.Now, Kind = "Fix", Name = finding.Title, Id = finding.Id,
            From = string.Join(", ", finding.Items.Select(i => i.Version).Distinct()), To = action.Label,
            Success = result.Success, Message = result.Summary, Trigger = caller,
        });
        await ScanAsync(ct);
        return new JobInfo
        {
            Success = result.Success,
            Message = result.Summary,
            Details = result.Steps.Select(s => $"{(s.Success ? "OK  " : "FAIL")} {s.Description}: {s.Message}").ToList(),
            Remediation = result,
        };
    }

    // ---------------- pipe API ----------------

    private Task<PipeResponse> HandleAsync(PipeRequest req, PipeCaller caller)
    {
        try
        {
            switch (req.Command)
            {
                case Commands.Status:
                    return Task.FromResult(PipeResponse.Success(BuildStatus()));

                case Commands.GetScan:
                    ScanResult? scan;
                    lock (_gate) scan = _lastScan?.WithoutInventory();
                    return Task.FromResult(PipeResponse.Success(scan));

                case Commands.Scan:
                    return Task.FromResult(Started(StartBackgroundJob("Scanning", "scan", ScanAsync)));

                case Commands.InstallUpdates:
                {
                    var ids = Payload<InstallUpdatesRequest>(req)?.Ids;
                    if (ids is not null && ids.Any(i => !WingetClient.IsValidId(i))) return Task.FromResult(PipeResponse.Fail("Invalid package id."));
                    return Task.FromResult(Started(StartBackgroundJob("Installing updates", "updates", c => InstallUpdatesAsync(ids, scheduled: false, c, caller.Name))));
                }

                case Commands.Remediate:
                {
                    var r = Payload<RemediateRequest>(req);
                    if (r is null) return Task.FromResult(PipeResponse.Fail("Missing request."));
                    if (!_settings.Settings.AllowUserRemediation && !caller.IsAdmin)
                        return Task.FromResult(PipeResponse.Fail("Your administrator has disabled fixes from this device. Ask IT to remediate it."));
                    Finding? finding;
                    lock (_gate) finding = _lastScan?.Findings.FirstOrDefault(f => f.Id == r.FindingId);
                    var action = finding?.Actions.FirstOrDefault(a => a.Id == r.ActionId);
                    if (finding is null || action is null) return Task.FromResult(PipeResponse.Fail("That issue is no longer present - run a new scan."));
                    return Task.FromResult(Started(StartBackgroundJob($"Fixing {finding.Title}", "remediate", c => RemediateAsync(finding, action, caller.Name, c))));
                }

                case Commands.GetHistory:
                    return Task.FromResult(PipeResponse.Success(_tracker.View()));

                case Commands.ClearManual:
                {
                    var id = Payload<ClearManualRequest>(req)?.Id;
                    if (string.IsNullOrWhiteSpace(id) || !WingetClient.IsValidId(id)) return Task.FromResult(PipeResponse.Fail("Invalid package id."));
                    _tracker.ClearManual(id);
                    lock (_gate) if (_lastScan is not null) _lastScan.Updates = _lastScan.Updates.Select(u => u.Id.Equals(id, StringComparison.OrdinalIgnoreCase) ? u with { NeedsManualUpdate = false, ManualReason = null } : u).ToList();
                    return Task.FromResult(PipeResponse.Success(_tracker.View()));
                }

                case Commands.GetSettings:
                    return Task.FromResult(PipeResponse.Success(BuildSettingsView()));

                case Commands.SetExclusions:
                {
                    if (!_settings.Settings.AllowUserExclusions && !caller.IsAdmin)
                        return Task.FromResult(PipeResponse.Fail("Exclusions are managed by your administrator."));
                    var ids = Payload<ExclusionsRequest>(req)?.Ids ?? [];
                    var clean = ids.Select(i => i.Trim()).Where(i => i.Length is > 0 and <= 128 && i.All(ch => char.IsLetterOrDigit(ch) || ".-_+*".Contains(ch)))
                                   .Distinct(StringComparer.OrdinalIgnoreCase).Take(500).ToList();
                    var raw = SettingsStore.Load(AppPaths.SettingsFile);
                    raw.ExcludedPackageIds = clean;
                    SettingsStore.Save(AppPaths.SettingsFile, raw);
                    _settings = SettingsStore.LoadEffective(AppPaths.SettingsFile);
                    lock (_gate)
                        if (_lastScan is not null)
                            _lastScan.Updates = ExclusionMatcher.Apply(_lastScan.Updates, _settings.Settings.ExcludedPackageIds, _settings.PolicyExcludedPackageIds);
                    AppLog.Info($"Exclusions updated by {caller.Name}: {string.Join(", ", clean)}");
                    return Task.FromResult(PipeResponse.Success(BuildSettingsView()));
                }

                case Commands.SetSchedule:
                {
                    if (_settings.ScheduleLockedByPolicy) return Task.FromResult(PipeResponse.Fail("The update schedule is managed by your administrator."));
                    var sch = Payload<UpdateSchedule>(req);
                    if (sch is null) return Task.FromResult(PipeResponse.Fail("Missing schedule."));
                    if (sch.Validate() is { } err) return Task.FromResult(PipeResponse.Fail(err));
                    var raw = SettingsStore.Load(AppPaths.SettingsFile);
                    raw.Schedule = sch;
                    SettingsStore.Save(AppPaths.SettingsFile, raw);
                    _settings = SettingsStore.LoadEffective(AppPaths.SettingsFile);
                    _state.ScheduleAnchor = DateTimeOffset.Now; // a new schedule should not fire "missed" runs
                    _state.DeferredUntil = null;
                    SaveState();
                    AppLog.Info($"Schedule updated by {caller.Name}.");
                    return Task.FromResult(PipeResponse.Success(BuildSettingsView()));
                }

                case Commands.Defer:
                {
                    var minutes = Math.Clamp(Payload<DeferRequest>(req)?.Minutes ?? 60, 15, 24 * 60);
                    var sch = _settings.Settings.Schedule;
                    if (!_settings.Settings.AllowUserDeferral && !caller.IsAdmin) return Task.FromResult(PipeResponse.Fail("Postponing updates is disabled by your administrator."));
                    if (_state.DeferralsUsed >= sch.MaxDeferrals) return Task.FromResult(PipeResponse.Fail($"Updates have already been postponed {sch.MaxDeferrals} times."));
                    var now = DateTimeOffset.Now;
                    var next = NextUpdateAt(now) ?? now;
                    _state.DeferredUntil = Max(next, now).AddMinutes(minutes);
                    _state.DeferralsUsed++;
                    SaveState();
                    AppLog.Info($"Updates postponed by {caller.Name} until {_state.DeferredUntil}.");
                    return Task.FromResult(PipeResponse.Success(BuildStatus()));
                }

                default:
                    return Task.FromResult(PipeResponse.Fail($"Unknown command '{req.Command}'."));
            }
        }
        catch (Exception ex)
        {
            AppLog.Error($"Pipe command {req.Command} failed", ex);
            return Task.FromResult(PipeResponse.Fail(ex.Message));
        }
    }

    private static PipeResponse Started(string? jobId) =>
        jobId is null ? PipeResponse.Fail("The agent is busy with another task; try again in a moment.") : PipeResponse.Success(new JobStarted(jobId));

    private static T? Payload<T>(PipeRequest req) => req.Payload is { } p ? p.Deserialize<T>(Json.Compact) : default;

    private AgentStatus BuildStatus()
    {
        var now = DateTimeOffset.Now;
        var sch = _settings.Settings.Schedule;
        lock (_gate)
        {
            return new AgentStatus
            {
                Version = AppPaths.Version,
                AvailableVersion = _state.AvailableVersion is { } av && SelfUpdater.IsNewer(av, AppPaths.Version) ? av : null,
                BusyWith = _busyWith,
                LastScanAt = _state.LastScanAt,
                NextScanAt = NextScanAt(now),
                NextUpdateAt = NextUpdateAt(now),
                DeferredUntil = _state.DeferredUntil > now ? _state.DeferredUntil : null,
                CanDefer = _settings.Settings.AllowUserDeferral && _state.DeferralsUsed < sch.MaxDeferrals && sch.Enabled,
                DeferralsLeft = Math.Max(0, sch.MaxDeferrals - _state.DeferralsUsed),
                Counts = _lastScan?.Counts ?? new ScanCounts(),
                LastJob = _lastJob,
                AllowUserExclusions = _settings.Settings.AllowUserExclusions,
                AllowUserRemediation = _settings.Settings.AllowUserRemediation,
                ScheduleLocked = _settings.ScheduleLockedByPolicy,
                NotifyMinutesBefore = sch.NotifyMinutesBefore,
                ManualUpdatesNeeded = _tracker?.FlaggedCount ?? 0,
            };
        }
    }

    private SettingsView BuildSettingsView() => new()
    {
        Schedule = _settings.Settings.Schedule,
        ExcludedPackageIds = _settings.Settings.ExcludedPackageIds,
        PolicyExcludedPackageIds = _settings.PolicyExcludedPackageIds,
        ScheduleLocked = _settings.ScheduleLockedByPolicy,
        AllowUserExclusions = _settings.Settings.AllowUserExclusions,
        AllowUserRemediation = _settings.Settings.AllowUserRemediation,
        AllowUserDeferral = _settings.Settings.AllowUserDeferral,
        ManagedByPolicy = _settings.ManagedByPolicy,
    };

    private void SaveState()
    {
        try { FileUtil.WriteAllTextAtomic(AppPaths.AgentStateFile, JsonSerializer.Serialize(_state, Json.Options)); }
        catch (Exception ex) { AppLog.Warn($"Could not save agent state: {ex.Message}"); }
    }

    private static T? Load<T>(string path) where T : class
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), Json.Options) : null; }
        catch { return null; }
    }
}

/// <summary>
/// Ensures %ProgramData%\PatchSentinel is owned by Administrators and only writable by SYSTEM/Administrators,
/// so a standard user cannot pre-create it and plant rules or settings the SYSTEM service would trust.
/// </summary>
internal static class DataDirSecurity
{
    public static void Prepare(string path)
    {
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        try
        {
            var dir = new DirectoryInfo(path);
            if (dir.Exists)
            {
                var owner = dir.GetAccessControl().GetOwner(typeof(SecurityIdentifier));
                if (owner != admins && owner != system)
                {
                    var quarantine = $"{path}.untrusted-{DateTime.Now:yyyyMMddHHmmss}";
                    Directory.Move(path, quarantine);
                    AppLog.Warn($"{path} was not owned by Administrators/SYSTEM; moved to {quarantine}.");
                    dir = new DirectoryInfo(path);
                }
            }

            var sec = new DirectorySecurity();
            sec.SetOwner(admins);
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));

            if (!dir.Exists) dir.Create(sec);
            else dir.SetAccessControl(sec);
        }
        catch (Exception ex)
        {
            Directory.CreateDirectory(path);
            AppLog.Warn($"Could not secure {path}: {ex.Message}");
        }
    }
}
