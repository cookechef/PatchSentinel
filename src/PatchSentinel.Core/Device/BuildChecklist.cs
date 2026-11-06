using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Device;

/// <summary>One step of the device build checklist (from the rules catalogue, so it can be edited on GitHub).</summary>
public sealed class BuildCheckRule
{
    public int Step { get; set; }
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    /// <summary>appsAbsent, appsPresentAny, appsPresentAll, builtin, manual.</summary>
    public string Type { get; set; } = "manual";
    /// <summary>For builtin checks: windowsUpdate, problemDevices, bios, intelDsa, oemTools, antivirus, joined, ou, bitlocker, localAccounts, staticDns.</summary>
    public string? Check { get; set; }
    /// <summary>App name regex fragments (appsAbsent / appsPresentAny / antivirus).</summary>
    public List<string> Patterns { get; set; } = [];
    /// <summary>appsPresentAll: each group needs at least one match.</summary>
    public List<AppGroup> Groups { get; set; } = [];
    /// <summary>Status when an app check is not met: Fail (default), Warn or Info (for "if required" steps).</summary>
    public CheckStatus WhenMissing { get; set; } = CheckStatus.Fail;
    public string? Hint { get; set; }
    /// <summary>Buttons for this step (install or run a tool, open a portal...).</summary>
    public List<BuildAction> Actions { get; set; } = [];
}

public sealed class AppGroup
{
    public string Label { get; set; } = "";
    public List<string> Patterns { get; set; } = [];
}

public static class BuildChecklist
{
    public static List<BuildCheckResult> Evaluate(IReadOnlyList<BuildCheckRule> rules, DeviceInfo d, IReadOnlyList<InstalledItem> inventory, DateOnly today,
        IReadOnlyDictionary<string, string>? links = null)
    {
        var apps = inventory.Where(i => i.Source == ItemSource.Registry && !i.IsSystemComponent).ToList();
        var results = new List<BuildCheckResult>();
        foreach (var rule in rules.OrderBy(r => r.Step))
        {
            BuildCheckResult r;
            try { r = EvaluateOne(rule, d, apps, today); }
            catch (Exception ex) { r = new BuildCheckResult { Status = CheckStatus.Warn, Detail = $"Could not check: {ex.Message}" }; }
            r.Step = rule.Step;
            r.Id = rule.Id;
            r.Title = rule.Title;
            if (!string.IsNullOrEmpty(rule.Hint) && r.Status is CheckStatus.Fail or CheckStatus.Warn) r.Detail = $"{r.Detail} {rule.Hint}".Trim();
            r.Actions = BuildActions.Visible(rule, r, d, apps, links ?? new Dictionary<string, string>());
            results.Add(r);
        }
        return results;
    }

    private static Regex Rx(IEnumerable<string> patterns) =>
        new(@"(?<![A-Za-z0-9])(?:" + string.Join("|", patterns) + ")", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250));

    private static List<InstalledItem> Find(IEnumerable<InstalledItem> apps, IEnumerable<string> patterns)
    {
        var list = patterns.ToList();
        if (list.Count == 0) return [];
        var rx = Rx(list);
        return apps.Where(a => rx.IsMatch(a.Name)).GroupBy(a => a.Name).Select(g => g.First()).ToList();
    }

    private static string Names(IEnumerable<InstalledItem> items) => string.Join(", ", items.Select(i => string.IsNullOrEmpty(i.Version) ? i.Name : $"{i.Name} {i.Version}").Take(6));

    private static BuildCheckResult R(CheckStatus s, string detail) => new() { Status = s, Detail = detail };

    private static BuildCheckResult EvaluateOne(BuildCheckRule rule, DeviceInfo d, List<InstalledItem> apps, DateOnly today)
    {
        switch (rule.Type)
        {
            case "manual":
                return R(CheckStatus.Manual, "Check by hand.");

            case "appsAbsent":
            {
                var found = Find(apps, rule.Patterns);
                return found.Count == 0 ? R(CheckStatus.Pass, "None found.") : R(CheckStatus.Fail, $"Still installed: {Names(found)}.");
            }

            case "appsPresentAny":
            {
                var found = Find(apps, rule.Patterns);
                return found.Count > 0 ? R(CheckStatus.Pass, $"Installed: {Names(found)}.")
                    : R(rule.WhenMissing, rule.WhenMissing == CheckStatus.Info ? "None installed (only needed if required)." : "Not installed.");
            }

            case "appsPresentAll":
            {
                var have = new List<string>();
                var missing = new List<string>();
                foreach (var g in rule.Groups)
                {
                    var found = Find(apps, g.Patterns);
                    if (found.Count > 0) have.Add(found[0].Name); else missing.Add(g.Label);
                }
                return missing.Count == 0 ? R(CheckStatus.Pass, $"Installed: {string.Join(", ", have)}.")
                    : R(rule.WhenMissing, $"Missing: {string.Join(", ", missing)}.{(have.Count > 0 ? $" Installed: {string.Join(", ", have)}." : "")}");
            }

            case "builtin":
                return Builtin(rule, d, apps, today);
        }
        return R(CheckStatus.Info, "Unknown check type.");
    }

    private static BuildCheckResult Builtin(BuildCheckRule rule, DeviceInfo d, List<InstalledItem> apps, DateOnly today)
    {
        switch (rule.Check)
        {
            case "windowsUpdate":
            {
                var version = $"{d.OsSummary}.";
                if (!DateTime.TryParse(d.LastWindowsUpdate, out var last))
                    return R(CheckStatus.Warn, $"{version} Could not read when Windows Update last installed updates.");
                var days = (int)(DateTime.Now - last).TotalDays;
                var status = days <= 35 ? CheckStatus.Pass : days <= 60 ? CheckStatus.Warn : CheckStatus.Fail;
                if (d.RebootPending && status == CheckStatus.Pass) status = CheckStatus.Warn;
                return R(status, $"{version} Last updates installed {last:dd MMM yyyy} ({days} days ago).{(d.RebootPending ? " A restart is pending to finish updates." : "")}");
            }

            case "problemDevices":
                return d.ProblemDevices.Count == 0
                    ? R(CheckStatus.Pass, $"All devices have working drivers. {d.MakeModel}, {d.CpuName}, {d.RamGB} GB RAM.")
                    : R(CheckStatus.Warn, $"{d.ProblemDevices.Count} device(s) have a driver problem: {string.Join(", ", d.ProblemDevices.Take(5).Select(p => $"{p.Name} (code {p.ErrorCode})"))}.");

            case "bios":
            {
                var detail = $"BIOS {d.BiosVersion}, dated {d.BiosDate ?? "unknown"}.";
                if (DateOnly.TryParse(d.BiosDate, out var bd) && today.DayNumber - bd.DayNumber > 730)
                    return R(CheckStatus.Warn, $"{detail} Over two years old - check the manufacturer's support site for a newer BIOS/firmware.");
                return R(CheckStatus.Info, detail);
            }

            case "intelDsa":
            {
                var t = d.OemTools.FirstOrDefault(o => o.Vendor == "Intel");
                if (t is null || !t.Applicable) return R(CheckStatus.Info, "Not an Intel processor - not needed.");
                return ToolResult(t, today);
            }

            case "oemTools":
            {
                var tools = d.OemTools.Where(o => o.Vendor != "Intel" && o.Applicable).ToList();
                if (tools.Count == 0) return R(CheckStatus.Info, $"No manufacturer update tool is expected for {d.Manufacturer ?? "this manufacturer"} (use Windows Update).");
                return ToolResult(tools[0], today);
            }

            case "antivirus":
            {
                // Report what is protecting the device. Any active antivirus passes (Bitdefender, Microsoft Defender, SentinelOne...).
                static string Friendly(string? n) => n is null ? "" : n.Replace("Windows Defender", "Microsoft Defender");
                var active = d.Antivirus.Where(a => a.Enabled == true).Select(a => Friendly(a.Name) + (a.UpToDate == false ? " (definitions out of date)" : "")).Distinct().ToList();
                var inactive = d.Antivirus.Where(a => a.Enabled != true).Select(a => Friendly(a.Name)).Distinct().ToList();
                var installed = Find(apps, rule.Patterns).Select(a => a.Name).ToList();
                if (active.Count > 0)
                    return R(d.Antivirus.Any(a => a.Enabled == true && a.UpToDate == false) ? CheckStatus.Warn : CheckStatus.Pass,
                        $"Active: {string.Join(", ", active)}.{(inactive.Count > 0 ? $" Also registered but not active: {string.Join(", ", inactive)}." : "")}");
                if (installed.Count > 0)
                    return R(CheckStatus.Pass, $"Installed: {string.Join(", ", installed)}. (Windows Security does not report antivirus status on this edition of Windows.)");
                return R(CheckStatus.Fail, inactive.Count > 0 ? $"Antivirus is registered but switched off: {string.Join(", ", inactive)}." : "No antivirus is reported as active.");
            }

            case "joined":
                if (d.EntraJoined || d.DomainJoined || d.PartOfDomain)
                    return R(CheckStatus.Pass, string.Join("; ", new[]
                    {
                        d.EntraJoined ? $"Microsoft Entra joined{(string.IsNullOrEmpty(d.TenantName) ? "" : $" ({d.TenantName})")}" : null,
                        d.DomainJoined || d.PartOfDomain ? $"Domain joined ({d.Domain})" : null,
                    }.Where(s => s is not null)) + ".");
                return R(CheckStatus.Fail, $"Not joined to a domain or Microsoft Entra ID (workgroup '{d.Domain}').");

            case "ou":
                return !string.IsNullOrWhiteSpace(d.OrganisationalUnit)
                    ? R(CheckStatus.Info, $"Computer object: {d.OrganisationalUnit}. Check this is the right OU.")
                    : R(CheckStatus.Manual, d.EntraJoined ? "Entra joined - check the device is in the right group in Entra / Intune." : "No OU recorded yet (appears after Group Policy has applied).");

            case "bitlocker":
            {
                var osVol = d.BitLocker.FirstOrDefault(b => b.IsOsVolume) ?? d.BitLocker.FirstOrDefault(b => string.Equals(b.Drive, "C:", StringComparison.OrdinalIgnoreCase));
                if (osVol is null) return R(CheckStatus.Warn, "BitLocker status could not be read (not available on Windows Home, or no permission).");
                var on = string.Equals(osVol.Protection, "On", StringComparison.OrdinalIgnoreCase);
                var detail = $"{osVol.Drive} protection {osVol.Protection}{(string.IsNullOrEmpty(osVol.VolumeStatus) ? "" : $", {osVol.VolumeStatus}")}" +
                             $"{(osVol.Protectors.Count > 0 ? $", key protectors: {string.Join(", ", osVol.Protectors)}" : "")}.";
                return on ? R(CheckStatus.Pass, detail + " Confirm the recovery key is saved in IT Glue or the agreed location.")
                          : R(CheckStatus.Fail, detail + " BitLocker is not protecting the system drive.");
            }

            case "localAccounts":
            {
                var enabled = d.LocalAccounts.Where(a => a.Enabled && !a.BuiltIn).ToList();
                if (enabled.Count == 0) return R(CheckStatus.Pass, "No enabled local user accounts apart from the built-in ones.");
                return R(CheckStatus.Warn, $"Enabled local account(s): {string.Join(", ", enabled.Select(a => a.Name + (a.IsAdmin ? " (administrator)" : "")))}. " +
                                          "Disable the generic setup account (net user <name> /active:no) if it is one of these.");
            }

            case "staticDns":
            {
                var fix = d.Network.Where(n => n.StaticDnsToFix).ToList();
                var ignored = d.Network.Where(n => n.StaticDns && n.StaticDnsExpected).ToList();
                var note = ignored.Count == 0 ? "" :
                    $" Ignored {string.Join("; ", ignored.Select(n => $"{n.Alias} ({string.Join(", ", n.Dns)})"))} - set by a VPN / secure-access client or a local DNS resolver, which is expected.";
                return fix.Count == 0
                    ? R(CheckStatus.Pass, (ignored.Count == 0 ? "No static DNS: DNS servers come from DHCP on all connected adapters." : "No static DNS on the network adapters.") + note)
                    : R(CheckStatus.Fail, $"Static DNS set on: {string.Join("; ", fix.Select(n => $"{n.Alias} ({string.Join(", ", n.Dns)})"))}.{note}");
            }
        }
        return R(CheckStatus.Info, $"Unknown built-in check '{rule.Check}'.");
    }

    private static BuildCheckResult ToolResult(OemToolStatus t, DateOnly today)
    {
        if (!t.Installed) return R(CheckStatus.Fail, $"{t.Tool} is not installed. Download: {t.DownloadUrl}");
        if (t.LastActivity is null) return R(CheckStatus.Warn, $"{t.InstalledName} is installed but there is no sign it has ever been run. Open it and install the recommended updates.");
        var days = today.DayNumber - DateOnly.FromDateTime(t.LastActivity.Value.LocalDateTime).DayNumber;
        return days > 90
            ? R(CheckStatus.Warn, $"{t.InstalledName} last ran {t.LastActivity:dd MMM yyyy} ({days} days ago). Run it again for current drivers.")
            : R(CheckStatus.Pass, $"{t.InstalledName} installed, last ran {t.LastActivity:dd MMM yyyy}.");
    }
}
