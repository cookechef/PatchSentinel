using System.Net;
using System.Text;
using PatchSentinel.Core.Device;

namespace PatchSentinel.Core.Reporting;

public sealed record DeviceRow(string Section, string Field, string Value, CheckStatus? Status = null);

/// <summary>Turns <see cref="DeviceInfo"/> and the build checklist into rows, HTML and spreadsheet sheets.</summary>
public static class DeviceReport
{
    public static List<DeviceRow> Rows(DeviceInfo d)
    {
        var rows = new List<DeviceRow>();
        void Add(string section, string field, string? value, CheckStatus? status = null)
        {
            if (!string.IsNullOrWhiteSpace(value)) rows.Add(new DeviceRow(section, field, value.Trim(), status));
        }

        // Identity
        Add("Device", "Device name", d.ComputerName);
        Add("Device", "Make / model", d.MakeModel);
        if (!string.IsNullOrWhiteSpace(d.ProductName) && d.ProductName != d.Model) Add("Device", "Model number", d.Model);
        Add("Device", "Serial number", d.SerialNumber);
        Add("Device", "Estimated age", d.AgeEstimate ?? "Unknown (processor not recognised)",
            d.CpuReleaseYear is { } y && DateTime.Now.Year - y >= 6 ? CheckStatus.Warn : null);
        Add("Device", "Joined to", d.EntraJoined && (d.DomainJoined || d.PartOfDomain) ? $"Microsoft Entra ID (hybrid) and {d.Domain}"
            : d.EntraJoined ? $"Microsoft Entra ID{(string.IsNullOrEmpty(d.TenantName) ? "" : $" - {d.TenantName}")}"
            : d.PartOfDomain ? $"Domain {d.Domain}" : $"Workgroup ({d.Domain})",
            d.EntraJoined || d.PartOfDomain ? CheckStatus.Pass : CheckStatus.Warn);
        Add("Device", "OU", d.OrganisationalUnit);

        // Hardware
        Add("Hardware", "Processor", $"{d.CpuName}{(d.CpuCores is { } c ? $" ({c} cores / {d.CpuThreads} threads)" : "")}");
        Add("Hardware", "Memory (RAM)", d.RamGB is { } ram ? $"{ram:0.#} GB" + (d.RamModules.Count > 0 ? $" ({string.Join(" + ", d.RamModules.Select(m => $"{m.CapacityGB:0.#} GB"))}{(d.RamModules.FirstOrDefault()?.Speed is > 0 and var s ? $" @ {s} MT/s" : "")})" : "") : null,
            d.RamGB is < 7.5 ? CheckStatus.Warn : null);
        foreach (var disk in d.Disks)
            Add("Hardware", "Disk", $"{disk.Model} - {disk.SizeGB:0} GB {disk.MediaType} {disk.BusType}".Replace("  ", " ") + (disk.Health is { Length: > 0 } h && h != "Healthy" ? $" - health: {h}" : ""),
                disk.Health is { Length: > 0 } hh && hh != "Healthy" ? CheckStatus.Fail : null);
        foreach (var v in d.Volumes)
        {
            var pct = v.SizeGB is > 0 && v.FreeGB is { } f ? f / v.SizeGB.Value * 100 : (double?)null;
            Add("Hardware", $"Drive {v.Name}", $"{v.FreeGB:0.#} GB free of {v.SizeGB:0.#} GB{(pct is { } p ? $" ({p:0}% free)" : "")}",
                pct is < 10 ? CheckStatus.Fail : pct is < 20 ? CheckStatus.Warn : null);
        }
        Add("Hardware", "BIOS", $"{d.BiosVersion}{(string.IsNullOrEmpty(d.BiosDate) ? "" : $" ({d.BiosDate})")}");
        Add("Hardware", "TPM", d.TpmPresent == true ? $"Present{(string.IsNullOrEmpty(d.TpmVersion) ? "" : $", version {d.TpmVersion}")}" : d.TpmPresent == false ? "Not found" : null,
            d.TpmPresent == false ? CheckStatus.Warn : null);
        Add("Hardware", "Secure Boot", d.SecureBoot switch { true => "On", false => "Off", _ => null }, d.SecureBoot == false ? CheckStatus.Warn : null);

        // OS
        var win10 = d.OsCaption?.Contains("Windows 10", StringComparison.OrdinalIgnoreCase) == true;
        Add("Operating system", "Windows", d.OsSummary + (win10 ? " - Windows 10 support ended 14 Oct 2025 unless covered by Extended Security Updates" : ""),
            win10 ? CheckStatus.Fail : null);
        if (win10 && d.Windows11CpuSupported is { } w11)
            Add("Operating system", "Windows 11 upgrade", w11 ? "Processor is supported for Windows 11" : "Processor is NOT supported for Windows 11 - plan a replacement",
                w11 ? CheckStatus.Info : CheckStatus.Warn);
        Add("Operating system", "Edition / architecture", $"{d.OsEdition} {d.OsArchitecture}".Trim());
        Add("Operating system", "Installed", d.OsInstallDate);
        Add("Operating system", "Last restart", FormatDate(d.LastBoot));
        Add("Operating system", "Last Windows Update install", FormatDate(d.LastWindowsUpdate) + (d.RebootPending ? " (restart pending)" : ""), d.RebootPending ? CheckStatus.Warn : null);
        if (d.RecentHotfixes.Count > 0) Add("Operating system", "Recent updates", string.Join(", ", d.RecentHotfixes.Select(h => $"{h.Id} ({h.InstalledOn})")));

        // Network
        Add("Network", "Public IP", d.PublicIp);
        foreach (var n in d.Network)
        {
            Add("Network", n.Alias ?? "Adapter", $"{string.Join(", ", n.IPv4)}{(n.Dhcp ? " (DHCP)" : " (static IP)")} - gateway {string.Join(", ", n.Gateway)} - DNS {string.Join(", ", n.Dns)}{(n.StaticDnsToFix ? " (static DNS)" : n.StaticDns ? " (DNS set by VPN / secure-access client)" : "")} - MAC {n.Mac}",
                n.StaticDnsToFix ? CheckStatus.Warn : null);
        }

        // Security
        foreach (var av in d.Antivirus)
            Add("Security", "Antivirus", $"{av.Name} - {(av.Enabled == true ? "on" : "off")}{(av.UpToDate == false ? ", definitions out of date" : "")}",
                av.Enabled == true && av.UpToDate != false ? CheckStatus.Pass : CheckStatus.Warn);
        if (d.Antivirus.Count == 0) Add("Security", "Antivirus", "None reported by Windows Security", CheckStatus.Fail);
        if (d.Defender is { } def)
            Add("Security", "Microsoft Defender", $"{def.RunningMode} mode, real-time protection {(def.RealTimeProtection == true ? "on" : "off")}, signatures {def.SignaturesUpdated}");
        foreach (var fw in d.FirewallProducts) Add("Security", "Firewall product", $"{fw.Name} - {(fw.Enabled == true ? "on" : "off")}");
        if (d.FirewallProfiles.Count > 0)
        {
            var off = d.FirewallProfiles.Where(p => !p.Enabled).Select(p => p.Name).ToList();
            Add("Security", "Windows Firewall", string.Join(", ", d.FirewallProfiles.Select(p => $"{p.Name} {(p.Enabled ? "on" : "off")}")),
                off.Count == 0 ? CheckStatus.Pass : d.FirewallProducts.Any(f => f.Enabled == true) ? CheckStatus.Info : CheckStatus.Fail);
        }
        foreach (var b in d.BitLocker)
        {
            var on = string.Equals(b.Protection, "On", StringComparison.OrdinalIgnoreCase);
            Add("Security", $"BitLocker {b.Drive}", $"Protection {b.Protection}{(string.IsNullOrEmpty(b.VolumeStatus) ? "" : $", {b.VolumeStatus}")}{(b.Method is { Length: > 0 } m && m != "None" ? $", {m}" : "")}{(b.Protectors.Count > 0 ? $", protectors: {string.Join(", ", b.Protectors)}" : "")}",
                on ? CheckStatus.Pass : b.IsOsVolume ? CheckStatus.Fail : CheckStatus.Warn);
        }
        if (d.BitLocker.Count == 0) Add("Security", "BitLocker", "Status not available (Windows Home or no permission)", CheckStatus.Warn);
        var admins = d.LocalAccounts.Where(a => a.Enabled && a.IsAdmin).Select(a => a.Name).ToList();
        Add("Security", "Enabled local accounts", string.Join(", ", d.LocalAccounts.Where(a => a.Enabled).Select(a => a.Name + (a.IsAdmin ? " (admin)" : ""))) is { Length: > 0 } la ? la : "None",
            d.LocalAccounts.Any(a => a.Enabled && !a.BuiltIn) ? CheckStatus.Warn : null);

        // Drivers / manufacturer tools
        Add("Drivers and tools", "Driver problems", d.ProblemDevices.Count == 0 ? "None" : string.Join(", ", d.ProblemDevices.Select(p => $"{p.Name} (code {p.ErrorCode})")),
            d.ProblemDevices.Count == 0 ? CheckStatus.Pass : CheckStatus.Warn);
        foreach (var t in d.OemTools.Where(t => t.Applicable || t.Installed))
        {
            var status = !t.Installed ? CheckStatus.Fail : t.LastActivity is null ? CheckStatus.Warn
                : (DateTimeOffset.Now - t.LastActivity.Value).TotalDays > 90 ? CheckStatus.Warn : CheckStatus.Pass;
            Add("Drivers and tools", t.Tool,
                !t.Installed ? $"Not installed - {t.DownloadUrl}"
                : $"{t.InstalledName}{(string.IsNullOrEmpty(t.InstalledVersion) ? "" : $" {t.InstalledVersion}")}, " +
                  (t.LastActivity is { } la2 ? $"last ran {la2:dd MMM yyyy}" : "no sign it has ever run"),
                status);
        }
        return rows;
    }

    private static string? FormatDate(string? s) => DateTime.TryParse(s, out var d) ? d.ToString(d.TimeOfDay == TimeSpan.Zero ? "dd MMM yyyy" : "dd MMM yyyy HH:mm") : s;

    public static string StatusText(CheckStatus s) => s switch
    {
        CheckStatus.Pass => "OK",
        CheckStatus.Warn => "Check",
        CheckStatus.Fail => "Action needed",
        CheckStatus.Manual => "Manual check",
        _ => "Info",
    };

    public static CellStyle Style(CheckStatus? s) => s switch
    {
        CheckStatus.Pass => CellStyle.Green,
        CheckStatus.Warn => CellStyle.Amber,
        CheckStatus.Fail => CellStyle.Red,
        CheckStatus.Info or CheckStatus.Manual => CellStyle.Blue,
        _ => CellStyle.Normal,
    };

    // ---------------- spreadsheet ----------------

    public static XSheet DeviceSheet(DeviceInfo d)
    {
        var sheet = new XSheet { Name = "Device", Columns = [("Section", 18), ("Item", 30), ("Value", 90), ("Status", 14)], AutoFilter = false };
        foreach (var r in Rows(d))
            sheet.Rows.Add([new XCell(r.Section), new XCell(r.Field), new XCell(r.Value, CellStyle.Wrap), r.Status is { } s ? new XCell(StatusText(s), Style(s)) : new XCell("")]);
        return sheet;
    }

    public static XSheet ChecklistSheet(IReadOnlyList<BuildCheckResult> checks, BuildHandover? handover = null)
    {
        var sheet = new XSheet
        {
            Name = "Build checklist",
            Columns = [("Step", 6), ("Check", 55), ("Status", 15), ("Detail", 80), ("Sign-off", 14), ("Signed off by", 18), ("When", 17), ("Note", 40)],
        };
        foreach (var c in checks)
        {
            var so = c.Signoff;
            sheet.Rows.Add([new XCell(c.Step.ToString()), new XCell(c.Title, CellStyle.Wrap), new XCell(StatusText(c.Status), Style(c.Status)), new XCell(c.Detail, CellStyle.Wrap),
                new XCell(so is null ? "" : so.Status == SignoffStatus.Checked ? "Checked" : "Not required", so is null ? CellStyle.Normal : CellStyle.Green),
                new XCell(so?.By), new XCell(so?.At.LocalDateTime.ToString("yyyy-MM-dd HH:mm")), new XCell(so?.Note, CellStyle.Wrap)]);
        }
        if (handover is not null)
        {
            sheet.Rows.Add([new XCell(""), new XCell(""), new XCell(""), new XCell(""), new XCell(""), new XCell(""), new XCell(""), new XCell("")]);
            sheet.Rows.Add([new XCell(""), new XCell("Build signed off", CellStyle.Section), new XCell(handover.StepsOutstanding == 0 ? "Complete" : $"{handover.StepsOutstanding} outstanding", handover.StepsOutstanding == 0 ? CellStyle.Green : CellStyle.Amber),
                new XCell(handover.Outstanding.Count > 0 ? "Outstanding: " + string.Join("; ", handover.Outstanding) : "All steps OK or signed off.", CellStyle.Wrap),
                new XCell("Handover"), new XCell(handover.By), new XCell(handover.At.LocalDateTime.ToString("yyyy-MM-dd HH:mm")), new XCell(handover.Note, CellStyle.Wrap)]);
        }
        return sheet;
    }

    // ---------------- HTML ----------------

    public const string Css = """
.dv{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:14px;margin-top:10px}
.dvc{background:#fff;border:1px solid #eaecf0;border-radius:10px;padding:12px 14px}
.dvc h3{margin:0 0 8px;font-size:14px}.dvc table{border:0;font-size:13px}.dvc td{border-bottom:1px solid #f2f4f7;padding:5px 6px}
.dvc td:first-child{color:#667085;width:38%}
.st{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;white-space:nowrap;margin-left:6px}
.st-Pass{background:#dcfae6;color:#067647}.st-Warn{background:#fef0c7;color:#93370d}.st-Fail{background:#fee4e2;color:#b42318}
.st-Info,.st-Manual{background:#eef4ff;color:#3538cd}
""";

    public static string Html(DeviceInfo d, IReadOnlyList<BuildCheckResult> checks, BuildHandover? handover = null)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        static string Badge(CheckStatus? s) => s is { } v ? $"<span class=\"st st-{v}\">{E(StatusText(v))}</span>" : "";
        var sb = new StringBuilder();
        sb.Append("<h2>Device information</h2><div class=\"dv\">");
        foreach (var g in Rows(d).GroupBy(r => r.Section))
        {
            sb.Append($"<div class=\"dvc\"><h3>{E(g.Key)}</h3><table>");
            foreach (var r in g) sb.Append($"<tr><td>{E(r.Field)}</td><td>{E(r.Value)}{Badge(r.Status)}</td></tr>");
            sb.Append("</table></div>");
        }
        sb.Append("</div>");

        if (checks.Count > 0)
        {
            var fail = checks.Count(c => c.Status == CheckStatus.Fail);
            var warn = checks.Count(c => c.Status == CheckStatus.Warn);
            sb.Append($"<h2>Device build checklist <span class=\"muted\" style=\"font-size:13px;font-weight:400\">{fail} need action, {warn} to check</span></h2>");
            sb.Append(handover is null
                ? "<p class=\"small muted\">The build has not been signed off.</p>"
                : $"<p><b>{E(handover.Text)}</b>{(handover.Outstanding.Count > 0 ? $"<br><span class=\"small muted\">Outstanding: {E(string.Join("; ", handover.Outstanding))}</span>" : "")}</p>");
            sb.Append("<table><tr><th>Step</th><th>Check</th><th>Status</th><th>Detail</th><th>Sign-off</th></tr>");
            foreach (var c in checks)
                sb.Append($"<tr><td>{c.Step}</td><td>{E(c.Title)}</td><td>{Badge(c.Status)}</td><td class=\"small\">{E(c.Detail)}</td><td class=\"small\">{E(c.Signoff?.Text)}</td></tr>");
            sb.Append("</table>");
        }
        return sb.ToString();
    }

    public static string ToCsv(DeviceInfo d, IReadOnlyList<BuildCheckResult> checks, BuildHandover? handover = null)
    {
        static string Q(string? v) => "\"" + (v ?? "").Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder("Section,Item,Value,Status,Sign-off\r\n");
        foreach (var r in Rows(d)) sb.Append($"{Q(r.Section)},{Q(r.Field)},{Q(r.Value)},{Q(r.Status is { } s ? StatusText(s) : "")}\r\n");
        foreach (var c in checks) sb.Append($"{Q("Build checklist")},{Q($"{c.Step}. {c.Title}")},{Q(c.Detail)},{Q(StatusText(c.Status))},{Q(c.Signoff?.Text)}\r\n");
        if (handover is not null) sb.Append($"{Q("Build checklist")},{Q("Build signed off")},{Q(string.Join("; ", handover.Outstanding))},{Q(handover.StepsOutstanding == 0 ? "Complete" : $"{handover.StepsOutstanding} outstanding")},{Q(handover.Text)}\r\n");
        return sb.ToString();
    }
}
