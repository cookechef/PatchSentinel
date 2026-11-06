using System.IO.Compression;
using System.Net;
using System.Text;
using PatchSentinel.Core.Rules;

namespace PatchSentinel.Core.Reporting;

/// <summary>Exports the installed-software list as CSV, HTML or Excel (.xlsx, written directly as Open XML).</summary>
public static class InventoryExporter
{
    private static readonly string[] Headers =
    [
        "Computer", "Name", "Version", "Publisher", "Install date", "Size (MB)", "Installed for", "Architecture",
        "Category", "Concern", "Purpose", "Security advisory", "Install location", "System component",
        "MSI product code", "Uninstall command", "Quiet uninstall command", "Registry key",
    ];

    private static IEnumerable<InstalledItem> Ordered(IEnumerable<InstalledItem> items) =>
        items.Where(i => i.Source == ItemSource.Registry)
             .OrderByDescending(i => i.Classification?.Concern ?? (Concern)(-1))
             .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase);

    private static string?[] Row(InstalledItem i, string computer) =>
    [
        computer, i.Name, i.Version, i.Publisher, i.InstallDate?.ToString("yyyy-MM-dd"), i.SizeMB?.ToString("0.#"),
        i.Scope == InstallScope.Machine ? "All users" : "User", i.Architecture,
        i.Classification?.Category, i.Classification is { } c ? ConcernText(c.Concern) : "", i.Classification?.Purpose, i.Classification?.Advisory,
        i.InstallLocation, i.IsSystemComponent ? "Yes" : "No", i.ProductCode, i.UninstallString, i.QuietUninstallString, i.RegistryKey,
    ];

    public static string ConcernText(Concern c) => c switch
    {
        Concern.High => "High - investigate",
        Concern.Review => "Review",
        _ => "Info",
    };

    // ---------------- CSV ----------------

    public static string ToCsv(IEnumerable<InstalledItem> items, string computer, Device.DeviceInfo? device = null)
    {
        if (device is not null) computer = $"{computer}{(string.IsNullOrEmpty(device.SerialNumber) ? "" : $" ({device.SerialNumber})")}";
        static string Q(string? v)
        {
            v ??= "";
            if (v.Length > 0 && "=+-@".Contains(v[0])) v = "'" + v; // stop spreadsheet formula injection
            return "\"" + v.Replace("\"", "\"\"") + "\"";
        }
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', Headers.Select(Q)));
        foreach (var i in Ordered(items)) sb.AppendLine(string.Join(',', Row(i, computer).Select(Q)));
        return sb.ToString();
    }

    // ---------------- HTML ----------------

    public static string ToHtml(IEnumerable<InstalledItem> items, string computer,
        Device.DeviceInfo? device = null, IReadOnlyList<Device.BuildCheckResult>? checks = null)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        var list = Ordered(items).ToList();
        var review = list.Where(i => i.Classification?.Concern is Concern.Review or Concern.High).ToList();
        var sb = new StringBuilder();
        sb.Append($$"""
<!DOCTYPE html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Installed software - {{E(computer)}}</title>
<style>
:root{--ink:#1d2939;--muted:#667085;--line:#eaecf0;--high:#b42318;--review:#b54708}
*{box-sizing:border-box}body{font-family:"Segoe UI",system-ui,sans-serif;color:var(--ink);margin:0;background:#f9fafb}
main{max-width:1280px;margin:0 auto;padding:28px 22px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.muted{color:var(--muted)}input{font:inherit;padding:7px 10px;border:1px solid #d0d5dd;border-radius:8px;width:320px;margin:14px 0}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{background:#f2f4f7;position:sticky;top:0}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.High{background:#fee4e2;color:var(--high)}.Review{background:#fef0c7;color:var(--review)}.Info{background:#eef4ff;color:#3538cd}
.small{font-size:12px}.adv{max-width:420px}
@media print{input{display:none}body{background:#fff}th{position:static} }
{{DeviceReport.Css}}
</style></head><body><main>
<h1>{{(device is null ? "Installed software" : "Device and software report")}}</h1>
<div class="muted">{{E(computer)}} &middot; {{list.Count}} apps &middot; exported {{DateTime.Now:dd MMM yyyy HH:mm}} by PatchSentinel {{E(AppPaths.Version)}}</div>
""");
        if (device is not null) sb.Append(DeviceReport.Html(device, checks ?? []));

        if (review.Count > 0)
        {
            sb.Append($"<h2>Needs a security review ({review.Count})</h2><table><tr><th>Concern</th><th>Application</th><th>Version</th><th>Category</th><th>Advisory</th></tr>");
            foreach (var i in review)
                sb.Append($"<tr><td><span class=\"badge {i.Classification!.Concern}\">{E(ConcernText(i.Classification.Concern))}</span></td><td><b>{E(i.Name)}</b><div class=\"small muted\">{E(i.Publisher)}</div></td>" +
                          $"<td>{E(i.Version)}</td><td>{E(i.Classification.Category)}</td><td class=\"small adv\">{E(i.Classification.Advisory)}</td></tr>");
            sb.Append("</table>");
        }

        sb.Append("<h2>All installed apps</h2><input id=\"q\" placeholder=\"Filter by name, publisher or category...\" oninput=\"f()\">");
        sb.Append("<table id=\"t\"><tr><th>Application</th><th>Version</th><th>Publisher</th><th>Installed</th><th>Size (MB)</th><th>For</th><th>Category</th><th>Purpose / advisory</th></tr>");
        foreach (var i in list)
        {
            var c = i.Classification;
            sb.Append($"<tr><td>{E(i.Name)}</td><td>{E(i.Version)}</td><td>{E(i.Publisher)}</td><td>{E(i.InstallDate?.ToString("dd MMM yyyy"))}</td>" +
                      $"<td>{E(i.SizeMB?.ToString("0.#"))}</td><td>{(i.Scope == InstallScope.Machine ? "All users" : "User")}</td>" +
                      $"<td>{(c is null ? "" : $"<span class=\"badge {c.Concern}\">{E(c.Category)}</span>")}</td>" +
                      $"<td class=\"small adv\">{(c is null ? "" : E(c.Concern == Concern.Info ? c.Purpose : c.Advisory))}</td></tr>");
        }
        sb.Append("""
</table>
<p class="small muted">Categories and advisories come from the PatchSentinel rules catalogue. They describe what this kind of software can do; whether it is appropriate depends on your organisation's policy.</p>
<script>function f(){var q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#t tr').forEach(function(r,i){if(i)r.style.display=r.textContent.toLowerCase().indexOf(q)>=0?'':'none'})}</script>
</main></body></html>
""");
        return sb.ToString();
    }

    // ---------------- Excel (.xlsx) ----------------

    public static void WriteXlsx(IEnumerable<InstalledItem> items, string computer, Stream output,
        Device.DeviceInfo? device = null, IReadOnlyList<Device.BuildCheckResult>? checks = null)
    {
        var widths = new[] { 16, 42, 16, 26, 12, 10, 12, 8, 30, 16, 40, 60, 40, 10, 40, 50, 50, 60 };
        var apps = new XSheet { Name = "Installed apps", Columns = Headers.Select((h, i) => (h, widths[i])).ToList() };
        foreach (var i in Ordered(items))
        {
            var v = Row(i, computer);
            var cells = new XCell[v.Length];
            for (var c = 0; c < v.Length; c++)
                cells[c] = c switch
                {
                    5 when i.SizeMB is { } mb => new XCell(null, CellStyle.Number, mb),
                    9 => new XCell(v[c], i.Classification?.Concern switch { Concern.High => CellStyle.Red, Concern.Review => CellStyle.Amber, _ => CellStyle.Normal }),
                    10 or 11 => new XCell(v[c], CellStyle.Wrap),
                    _ => new XCell(v[c]),
                };
            apps.Rows.Add(cells);
        }

        var sheets = new List<XSheet>();
        if (device is not null) sheets.Add(DeviceReport.DeviceSheet(device));
        if (checks is { Count: > 0 }) sheets.Add(DeviceReport.ChecklistSheet(checks));
        sheets.Add(apps);
        WorkbookWriter.Write(output, sheets, $"PatchSentinel - {computer}");
    }
}
