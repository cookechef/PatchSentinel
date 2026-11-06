using System.Net;
using System.Text;
using PatchSentinel.Core.Browsers;
using PatchSentinel.Core.Rules;

namespace PatchSentinel.Core.Reporting;

/// <summary>Exports the browser extension list as CSV, HTML or an Excel sheet.</summary>
public static class ExtensionExporter
{
    private static readonly string[] Headers =
    [
        "Computer", "Browser", "User", "Profile", "Extension", "Version", "Latest version", "Status", "Concern", "Enabled",
        "Installed from", "Manifest", "Access", "Advice", "Installed", "Extension ID", "Store page",
    ];

    private static readonly int[] Widths = [16, 16, 14, 14, 36, 12, 12, 26, 16, 8, 16, 9, 34, 70, 12, 36, 50];

    public static IEnumerable<BrowserExtension> Ordered(IEnumerable<BrowserExtension> list) =>
        list.OrderByDescending(e => e.Concern).ThenBy(e => e.BrowserName).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase);

    private static string?[] Row(BrowserExtension e, string computer) =>
    [
        computer, e.BrowserName, e.UserName, e.Profile, e.Name, e.Version, e.LatestVersion, e.StatusText,
        InventoryExporter.ConcernText(e.Concern), e.Enabled ? "Yes" : "No", e.InstallSource,
        e.ManifestVersion is { } mv ? $"V{mv}" : "", e.AccessText, e.Advice, e.InstallDate?.ToString("yyyy-MM-dd"), e.Id, e.StoreUrl,
    ];

    public static string ToCsv(IEnumerable<BrowserExtension> list, string computer)
    {
        static string Q(string? v)
        {
            v ??= "";
            if (v.Length > 0 && "=+-@".Contains(v[0])) v = "'" + v;
            return "\"" + v.Replace("\"", "\"\"") + "\"";
        }
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', Headers.Select(Q)));
        foreach (var e in Ordered(list)) sb.AppendLine(string.Join(',', Row(e, computer).Select(Q)));
        return sb.ToString();
    }

    public static XSheet Sheet(IEnumerable<BrowserExtension> list, string computer)
    {
        var sheet = new XSheet { Name = "Browser extensions", Columns = Headers.Select((h, i) => (h, Widths[i])).ToList() };
        foreach (var e in Ordered(list))
        {
            var v = Row(e, computer);
            var style = e.Concern switch { Concern.High => CellStyle.Red, Concern.Review => CellStyle.Amber, _ => e.Status == ExtensionStatus.UpToDate ? CellStyle.Green : CellStyle.Normal };
            sheet.Rows.Add(v.Select((t, c) => c switch
            {
                7 or 8 => new XCell(t, style),
                13 => new XCell(t, CellStyle.Wrap),
                _ => new XCell(t),
            }).ToArray());
        }
        return sheet;
    }

    public static void WriteXlsx(IEnumerable<BrowserExtension> list, string computer, Stream output) =>
        WorkbookWriter.Write(output, [Sheet(list, computer)], $"Browser extensions - {computer}");

    /// <summary>A table fragment for the scan and device reports (uses the badge classes from those reports).</summary>
    public static string HtmlSection(IReadOnlyCollection<BrowserExtension> list)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        if (list.Count == 0) return "";
        var review = list.Count(e => e.Concern != Concern.Info);
        var sb = new StringBuilder();
        sb.Append($"<h2>Browser extensions ({list.Count}{(review > 0 ? $", {review} to review" : "")})</h2>");
        sb.Append("<table><tr><th>Concern</th><th>Extension</th><th>Browser / profile</th><th>Version</th><th>Status</th><th>Access</th><th>Advice</th></tr>");
        foreach (var e in Ordered(list))
        {
            var name = e.StoreUrl is { } u ? $"<a href=\"{E(u)}\">{E(e.Name)}</a>" : E(e.Name);
            sb.Append($"<tr><td><span class=\"badge {e.Concern}\">{E(InventoryExporter.ConcernText(e.Concern))}</span></td>" +
                      $"<td><b>{name}</b><div class=\"small muted\">{E(e.Id)}{(e.Enabled ? "" : " &middot; turned off")}</div></td>" +
                      $"<td>{E(e.BrowserName)}<div class=\"small muted\">{E(e.UserName)} &middot; {E(e.Profile)}</div></td>" +
                      $"<td>{E(e.Version)}{(e.LatestVersion is { } l && l != e.Version ? $"<div class=\"small muted\">latest {E(l)}</div>" : "")}</td>" +
                      $"<td>{E(e.StatusText)}</td><td class=\"small\">{E(e.AccessText)}</td><td class=\"small adv\">{E(e.Advice)}</td></tr>");
        }
        sb.Append("</table>");
        return sb.ToString();
    }

    public static string ToHtml(IReadOnlyCollection<BrowserExtension> list, string computer)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        return $$"""
<!DOCTYPE html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Browser extensions - {{E(computer)}}</title>
<style>
:root{--ink:#1d2939;--muted:#667085;--line:#eaecf0}
*{box-sizing:border-box}body{font-family:"Segoe UI",system-ui,sans-serif;color:var(--ink);margin:0;background:#f9fafb}
main{max-width:1280px;margin:0 auto;padding:28px 22px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.muted{color:var(--muted)}a{color:#175cd3}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{background:#f2f4f7}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.High{background:#fee4e2;color:#b42318}.Review{background:#fef0c7;color:#b54708}.Info{background:#eef4ff;color:#3538cd}
.small{font-size:12px}.adv{max-width:460px}
</style></head><body><main>
<h1>Browser extensions</h1>
<div class="muted">{{E(computer)}} &middot; exported {{DateTime.Now:dd MMM yyyy HH:mm}} by PatchSentinel {{E(AppPaths.Version)}}</div>
{{HtmlSection(list)}}
<p class="small muted">Versions are compared with the Chrome Web Store, Microsoft Edge Add-ons and addons.mozilla.org. Only extension IDs are sent to the stores.</p>
</main></body></html>
""";
    }
}
