using System.Net;
using System.Text;
using System.Text.Json;

namespace PatchSentinel.Core.Reporting;

/// <summary>JSON / CSV / HTML exports, suitable as Cyber Essentials Plus remediation evidence or RMM ingestion.</summary>
public static class ReportWriter
{
    public static string ToJson(ScanResult r, bool includeInventory = false) =>
        JsonSerializer.Serialize(includeInventory ? r : r.WithoutInventory(), Json.Options);

    public static string ToCsv(ScanResult r)
    {
        var today = DateOnly.FromDateTime(r.ScannedAt.LocalDateTime);
        var sb = new StringBuilder();
        sb.AppendLine("Computer,Type,Severity,Title,Status,EOL date,Latest version,Installed,Apps that would break,Advice");
        foreach (var f in r.Findings)
            sb.AppendLine(string.Join(',', Csv(r.ComputerName), Csv(f.Kind.ToString()), Csv(f.Severity.ToString()), Csv(f.Title), Csv(f.StatusText(today)),
                Csv(f.EolDate is { } d && d != DateOnly.MinValue ? d.ToString("yyyy-MM-dd") : ""), Csv(f.LatestVersion ?? ""),
                Csv(string.Join("; ", f.Items.Select(i => i.Describe()))), Csv(f.BreakingDependents.ToString()), Csv(f.Advice ?? "")));
        foreach (var u in r.Updates)
            sb.AppendLine(string.Join(',', Csv(r.ComputerName), "Update", "", Csv(u.Name), Csv(u.Excluded ? "Excluded" : "Update available"), "",
                Csv(u.AvailableVersion), Csv($"{u.Id} {u.InstalledVersion}"), "", ""));
        return sb.ToString();
    }

    private static string Csv(string s) =>
        s.IndexOfAny([',', '"', '\n', '\r']) >= 0 || s.StartsWith('=') || s.StartsWith('+') || s.StartsWith('-') || s.StartsWith('@')
            ? "\"" + (s.StartsWith('=') || s.StartsWith('+') || s.StartsWith('-') || s.StartsWith('@') ? "'" : "") + s.Replace("\"", "\"\"") + "\""
            : s;

    public static string ToHtml(ScanResult r)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        var today = DateOnly.FromDateTime(r.ScannedAt.LocalDateTime);
        var c = r.Counts;
        var sb = new StringBuilder();
        sb.Append($$"""
<!DOCTYPE html>
<html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PatchSentinel report - {{E(r.ComputerName)}}</title>
<style>
:root{--crit:#b42318;--high:#c4320a;--med:#b54708;--ok:#067647;--ink:#1d2939;--muted:#667085;--line:#eaecf0}
*{box-sizing:border-box}body{font-family:"Segoe UI",system-ui,sans-serif;color:var(--ink);margin:0;background:#f9fafb}
main{max-width:1100px;margin:0 auto;padding:32px 24px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:20px}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 16px}.card b{display:block;font-size:28px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{background:#f2f4f7;font-weight:600}
.sev{font-weight:600;white-space:nowrap}.Critical{color:var(--crit)}.High{color:var(--high)}.Medium{color:var(--med)}.Low,.Info{color:var(--muted)}
ul{margin:4px 0;padding-left:18px}.break{color:var(--crit);font-weight:600}.small{font-size:12px}
@media print{body{background:#fff}.card,table{break-inside:avoid} }
</style></head><body><main>
<h1>Legacy software and patch report</h1>
<div class="muted">{{E(r.ComputerName)}} &middot; {{E(r.OsDescription)}} &middot; scanned {{r.ScannedAt:dd MMM yyyy HH:mm}} as {{E(r.ScanContext)}}</div>
<div class="cards">
<div class="card"><b class="Critical">{{c.EndOfLife}}</b>End-of-life items</div>
<div class="card"><b class="Medium">{{c.NearingEndOfLife}}</b>Approaching end of life</div>
<div class="card"><b class="High">{{c.OutdatedPatch}}</b>Missing security patches</div>
<div class="card"><b>{{c.UpdatesAvailable}}</b>App updates available</div>
</div>
""");

        sb.Append("<h2>Legacy and end-of-life software</h2>");
        if (r.Findings.Count == 0) sb.Append("<p class=\"Low\">No end-of-life or unpatched runtimes found.</p>");
        else
        {
            sb.Append("<table><tr><th>Severity</th><th>Software</th><th>Status</th><th>Installed copies</th><th>Applications using it</th><th>Recommended action</th></tr>");
            foreach (var f in r.Findings)
            {
                var rec = f.Actions.FirstOrDefault(a => a.Recommended) ?? f.Actions.FirstOrDefault();
                sb.Append($"<tr><td class=\"sev {f.Severity}\">{f.Severity}</td><td><b>{E(f.Title)}</b><div class=\"small muted\">{E(f.Summary)}</div></td><td>{E(f.StatusText(today))}</td><td><ul>");
                foreach (var i in f.Items) sb.Append($"<li class=\"small\">{E(i.Describe())}</li>");
                sb.Append("</ul></td><td>");
                if (f.Dependents.Count == 0) sb.Append("<span class=\"muted small\">None found</span>");
                else
                {
                    sb.Append("<ul>");
                    foreach (var d in f.Dependents.Take(15))
                        sb.Append($"<li class=\"small{(d.WouldBreak ? " break" : "")}\">{E(d.AppPath)}{(d.WouldBreak ? " - would break" : "")}</li>");
                    if (f.Dependents.Count > 15) sb.Append($"<li class=\"small muted\">and {f.Dependents.Count - 15} more</li>");
                    sb.Append("</ul>");
                }
                sb.Append($"</td><td class=\"small\">{E(rec?.Label ?? "See advice")}");
                if (!string.IsNullOrEmpty(f.Advice)) sb.Append($"<div class=\"muted\">{E(f.Advice)}</div>");
                if (f.References.Count > 0) sb.Append("<div>" + string.Join(" ", f.References.Select(u => $"<a href=\"{E(u)}\">reference</a>")) + "</div>");
                sb.Append("</td></tr>");
            }
            sb.Append("</table>");
        }

        sb.Append("<h2>Application updates (winget)</h2>");
        if (!r.WingetAvailable) sb.Append("<p class=\"muted\">winget was not available on this device.</p>");
        else if (r.Updates.Count == 0) sb.Append("<p class=\"Low\">All winget-managed applications are up to date.</p>");
        else
        {
            sb.Append("<table><tr><th>Application</th><th>Package ID</th><th>Installed</th><th>Available</th><th>Status</th></tr>");
            foreach (var u in r.Updates)
                sb.Append($"<tr><td>{E(u.Name)}</td><td>{E(u.Id)}</td><td>{E(u.InstalledVersion)}</td><td>{E(u.AvailableVersion)}</td><td>{(u.ExcludedByPolicy ? "Excluded by policy" : u.Excluded ? "Excluded" : u.RequiresExplicit ? "Pinned / manual" : "Pending")}</td></tr>");
            sb.Append("</table>");
        }

        if (r.Warnings.Count > 0)
        {
            sb.Append("<h2>Scan notes</h2><ul class=\"small muted\">");
            foreach (var w in r.Warnings) sb.Append($"<li>{E(w)}</li>");
            sb.Append("</ul>");
        }
        sb.Append($"<p class=\"small muted\">PatchSentinel {E(r.AgentVersion)} &middot; rules {E(r.RulesVersion)}{(r.OnlineEolData ? " + endoflife.date" : "")}</p></main></body></html>");
        return sb.ToString();
    }
}
