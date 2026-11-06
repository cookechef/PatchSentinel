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

    public static string ToCsv(IEnumerable<InstalledItem> items, string computer)
    {
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

    public static string ToHtml(IEnumerable<InstalledItem> items, string computer)
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
</style></head><body><main>
<h1>Installed software</h1>
<div class="muted">{{E(computer)}} &middot; {{list.Count}} apps &middot; exported {{DateTime.Now:dd MMM yyyy HH:mm}} by PatchSentinel {{E(AppPaths.Version)}}</div>
""");

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

    public static void WriteXlsx(IEnumerable<InstalledItem> items, string computer, Stream output)
    {
        var rows = Ordered(items).ToList();
        using var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
        void Add(string path, string xml)
        {
            var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
            using var w = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            w.Write(xml);
        }

        Add("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>""");
        Add("_rels/.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>""");
        Add("docProps/core.xml", $"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>Installed software - {X(computer)}</dc:title><dc:creator>PatchSentinel</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}</dcterms:created></cp:coreProperties>""");
        Add("xl/workbook.xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Installed apps" sheetId="1" r:id="rId1"/></sheets><definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">'Installed apps'!$A$1:$R$1</definedName></definedNames></workbook>""");
        Add("xl/_rels/workbook.xml.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>""");
        // Styles: 0 normal, 1 header (bold white on blue), 2 High (red), 3 Review (amber), 4 wrapped text, 5 number
        Add("xl/styles.xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="1"><numFmt numFmtId="164" formatCode="0.0"/></numFmts><fonts count="4"><font><sz val="10"/><name val="Segoe UI"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Segoe UI"/></font><font><b/><sz val="10"/><color rgb="FFB42318"/><name val="Segoe UI"/></font><font><b/><sz val="10"/><color rgb="FF93370D"/><name val="Segoe UI"/></font></fonts><fills count="5"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF005FB8"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFEE4E2"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFEF0C7"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="6"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="3" fillId="4" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>""");

        var widths = new[] { 16, 42, 16, 26, 12, 10, 12, 8, 30, 16, 40, 60, 40, 10, 40, 50, 50, 60 };
        var sheet = new StringBuilder();
        sheet.Append("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/><cols>""");
        for (var c = 0; c < widths.Length; c++) sheet.Append($"<col min=\"{c + 1}\" max=\"{c + 1}\" width=\"{widths[c]}\" customWidth=\"1\"/>");
        sheet.Append("</cols><sheetData>");

        sheet.Append("<row r=\"1\">");
        for (var c = 0; c < Headers.Length; c++) sheet.Append(Cell(c, 1, Headers[c], 1));
        sheet.Append("</row>");

        var r = 2;
        foreach (var i in rows)
        {
            var values = Row(i, computer);
            sheet.Append($"<row r=\"{r}\">");
            for (var c = 0; c < values.Length; c++)
            {
                var style = c == 9 ? i.Classification?.Concern switch { Concern.High => 2, Concern.Review => 3, _ => 0 } : c is 10 or 11 ? 4 : 0;
                if (c == 5 && i.SizeMB is { } mb) sheet.Append($"<c r=\"{Ref(c, r)}\" s=\"5\"><v>{mb.ToString(System.Globalization.CultureInfo.InvariantCulture)}</v></c>");
                else sheet.Append(Cell(c, r, values[c], style));
            }
            sheet.Append("</row>");
            r++;
        }
        sheet.Append($"</sheetData><autoFilter ref=\"A1:{Ref(Headers.Length - 1, Math.Max(1, r - 1))}\"/></worksheet>");
        Add("xl/worksheets/sheet1.xml", sheet.ToString());
    }

    private static string Cell(int col, int row, string? value, int style)
    {
        if (string.IsNullOrEmpty(value)) return style == 0 ? "" : $"<c r=\"{Ref(col, row)}\" s=\"{style}\"/>";
        return $"<c r=\"{Ref(col, row)}\" t=\"inlineStr\"{(style == 0 ? "" : $" s=\"{style}\"")}><is><t xml:space=\"preserve\">{X(value)}</t></is></c>";
    }

    private static string Ref(int col, int row)
    {
        var name = "";
        for (var c = col + 1; c > 0; c = (c - 1) / 26) name = (char)('A' + (c - 1) % 26) + name;
        return name + row;
    }

    /// <summary>XML-escapes and drops characters that are not allowed in XML (registry values sometimes contain them).</summary>
    private static string X(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            if (ch < 0x20 && ch is not '\t' and not '\n' and not '\r') continue;
            if (char.IsSurrogate(ch)) { sb.Append(ch); continue; }
            sb.Append(ch switch { '&' => "&amp;", '<' => "&lt;", '>' => "&gt;", '"' => "&quot;", _ => ch.ToString() });
        }
        if (sb.Length > 32767) sb.Length = 32767; // Excel cell limit
        return sb.ToString();
    }
}
