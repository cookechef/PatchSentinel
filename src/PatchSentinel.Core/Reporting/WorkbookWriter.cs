using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace PatchSentinel.Core.Reporting;

public enum CellStyle { Normal = 0, Header = 1, Red = 2, Amber = 3, Wrap = 4, Number = 5, Green = 6, Section = 7, Blue = 8 }

public sealed record XCell(string? Text, CellStyle Style = CellStyle.Normal, double? Number = null)
{
    public static implicit operator XCell(string? text) => new(text);
}

public sealed class XSheet
{
    public string Name { get; init; } = "Sheet1";
    public List<(string Header, int Width)> Columns { get; init; } = [];
    public List<XCell[]> Rows { get; } = [];
    public bool AutoFilter { get; init; } = true;
}

/// <summary>Writes simple multi-sheet .xlsx files directly as Open XML (no third-party library).</summary>
public static class WorkbookWriter
{
    public static void Write(Stream output, IReadOnlyList<XSheet> sheets, string title)
    {
        using var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
        void Add(string path, string xml)
        {
            var entry = zip.CreateEntry(path, CompressionLevel.Optimal);
            using var w = new StreamWriter(entry.Open(), new UTF8Encoding(false));
            w.Write(xml);
        }

        var ct = new StringBuilder("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>""");
        for (var i = 1; i <= sheets.Count; i++) ct.Append($"<Override PartName=\"/xl/worksheets/sheet{i}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>");
        ct.Append("</Types>");
        Add("[Content_Types].xml", ct.ToString());
        Add("_rels/.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>""");
        Add("docProps/core.xml", $"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>{X(title)}</dc:title><dc:creator>PatchSentinel</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}</dcterms:created></cp:coreProperties>""");

        var wb = new StringBuilder("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>""");
        var rels = new StringBuilder("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">""");
        var names = new List<string>();
        for (var i = 0; i < sheets.Count; i++)
        {
            var name = SheetName(sheets[i].Name, names);
            names.Add(name);
            wb.Append($"<sheet name=\"{X(name)}\" sheetId=\"{i + 1}\" r:id=\"rId{i + 1}\"/>");
            rels.Append($"<Relationship Id=\"rId{i + 1}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet{i + 1}.xml\"/>");
        }
        wb.Append("</sheets><definedNames>");
        for (var i = 0; i < sheets.Count; i++)
            if (sheets[i].AutoFilter && sheets[i].Columns.Count > 0)
                wb.Append($"<definedName name=\"_xlnm._FilterDatabase\" localSheetId=\"{i}\" hidden=\"1\">'{X(names[i].Replace("'", "''"))}'!$A$1:${ColName(sheets[i].Columns.Count - 1)}${Math.Max(1, sheets[i].Rows.Count + 1)}</definedName>");
        wb.Append("</definedNames></workbook>");
        rels.Append($"<Relationship Id=\"rId{sheets.Count + 1}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/></Relationships>");
        Add("xl/workbook.xml", wb.ToString());
        Add("xl/_rels/workbook.xml.rels", rels.ToString());
        Add("xl/styles.xml", Styles);

        for (var i = 0; i < sheets.Count; i++) Add($"xl/worksheets/sheet{i + 1}.xml", SheetXml(sheets[i]));
    }

    // 0 normal, 1 header, 2 red, 3 amber, 4 wrap, 5 number, 6 green, 7 section, 8 blue
    private const string Styles = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="1"><numFmt numFmtId="164" formatCode="0.0"/></numFmts><fonts count="6"><font><sz val="10"/><name val="Segoe UI"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Segoe UI"/></font><font><b/><sz val="10"/><color rgb="FFB42318"/><name val="Segoe UI"/></font><font><b/><sz val="10"/><color rgb="FF93370D"/><name val="Segoe UI"/></font><font><b/><sz val="10"/><color rgb="FF067647"/><name val="Segoe UI"/></font><font><b/><sz val="11"/><color rgb="FF1D2939"/><name val="Segoe UI"/></font></fonts><fills count="8"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF005FB8"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFEE4E2"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFEF0C7"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFDCFAE6"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFEAECF0"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFEEF4FF"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="9"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top"/></xf><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="top"/></xf><xf numFmtId="0" fontId="3" fillId="4" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="top"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment vertical="top"/></xf><xf numFmtId="0" fontId="4" fillId="5" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="top"/></xf><xf numFmtId="0" fontId="5" fillId="6" borderId="0" xfId="0" applyFont="1" applyFill="1"/><xf numFmtId="0" fontId="0" fillId="7" borderId="0" xfId="0" applyFill="1" applyAlignment="1"><alignment vertical="top"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>""";

    private static string SheetXml(XSheet s)
    {
        var sb = new StringBuilder("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/>""");
        if (s.Columns.Count > 0)
        {
            sb.Append("<cols>");
            for (var c = 0; c < s.Columns.Count; c++) sb.Append($"<col min=\"{c + 1}\" max=\"{c + 1}\" width=\"{s.Columns[c].Width}\" customWidth=\"1\"/>");
            sb.Append("</cols>");
        }
        sb.Append("<sheetData><row r=\"1\">");
        for (var c = 0; c < s.Columns.Count; c++) sb.Append(Cell(c, 1, new XCell(s.Columns[c].Header, CellStyle.Header)));
        sb.Append("</row>");
        for (var r = 0; r < s.Rows.Count; r++)
        {
            sb.Append($"<row r=\"{r + 2}\">");
            for (var c = 0; c < s.Rows[r].Length; c++) sb.Append(Cell(c, r + 2, s.Rows[r][c]));
            sb.Append("</row>");
        }
        sb.Append("</sheetData>");
        if (s.AutoFilter && s.Columns.Count > 0) sb.Append($"<autoFilter ref=\"A1:{ColName(s.Columns.Count - 1)}{Math.Max(1, s.Rows.Count + 1)}\"/>");
        sb.Append("</worksheet>");
        return sb.ToString();
    }

    private static string Cell(int col, int row, XCell? cell)
    {
        if (cell is null) return "";
        var r = $"{ColName(col)}{row}";
        var style = cell.Style == CellStyle.Normal ? "" : $" s=\"{(int)cell.Style}\"";
        if (cell.Number is { } n) return $"<c r=\"{r}\" s=\"{(cell.Style == CellStyle.Normal ? 5 : (int)cell.Style)}\"><v>{n.ToString(CultureInfo.InvariantCulture)}</v></c>";
        if (string.IsNullOrEmpty(cell.Text)) return style.Length == 0 ? "" : $"<c r=\"{r}\"{style}/>";
        return $"<c r=\"{r}\" t=\"inlineStr\"{style}><is><t xml:space=\"preserve\">{X(cell.Text)}</t></is></c>";
    }

    public static string ColName(int col)
    {
        var name = "";
        for (var c = col + 1; c > 0; c = (c - 1) / 26) name = (char)('A' + (c - 1) % 26) + name;
        return name;
    }

    private static string SheetName(string name, List<string> used)
    {
        var clean = new string(name.Where(ch => ch is not ('\\' or '/' or '?' or '*' or '[' or ']' or ':')).ToArray()).Trim();
        if (clean.Length == 0) clean = "Sheet";
        if (clean.Length > 31) clean = clean[..31];
        var candidate = clean;
        for (var i = 2; used.Contains(candidate, StringComparer.OrdinalIgnoreCase); i++) candidate = $"{clean[..Math.Min(clean.Length, 28)]} {i}";
        return candidate;
    }

    /// <summary>XML-escapes and drops characters XML does not allow; trims to Excel's cell limit.</summary>
    public static string X(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            if (ch < 0x20 && ch is not '\t' and not '\n' and not '\r') continue;
            sb.Append(ch switch { '&' => "&amp;", '<' => "&lt;", '>' => "&gt;", '"' => "&quot;", _ => ch.ToString() });
        }
        if (sb.Length > 32767) sb.Length = 32767;
        return sb.ToString();
    }
}
