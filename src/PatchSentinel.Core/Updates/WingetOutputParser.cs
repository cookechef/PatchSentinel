using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Updates;

/// <summary>
/// Parses the table printed by "winget upgrade". Columns are located from the header line so the
/// parser is not tied to English header text; progress spinners and VT escape codes are removed first.
/// </summary>
public static class WingetOutputParser
{
    private static readonly Regex Ansi = new(@"\x1B\[[0-9;?]*[ -/]*[@-~]", RegexOptions.Compiled);
    private static readonly Regex DashLine = new(@"^-{10,}\s*$", RegexOptions.Compiled);

    public static List<UpdateCandidate> ParseUpgradeTable(string output)
    {
        var lines = Ansi.Replace(output, "")
            .Replace("\r\n", "\n")
            .Split('\n')
            .Select(l => l.Split('\r').Last().TrimEnd()) // spinner frames are overwritten with \r
            .ToList();

        var result = new List<UpdateCandidate>();
        var tableIndex = 0;
        for (var i = 1; i < lines.Count; i++)
        {
            if (!DashLine.IsMatch(lines[i])) continue;
            var header = lines[i - 1];
            var starts = ColumnStarts(header);
            if (starts.Count < 4) continue;

            // Any table after the first one lists pinned packages or ones that need explicit targeting.
            var explicitOnly = tableIndex > 0;
            tableIndex++;

            for (var j = i + 1; j < lines.Count; j++)
            {
                var row = lines[j];
                if (string.IsNullOrWhiteSpace(row) || DashLine.IsMatch(row)) break;
                if (row.Length <= starts[2]) break; // summary text such as "3 upgrades available."
                var c = ParseRow(row, starts);
                if (c is null) continue;
                result.Add(c with { RequiresExplicit = explicitOnly });
            }
        }
        return result;
    }

    private static List<int> ColumnStarts(string header)
    {
        var starts = new List<int>();
        for (var i = 0; i < header.Length; i++)
            if (header[i] != ' ' && (i == 0 || header[i - 1] == ' ')) starts.Add(i);
        return starts.Count is >= 4 and <= 6 ? starts : [];
    }

    private static UpdateCandidate? ParseRow(string row, List<int> starts)
    {
        string Col(int idx)
        {
            if (idx >= starts.Count || starts[idx] >= row.Length) return "";
            var end = idx + 1 < starts.Count ? Math.Min(starts[idx + 1], row.Length) : row.Length;
            return row[starts[idx]..end].Trim();
        }

        var name = Col(0);
        var id = Col(1);
        var installed = Col(2);
        var available = Col(3);
        var source = starts.Count > 4 ? Col(4) : "";

        // Wide characters in names shift the columns; fall back to splitting from the right.
        if (id.Length == 0 || id.Contains(' ') || available.Length == 0)
        {
            var tokens = row.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var tail = starts.Count > 4 ? 4 : 3;
            if (tokens.Length < tail + 1) return null;
            id = tokens[^tail];
            installed = tokens[^(tail - 1)];
            available = tokens[^(tail - 2)];
            source = tail == 4 ? tokens[^1] : "";
            name = string.Join(' ', tokens[..^tail]);
        }

        if (id.Length == 0) return null;
        var truncated = id.EndsWith('…') || id.EndsWith("...", StringComparison.Ordinal);
        return new UpdateCandidate
        {
            Name = name,
            Id = id,
            InstalledVersion = installed,
            AvailableVersion = available,
            Source = source,
            IdTruncated = truncated || !WingetClient.IsValidId(id),
        };
    }
}
