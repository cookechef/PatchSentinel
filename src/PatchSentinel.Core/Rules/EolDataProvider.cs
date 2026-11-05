using System.Text.Json;
using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Rules;

/// <summary>Fetches release cycles (EOL dates and latest patch) from https://endoflife.date, cached for 24 hours.</summary>
public sealed class EolDataProvider(string cacheDir)
{
    private static readonly Regex ProductSlug = new(@"^[a-z0-9][a-z0-9.\-]{0,63}$", RegexOptions.Compiled);
    private static readonly TimeSpan MaxAge = TimeSpan.FromHours(24);

    public bool UsedOnlineData { get; private set; }

    public async Task<Dictionary<string, List<RuleCycle>>> GetAsync(IEnumerable<string> products, bool allowNetwork, List<string> warnings, CancellationToken ct)
    {
        var result = new Dictionary<string, List<RuleCycle>>(StringComparer.OrdinalIgnoreCase);
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 1024 * 1024 };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"PatchSentinel/{AppPaths.Version}");

        foreach (var product in products.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!ProductSlug.IsMatch(product)) continue;
            var cacheFile = Path.Combine(cacheDir, $"eol-{product}.json");
            string? json = null;
            var fresh = File.Exists(cacheFile) && DateTime.UtcNow - File.GetLastWriteTimeUtc(cacheFile) < MaxAge;
            if (fresh)
            {
                json = await File.ReadAllTextAsync(cacheFile, ct);
                UsedOnlineData = true;
            }
            else if (allowNetwork)
            {
                try
                {
                    json = await http.GetStringAsync($"https://endoflife.date/api/{product}.json", ct);
                    _ = ParseApi(json); // validate before caching
                    FileUtil.WriteAllTextAtomic(cacheFile, json);
                    UsedOnlineData = true;
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
                {
                    warnings.Add($"Could not refresh EOL data for '{product}' from endoflife.date ({ex.Message}); using built-in dates.");
                    json = File.Exists(cacheFile) ? await File.ReadAllTextAsync(cacheFile, ct) : null;
                }
            }
            else if (File.Exists(cacheFile))
            {
                json = await File.ReadAllTextAsync(cacheFile, ct);
            }

            if (json is null) continue;
            try { result[product] = ParseApi(json); }
            catch (Exception ex) { warnings.Add($"EOL data for '{product}' was unreadable: {ex.Message}"); }
        }
        return result;
    }

    /// <summary>Parses the endoflife.date v0 API array: [{ "cycle": "8", "eol": "2026-11-10" | false, "latest": "8.0.21" }].</summary>
    public static List<RuleCycle> ParseApi(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Expected a JSON array.");
        var list = new List<RuleCycle>();
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            var cycle = Str(e, "cycle");
            if (string.IsNullOrWhiteSpace(cycle)) continue;
            list.Add(new RuleCycle { Cycle = cycle, Eol = Str(e, "eol"), Latest = Str(e, "latest") });
        }
        return list;
    }

    private static string? Str(JsonElement e, string name)
    {
        if (!e.TryGetProperty(name, out var p)) return null;
        return p.ValueKind switch
        {
            JsonValueKind.String => p.GetString(),
            JsonValueKind.Number => p.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => null,
        };
    }
}
