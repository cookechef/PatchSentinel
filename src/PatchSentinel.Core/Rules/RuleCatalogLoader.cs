using System.Text.Json;
using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Rules;

public static class RuleCatalogLoader
{
    public const string DownloadedFileName = "eol-rules.json";
    /// <summary>Optional admin-maintained additions/overrides; rules with the same id replace built-in ones.</summary>
    public const string LocalFileName = "eol-rules.local.json";
    private const int MaxBytes = 2 * 1024 * 1024;

    public static RuleCatalog LoadEmbedded()
    {
        using var s = typeof(RuleCatalogLoader).Assembly.GetManifestResourceStream("PatchSentinel.Core.eol-rules.json")
                      ?? throw new InvalidOperationException("Embedded rules catalogue is missing.");
        using var r = new StreamReader(s);
        return Parse(r.ReadToEnd());
    }

    /// <summary>Built-in catalogue, replaced by a newer downloaded one, then merged with local overrides.</summary>
    public static RuleCatalog Load(string rulesDir, List<string> warnings)
    {
        var best = LoadEmbedded();
        var downloaded = TryLoad(Path.Combine(rulesDir, DownloadedFileName), warnings);
        if (downloaded is not null && string.CompareOrdinal(downloaded.CatalogVersion, best.CatalogVersion) > 0)
            best = downloaded;
        var local = TryLoad(Path.Combine(rulesDir, LocalFileName), warnings);
        return local is null ? best : Merge(best, local);
    }

    public static RuleCatalog Merge(RuleCatalog baseCatalog, RuleCatalog overrides)
    {
        var rules = baseCatalog.Rules.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var r in overrides.Rules) rules[r.Id] = r;
        var cats = baseCatalog.Categories.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var c in overrides.Categories) cats[c.Id] = c;
        return new RuleCatalog
        {
            SchemaVersion = baseCatalog.SchemaVersion,
            CatalogVersion = $"{baseCatalog.CatalogVersion}+local",
            Rules = rules.Values.ToList(),
            Categories = cats.Values.ToList(),
        };
    }

    public static RuleCatalog Parse(string json)
    {
        var catalog = JsonSerializer.Deserialize<RuleCatalog>(json, Json.Options)
                      ?? throw new InvalidDataException("Rules catalogue is empty.");
        if (catalog.SchemaVersion != 1) throw new InvalidDataException($"Unsupported rules schema version {catalog.SchemaVersion}.");
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in catalog.Rules)
        {
            if (string.IsNullOrWhiteSpace(r.Id) || !ids.Add(r.Id)) throw new InvalidDataException($"Rule id '{r.Id}' is missing or duplicated.");
            if (string.IsNullOrWhiteSpace(r.Match.NamePattern)) throw new InvalidDataException($"Rule '{r.Id}' has no namePattern.");
            _ = new Regex(r.Match.NamePattern, RegexOptions.None, TimeSpan.FromMilliseconds(250));
            foreach (var id in new[] { r.ReplacementWingetId, r.WingetIdTemplate })
                if (id is not null && !Updates.WingetClient.IsValidId(id.Replace("{major}", "1").Replace("{minor}", "0")))
                    throw new InvalidDataException($"Rule '{r.Id}' has an invalid winget id '{id}'.");
        }
        foreach (var c in catalog.Categories)
        {
            if (string.IsNullOrWhiteSpace(c.Id) || string.IsNullOrWhiteSpace(c.Category)) throw new InvalidDataException("A software category is missing its id or name.");
            _ = new SoftwareClassifier([c]); // validates the patterns
        }
        return catalog;
    }

    private static RuleCatalog? TryLoad(string path, List<string> warnings)
    {
        if (!File.Exists(path)) return null;
        try { return Parse(File.ReadAllText(path)); }
        catch (Exception ex) { warnings.Add($"Ignoring rules file {path}: {ex.Message}"); return null; }
    }

    /// <summary>Downloads the catalogue (HTTPS only), validates it, and stores it atomically.</summary>
    public static async Task<string> UpdateFromUrlAsync(string url, string rulesDir, CancellationToken ct)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Rules URL must be an absolute https:// URL.");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30), MaxResponseContentBufferSize = MaxBytes };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"PatchSentinel/{AppPaths.Version}");
        var json = await http.GetStringAsync(uri, ct);
        var catalog = Parse(json);
        var current = Load(rulesDir, []);
        FileUtil.WriteAllTextAtomic(Path.Combine(rulesDir, DownloadedFileName), json);
        return string.CompareOrdinal(catalog.CatalogVersion, current.CatalogVersion.Replace("+local", "")) > 0
            ? $"Rules updated to {catalog.CatalogVersion}."
            : $"Rules are current ({catalog.CatalogVersion}).";
    }
}
