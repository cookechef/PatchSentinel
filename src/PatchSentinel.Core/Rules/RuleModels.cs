namespace PatchSentinel.Core.Rules;

public sealed class RuleCatalog
{
    public int SchemaVersion { get; set; } = 1;
    /// <summary>Sortable version, e.g. 2026.11.05. A downloaded catalogue only replaces the built-in one if it is newer.</summary>
    public string CatalogVersion { get; set; } = "0";
    public List<EolRule> Rules { get; set; } = [];
}

public sealed class EolRule
{
    public string Id { get; set; } = "";
    /// <summary>Display title. "{cycle}" is replaced by the release cycle, otherwise the cycle is appended.</summary>
    public string Title { get; set; } = "";
    public string Product { get; set; } = "";
    public string Category { get; set; } = "Application";
    public bool Disabled { get; set; }
    public RuleMatch Match { get; set; } = new();

    /// <summary>Product slug on https://endoflife.date used to refresh EOL dates and latest patch versions.</summary>
    public string? EndOfLifeProduct { get; set; }
    /// <summary>Static fallback cycles (used offline and merged with endoflife.date data).</summary>
    public List<RuleCycle> Cycles { get; set; } = [];
    /// <summary>EOL date for products without cycles ("yyyy-MM-dd", "true" or "false").</summary>
    public string? Eol { get; set; }

    public bool CheckLatestPatch { get; set; }
    public Severity EolSeverity { get; set; } = Severity.Critical;
    public Severity NearingSeverity { get; set; } = Severity.Medium;
    public Severity OutdatedSeverity { get; set; } = Severity.High;

    public string? Advice { get; set; }
    public string? Replacement { get; set; }
    /// <summary>winget id of the supported replacement, e.g. Microsoft.DotNet.Runtime.10.</summary>
    public string? ReplacementWingetId { get; set; }
    /// <summary>winget id for in-place patching; supports {major} and {minor}, e.g. Microsoft.DotNet.Runtime.{major}.</summary>
    public string? WingetIdTemplate { get; set; }
    public List<string> References { get; set; } = [];
}

public sealed class RuleMatch
{
    public List<ItemSource> Sources { get; set; } = [ItemSource.Registry];
    public string NamePattern { get; set; } = "";
    public string? ExcludePattern { get; set; }
    public string? PublisherPattern { get; set; }
    public bool IncludeSystemComponents { get; set; }
    /// <summary>Take the version from the display name instead of DisplayVersion (e.g. Python, Java).</summary>
    public bool VersionFromName { get; set; }
}

public sealed class RuleCycle
{
    public string Cycle { get; set; } = "";
    /// <summary>"yyyy-MM-dd", "true" (EOL, date unknown) or "false"/null (supported).</summary>
    public string? Eol { get; set; }
    public string? Latest { get; set; }
}

public readonly record struct EolState(bool IsEol, DateOnly? Date)
{
    public static EolState Parse(string? s, DateOnly today)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Equals("false", StringComparison.OrdinalIgnoreCase)) return new(false, null);
        if (s.Equals("true", StringComparison.OrdinalIgnoreCase)) return new(true, DateOnly.MinValue);
        if (DateOnly.TryParseExact(s, "yyyy-MM-dd", out var d)) return new(d <= today, d);
        return new(false, null);
    }
}
