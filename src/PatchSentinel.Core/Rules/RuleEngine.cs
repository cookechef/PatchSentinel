using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Rules;

/// <summary>Matches the inventory against the EOL catalogue and produces findings (without dependents/actions).</summary>
public static class RuleEngine
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    public static List<Finding> Evaluate(
        IReadOnlyList<InstalledItem> items,
        RuleCatalog catalog,
        IReadOnlyDictionary<string, List<RuleCycle>> onlineCycles,
        DateOnly today,
        int nearingDays,
        List<string>? warnings = null)
    {
        var findings = new List<Finding>();
        foreach (var rule in catalog.Rules.Where(r => !r.Disabled))
        {
            Regex name;
            Regex? exclude = null, publisher = null;
            try
            {
                name = new Regex(rule.Match.NamePattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
                if (!string.IsNullOrEmpty(rule.Match.ExcludePattern))
                    exclude = new Regex(rule.Match.ExcludePattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
                if (!string.IsNullOrEmpty(rule.Match.PublisherPattern))
                    publisher = new Regex(rule.Match.PublisherPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
            }
            catch (ArgumentException ex)
            {
                warnings?.Add($"Rule '{rule.Id}' has an invalid pattern and was skipped: {ex.Message}");
                continue;
            }

            var matched = items
                .Where(i => rule.Match.Sources.Count == 0 || rule.Match.Sources.Contains(i.Source))
                .Where(i => rule.Match.IncludeSystemComponents || !i.IsSystemComponent)
                .Where(i => SafeMatch(name, i.Name)
                            && (exclude is null || !SafeMatch(exclude, i.Name))
                            && (publisher is null || SafeMatch(publisher, i.Publisher ?? "")))
                .ToList();
            if (matched.Count == 0) continue;

            var cycles = MergeCycles(rule.Cycles,
                rule.EndOfLifeProduct is not null && onlineCycles.TryGetValue(rule.EndOfLifeProduct, out var online) ? online : null);

            if (cycles.Count == 0)
            {
                var state = EolState.Parse(rule.Eol, today);
                AddFindings(findings, rule, null, state, null, matched, today, nearingDays);
                continue;
            }

            foreach (var group in matched
                         .Select(i => (Item: i, Cycle: BestCycle(cycles, EffectiveVersion(i, rule))))
                         .Where(x => x.Cycle is not null)
                         .GroupBy(x => x.Cycle!.Cycle))
            {
                var cycle = group.First().Cycle!;
                var state = EolState.Parse(cycle.Eol, today);
                AddFindings(findings, rule, cycle.Cycle, state, cycle.Latest, group.Select(g => g.Item).ToList(), today, nearingDays);
            }
        }

        return findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Kind)
            .ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static string? EffectiveVersion(InstalledItem item, EolRule rule) =>
        rule.Match.VersionFromName ? FirstVersionIn(item.Name) ?? item.Version : item.Version;

    private static string? FirstVersionIn(string s)
    {
        var parts = VersionUtil.Parse(s);
        return parts.Length == 0 ? null : string.Join('.', parts);
    }

    public static List<RuleCycle> MergeCycles(List<RuleCycle> fallback, List<RuleCycle>? online)
    {
        var map = new Dictionary<string, RuleCycle>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in fallback) map[c.Cycle] = c;
        if (online is not null)
        {
            foreach (var c in online)
            {
                if (map.TryGetValue(c.Cycle, out var existing))
                    map[c.Cycle] = new RuleCycle { Cycle = c.Cycle, Eol = c.Eol ?? existing.Eol, Latest = c.Latest ?? existing.Latest };
                else
                    map[c.Cycle] = c;
            }
        }
        return map.Values.ToList();
    }

    /// <summary>The most specific cycle the version belongs to (3.1 beats 3 for 3.1.32).</summary>
    public static RuleCycle? BestCycle(IEnumerable<RuleCycle> cycles, string? version) =>
        cycles.Where(c => VersionUtil.MatchesCycle(version, c.Cycle))
              .OrderByDescending(c => VersionUtil.Parse(c.Cycle).Length)
              .FirstOrDefault();

    private static void AddFindings(List<Finding> findings, EolRule rule, string? cycle, EolState state, string? latest,
        List<InstalledItem> items, DateOnly today, int nearingDays)
    {
        var title = FormatTitle(rule.Title, cycle);
        var n = items.Count;
        var copies = n == 1 ? "1 installation" : $"{n} installations";

        if (state.IsEol)
        {
            var since = state.Date is { } d && d != DateOnly.MinValue ? $" on {d:dd MMMM yyyy}" : "";
            findings.Add(NewFinding(rule, cycle, title, FindingKind.EndOfLife, rule.EolSeverity, state.Date, latest, items,
                $"{title} reached end of life{since} and no longer receives security updates. {copies} found; this will be flagged by vulnerability scans (e.g. Cyber Essentials Plus)."));
            return;
        }

        if (state.Date is { } eol && eol.DayNumber - today.DayNumber <= nearingDays)
        {
            var days = eol.DayNumber - today.DayNumber;
            findings.Add(NewFinding(rule, cycle, title, FindingKind.NearingEndOfLife, rule.NearingSeverity, eol, latest, items,
                $"{title} reaches end of life on {eol:dd MMMM yyyy} ({days} day{(days == 1 ? "" : "s")}). {copies} found. Plan the upgrade now so it is not flagged after that date."));
        }

        if (rule.CheckLatestPatch && !string.IsNullOrWhiteSpace(latest))
        {
            var outdated = items.Where(i => VersionUtil.Compare(EffectiveVersion(i, rule), latest) < 0).ToList();
            if (outdated.Count > 0)
            {
                var o = outdated.Count == 1 ? "1 installation is" : $"{outdated.Count} installations are";
                findings.Add(NewFinding(rule, cycle, title, FindingKind.OutdatedPatch, rule.OutdatedSeverity, state.Date, latest, outdated,
                    $"{o} of {title} older than the latest security patch ({latest}). Older patch versions stay on disk side by side and are reported as vulnerable."));
            }
        }
    }

    public static string FormatTitle(string template, string? cycle) =>
        template.Contains("{cycle}") ? template.Replace("{cycle}", cycle ?? "").Trim()
        : cycle is null ? template : $"{template} {cycle}";

    private static Finding NewFinding(EolRule rule, string? cycle, string title, FindingKind kind, Severity severity,
        DateOnly? eol, string? latest, List<InstalledItem> items, string summary) => new()
    {
        Id = $"{rule.Id}:{cycle ?? "all"}:{kind}",
        RuleId = rule.Id,
        Title = title,
        Product = rule.Product,
        Category = rule.Category,
        Cycle = cycle,
        Kind = kind,
        Severity = severity,
        EolDate = eol,
        LatestVersion = latest,
        Summary = summary,
        Advice = rule.Advice,
        Replacement = rule.Replacement,
        References = [.. rule.References],
        Items = items.OrderBy(i => i.Architecture).ThenBy(i => i.Version, Comparer<string?>.Create(VersionUtil.Compare)).ToList(),
    };

    private static bool SafeMatch(Regex r, string input)
    {
        try { return r.IsMatch(input); }
        catch (RegexMatchTimeoutException) { return false; }
    }
}
