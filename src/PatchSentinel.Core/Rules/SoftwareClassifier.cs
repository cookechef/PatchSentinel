using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Rules;

/// <summary>Tags installed apps with a category, purpose and security advisory from the catalogue.</summary>
public sealed class SoftwareClassifier
{
    private readonly List<(SoftwareCategoryRule Rule, Regex? Name, Regex? Publisher, Regex? Exclude)> _rules = [];

    public SoftwareClassifier(IEnumerable<SoftwareCategoryRule> rules, List<string>? warnings = null)
    {
        // Highest concern first, so an app matching several categories gets the most important one.
        foreach (var r in rules.OrderByDescending(r => r.Concern))
        {
            try
            {
                _rules.Add((r, Build(r.Patterns), Build(r.PublisherPatterns), Build(r.ExcludePatterns)));
            }
            catch (ArgumentException ex) { warnings?.Add($"Software category '{r.Id}' has an invalid pattern: {ex.Message}"); }
        }
    }

    private static Regex? Build(List<string> patterns) =>
        patterns.Count == 0 ? null
            : new Regex(@"(?<![A-Za-z0-9])(?:" + string.Join("|", patterns) + @")(?![A-Za-z0-9])",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250));

    public SoftwareClassification? Classify(InstalledItem item)
    {
        foreach (var (rule, name, publisher, exclude) in _rules)
        {
            try
            {
                if (exclude is not null && exclude.IsMatch(item.Name)) continue;
                var hit = (name is not null && name.IsMatch(item.Name)) || (publisher is not null && item.Publisher is not null && publisher.IsMatch(item.Publisher));
                if (hit) return new SoftwareClassification(rule.Id, rule.Category, rule.Purpose, rule.Concern, rule.Advisory);
            }
            catch (RegexMatchTimeoutException) { /* skip */ }
        }
        return null;
    }

    public List<InstalledItem> Apply(IEnumerable<InstalledItem> items) =>
        items.Select(i => i.Source == ItemSource.Registry ? i with { Classification = Classify(i) } : i).ToList();
}
