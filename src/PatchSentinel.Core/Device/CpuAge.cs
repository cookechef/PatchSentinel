using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Device;

/// <summary>
/// Estimates when a processor was released from its model name (Intel Core generation, Core Ultra series,
/// AMD Ryzen series, Snapdragon X). A good proxy for the age of the device when no purchase date is known.
/// </summary>
public static class CpuAge
{
    private static readonly Regex IntelCore = new(@"\bi[3579]-(\d{4,5})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex IntelUltra = new(@"Core\(?\w*\)?\s+Ultra\s+[3579]\s+(\d)\d{2}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex IntelCoreN = new(@"Core\(?\w*\)?\s+[3579]\s+(\d)\d{2}[A-Z]?\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex Ryzen = new(@"Ryzen\s+(?:Threadripper\s+)?(?:PRO\s+)?[3579]\s+(?:PRO\s+)?(\d)\d{3}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RyzenAi = new(@"Ryzen\s+AI", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Dictionary<int, int> IntelGenYear = new()
    {
        [2] = 2011, [3] = 2012, [4] = 2013, [5] = 2015, [6] = 2015, [7] = 2016, [8] = 2017,
        [9] = 2018, [10] = 2019, [11] = 2020, [12] = 2021, [13] = 2022, [14] = 2023,
    };

    private static readonly Dictionary<int, int> RyzenSeriesYear = new()
    {
        [1] = 2017, [2] = 2018, [3] = 2019, [4] = 2020, [5] = 2021, [6] = 2022, [7] = 2023, [8] = 2024, [9] = 2024,
    };

    /// <summary>Returns (release year, generation description, Windows 11 supported CPU) or nulls if unknown.</summary>
    public static (int? Year, string? Generation, bool? Windows11) Estimate(string? cpuName)
    {
        if (string.IsNullOrWhiteSpace(cpuName)) return (null, null, null);
        var n = Regex.Replace(cpuName, @"\s+", " ");

        if (IntelUltra.Match(n) is { Success: true } u)
        {
            var series = int.Parse(u.Groups[1].Value);
            return (series >= 2 ? 2024 : 2023, $"Intel Core Ultra series {series}", true);
        }
        if (IntelCore.Match(n) is { Success: true } m)
        {
            var digits = m.Groups[1].Value;
            // 10th gen onwards starts with "1" and has two generation digits: 1165G7 = 11th, 1235U = 12th, 10510U = 10th.
            var gen = digits[0] == '1' ? int.Parse(digits[..2]) : int.Parse(digits[..1]);
            if (IntelGenYear.TryGetValue(gen, out var y)) return (y, $"Intel Core {Ordinal(gen)} generation", gen >= 8);
        }
        if (IntelCoreN.Match(n) is { Success: true } c && n.Contains("Intel", StringComparison.OrdinalIgnoreCase))
        {
            var series = int.Parse(c.Groups[1].Value);
            return (series >= 2 ? 2025 : 2024, $"Intel Core series {series}", true);
        }
        if (RyzenAi.IsMatch(n)) return (2024, "AMD Ryzen AI 300 series", true);
        if (Ryzen.Match(n) is { Success: true } r)
        {
            var series = int.Parse(r.Groups[1].Value);
            if (RyzenSeriesYear.TryGetValue(series, out var y)) return (y, $"AMD Ryzen {series}000 series", series >= 2);
        }
        if (n.Contains("Snapdragon", StringComparison.OrdinalIgnoreCase) && n.Contains(" X", StringComparison.OrdinalIgnoreCase))
            return (2024, "Qualcomm Snapdragon X", true);
        return (null, null, null);
    }

    public static string? Describe(int? year, string? generation, DateOnly today)
    {
        if (year is null) return null;
        var age = today.Year - year.Value;
        var ageText = age <= 0 ? "under a year" : age == 1 ? "about 1 year" : $"about {age} years";
        return $"{ageText} old ({generation}, released around {year})";
    }

    private static string Ordinal(int n) => n switch
    {
        _ when n % 100 is 11 or 12 or 13 => $"{n}th",
        _ when n % 10 == 1 => $"{n}st",
        _ when n % 10 == 2 => $"{n}nd",
        _ when n % 10 == 3 => $"{n}rd",
        _ => $"{n}th",
    };
}
