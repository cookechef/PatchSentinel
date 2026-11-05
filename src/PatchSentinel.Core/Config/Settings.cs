using System.Globalization;
using System.Text.Json;
using Microsoft.Win32;

namespace PatchSentinel.Core.Config;

public enum ScheduleFrequency { Daily, Weekly }

public sealed class UpdateSchedule
{
    public bool Enabled { get; set; } = true;
    public ScheduleFrequency Frequency { get; set; } = ScheduleFrequency.Weekly;
    public List<DayOfWeek> Days { get; set; } = [DayOfWeek.Wednesday];
    /// <summary>Local time, 24-hour "HH:mm".</summary>
    public string Time { get; set; } = "12:30";
    /// <summary>Spreads load: each run starts up to this many minutes after <see cref="Time"/>.</summary>
    public int RandomDelayMinutes { get; set; } = 20;
    public int NotifyMinutesBefore { get; set; } = 15;
    public int MaxDeferrals { get; set; } = 3;
    /// <summary>If the device was off at the scheduled time, run shortly after it next starts.</summary>
    public bool RunIfMissed { get; set; } = true;

    public bool TryGetTime(out TimeSpan time) =>
        TimeSpan.TryParseExact(Time, @"hh\:mm", CultureInfo.InvariantCulture, out time) && time < TimeSpan.FromDays(1);

    public string? Validate()
    {
        if (!TryGetTime(out _)) return "Time must be in 24-hour HH:mm format, e.g. 12:30.";
        if (Frequency == ScheduleFrequency.Weekly && Days.Count == 0) return "Choose at least one day.";
        if (NotifyMinutesBefore is < 0 or > 240) return "Reminder must be between 0 and 240 minutes.";
        if (RandomDelayMinutes is < 0 or > 240) return "Random delay must be between 0 and 240 minutes.";
        return null;
    }

    /// <summary>First scheduled run strictly after <paramref name="after"/> (local time).</summary>
    public DateTime? NextOccurrence(DateTime after)
    {
        if (!TryGetTime(out var t)) return null;
        for (var d = -1; d <= 8; d++)
        {
            var date = after.Date.AddDays(d);
            if (Frequency == ScheduleFrequency.Weekly && !Days.Contains(date.DayOfWeek)) continue;
            var candidate = date + t + TimeSpan.FromMinutes(Jitter(date));
            if (candidate > after) return candidate;
        }
        return null;
    }

    /// <summary>Most recent scheduled run at or before <paramref name="at"/>.</summary>
    public DateTime? PreviousOccurrence(DateTime at)
    {
        if (!TryGetTime(out var t)) return null;
        for (var d = 0; d <= 8; d++)
        {
            var date = at.Date.AddDays(-d);
            if (Frequency == ScheduleFrequency.Weekly && !Days.Contains(date.DayOfWeek)) continue;
            var candidate = date + t + TimeSpan.FromMinutes(Jitter(date));
            if (candidate <= at) return candidate;
        }
        return null;
    }

    /// <summary>Stable per-day, per-device offset so a fleet does not all start at once.</summary>
    private int Jitter(DateTime date)
    {
        if (RandomDelayMinutes <= 0) return 0;
        unchecked
        {
            uint h = 2166136261;
            foreach (var c in Environment.MachineName + date.ToString("yyyyMMdd", CultureInfo.InvariantCulture)) h = (h ^ c) * 16777619;
            return (int)(h % (uint)(RandomDelayMinutes + 1));
        }
    }
}

public sealed class AgentSettings
{
    public UpdateSchedule Schedule { get; set; } = new();
    public int ScanIntervalHours { get; set; } = 12;
    public List<string> ExcludedPackageIds { get; set; } = [];
    public int NearingEolWarningDays { get; set; } = 90;
    public bool UseEndOfLifeApi { get; set; } = true;
    public bool AutoUpdateRules { get; set; } = true;
    public string? RulesUrl { get; set; }
    public bool AllowUserExclusions { get; set; } = true;
    public bool AllowUserRemediation { get; set; } = true;
    public bool AllowUserDeferral { get; set; } = true;
    public List<string> ExtraDependencyScanPaths { get; set; } = [];
    public int DependencyScanBudgetSeconds { get; set; } = 90;
}

/// <summary>Settings after Group Policy / RMM registry overrides have been applied.</summary>
public sealed class EffectiveSettings
{
    public AgentSettings Settings { get; set; } = new();
    public List<string> PolicyExcludedPackageIds { get; set; } = [];
    public bool ScheduleLockedByPolicy { get; set; }
    public bool ManagedByPolicy { get; set; }

    public string? EffectiveRulesUrl => string.IsNullOrWhiteSpace(Settings.RulesUrl) ? AppPaths.BuiltInRulesUrl : Settings.RulesUrl;
}

public static class SettingsStore
{
    public static AgentSettings Load(string path)
    {
        try
        {
            if (File.Exists(path))
                return JsonSerializer.Deserialize<AgentSettings>(File.ReadAllText(path), Json.Options) ?? new AgentSettings();
        }
        catch (Exception ex) { AppLog.Warn($"Settings file unreadable, using defaults: {ex.Message}"); }
        return new AgentSettings();
    }

    public static void Save(string path, AgentSettings settings) =>
        FileUtil.WriteAllTextAtomic(path, JsonSerializer.Serialize(settings, Json.Options));

    public static EffectiveSettings LoadEffective(string path) => PolicyReader.Apply(Load(path));
}

/// <summary>
/// Reads HKLM\SOFTWARE\Policies\PatchSentinel so admins can enforce settings via GPO, Intune or an RMM script.
/// </summary>
public static class PolicyReader
{
    public const string PolicyKey = @"SOFTWARE\Policies\PatchSentinel";

    public static EffectiveSettings Apply(AgentSettings s)
    {
        var eff = new EffectiveSettings { Settings = s };
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var k = hklm.OpenSubKey(PolicyKey);
            if (k is null) return eff;
            eff.ManagedByPolicy = true;

            if (Bool(k, "AllowUserExclusions") is { } aue) s.AllowUserExclusions = aue;
            if (Bool(k, "AllowUserRemediation") is { } aur) s.AllowUserRemediation = aur;
            if (Bool(k, "AllowUserDeferral") is { } aud) s.AllowUserDeferral = aud;
            if (Bool(k, "UseEndOfLifeApi") is { } eol) s.UseEndOfLifeApi = eol;
            if (Bool(k, "AutoUpdateRules") is { } aur2) s.AutoUpdateRules = aur2;
            if (Int(k, "NearingEolWarningDays") is { } ned) s.NearingEolWarningDays = Math.Clamp(ned, 0, 730);
            if (Int(k, "ScanIntervalHours") is { } sih) s.ScanIntervalHours = Math.Clamp(sih, 1, 168);
            if (k.GetValue("RulesUrl") is string url && url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) s.RulesUrl = url;
            if (k.GetValue("ExcludedPackageIds") is string[] ids) eff.PolicyExcludedPackageIds = ids.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i.Trim()).ToList();
            else if (k.GetValue("ExcludedPackageIds") is string idList)
                eff.PolicyExcludedPackageIds = idList.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

            var sch = s.Schedule;
            var locked = false;
            if (Bool(k, "ScheduleEnabled") is { } se) { sch.Enabled = se; locked = true; }
            if (k.GetValue("ScheduleFrequency") is string f && Enum.TryParse<ScheduleFrequency>(f, true, out var freq)) { sch.Frequency = freq; locked = true; }
            if (k.GetValue("ScheduleDays") is string days)
            {
                var parsed = days.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries).Select(ParseDay).Where(d => d.HasValue).Select(d => d!.Value).Distinct().ToList();
                if (parsed.Count > 0) { sch.Days = parsed; locked = true; }
            }
            if (k.GetValue("ScheduleTime") is string t && TimeSpan.TryParseExact(t, @"hh\:mm", CultureInfo.InvariantCulture, out _)) { sch.Time = t; locked = true; }
            if (Int(k, "NotifyMinutesBefore") is { } nmb) { sch.NotifyMinutesBefore = Math.Clamp(nmb, 0, 240); locked = true; }
            if (Int(k, "MaxDeferrals") is { } md) { sch.MaxDeferrals = Math.Clamp(md, 0, 20); locked = true; }
            if (Int(k, "RandomDelayMinutes") is { } rdm) { sch.RandomDelayMinutes = Math.Clamp(rdm, 0, 240); locked = true; }
            eff.ScheduleLockedByPolicy = locked;
        }
        catch (Exception ex) { AppLog.Warn($"Could not read policy: {ex.Message}"); }
        return eff;
    }

    private static bool? Bool(RegistryKey k, string name) => Int(k, name) is { } i ? i != 0 : null;

    private static int? Int(RegistryKey k, string name) => k.GetValue(name) switch
    {
        int i => i,
        string str when int.TryParse(str, out var i) => i,
        _ => null,
    };

    private static DayOfWeek? ParseDay(string s)
    {
        s = s.Trim();
        foreach (var d in Enum.GetValues<DayOfWeek>())
            if (d.ToString().StartsWith(s, StringComparison.OrdinalIgnoreCase) && s.Length >= 2) return d;
        return null;
    }
}
