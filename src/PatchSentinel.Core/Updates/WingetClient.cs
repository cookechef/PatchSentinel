using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Updates;

/// <summary>Thin wrapper around winget.exe that also works from the SYSTEM account (service / RMM).</summary>
public sealed class WingetClient
{
    private static readonly Regex IdPattern = new(@"^[A-Za-z0-9][A-Za-z0-9.\-_+]{0,127}$", RegexOptions.Compiled);
    private const string Common = "--accept-source-agreements --disable-interactivity";

    // winget exit codes that mean "nothing to do" rather than failure.
    public const int UpdateNotApplicable = unchecked((int)0x8A15002B);
    public const int PackageAlreadyInstalled = unchecked((int)0x8A150061);
    public const int NoApplicableInstaller = unchecked((int)0x8A150010);

    public string ExePath { get; }

    private WingetClient(string exePath) => ExePath = exePath;

    public static bool IsValidId(string id) => IdPattern.IsMatch(id);

    public static WingetClient? TryCreate(bool isSystem)
    {
        var path = Locate(isSystem);
        return path is null ? null : new WingetClient(path);
    }

    /// <summary>
    /// In a user session winget is an App Execution Alias. Under SYSTEM it is not on PATH, so we use the
    /// newest Microsoft.DesktopAppInstaller package folder under Program Files\WindowsApps directly.
    /// </summary>
    public static string? Locate(bool isSystem)
    {
        if (!isSystem)
        {
            var alias = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "WindowsApps", "winget.exe");
            if (File.Exists(alias)) return alias;
        }

        try
        {
            var windowsApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
            var native = Platform.NativeArchitecture;
            var best = Directory.GetDirectories(windowsApps, "Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe")
                .Select(d => (Dir: d, Parts: Path.GetFileName(d).Split('_')))
                .Where(x => x.Parts.Length >= 3 && File.Exists(Path.Combine(x.Dir, "winget.exe")))
                .OrderByDescending(x => x.Parts[2].Equals(native, StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(x => x.Parts[1], Comparer<string>.Create(VersionUtil.Compare))
                .FirstOrDefault();
            if (best.Dir is not null) return Path.Combine(best.Dir, "winget.exe");
        }
        catch { /* access denied when not elevated - fall through */ }

        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), "winget.exe");
                if (File.Exists(candidate)) return candidate;
            }
            catch { /* bad PATH entry */ }
        }
        return null;
    }

    public async Task<List<UpdateCandidate>> ListUpgradesAsync(CancellationToken ct)
    {
        var r = await ProcessRunner.RunAsync(ExePath, $"upgrade {Common}", TimeSpan.FromMinutes(10), ct);
        if (r.TimedOut) throw new TimeoutException("winget upgrade timed out.");
        var list = WingetOutputParser.ParseUpgradeTable(r.StdOut);
        if (list.Count == 0 && r.ExitCode != 0 && !r.StdOut.Contains("No installed package", StringComparison.OrdinalIgnoreCase)
            && !r.StdOut.Contains("No available upgrade", StringComparison.OrdinalIgnoreCase))
            AppLog.Warn($"winget upgrade returned {r.ExitCode}: {Tail(r.StdOut + r.StdErr)}");
        return list;
    }

    public Task<UpdateResult> UpgradeAsync(string id, string name, CancellationToken ct) =>
        RunPackageCommandAsync("upgrade", id, name, "--silent --accept-package-agreements", ct);

    public Task<UpdateResult> InstallAsync(string id, CancellationToken ct) =>
        RunPackageCommandAsync("install", id, id, "--silent --accept-package-agreements --source winget", ct);

    public Task<UpdateResult> UninstallAsync(string id, CancellationToken ct) =>
        RunPackageCommandAsync("uninstall", id, id, "--silent", ct);

    private async Task<UpdateResult> RunPackageCommandAsync(string verb, string id, string name, string extra, CancellationToken ct)
    {
        if (!IsValidId(id)) return new UpdateResult(id, name, false, -1, "Invalid package id.");
        var r = await ProcessRunner.RunAsync(ExePath, $"{verb} --id \"{id}\" --exact {extra} {Common}", TimeSpan.FromMinutes(60), ct);
        if (r.TimedOut) return new UpdateResult(id, name, false, -1, $"winget {verb} timed out after 60 minutes.");
        var ok = r.ExitCode is 0 or UpdateNotApplicable or PackageAlreadyInstalled;
        var msg = r.ExitCode switch
        {
            0 => $"{verb} succeeded",
            UpdateNotApplicable => "Already up to date",
            PackageAlreadyInstalled => "Already installed",
            NoApplicableInstaller => "No installer applicable to this device (try running in the user's context)",
            _ => $"winget {verb} failed (0x{r.ExitCode:X8}): {Tail(r.StdOut + r.StdErr)}",
        };
        return new UpdateResult(id, name, ok, r.ExitCode, msg);
    }

    private static string Tail(string s)
    {
        var lines = s.Split('\n').Select(l => l.Split('\r').Last().Trim()).Where(l => l.Length > 0 && l.Any(char.IsLetter)).ToList();
        return string.Join(" | ", lines.TakeLast(3));
    }
}

public static class ExclusionMatcher
{
    /// <summary>Case-insensitive match against package id or name; '*' is a wildcard (e.g. "Adobe.*").</summary>
    public static bool IsMatch(IEnumerable<string> patterns, string id, string? name = null)
    {
        foreach (var raw in patterns)
        {
            var p = raw.Trim();
            if (p.Length == 0) continue;
            var rx = "^" + Regex.Escape(p).Replace(@"\*", ".*") + "$";
            if (Regex.IsMatch(id, rx, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) return true;
            if (name is not null && Regex.IsMatch(name, rx, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)) return true;
        }
        return false;
    }

    public static List<UpdateCandidate> Apply(IEnumerable<UpdateCandidate> updates, IReadOnlyCollection<string> userPatterns, IReadOnlyCollection<string> policyPatterns) =>
        updates.Select(u =>
        {
            var byPolicy = IsMatch(policyPatterns, u.Id, u.Name);
            var byUser = IsMatch(userPatterns, u.Id, u.Name);
            return u with { Excluded = byPolicy || byUser, ExcludedByPolicy = byPolicy };
        }).ToList();
}
