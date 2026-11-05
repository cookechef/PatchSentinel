using System.Text.Json.Serialization;

namespace PatchSentinel.Core;

public enum ItemSource
{
    /// <summary>Add/Remove Programs (Uninstall registry keys).</summary>
    Registry,
    /// <summary>A folder under dotnet\shared\&lt;framework&gt;\&lt;version&gt; - what vulnerability scanners such as Qualys detect.</summary>
    DotNetSharedFramework,
    /// <summary>A folder under dotnet\sdk\&lt;version&gt;.</summary>
    DotNetSdk,
    /// <summary>The in-place .NET Framework 4.x release.</summary>
    DotNetFramework,
}

public enum InstallScope { Machine, User }

public enum FindingKind { EndOfLife, NearingEndOfLife, OutdatedPatch }

public enum Severity { Info, Low, Medium, High, Critical }

public sealed record InstalledItem
{
    public string Name { get; init; } = "";
    public string? Version { get; init; }
    public string? Publisher { get; init; }
    public ItemSource Source { get; init; }
    public InstallScope Scope { get; init; } = InstallScope.Machine;
    public string? Architecture { get; init; }
    public string? InstallLocation { get; init; }
    public string? UninstallString { get; init; }
    public string? QuietUninstallString { get; init; }
    /// <summary>MSI product code when the item was installed by Windows Installer.</summary>
    public string? ProductCode { get; init; }
    public string? RegistryKey { get; init; }
    public string? UserSid { get; init; }
    public bool IsSystemComponent { get; init; }

    [JsonIgnore]
    public string Key => $"{Source}|{Name}|{Version}|{Architecture}|{Scope}|{UserSid}|{InstallLocation}";

    public string Describe()
    {
        var arch = string.IsNullOrEmpty(Architecture) ? "" : $" ({Architecture})";
        var scope = Scope == InstallScope.User ? " [per-user]" : "";
        return Source switch
        {
            ItemSource.DotNetSharedFramework or ItemSource.DotNetSdk => $"{Name} {Version}{arch} - {InstallLocation}",
            _ => $"{Name} {Version}{arch}{scope}".Trim(),
        };
    }
}

/// <summary>An application that depends on a .NET runtime (found via its *.runtimeconfig.json).</summary>
public sealed record Dependent
{
    public string AppPath { get; init; } = "";
    public string Framework { get; init; } = "";
    public string RequestedVersion { get; init; } = "";
    public string RollForward { get; init; } = "Minor";
    public string Architecture { get; init; } = "x64";
    /// <summary>True when removing the items in the finding would leave no runtime this app can start on.</summary>
    public bool WouldBreak { get; init; }
}

public enum StepKind { MsiUninstall, CommandUninstall, InteractiveUninstall, WingetUninstall, WingetInstall, WingetUpgrade, DeleteDotNetFolder, VerifyDotNetNewer }

public sealed record RemediationStep
{
    public StepKind Kind { get; init; }
    /// <summary>MSI product code, command line, winget package id or folder path depending on <see cref="Kind"/>.</summary>
    public string Target { get; init; } = "";
    public string Description { get; init; } = "";
    /// <summary>Must run in the logged-on user's context (per-user installs, interactive or untrusted uninstallers).</summary>
    public bool RequiresUserContext { get; init; }
    public string? UserSid { get; init; }
}

public enum ActionKind { ReplaceAndRemove, Remove, InstallReplacement, UpgradeInPlace, RemoveSupersededPatches }

public sealed record RemediationAction
{
    public string Id { get; init; } = "";
    public ActionKind Kind { get; init; }
    public string Label { get; init; } = "";
    public string Description { get; init; } = "";
    public bool Recommended { get; init; }
    public string? Warning { get; init; }
    public List<RemediationStep> Steps { get; init; } = [];

    [JsonIgnore] public bool HasMachineSteps => Steps.Any(s => !s.RequiresUserContext);
    [JsonIgnore] public bool HasUserSteps => Steps.Any(s => s.RequiresUserContext);
}

public sealed class Finding
{
    /// <summary>Stable identifier: ruleId:cycle:kind.</summary>
    public string Id { get; set; } = "";
    public string RuleId { get; set; } = "";
    public string Title { get; set; } = "";
    public string Product { get; set; } = "";
    public string Category { get; set; } = "";
    public string? Cycle { get; set; }
    public FindingKind Kind { get; set; }
    public Severity Severity { get; set; }
    public DateOnly? EolDate { get; set; }
    public string? LatestVersion { get; set; }
    public string Summary { get; set; } = "";
    public string? Advice { get; set; }
    public string? Replacement { get; set; }
    public List<string> References { get; set; } = [];
    public List<InstalledItem> Items { get; set; } = [];
    public List<Dependent> Dependents { get; set; } = [];
    public List<RemediationAction> Actions { get; set; } = [];

    [JsonIgnore] public int BreakingDependents => Dependents.Count(d => d.WouldBreak);

    public string StatusText(DateOnly today) => Kind switch
    {
        FindingKind.EndOfLife => EolDate is { } d && d != DateOnly.MinValue
            ? $"End of life since {d:dd MMM yyyy}"
            : "End of life",
        FindingKind.NearingEndOfLife => EolDate is { } d2
            ? $"End of life on {d2:dd MMM yyyy} ({d2.DayNumber - today.DayNumber} days)"
            : "Nearing end of life",
        FindingKind.OutdatedPatch => LatestVersion is null ? "Missing security patches" : $"Missing security patches (latest {LatestVersion})",
        _ => "",
    };
}

public sealed record UpdateCandidate
{
    public string Name { get; init; } = "";
    public string Id { get; init; } = "";
    public string InstalledVersion { get; init; } = "";
    public string AvailableVersion { get; init; } = "";
    public string Source { get; init; } = "";
    public bool Excluded { get; init; }
    public bool ExcludedByPolicy { get; init; }
    /// <summary>Framework/store package that Windows keeps up to date itself; winget often reports it as permanently outdated.</summary>
    public bool ManagedByWindows { get; init; }
    /// <summary>winget truncated the package id in its table output; it cannot be targeted safely.</summary>
    public bool IdTruncated { get; init; }
    /// <summary>Package is pinned or requires explicit targeting, so winget will not upgrade it with --all.</summary>
    public bool RequiresExplicit { get; init; }

    [JsonIgnore] public bool Installable => !Excluded && !IdTruncated && !RequiresExplicit;
}

public sealed record UpdateResult(string Id, string Name, bool Success, int ExitCode, string Message);

public sealed class ScanCounts
{
    public int EndOfLife { get; set; }
    public int NearingEndOfLife { get; set; }
    public int OutdatedPatch { get; set; }
    public int UpdatesAvailable { get; set; }
    public int UpdatesExcluded { get; set; }
}

public sealed class ScanResult
{
    public DateTimeOffset ScannedAt { get; set; }
    public string ComputerName { get; set; } = "";
    public string OsDescription { get; set; } = "";
    public string AgentVersion { get; set; } = "";
    public string RulesVersion { get; set; } = "";
    public bool OnlineEolData { get; set; }
    public bool WingetAvailable { get; set; }
    public string ScanContext { get; set; } = "";
    public List<Finding> Findings { get; set; } = [];
    public List<UpdateCandidate> Updates { get; set; } = [];
    public List<InstalledItem> Inventory { get; set; } = [];
    public List<string> Warnings { get; set; } = [];

    public ScanCounts Counts => new()
    {
        EndOfLife = Findings.Count(f => f.Kind == FindingKind.EndOfLife),
        NearingEndOfLife = Findings.Count(f => f.Kind == FindingKind.NearingEndOfLife),
        OutdatedPatch = Findings.Count(f => f.Kind == FindingKind.OutdatedPatch),
        UpdatesAvailable = Updates.Count(u => u.Installable),
        UpdatesExcluded = Updates.Count(u => u.Excluded),
    };

    /// <summary>Copy without the (large) inventory, for IPC.</summary>
    public ScanResult WithoutInventory()
    {
        var copy = (ScanResult)MemberwiseClone();
        copy.Inventory = [];
        return copy;
    }
}
