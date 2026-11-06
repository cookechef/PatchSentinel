using PatchSentinel.Core.Rules;

namespace PatchSentinel.Core.Browsers;

public enum Browser { Chrome, Edge, Brave, Firefox }

public enum ExtensionStatus
{
    UpToDate,
    /// <summary>The store has a newer version than the one installed.</summary>
    UpdateAvailable,
    /// <summary>Manifest V2 extension: no longer supported by Chrome/Edge and disabled by the browser.</summary>
    RetiredManifestV2,
    /// <summary>Was installed from the store but is no longer listed there (removed, often for malware or abandonment).</summary>
    RemovedFromStore,
    /// <summary>Firefox: blocked by Mozilla's blocklist.</summary>
    Blocklisted,
    /// <summary>Installed outside the store (sideloaded or developer mode) - never updated automatically.</summary>
    NotFromStore,
    /// <summary>Store could not be checked (offline or not a public listing).</summary>
    Unknown,
}

public sealed class BrowserExtension
{
    public Browser Browser { get; set; }
    public string UserName { get; set; } = "";
    public string Profile { get; set; } = "";
    public string ProfilePath { get; set; } = "";
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Version { get; set; }
    public string? LatestVersion { get; set; }
    public int? ManifestVersion { get; set; }
    public bool Enabled { get; set; } = true;
    /// <summary>Store, Policy, Sideloaded, Developer (unpacked), Built-in.</summary>
    public string InstallSource { get; set; } = "Store";
    public string? UpdateUrl { get; set; }
    public DateTimeOffset? InstallDate { get; set; }
    public List<string> Permissions { get; set; } = [];
    public List<string> HostPermissions { get; set; } = [];
    /// <summary>Can read and change data on all websites.</summary>
    public bool BroadAccess { get; set; }
    public List<string> SensitivePermissions { get; set; } = [];
    public bool BlockedByPolicy { get; set; }
    /// <summary>PatchSentinel has asked the browser to uninstall it; waiting for the browser to restart.</summary>
    public bool PendingRemoval { get; set; }
    public bool FirefoxBlocklisted { get; set; }
    public bool FirefoxUnsigned { get; set; }

    public ExtensionStatus Status { get; set; } = ExtensionStatus.Unknown;
    public Concern Concern { get; set; } = Concern.Info;
    public string Advice { get; set; } = "";
    public string? StoreUrl { get; set; }

    public string BrowserName => Browser switch { Browser.Edge => "Microsoft Edge", Browser.Chrome => "Google Chrome", Browser.Brave => "Brave", _ => "Firefox" };

    public string StatusText => PendingRemoval ? "Uninstall pending (restart browser)" : BlockedByPolicy ? "Blocked by policy" : Status switch
    {
        ExtensionStatus.UpToDate => "Up to date",
        ExtensionStatus.UpdateAvailable => $"Update available ({LatestVersion})",
        ExtensionStatus.RetiredManifestV2 => "Retired (Manifest V2)",
        ExtensionStatus.RemovedFromStore => "Removed from the store",
        ExtensionStatus.Blocklisted => "Blocked by Mozilla",
        ExtensionStatus.NotFromStore => InstallSource == "Developer" ? "Developer mode (unpacked)" : "Not from the store",
        _ => "Not checked",
    };

    public string AccessText => BroadAccess ? "All websites" + (SensitivePermissions.Count > 0 ? $" + {string.Join(", ", SensitivePermissions)}" : "")
        : SensitivePermissions.Count > 0 ? string.Join(", ", SensitivePermissions) : HostPermissions.Count > 0 ? "Some websites" : "Limited";
}
