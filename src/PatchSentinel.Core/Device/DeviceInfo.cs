namespace PatchSentinel.Core.Device;

/// <summary>Hardware, network, OS and security facts about this PC, collected by the agent as SYSTEM.</summary>
public sealed class DeviceInfo
{
    public DateTimeOffset CollectedAt { get; set; }

    // Identity
    public string ComputerName { get; set; } = "";
    public string? Domain { get; set; }
    public bool PartOfDomain { get; set; }
    public bool EntraJoined { get; set; }
    public bool DomainJoined { get; set; }
    public string? TenantName { get; set; }
    public string? OrganisationalUnit { get; set; }

    // Hardware
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    /// <summary>Friendly product name where the model is a code (e.g. Lenovo "ThinkPad T14 Gen 3").</summary>
    public string? ProductName { get; set; }
    public string? SystemSku { get; set; }
    public string? SerialNumber { get; set; }
    public string? BiosVersion { get; set; }
    public string? BiosDate { get; set; }
    public string? ChassisTypes { get; set; }
    public string? CpuName { get; set; }
    public int? CpuCores { get; set; }
    public int? CpuThreads { get; set; }
    public double? RamGB { get; set; }
    public List<RamModule> RamModules { get; set; } = [];
    public List<LogicalDisk> Volumes { get; set; } = [];
    public List<PhysicalDisk> Disks { get; set; } = [];

    // Age
    public int? CpuReleaseYear { get; set; }
    public string? AgeEstimate { get; set; }
    public bool? Windows11CpuSupported { get; set; }

    // Operating system
    public string? OsCaption { get; set; }
    public string? OsVersion { get; set; }
    public string? OsBuild { get; set; }
    public int? OsUbr { get; set; }
    public string? OsDisplayVersion { get; set; }
    public string? OsEdition { get; set; }
    public string? OsArchitecture { get; set; }
    public string? OsInstallDate { get; set; }
    public string? LastBoot { get; set; }
    public string? LastWindowsUpdate { get; set; }
    public bool RebootPending { get; set; }
    public List<HotfixInfo> RecentHotfixes { get; set; } = [];

    // Network
    public string? PublicIp { get; set; }
    public List<NetworkAdapterInfo> Network { get; set; } = [];

    // Security
    public List<SecurityProduct> Antivirus { get; set; } = [];
    public List<SecurityProduct> FirewallProducts { get; set; } = [];
    public List<FirewallProfile> FirewallProfiles { get; set; } = [];
    public DefenderStatus? Defender { get; set; }
    public List<BitLockerVolume> BitLocker { get; set; } = [];
    public bool? TpmPresent { get; set; }
    public string? TpmVersion { get; set; }
    public bool? SecureBoot { get; set; }

    // Accounts / drivers / tools
    public List<LocalAccount> LocalAccounts { get; set; } = [];
    public List<ProblemDevice> ProblemDevices { get; set; } = [];
    public List<OemToolStatus> OemTools { get; set; } = [];

    public List<string> Warnings { get; set; } = [];

    public string MakeModel => string.Join(' ', new[] { Manufacturer, string.IsNullOrWhiteSpace(ProductName) ? Model : ProductName }
        .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct());

    public string OsSummary => $"{OsCaption}{(string.IsNullOrEmpty(OsDisplayVersion) ? "" : $" {OsDisplayVersion}")} (build {OsBuild}{(OsUbr is { } u ? $".{u}" : "")})".Trim();

    public string PrivateIps => string.Join(", ", Network.SelectMany(n => n.IPv4).Distinct());
}

public sealed class RamModule { public double? CapacityGB { get; set; } public int? Speed { get; set; } public string? Manufacturer { get; set; } }
public sealed class LogicalDisk { public string? Name { get; set; } public double? SizeGB { get; set; } public double? FreeGB { get; set; } public string? FileSystem { get; set; } }
public sealed class PhysicalDisk { public string? Model { get; set; } public string? MediaType { get; set; } public string? BusType { get; set; } public double? SizeGB { get; set; } public string? Health { get; set; } }
public sealed class HotfixInfo { public string? Id { get; set; } public string? InstalledOn { get; set; } }

public sealed class NetworkAdapterInfo
{
    public string? Alias { get; set; }
    public string? Description { get; set; }
    public string? Mac { get; set; }
    public List<string> IPv4 { get; set; } = [];
    public List<string> Gateway { get; set; } = [];
    public List<string> Dns { get; set; } = [];
    public bool Dhcp { get; set; }
    /// <summary>DNS servers typed in by hand on this adapter (rather than from DHCP).</summary>
    public bool StaticDns { get; set; }

    private static readonly System.Text.RegularExpressions.Regex VirtualAdapter = new(
        @"WARP|Cloudflare|WireGuard|TAP-Windows|OpenVPN|Wintun|Zscaler|Check Point|Fortinet|FortiClient|PANGP|GlobalProtect|AnyConnect|Cisco Secure|" +
        @"Juniper|Pulse|Ivanti|SonicWall|NetExtender|WatchGuard|Netskope|Tailscale|ZeroTier|NordLynx|Hyper-V|vEthernet|VMware|VirtualBox|Npcap|Loopback",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Compiled);

    /// <summary>Static DNS that is expected: loopback resolvers (127.x / ::1) or a VPN / secure-access / virtual adapter.</summary>
    public bool StaticDnsExpected =>
        (Dns.Count > 0 && Dns.All(d => d is not null && (d.StartsWith("127.", StringComparison.Ordinal) || d == "::1")))
        || VirtualAdapter.IsMatch($"{Alias} {Description}");

    /// <summary>Static DNS a technician should remove (set by hand on a normal network adapter).</summary>
    public bool StaticDnsToFix => StaticDns && !StaticDnsExpected;
}

public sealed class SecurityProduct
{
    public string? Name { get; set; }
    public int? ProductState { get; set; }
    public bool? Enabled { get; set; }
    public bool? UpToDate { get; set; }
}

public sealed class FirewallProfile { public string? Name { get; set; } public bool Enabled { get; set; } }

public sealed class DefenderStatus
{
    public bool? AntivirusEnabled { get; set; }
    public bool? RealTimeProtection { get; set; }
    public string? SignaturesUpdated { get; set; }
    public string? RunningMode { get; set; }
}

public sealed class BitLockerVolume
{
    public string? Drive { get; set; }
    public string? VolumeStatus { get; set; }
    public string? Protection { get; set; }
    public string? Method { get; set; }
    public double? Percent { get; set; }
    public List<string> Protectors { get; set; } = [];
    public bool IsOsVolume { get; set; }
}

public sealed class LocalAccount
{
    public string? Name { get; set; }
    public bool Enabled { get; set; }
    public bool IsAdmin { get; set; }
    public string? LastLogon { get; set; }
    public bool BuiltIn { get; set; }
}

public sealed class ProblemDevice { public string? Name { get; set; } public int? ErrorCode { get; set; } public string? Class { get; set; } }

/// <summary>Manufacturer driver/update tool (Dell Command | Update, Lenovo Vantage, HP Support Assistant, Intel DSA...).</summary>
public sealed class OemToolStatus
{
    public string Vendor { get; set; } = "";
    public string Tool { get; set; } = "";
    public bool Applicable { get; set; }
    public bool Installed { get; set; }
    public string? InstalledName { get; set; }
    public string? InstalledVersion { get; set; }
    /// <summary>Newest log/data file written by the tool - evidence it has actually run.</summary>
    public DateTimeOffset? LastActivity { get; set; }
    public string? DownloadUrl { get; set; }
}

public enum CheckStatus { Pass, Warn, Fail, Info, Manual }

public sealed class BuildCheckResult
{
    public int Step { get; set; }
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public CheckStatus Status { get; set; }
    public string Detail { get; set; } = "";
    /// <summary>Buttons that apply to this step on this device.</summary>
    public List<BuildActionView> Actions { get; set; } = [];
    /// <summary>A technician's sign-off for this step (checked or not required), if any.</summary>
    public BuildSignoff? Signoff { get; set; }
}
