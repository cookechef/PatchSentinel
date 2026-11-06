using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Device;

/// <summary>
/// Collects device information with one PowerShell/CIM script (no extra libraries needed), then adds the public IP,
/// CPU age estimate and manufacturer driver tool status.
/// </summary>
public static class DeviceCollector
{
    /// <param name="ModelPattern">Regex on the model/product name; empty = any model (the fallback for that make).</param>
    /// <param name="LegacyAppPattern">An older tool that still works but is not the one to use on this model.</param>
    /// <param name="Files">Program files that mean the tool is installed (for tools with no Add/Remove Programs entry).</param>
    private sealed record OemToolDef(string Vendor, string Tool, string ManufacturerPattern, string ModelPattern, string AppPattern, string[] Folders,
        string[] StoreApps, string DownloadUrl, string? MinVersion = null, string? LegacyAppPattern = null, string? LegacyName = null, string[]? Files = null);

    public const string HpBusinessModels = @"Elite|ProBook|ProDesk|ProOne|ZBook|Dragonfly|\bZ\d|\bHP Pro\b|\bmt\d{2}|\bt\d{3}\b";

    private static readonly string[] DellCommandFolders = [@"Dell\UpdateService\Log", @"Dell\CommandUpdate", @"Dell\UpdateService\Service"];

    /// <summary>
    /// Which tool each make and model range should use. Dell business models (Latitude, OptiPlex, Precision, XPS, Pro,
    /// Pro Max) use Dell Command | Update; consumer models (Inspiron, Vostro, Alienware, Dell Plus/Premium) use
    /// SupportAssist. Lenovo Think models use Commercial Vantage (System Update is the older tool); IdeaPad, Yoga,
    /// Legion and LOQ use Lenovo Vantage.
    /// </summary>
    private static readonly OemToolDef[] OemTools =
    [
        new("Dell", "Dell Command | Update", "Dell", @"Latitude|OptiPlex|Precision|XPS|Rugged|Wyse|\bPro\b|Pro Max",
            @"Dell Command \| Update|Dell Command Update", DellCommandFolders, [],
            "https://www.dell.com/support/kbdoc/000177325/dell-command-update", MinVersion: "5.0"),
        new("Dell", "Dell SupportAssist", "Dell", @"Inspiron|Vostro|Alienware|\bG1[5-6]\b|\bPlus\b|\bPremium\b|Dell (?:14|15|16)\b",
            @"SupportAssist|Dell Update", [@"Dell\SARemediation", @"Dell\SupportAssist", @"SupportAssist", @"Dell\UpdateService\Log"], [],
            "https://www.dell.com/support/assist", MinVersion: "4.0",
            LegacyAppPattern: @"Dell Command \| Update", LegacyName: "Dell Command | Update"),
        new("Dell", "Dell Command | Update or SupportAssist", "Dell", "",
            @"Dell Command \| Update|Dell Command Update|SupportAssist|Dell Update", [.. DellCommandFolders, @"Dell\SARemediation", @"Dell\SupportAssist"], [],
            "https://www.dell.com/support/kbdoc/000177325/dell-command-update"),

        new("Lenovo", "Lenovo Commercial Vantage", "Lenovo", @"Think",
            @"Lenovo Commercial Vantage", [@"Lenovo\Commercial Vantage", @"Lenovo\Vantage", @"Lenovo\ImController\Logs", @"Lenovo\SUHelper"],
            ["E046963F.LenovoSettingsforEnterprise_*"],
            "https://support.lenovo.com/solutions/hf003321",
            LegacyAppPattern: @"Lenovo System Update|Lenovo Vantage(?! Service)", LegacyName: "Lenovo System Update or Lenovo Vantage"),
        new("Lenovo", "Lenovo Vantage", "Lenovo", @"IdeaPad|IdeaCentre|Yoga|Legion|LOQ|\bV1[45]\b|\bV\d{2}\b",
            @"Lenovo Vantage(?! Service)", [@"Lenovo\Vantage", @"Lenovo\ImController\Logs"], ["E046963F.LenovoCompanion_*"],
            "https://www.lenovo.com/gb/en/software/vantage"),
        new("Lenovo", "Lenovo Vantage / System Update", "Lenovo", "",
            @"Lenovo (?:Commercial )?Vantage|Lenovo System Update|Lenovo Vantage Service",
            [@"Lenovo\SystemUpdate", @"Lenovo\Vantage", @"Lenovo\Commercial Vantage", @"Lenovo\ImController\Logs"],
            ["E046963F.LenovoCompanion_*", "E046963F.LenovoSettingsforEnterprise_*"],
            "https://support.lenovo.com/solutions/ht037099"),

        new("HP", "HP Image Assistant", "^HP|Hewlett", HpBusinessModels, @"HP Image Assistant",
            [@"PatchSentinel\logs\hpia", @"HP\HPIA"], [], "https://ftp.ext.hp.com/pub/caps-softpaq/cmit/HPIA.html",
            LegacyAppPattern: @"HP Support Assistant", LegacyName: "HP Support Assistant",
            Files: [@"%ProgramFiles%\HP\HPImageAssistant\HPImageAssistant.exe", @"C:\SWSetup\HPImageAssistant\HPImageAssistant.exe"]),
        new("HP", "HP Support Assistant", "^HP|Hewlett", "", @"HP Support Assistant|HP Support Solutions Framework|HP Image Assistant",
            [@"HP\HP Support Framework", @"Hewlett-Packard\HP Support Framework", @"HP\HPIA"],
            ["AD2F1837.HPSupportAssistant_*", "AD2F1837.myHP_*"],
            "https://support.hp.com/gb-en/help/hp-support-assistant"),
        new("ASUS", "MyASUS", "ASUS", "", @"MyASUS|ASUS System Control Interface", [@"ASUS\ASUS System Control Interface"], ["B9ECED6F.MyASUS_*"],
            "https://www.asus.com/supportonly/myasus/"),
        new("Acer", "Acer Care Center", "Acer", "", @"Acer Care Center|AcerCareCenter|Acer Product Registration", [@"Acer\Care Center"], ["AcerIncorporated.AcerCareCenterS_*"],
            "https://www.acer.com/gb-en/support"),
    ];

    private static readonly OemToolDef IntelDsa = new("Intel", "Intel Driver & Support Assistant", "", "", @"Intel(?:\(R\)|®)? Driver (?:&|and) Support Assistant",
        [@"Intel\Driver and Support Assistant", @"Intel\DSA"], [], "https://www.intel.com/content/www/us/en/support/detect.html");

    public static async Task<DeviceInfo> CollectAsync(IReadOnlyList<InstalledItem> inventory, bool lookupPublicIp, DateOnly today, CancellationToken ct)
    {
        var info = await RunScriptAsync(ct) ?? new DeviceInfo { ComputerName = Environment.MachineName, Warnings = ["Device details could not be read (PowerShell failed)."] };
        info.CollectedAt = DateTimeOffset.Now;
        if (string.IsNullOrEmpty(info.ComputerName)) info.ComputerName = Environment.MachineName;

        foreach (var av in info.Antivirus.Concat(info.FirewallProducts)) DecodeState(av);
        var (year, gen, win11) = CpuAge.Estimate(info.CpuName);
        info.CpuReleaseYear = year;
        info.Windows11CpuSupported = win11;
        info.AgeEstimate = CpuAge.Describe(year, gen, today);

        info.OemTools = DetectOemTools(info, inventory);
        if (lookupPublicIp) info.PublicIp = await PublicIpAsync(ct);
        return info;
    }

    // ---------------- PowerShell ----------------

    private const string Script = """
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
function D($d) { if ($d) { try { return ([datetime]$d).ToString('yyyy-MM-dd') } catch { return $null } } return $null }
function DT($d) { if ($d) { try { return ([datetime]$d).ToString('yyyy-MM-ddTHH:mm:ss') } catch { return $null } } return $null }
$r = [ordered]@{}
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$os = Get-CimInstance Win32_OperatingSystem
$csp = Get-CimInstance Win32_ComputerSystemProduct
$cpu = @(Get-CimInstance Win32_Processor)
$r.computerName = $env:COMPUTERNAME
$r.domain = $cs.Domain
$r.partOfDomain = [bool]$cs.PartOfDomain
$ds = (dsregcmd /status) | Out-String
$r.entraJoined = $ds -match 'AzureAdJoined\s*:\s*YES'
$r.domainJoined = $ds -match 'DomainJoined\s*:\s*YES'
if ($ds -match 'TenantName\s*:\s*(.+)') { $r.tenantName = $Matches[1].Trim() }
$r.organisationalUnit = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine').'Distinguished-Name'
$r.manufacturer = "$($cs.Manufacturer)".Trim()
$r.model = "$($cs.Model)".Trim()
$r.productName = "$($csp.Version)".Trim()
$r.systemSku = "$($cs.SystemSKUNumber)".Trim()
$r.serialNumber = "$($bios.SerialNumber)".Trim()
$r.biosVersion = "$($bios.SMBIOSBIOSVersion)".Trim()
$r.biosDate = D $bios.ReleaseDate
$r.chassisTypes = (@((Get-CimInstance Win32_SystemEnclosure).ChassisTypes) -join ',')
$r.cpuName = ("$(($cpu | Select-Object -First 1).Name)" -replace '\s+', ' ').Trim()
$r.cpuCores = [int](($cpu | Measure-Object NumberOfCores -Sum).Sum)
$r.cpuThreads = [int](($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum)
$r.ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
$r.ramModules = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object { [ordered]@{ capacityGB = [math]::Round($_.Capacity / 1GB, 1); speed = [int]$_.Speed; manufacturer = "$($_.Manufacturer)".Trim() } })
$r.volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { [ordered]@{ name = $_.DeviceID; sizeGB = [math]::Round($_.Size / 1GB, 1); freeGB = [math]::Round($_.FreeSpace / 1GB, 1); fileSystem = $_.FileSystem } })
$r.disks = @(Get-PhysicalDisk | ForEach-Object { [ordered]@{ model = "$($_.FriendlyName)".Trim(); mediaType = "$($_.MediaType)"; busType = "$($_.BusType)"; sizeGB = [math]::Round($_.Size / 1GB, 1); health = "$($_.HealthStatus)" } })
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$r.osCaption = "$($os.Caption)".Trim()
$r.osVersion = $os.Version
$r.osBuild = $os.BuildNumber
$r.osUbr = [int]$cv.UBR
$r.osDisplayVersion = $cv.DisplayVersion
$r.osEdition = $cv.EditionID
$r.osArchitecture = $os.OSArchitecture
$r.osInstallDate = D $os.InstallDate
$r.lastBoot = DT $os.LastBootUpTime
try { $r.lastWindowsUpdate = DT ((New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate) } catch {}
$r.rebootPending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$r.recentHotfixes = @(Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ id = $_.HotFixID; installedOn = D $_.InstalledOn } })
$r.network = @(Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' } | ForEach-Object {
  $guid = $_.NetAdapter.InterfaceGuid
  $ns = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid").NameServer
  [ordered]@{
    alias = $_.InterfaceAlias; description = $_.InterfaceDescription; mac = $_.NetAdapter.MacAddress
    iPv4 = @($_.IPv4Address | ForEach-Object { $_.IPAddress })
    gateway = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
    dns = @($_.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object { $_.ServerAddresses })
    dhcp = ("$((Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).Dhcp)" -eq 'Enabled')
    staticDns = [bool]("$ns".Trim())
  } })
$r.antivirus = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { [ordered]@{ name = $_.displayName; productState = [int]$_.productState } })
$r.firewallProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | ForEach-Object { [ordered]@{ name = $_.displayName; productState = [int]$_.productState } })
$r.firewallProfiles = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = "$($_.Name)"; enabled = ("$($_.Enabled)" -eq 'True') } })
$mp = Get-MpComputerStatus
if ($mp) { $r.defender = [ordered]@{ antivirusEnabled = [bool]$mp.AntivirusEnabled; realTimeProtection = [bool]$mp.RealTimeProtectionEnabled; signaturesUpdated = D $mp.AntivirusSignatureLastUpdated; runningMode = "$($mp.AMRunningMode)" } }
$bl = @(Get-BitLockerVolume)
if ($bl.Count -gt 0) {
  $r.bitLocker = @($bl | ForEach-Object { [ordered]@{ drive = $_.MountPoint; volumeStatus = "$($_.VolumeStatus)"; protection = "$($_.ProtectionStatus)"; method = "$($_.EncryptionMethod)"; percent = [double]$_.EncryptionPercentage; protectors = @($_.KeyProtector | ForEach-Object { "$($_.KeyProtectorType)" }); isOsVolume = ("$($_.VolumeType)" -eq 'OperatingSystem') } })
} else {
  $r.bitLocker = @(Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume | ForEach-Object { [ordered]@{ drive = $_.DriveLetter; protection = $(if ($_.ProtectionStatus -eq 1) { 'On' } elseif ($_.ProtectionStatus -eq 0) { 'Off' } else { 'Unknown' }); isOsVolume = ($_.DriveLetter -eq $env:SystemDrive) } })
}
$tpm = Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm
$r.tpmPresent = [bool]$tpm
if ($tpm) { $r.tpmVersion = ("$($tpm.SpecVersion)" -split ',')[0].Trim() }
try { $r.secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $r.secureBoot = $null }
$admins = @()
try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { ("$($_.Name)" -split '\\')[-1] }) } catch { $admins = @((net localgroup administrators) | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'completed' } | ForEach-Object { ("$_" -split '\\')[-1].Trim() }) }
$r.localAccounts = @(Get-LocalUser | ForEach-Object { [ordered]@{ name = $_.Name; enabled = [bool]$_.Enabled; isAdmin = ($admins -contains $_.Name); lastLogon = D $_.LastLogon; builtIn = ("$($_.SID)" -match '-50[0-4]$') } })
$r.problemDevices = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 22 } | Select-Object -First 50 | ForEach-Object { [ordered]@{ name = "$($_.Name)"; errorCode = [int]$_.ConfigManagerErrorCode; class = "$($_.PNPClass)" } })
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$r | ConvertTo-Json -Depth 6 -Compress
""";

    private static async Task<DeviceInfo?> RunScriptAsync(CancellationToken ct)
    {
        try
        {
            var ps = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(ps)) return null;
            var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(Script));
            var r = await ProcessRunner.RunAsync(ps, $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}", TimeSpan.FromMinutes(2), ct);
            var json = r.StdOut.Trim();
            var start = json.IndexOf('{');
            if (start < 0) { AppLog.Warn($"Device script produced no data: {r.StdErr.Trim()}"); return null; }
            return JsonSerializer.Deserialize<DeviceInfo>(json[start..], Json.Options);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            AppLog.Warn($"Device information could not be collected: {ex.Message}");
            return null;
        }
    }

    /// <summary>Security Center productState: byte 2 = 0x10/0x11 when enabled, byte 1 = 0x00 when definitions are up to date.</summary>
    private static void DecodeState(SecurityProduct p)
    {
        if (p.ProductState is not { } s) return;
        var enabledByte = (s >> 8) & 0xFF;
        p.Enabled = enabledByte is 0x10 or 0x11;
        p.UpToDate = (s & 0xFF) == 0x00;
    }

    // ---------------- manufacturer tools ----------------

    public static List<OemToolStatus> DetectOemTools(DeviceInfo info, IReadOnlyList<InstalledItem> inventory)
    {
        var list = new List<OemToolStatus>();
        var maker = info.Manufacturer ?? "";
        var model = BuildActions.ModelText(info);
        foreach (var vendor in OemTools.GroupBy(d => d.Vendor))
        {
            var applicable = Regex.IsMatch(maker, vendor.First().ManufacturerPattern, RegexOptions.IgnoreCase);
            // The tool for this model range, else the make's fallback.
            var def = vendor.FirstOrDefault(d => d.ModelPattern.Length > 0 && Regex.IsMatch(model, d.ModelPattern, RegexOptions.IgnoreCase))
                      ?? vendor.FirstOrDefault(d => d.ModelPattern.Length == 0) ?? vendor.First();
            var status = Detect(def, inventory);
            if (!applicable && !status.Installed)
            {
                // A different make's tool left on the device (e.g. an imaged PC): report it if any of its tools is installed.
                var any = vendor.Select(d => Detect(d, inventory)).FirstOrDefault(t => t.Installed);
                if (any is null) continue;
                status = any;
            }
            status.Applicable = applicable;
            if (def.LegacyAppPattern is { } legacy)
            {
                var rx = new Regex(legacy, RegexOptions.IgnoreCase);
                status.LegacyInstalled = inventory.FirstOrDefault(i => i.Source == ItemSource.Registry && rx.IsMatch(i.Name))?.Name;
                status.LegacyName = def.LegacyName;
            }
            list.Add(status);
        }
        // Surface (and other Microsoft hardware) gets drivers and firmware through Windows Update.
        if (Regex.IsMatch(maker, "^Microsoft", RegexOptions.IgnoreCase) && Regex.IsMatch(model, "Surface", RegexOptions.IgnoreCase))
            list.Add(new OemToolStatus
            {
                Vendor = "Microsoft", Tool = "Windows Update", Applicable = true, Installed = true, BuiltIn = true,
                InstalledName = "Windows Update (Surface drivers and firmware)",
                DownloadUrl = "https://support.microsoft.com/surface/download-drivers-and-firmware-for-surface",
            });

        var intel = Detect(IntelDsa, inventory);
        intel.Applicable = info.CpuName?.Contains("Intel", StringComparison.OrdinalIgnoreCase) == true;
        if (intel.Applicable || intel.Installed) list.Add(intel);
        return list;
    }

    private static OemToolStatus Detect(OemToolDef def, IReadOnlyList<InstalledItem> inventory)
    {
        var rx = new Regex(def.AppPattern, RegexOptions.IgnoreCase);
        var app = inventory.FirstOrDefault(i => i.Source == ItemSource.Registry && rx.IsMatch(i.Name));
        var storeApp = def.StoreApps.Length > 0 ? FindStoreApp(def.StoreApps) : null;
        var file = def.Files?.Select(BuildActions.Expand).FirstOrDefault(File.Exists);
        if (app is null && storeApp is null && file is not null)
        {
            string? ver = null;
            try { ver = System.Diagnostics.FileVersionInfo.GetVersionInfo(file).ProductVersion; } catch { /* ignore */ }
            app = new InstalledItem { Name = def.Tool, Version = ver };
        }
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return new OemToolStatus
        {
            Vendor = def.Vendor,
            Tool = def.Tool,
            Installed = app is not null || storeApp is not null,
            InstalledName = storeApp ?? app?.Name,
            InstalledVersion = storeApp is null ? app?.Version : null,
            MinVersion = def.MinVersion,
            LastActivity = NewestWrite(def.Folders.Select(f => Path.Combine(programData, f))),
            DownloadUrl = def.DownloadUrl,
        };
    }

    private static string? FindStoreApp(string[] patterns)
    {
        try
        {
            var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
            foreach (var p in patterns)
            {
                var hit = Directory.GetDirectories(root, p).FirstOrDefault();
                if (hit is not null) return Path.GetFileName(hit).Split('_')[0] + " (Microsoft Store app)";
            }
        }
        catch { /* only SYSTEM/admins can list WindowsApps */ }
        return null;
    }

    private static DateTimeOffset? NewestWrite(IEnumerable<string> folders)
    {
        DateTime? newest = null;
        var opts = new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 3, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
        foreach (var f in folders.Where(Directory.Exists))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(f, "*", opts).Take(3000))
                {
                    var t = File.GetLastWriteTime(file);
                    if (newest is null || t > newest) newest = t;
                }
            }
            catch { /* ignore */ }
        }
        return newest is null ? null : new DateTimeOffset(newest.Value);
    }

    // ---------------- public IP ----------------

    private static async Task<string?> PublicIpAsync(CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(6) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd($"PatchSentinel/{AppPaths.Version}");
            var text = (await http.GetStringAsync("https://api.ipify.org", ct)).Trim();
            return IPAddress.TryParse(text, out _) ? text : null;
        }
        catch { return null; }
    }
}
