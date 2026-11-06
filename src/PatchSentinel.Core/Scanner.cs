using System.Runtime.InteropServices;
using PatchSentinel.Core.Config;
using PatchSentinel.Core.Inventory;
using PatchSentinel.Core.Remediation;
using PatchSentinel.Core.Rules;
using PatchSentinel.Core.Updates;

namespace PatchSentinel.Core;

public sealed class ScanOptions
{
    public bool IncludeUpdates { get; set; } = true;
    public bool AllowNetwork { get; set; } = true;
    public bool ScanDependencies { get; set; } = true;
    public bool CollectDevice { get; set; } = true;
    public bool CheckExtensions { get; set; } = true;
    public DateOnly? Today { get; set; }
}

/// <summary>One complete pass: inventory, EOL rules, dependency check, remediation plan and available winget updates.</summary>
public static class Scanner
{
    public static async Task<ScanResult> ScanAsync(EffectiveSettings eff, ScanOptions opt, CancellationToken ct)
    {
        var s = eff.Settings;
        var warnings = new List<string>();
        var isSystem = Platform.IsSystem;
        var today = opt.Today ?? DateOnly.FromDateTime(DateTime.Now);

        var inventory = new List<InstalledItem>();
        inventory.AddRange(RegistryInventory.Collect(allLoadedUserHives: isSystem, Platform.CurrentUserSid, warnings));
        inventory.AddRange(DotNetInventory.Collect(warnings));

        var catalog = RuleCatalogLoader.Load(AppPaths.RulesDir, warnings);
        var eolProvider = new EolDataProvider(CacheDirFor(isSystem));
        var products = catalog.Rules.Where(r => !r.Disabled && r.EndOfLifeProduct is not null).Select(r => r.EndOfLifeProduct!);
        var online = s.UseEndOfLifeApi
            ? await eolProvider.GetAsync(products, opt.AllowNetwork, warnings, ct)
            : new Dictionary<string, List<RuleCycle>>();

        inventory = new SoftwareClassifier(catalog.Categories, warnings).Apply(inventory);
        var findings = RuleEngine.Evaluate(inventory, catalog, online, today, s.NearingEolWarningDays, warnings);

        var winget = WingetClient.TryCreate(isSystem);
        var refs = new List<RuntimeConfigReference>();
        if (opt.ScanDependencies && findings.Any(f => f.Items.Any(i => i.Source == ItemSource.DotNetSharedFramework)))
        {
            var roots = DotNetDependencyScanner.DefaultRoots(allUsers: isSystem, s.ExtraDependencyScanPaths);
            var dotnetRoots = DotNetInventory.GetRoots().Select(r => r.Root).ToList();
            refs = await Task.Run(() => DotNetDependencyScanner.Scan(roots, dotnetRoots, TimeSpan.FromSeconds(Math.Clamp(s.DependencyScanBudgetSeconds, 10, 900)), warnings, ct), ct);
        }

        var rulesById = catalog.Rules.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
            RemediationPlanner.Plan(f, rulesById.GetValueOrDefault(f.RuleId), inventory, refs, winget is not null);

        Device.DeviceInfo? device = null;
        var checks = new List<Device.BuildCheckResult>();
        if (s.CollectDeviceInfo && opt.CollectDevice)
        {
            device = await Device.DeviceCollector.CollectAsync(inventory, s.PublicIpLookup && opt.AllowNetwork, today, ct);
            warnings.AddRange(device.Warnings);
            if (catalog.BuildChecklist.Count > 0) checks = Device.BuildChecklist.Evaluate(catalog.BuildChecklist, device, inventory, today, catalog.Links);
        }

        var signoffs = Device.BuildSignoffStore.Load();
        Device.BuildSignoffStore.Apply(checks, signoffs);

        var extensions = s.ScanBrowserExtensions && opt.CheckExtensions
            ? await ScanExtensionsAsync(s.ExtensionStoreLookup && opt.AllowNetwork, isSystem, warnings, ct)
            : [];

        var updates = new List<UpdateCandidate>();
        if (opt.IncludeUpdates)
        {
            if (winget is null)
                warnings.Add("winget (App Installer) was not found, so application updates could not be checked. Install 'App Installer' from the Microsoft Store or via your RMM.");
            else
            {
                try { updates = ExclusionMatcher.Apply(await winget.ListUpgradesAsync(ct), s.ExcludedPackageIds, eff.PolicyExcludedPackageIds); }
                catch (Exception ex) when (ex is not OperationCanceledException) { warnings.Add($"winget update check failed: {ex.Message}"); }
            }
        }

        return new ScanResult
        {
            ScannedAt = DateTimeOffset.Now,
            ComputerName = Environment.MachineName,
            OsDescription = RuntimeInformation.OSDescription,
            AgentVersion = AppPaths.Version,
            RulesVersion = catalog.CatalogVersion,
            OnlineEolData = eolProvider.UsedOnlineData,
            WingetAvailable = winget is not null,
            ScanContext = isSystem ? "SYSTEM (all users)" : $"{Environment.UserName}{(Platform.IsElevated ? " (elevated)" : "")}",
            Findings = findings,
            Updates = updates.OrderBy(u => u.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            Inventory = inventory,
            Device = device,
            BuildChecks = checks,
            BuildHandover = signoffs.Handover,
            Extensions = extensions,
            Warnings = warnings.Distinct().ToList(),
        };
    }

    /// <summary>Uninstalls the browsers finished during the last extension scan (the agent records them in the history).</summary>
    public static List<Browsers.PendingRemoval> LastCompletedRemovals { get; private set; } = [];

    public static async Task<List<Browsers.BrowserExtension>> ScanExtensionsAsync(bool online, bool isSystem, List<string> warnings, CancellationToken ct)
    {
        Browsers.ExtensionChecker.CacheDir = CacheDirFor(isSystem);
        var allUsers = isSystem || Platform.IsElevated;
        var list = await Task.Run(() => Browsers.ExtensionInventory.Collect(allUsers, warnings), ct);
        LastCompletedRemovals = [];
        if (allUsers)
        {
            try { LastCompletedRemovals = Browsers.ExtensionPolicy.CompletePendingRemovals(list); }
            catch (Exception ex) { warnings.Add($"Could not tidy up extension uninstall policies: {ex.Message}"); }
        }
        await Browsers.ExtensionChecker.CheckAsync(list, online, warnings, ct);
        return list.OrderByDescending(e => e.Concern).ThenBy(e => e.BrowserName).ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Non-admin users cannot write to ProgramData\PatchSentinel, so they cache under LocalAppData.</summary>
    private static string CacheDirFor(bool isSystem)
    {
        if (isSystem || Platform.IsElevated) return AppPaths.CacheDir;
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PatchSentinel", "cache");
    }
}
