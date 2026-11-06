using PatchSentinel.Core;
using PatchSentinel.Core.Config;
using PatchSentinel.Core.Remediation;
using PatchSentinel.Core.Rules;
using PatchSentinel.Core.Updates;
using Xunit;

namespace PatchSentinel.Core.Tests;

public class VersionTests
{
    [Fact]
    public void Cycle_matching_is_component_based()
    {
        Assert.True(VersionUtil.MatchesCycle("3.1.32", "3.1"));
        Assert.False(VersionUtil.MatchesCycle("3.10.4", "3.1"));
        Assert.True(VersionUtil.MatchesCycle("6.0.36", "6"));
        Assert.True(VersionUtil.MatchesCycle("8.0.11", "8.0"));
        Assert.False(VersionUtil.MatchesCycle("10.0.1", "1"));
    }

    [Fact]
    public void Compare_treats_missing_parts_as_zero()
    {
        Assert.Equal(0, VersionUtil.Compare("7.4.6.0", "7.4.6"));
        Assert.True(VersionUtil.Compare("8.0.11", "8.0.21") < 0);
        Assert.True(VersionUtil.Compare("10.0.0", "9.0.9") > 0);
    }

    [Fact]
    public void Template_expands_major_and_minor()
    {
        Assert.Equal("Microsoft.DotNet.Runtime.8", VersionUtil.ApplyTemplate("Microsoft.DotNet.Runtime.{major}", "8.0.11"));
        Assert.Equal("Python.Python.3.12", VersionUtil.ApplyTemplate("Python.Python.{major}.{minor}", "3.12.4"));
    }
}

public class RuleEngineTests
{
    private static readonly DateOnly Today = new(2026, 11, 5);

    private static InstalledItem Shared(string fw, string v, string arch = "x64") => new()
    {
        Name = fw, Version = v, Source = ItemSource.DotNetSharedFramework, Architecture = arch,
        InstallLocation = Path.Combine("C:", "Program Files", "dotnet", "shared", fw, v),
    };

    private static List<Finding> Evaluate(params InstalledItem[] items) =>
        RuleEngine.Evaluate(items, RuleCatalogLoader.LoadEmbedded(), new Dictionary<string, List<RuleCycle>>(), Today, 90);

    [Fact]
    public void Embedded_catalogue_is_valid()
    {
        var c = RuleCatalogLoader.LoadEmbedded();
        Assert.True(c.Rules.Count >= 15);
        Assert.Contains(c.Rules, r => r.Id == "dotnet-runtime");
    }

    [Fact]
    public void Dotnet6_and_7_are_end_of_life()
    {
        var f = Evaluate(Shared("Microsoft.NETCore.App", "6.0.5"), Shared("Microsoft.NETCore.App", "6.0.36"), Shared("Microsoft.NETCore.App", "7.0.20"));
        var six = Assert.Single(f, x => x.Id == "dotnet-runtime:6:EndOfLife");
        Assert.Equal(2, six.Items.Count);
        Assert.Equal(Severity.Critical, six.Severity);
        Assert.Single(f, x => x.Id == "dotnet-runtime:7:EndOfLife");
    }

    [Fact]
    public void Dotnet8_is_flagged_as_nearing_end_of_life()
    {
        var f = Evaluate(Shared("Microsoft.NETCore.App", "8.0.11"));
        var near = Assert.Single(f, x => x.Kind == FindingKind.NearingEndOfLife);
        Assert.Equal(new DateOnly(2026, 11, 10), near.EolDate);
    }

    [Fact]
    public void Online_latest_patch_produces_outdated_finding()
    {
        var online = new Dictionary<string, List<RuleCycle>> { ["dotnet"] = [new RuleCycle { Cycle = "10", Eol = "2028-11-14", Latest = "10.0.5" }] };
        var f = RuleEngine.Evaluate([Shared("Microsoft.NETCore.App", "10.0.1"), Shared("Microsoft.NETCore.App", "10.0.5")],
            RuleCatalogLoader.LoadEmbedded(), online, Today, 90);
        var o = Assert.Single(f);
        Assert.Equal(FindingKind.OutdatedPatch, o.Kind);
        Assert.Equal("10.0.1", Assert.Single(o.Items).Version);
    }

    [Fact]
    public void Access_database_engine_2016_is_end_of_life()
    {
        var f = Evaluate(new InstalledItem { Name = "Microsoft Access database engine 2016 (English)", Version = "16.0.5044.1000", Source = ItemSource.Registry });
        Assert.Equal(FindingKind.EndOfLife, Assert.Single(f).Kind);
    }

    [Fact]
    public void Python_uses_version_from_name_not_display_version()
    {
        var f = Evaluate(new InstalledItem { Name = "Python 3.8.10 (64-bit)", Version = "3.8.10150.0", Source = ItemSource.Registry });
        Assert.Equal("python:3.8:EndOfLife", Assert.Single(f).Id);
    }

    [Fact]
    public void System_components_are_ignored_by_default()
    {
        var f = Evaluate(new InstalledItem { Name = "Microsoft Access database engine 2016 (English)", Source = ItemSource.Registry, IsSystemComponent = true });
        Assert.Empty(f);
    }
}

public class RollForwardTests
{
    [Fact]
    public void Default_minor_policy_does_not_cross_major()
    {
        Assert.False(RollForwardResolver.CanResolve("6.0.0", "Minor", ["8.0.11", "10.0.1"]));
        Assert.True(RollForwardResolver.CanResolve("6.0.0", "Minor", ["6.0.36"]));
        Assert.True(RollForwardResolver.CanResolve("6.0.0", "Major", ["8.0.11"]));
        Assert.False(RollForwardResolver.CanResolve("6.0.5", "Disable", ["6.0.36"]));
        Assert.True(RollForwardResolver.CanResolve("6.0.5", "LatestPatch", ["6.0.36"]));
    }

    [Fact]
    public void Dependents_are_marked_when_removal_would_break_them()
    {
        var six = new InstalledItem { Name = "Microsoft.NETCore.App", Version = "6.0.36", Source = ItemSource.DotNetSharedFramework, Architecture = "x64", InstallLocation = "a" };
        var eight = new InstalledItem { Name = "Microsoft.NETCore.App", Version = "8.0.11", Source = ItemSource.DotNetSharedFramework, Architecture = "x64", InstallLocation = "b" };
        var refs = new List<RuntimeConfigReference>
        {
            new("c1", "App1.exe", "Microsoft.NETCore.App", "6.0.0", "Minor", "x64", false),
            new("c2", "App2.exe", "Microsoft.NETCore.App", "6.0.0", "Major", "x64", false),
            new("c3", "App3.exe", "Microsoft.NETCore.App", "8.0.0", "Minor", "x64", false),
        };
        var deps = RemediationPlanner.FindDependents([six], [six, eight], refs);
        Assert.Equal(2, deps.Count);
        Assert.True(deps.Single(d => d.AppPath == "App1.exe").WouldBreak);
        Assert.False(deps.Single(d => d.AppPath == "App2.exe").WouldBreak);
    }

    [Fact]
    public void Runtimeconfig_parsing_adds_implicit_netcore_reference()
    {
        const string json = """{ "runtimeOptions": { "tfm": "net6.0", "framework": { "name": "Microsoft.WindowsDesktop.App", "version": "6.0.0" } } }""";
        var refs = DotNetDependencyScanner.Parse(json, "MyApp.runtimeconfig.json");
        Assert.Equal(2, refs.Count);
        Assert.Contains(refs, r => r.Framework == "Microsoft.NETCore.App" && r.Implicit);
    }

    [Fact]
    public void Self_contained_apps_are_ignored()
    {
        const string json = """{ "runtimeOptions": { "includedFrameworks": [ { "name": "Microsoft.NETCore.App", "version": "6.0.0" } ] } }""";
        Assert.Empty(DotNetDependencyScanner.Parse(json, "x.runtimeconfig.json"));
    }
}

public class WingetParserTests
{
    private const string Sample =
        "   - \r   \\ \r" +
        "Name                               Id                          Version      Available    Source\n" +
        "-----------------------------------------------------------------------------------------------\n" +
        "7-Zip 23.01 (x64)                  7zip.7zip                   23.01        24.08        winget\n" +
        "Microsoft .NET Runtime - 8.0.11    Microsoft.DotNet.Runtime.8  8.0.11       8.0.21       winget\n" +
        "Some Very Long Application Name    Vendor.VeryLongPackageId…   1.0          2.0          winget\n" +
        "3 upgrades available.\n" +
        "\n" +
        "The following packages have an upgrade available, but require explicit targeting for upgrade:\n" +
        "Name      Id             Version  Available Source\n" +
        "--------------------------------------------------\n" +
        "Zoom      Zoom.Zoom      5.0      6.0       winget\n";

    [Fact]
    public void Parses_rows_and_flags()
    {
        var list = WingetOutputParser.ParseUpgradeTable(Sample);
        Assert.Equal(4, list.Count);
        var dotnet = list.Single(u => u.Id == "Microsoft.DotNet.Runtime.8");
        Assert.Equal("8.0.11", dotnet.InstalledVersion);
        Assert.Equal("8.0.21", dotnet.AvailableVersion);
        Assert.Equal("Microsoft .NET Runtime - 8.0.11", dotnet.Name);
        Assert.True(list.Single(u => u.Name.StartsWith("Some")).IdTruncated);
        Assert.True(list.Single(u => u.Id == "Zoom.Zoom").RequiresExplicit);
        Assert.False(list.Single(u => u.Id == "7zip.7zip").RequiresExplicit);
    }

    [Fact]
    public void Windows_managed_framework_packages_are_excluded()
    {
        var list = ExclusionMatcher.Apply([new UpdateCandidate { Name = "Microsoft.WindowsAppRuntime.1.8", Id = "Microsoft.WindowsAppRuntime.1.8", InstalledVersion = "1.8.4", AvailableVersion = "1.8.10" }], [], []);
        var u = Assert.Single(list);
        Assert.True(u.ManagedByWindows);
        Assert.False(u.Installable);
    }

    [Fact]
    public void Exclusions_support_wildcards()
    {
        var list = ExclusionMatcher.Apply(WingetOutputParser.ParseUpgradeTable(Sample), ["7zip.*"], ["Zoom.Zoom"]);
        Assert.True(list.Single(u => u.Id == "7zip.7zip").Excluded);
        Assert.True(list.Single(u => u.Id == "Zoom.Zoom").ExcludedByPolicy);
        Assert.False(list.Single(u => u.Id == "Microsoft.DotNet.Runtime.8").Excluded);
    }
}

public class MiscTests
{
    [Fact]
    public void Command_line_split_handles_unquoted_paths()
    {
        Assert.Equal(("C:\\Program Files\\App\\uninst.exe", "/S"), CommandLine.Split("C:\\Program Files\\App\\uninst.exe /S"));
        Assert.Equal(("C:\\a b\\u.exe", "/x"), CommandLine.Split("\"C:\\a b\\u.exe\" /x"));
        Assert.Equal(("MsiExec.exe", "/X{11111111-2222-3333-4444-555555555555}"), CommandLine.Split("MsiExec.exe /X{11111111-2222-3333-4444-555555555555}"));
    }

    [Fact]
    public void Schedule_next_occurrence_respects_days()
    {
        var s = new UpdateSchedule { Frequency = ScheduleFrequency.Weekly, Days = [DayOfWeek.Wednesday], Time = "12:30", RandomDelayMinutes = 0 };
        var next = s.NextOccurrence(new DateTime(2026, 11, 5, 9, 0, 0)); // Thursday
        Assert.Equal(new DateTime(2026, 11, 11, 12, 30, 0), next);
        var daily = new UpdateSchedule { Frequency = ScheduleFrequency.Daily, Time = "08:00", RandomDelayMinutes = 0 };
        Assert.Equal(new DateTime(2026, 11, 6, 8, 0, 0), daily.NextOccurrence(new DateTime(2026, 11, 5, 9, 0, 0)));
        Assert.NotNull(new UpdateSchedule { Time = "25:00" }.Validate());
    }

    [Fact]
    public void Eol_api_parsing_handles_bool_and_dates()
    {
        var cycles = EolDataProvider.ParseApi("""[{"cycle":"10","eol":"2028-11-14","latest":"10.0.5"},{"cycle":"6","eol":true},{"cycle":3.1,"eol":false}]""");
        Assert.Equal(3, cycles.Count);
        Assert.Equal("true", cycles[1].Eol);
        Assert.Equal("3.1", cycles[2].Cycle);
    }

    [Fact]
    public void Dotnet_path_validator_only_allows_version_folders()
    {
        var root = Path.Combine(Path.GetTempPath(), "ps-test-dotnet");
        Assert.True(DotNetPathValidator.IsDeletable(Path.Combine(root, "shared", "Microsoft.NETCore.App", "6.0.36"), [root], out _));
        Assert.True(DotNetPathValidator.IsDeletable(Path.Combine(root, "sdk", "6.0.428"), [root], out _));
        Assert.False(DotNetPathValidator.IsDeletable(Path.Combine(root, "shared", "Microsoft.NETCore.App"), [root], out _));
        Assert.False(DotNetPathValidator.IsDeletable(Path.Combine(root, "shared", "Microsoft.NETCore.App", "6.0.36", ".."), [root], out _));
        Assert.False(DotNetPathValidator.IsDeletable(Path.Combine(root, "host", "fxr", "6.0.36"), [root], out _));
        Assert.False(DotNetPathValidator.IsDeletable(Path.Combine(Path.GetTempPath(), "elsewhere", "6.0.36"), [root], out _));
    }
}

public class PlannerTests
{
    private static readonly DateOnly Today = new(2026, 11, 5);

    [Fact]
    public void Eol_runtime_plan_uses_bundle_then_folder_cleanup()
    {
        var folder = Path.Combine("C:", "Program Files", "dotnet", "shared", "Microsoft.NETCore.App", "6.0.36");
        var orphan = Path.Combine("C:", "Program Files", "dotnet", "shared", "Microsoft.NETCore.App", "6.0.5");
        var inventory = new List<InstalledItem>
        {
            new() { Name = "Microsoft.NETCore.App", Version = "6.0.36", Source = ItemSource.DotNetSharedFramework, Architecture = "x64", InstallLocation = folder },
            new() { Name = "Microsoft.NETCore.App", Version = "6.0.5", Source = ItemSource.DotNetSharedFramework, Architecture = "x64", InstallLocation = orphan },
            new() { Name = "Microsoft .NET Runtime - 6.0.36 (x64)", Version = "48.144.23141", Source = ItemSource.Registry, Architecture = "x64",
                    UninstallString = "\"C:\\ProgramData\\Package Cache\\{abc}\\dotnet-runtime-6.0.36-win-x64.exe\"  /uninstall" },
        };
        var catalog = RuleCatalogLoader.LoadEmbedded();
        var f = Assert.Single(RuleEngine.Evaluate(inventory, catalog, new Dictionary<string, List<RuleCycle>>(), Today, 90));
        RemediationPlanner.Plan(f, catalog.Rules.Single(r => r.Id == f.RuleId), inventory, [], wingetAvailable: true);

        Assert.Equal("replace-and-remove", f.Actions[0].Id);
        var remove = f.Actions.Single(a => a.Id == "remove");
        Assert.True(remove.Recommended);
        Assert.Equal(StepKind.CommandUninstall, remove.Steps[0].Kind);
        Assert.Contains(remove.Steps, s => s.Kind == StepKind.CommandUninstall && s.Target.Contains("/quiet"));
        Assert.Equal(2, remove.Steps.Count(s => s.Kind == StepKind.DeleteDotNetFolder));
        Assert.Equal(StepKind.DeleteDotNetFolder, remove.Steps[^1].Kind);
    }

    [Fact]
    public void Superseded_patches_can_be_removed_safely()
    {
        var a = new InstalledItem { Name = "Microsoft.NETCore.App", Version = "10.0.1", Source = ItemSource.DotNetSharedFramework, Architecture = "x64", InstallLocation = "p1" };
        var b = new InstalledItem { Name = "Microsoft.NETCore.App", Version = "10.0.5", Source = ItemSource.DotNetSharedFramework, Architecture = "x64", InstallLocation = "p2" };
        var online = new Dictionary<string, List<RuleCycle>> { ["dotnet"] = [new RuleCycle { Cycle = "10", Eol = "2028-11-14", Latest = "10.0.5" }] };
        var catalog = RuleCatalogLoader.LoadEmbedded();
        var f = Assert.Single(RuleEngine.Evaluate([a, b], catalog, online, Today, 90));
        RemediationPlanner.Plan(f, catalog.Rules.Single(r => r.Id == f.RuleId), [a, b], [], wingetAvailable: false);
        var act = Assert.Single(f.Actions);
        Assert.Equal(ActionKind.RemoveSupersededPatches, act.Kind);
        Assert.True(act.Recommended);
        Assert.Equal("p1", Assert.Single(act.Steps).Target);
    }

    [Fact]
    public void Per_user_and_untrusted_uninstallers_run_in_user_context()
    {
        var user = new InstalledItem { Name = "X", Source = ItemSource.Registry, Scope = InstallScope.User, QuietUninstallString = "\"C:\\Users\\bob\\AppData\\x\\u.exe\" /S" };
        Assert.True(Assert.Single(RemediationPlanner.RegistryUninstallSteps(user)).RequiresUserContext);
        var machineUntrusted = new InstalledItem { Name = "Y", Source = ItemSource.Registry, QuietUninstallString = "\"C:\\Users\\Public\\u.exe\" /S" };
        Assert.True(Assert.Single(RemediationPlanner.RegistryUninstallSteps(machineUntrusted)).RequiresUserContext);
        var msi = new InstalledItem { Name = "Z", Source = ItemSource.Registry, UninstallString = "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}" };
        Assert.Equal(StepKind.MsiUninstall, Assert.Single(RemediationPlanner.RegistryUninstallSteps(msi)).Kind);
    }
}

public class WingetShowTests
{
    [Fact]
    public void Show_output_links_are_parsed()
    {
        const string output = "Found DrayTek Smart VPN Client [DrayTek.SmartVPN]\nVersion: 5.7.3\nPublisher: DrayTek\nPublisher Url: https://www.draytek.com\n" +
                              "Homepage: https://www.draytek.com/products/smart-vpn-client/\nLicense: Proprietary\nInstaller:\n  Installer Type: exe\n" +
                              "  Installer Url: https://fw.draytek.com.tw/SmartVPN/Smart_VPN_Client_5.7.3.exe\n  Installer SHA256: ABC\n";
        var links = WingetClient.ParseShowLinks(output);
        Assert.NotNull(links);
        Assert.Equal("https://www.draytek.com/products/smart-vpn-client/", links!.VendorPage);
        Assert.Equal("https://fw.draytek.com.tw/SmartVPN/Smart_VPN_Client_5.7.3.exe", links.InstallerUrl);
    }
}

public class SoftwareClassifierTests
{
    private static SoftwareClassifier Classifier() => new(RuleCatalogLoader.LoadEmbedded().Categories);
    private static InstalledItem App(string name, string? publisher = null) => new() { Name = name, Publisher = publisher, Source = ItemSource.Registry };

    [Fact]
    public void Monitoring_and_remote_access_tools_need_review()
    {
        var c = Classifier();
        Assert.Equal("employee-monitoring", c.Classify(App("memtime 2.1.4"))!.Id);
        Assert.Equal("employee-monitoring", c.Classify(App("Clockify"))!.Id);
        Assert.Equal(Concern.Review, c.Classify(App("ScreenConnect Client (1a2b3c)"))!.Concern);
        Assert.Equal("network-scanner", c.Classify(App("Advanced IP Scanner 2.5.1"))!.Id);
        Assert.Equal("pup", c.Classify(App("Avast Driver Updater"))!.Id);
        Assert.Equal("rmm-agent", c.Classify(App("AteraAgent"))!.Id);
    }

    [Fact]
    public void Ordinary_apps_are_not_tagged_and_words_must_match_whole()
    {
        var c = Classifier();
        Assert.Null(c.Classify(App("Microsoft Edge")));
        Assert.Null(c.Classify(App("7-Zip 24.08 (x64)")));
        Assert.Null(c.Classify(App("ZoomText 2024")));
        Assert.Equal("messaging", c.Classify(App("Zoom Workplace"))!.Id);
    }
}

public class SoftwareClassifierMoreTests
{
    [Fact]
    public void Apps_seen_in_the_field_are_categorised()
    {
        var c = new SoftwareClassifier(RuleCatalogLoader.LoadEmbedded().Categories);
        InstalledItem App(string n) => new() { Name = n, Source = ItemSource.Registry };
        Assert.Equal("remote-access", c.Classify(App("AnyViewer 5.8.0"))!.Id);
        Assert.Equal("business-vpn", c.Classify(App("Cloudflare One Client"))!.Id);
        Assert.Equal("business-vpn", c.Classify(App("Check Point SASE"))!.Id);
        Assert.Equal("security", c.Classify(App("CyberSmart Active Protect"))!.Id);
        Assert.Equal("admin-tools", c.Classify(App("Chocolatey (Install Only)"))!.Id);
        Assert.Equal("rmm-agent", c.Classify(App("Action1 Agent"))!.Id);
    }
}

public class DeviceTests
{
    [Fact]
    public void Cpu_release_year_is_estimated_from_the_model()
    {
        Assert.Equal(2020, PatchSentinel.Core.Device.CpuAge.Estimate("11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz").Year);
        Assert.Equal(2021, PatchSentinel.Core.Device.CpuAge.Estimate("12th Gen Intel(R) Core(TM) i5-1235U").Year);
        Assert.Equal(2019, PatchSentinel.Core.Device.CpuAge.Estimate("Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz").Year);
        Assert.Equal(2016, PatchSentinel.Core.Device.CpuAge.Estimate("Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz").Year);
        Assert.Equal(false, PatchSentinel.Core.Device.CpuAge.Estimate("Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz").Windows11);
        Assert.Equal(2023, PatchSentinel.Core.Device.CpuAge.Estimate("Intel(R) Core(TM) Ultra 7 155H").Year);
        Assert.Equal(2021, PatchSentinel.Core.Device.CpuAge.Estimate("AMD Ryzen 5 5600U with Radeon Graphics").Year);
        Assert.Equal(2020, PatchSentinel.Core.Device.CpuAge.Estimate("AMD Ryzen 7 PRO 4750U with Radeon Graphics").Year);
        Assert.Null(PatchSentinel.Core.Device.CpuAge.Estimate("Some Unknown CPU").Year);
    }

    [Fact]
    public void Build_checklist_flags_missing_tools_and_settings()
    {
        var device = new PatchSentinel.Core.Device.DeviceInfo
        {
            ComputerName = "PC1", Manufacturer = "Dell Inc.", CpuName = "Intel(R) Core(TM) i5-1235U", EntraJoined = true,
            LastWindowsUpdate = DateTime.Now.AddDays(-3).ToString("s"),
            BitLocker = [new() { Drive = "C:", Protection = "Off", IsOsVolume = true }],
            Network = [new() { Alias = "Ethernet", Dns = ["8.8.8.8"], StaticDns = true }],
            LocalAccounts = [new() { Name = "setup", Enabled = true, IsAdmin = true }],
            OemTools = [new() { Vendor = "Dell", Tool = "Dell Command | Update", Applicable = true, Installed = false, DownloadUrl = "x" },
                        new() { Vendor = "Intel", Tool = "Intel DSA", Applicable = true, Installed = true, InstalledName = "Intel DSA" }],
        };
        var apps = new List<InstalledItem>
        {
            new() { Name = "McAfee LiveSafe", Source = ItemSource.Registry },
            new() { Name = "7-Zip 24.08 (x64)", Source = ItemSource.Registry },
            new() { Name = "Google Chrome", Source = ItemSource.Registry },
            new() { Name = "AteraAgent", Source = ItemSource.Registry },
        };
        var rules = RuleCatalogLoader.LoadEmbedded().BuildChecklist;
        Assert.True(rules.Count >= 17);
        var r = PatchSentinel.Core.Device.BuildChecklist.Evaluate(rules, device, apps, new DateOnly(2026, 11, 6)).ToDictionary(x => x.Id);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Fail, r["bloatware"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Pass, r["windows-update"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Fail, r["oem-tool"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Warn, r["intel-dsa"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Pass, r["atera"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Pass, r["joined"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Fail, r["bitlocker"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Fail, r["standard-apps"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Info, r["vpn"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Warn, r["setup-account"].Status);
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Fail, r["static-dns"].Status);
        Assert.False(r.ContainsKey("bespoke"));
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Fail, r["antivirus"].Status);
    }
}

public class StaticDnsTests
{
    [Fact]
    public void Vpn_and_loopback_dns_are_not_flagged()
    {
        var rules = RuleCatalogLoader.LoadEmbedded().BuildChecklist.Where(r => r.Id == "static-dns").ToList();
        var warp = new PatchSentinel.Core.Device.DeviceInfo { Network = [new() { Alias = "Ethernet 3", Description = "Cloudflare WARP Interface Tunnel", Dns = ["127.0.2.2", "127.0.2.3"], StaticDns = true },
                                                                         new() { Alias = "Wi-Fi", Dns = ["192.168.1.1"], StaticDns = false }] };
        var r = PatchSentinel.Core.Device.BuildChecklist.Evaluate(rules, warp, [], new DateOnly(2026, 11, 6)).Single();
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Pass, r.Status);
        Assert.Contains(new[] { r.Detail }, d => d.Contains("Ignored Ethernet 3"));

        var manual = new PatchSentinel.Core.Device.DeviceInfo { Network = [new() { Alias = "Ethernet", Description = "Intel(R) Ethernet Connection I219-LM", Dns = ["8.8.8.8"], StaticDns = true }] };
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Fail, PatchSentinel.Core.Device.BuildChecklist.Evaluate(rules, manual, [], new DateOnly(2026, 11, 6)).Single().Status);
    }
}

public class AntivirusCheckTests
{
    [Fact]
    public void Any_active_antivirus_passes()
    {
        var rules = RuleCatalogLoader.LoadEmbedded().BuildChecklist.Where(r => r.Id == "antivirus").ToList();
        var d = new PatchSentinel.Core.Device.DeviceInfo { Antivirus = [new() { Name = "Windows Defender", Enabled = true, UpToDate = true }] };
        var r = PatchSentinel.Core.Device.BuildChecklist.Evaluate(rules, d, [], new DateOnly(2026, 11, 6)).Single();
        Assert.Equal(PatchSentinel.Core.Device.CheckStatus.Pass, r.Status);
        Assert.Equal("Active: Microsoft Defender.", r.Detail);
    }
}

public class BrowserExtensionTests
{
    private static readonly string A = new('a', 32), B = new('b', 32), C = new('c', 32);

    [Fact]
    public void Reads_chromium_profile_with_localised_names_and_preferences()
    {
        var root = Path.Combine(Path.GetTempPath(), "ps-ud-" + Guid.NewGuid().ToString("N"));
        var prof = Path.Combine(root, "Default");
        try
        {
            void Ext(string id, string ver, string manifest, string? messages = null)
            {
                var d = Path.Combine(prof, "Extensions", id, ver);
                Directory.CreateDirectory(d);
                File.WriteAllText(Path.Combine(d, "manifest.json"), manifest);
                if (messages is null) return;
                Directory.CreateDirectory(Path.Combine(d, "_locales", "en"));
                File.WriteAllText(Path.Combine(d, "_locales", "en", "messages.json"), messages);
            }
            Ext(A, "1.0.0_0", """{"name":"__MSG_appName__","default_locale":"en","version":"1.0.0","manifest_version":3,"update_url":"https://clients2.google.com/service/update2/crx","host_permissions":["<all_urls>"],"permissions":["cookies"]}""",
                """{"appName":{"message":"Good Ext"}}""");
            Ext(A, "0.9.0_0", """{"name":"Old","version":"0.9.0","manifest_version":3}""");
            Ext(B, "2.0_0", """{"name":"MV2 thing","version":"2.0","manifest_version":2,"permissions":["tabs","http://*/*"]}""");
            Ext(C, "1.0_0", """{"name":"A theme","version":"1.0","theme":{}}""");
            File.WriteAllText(Path.Combine(prof, "Secure Preferences"),
                "{\"extensions\":{\"settings\":{\"" + A + "\":{\"location\":1,\"from_webstore\":true},\"" + B + "\":{\"location\":1,\"disable_reasons\":[1]}}}}");

            var list = Browsers.ExtensionInventory.ReadChromium(Browsers.Browser.Chrome, "tester", root).ToList();
            Assert.Equal(2, list.Count);
            var good = list.Single(e => e.Id == A);
            Assert.Equal("Good Ext", good.Name);
            Assert.Equal("1.0.0", good.Version);
            Assert.Equal("Store", good.InstallSource);
            Assert.True(good.BroadAccess);
            Assert.Contains("cookies", good.SensitivePermissions);
            var mv2 = list.Single(e => e.Id == B);
            Assert.False(mv2.Enabled);
            Assert.Equal("Sideloaded", mv2.InstallSource);
            Assert.Equal(2, mv2.ManifestVersion);
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    [Fact]
    public void Omaha_response_marks_missing_extensions_as_not_listed()
    {
        var xml = "<?xml version=\"1.0\"?><gupdate xmlns=\"http://www.google.com/update2/response\" protocol=\"2.0\">" +
                  $"<app appid=\"{A}\" status=\"ok\"><updatecheck version=\"1.2.0\" status=\"ok\"/></app>" +
                  $"<app appid=\"{B}\" status=\"ok\"><updatecheck status=\"noupdate\"/></app>" +
                  $"<app appid=\"{C}\" status=\"error-unknownApplication\"/></gupdate>";
        var r = Browsers.ExtensionChecker.ParseOmaha(xml);
        Assert.True(r[A].Listed);
        Assert.Equal("1.2.0", r[A].Version);
        Assert.False(r[B].Listed);
        Assert.False(r[C].Listed);
    }

    [Fact]
    public void Assessment_flags_removed_retired_outdated_and_sideloaded()
    {
        Browsers.BrowserExtension Make(string ver = "1.0", int mv = 3, string source = "Store") => new()
        {
            Browser = Browsers.Browser.Chrome, Id = A, Name = "X", Version = ver, ManifestVersion = mv, InstallSource = source,
            UpdateUrl = source == "Store" ? "https://clients2.google.com/service/update2/crx" : null,
        };
        var store = Browsers.ExtensionStore.ChromeWebStore;

        var removed = Make();
        Browsers.ExtensionChecker.Assess(removed, store, new Browsers.StoreInfo { Listed = false });
        Assert.Equal(Browsers.ExtensionStatus.RemovedFromStore, removed.Status);
        Assert.Equal(Concern.High, removed.Concern);

        var retired = Make(mv: 2);
        Browsers.ExtensionChecker.Assess(retired, store, new Browsers.StoreInfo { Listed = true, Version = "1.0" });
        Assert.Equal(Browsers.ExtensionStatus.RetiredManifestV2, retired.Status);

        var old = Make("1.0");
        Browsers.ExtensionChecker.Assess(old, store, new Browsers.StoreInfo { Listed = true, Version = "1.4" });
        Assert.Equal(Browsers.ExtensionStatus.UpdateAvailable, old.Status);
        Assert.Equal("1.4", old.LatestVersion);

        var ok = Make("1.4");
        Browsers.ExtensionChecker.Assess(ok, store, new Browsers.StoreInfo { Listed = true, Version = "1.4" });
        Assert.Equal(Browsers.ExtensionStatus.UpToDate, ok.Status);
        Assert.Equal(Concern.Info, ok.Concern);

        var side = Make(source: "Sideloaded");
        side.BroadAccess = true;
        side.SensitivePermissions = ["cookies"];
        Browsers.ExtensionChecker.Assess(side, Browsers.ExtensionStore.None, null);
        Assert.Equal(Browsers.ExtensionStatus.NotFromStore, side.Status);
        Assert.Equal(Concern.High, side.Concern);

        // Firefox still supports Manifest V2.
        var ff = new Browsers.BrowserExtension { Browser = Browsers.Browser.Firefox, Id = "a@b", Name = "F", Version = "2.0", ManifestVersion = 2, InstallSource = "Store" };
        Browsers.ExtensionChecker.Assess(ff, Browsers.ExtensionStore.FirefoxAddons, new Browsers.StoreInfo { Listed = true, Version = "2.0" });
        Assert.Equal(Browsers.ExtensionStatus.UpToDate, ff.Status);
    }
}

public class BuildActionTests
{
    private static readonly Dictionary<string, string> Links = new(StringComparer.OrdinalIgnoreCase)
    {
        ["atera"] = "https://app.atera.com/", ["sentinelone"] = "", ["bad"] = "javascript:alert(1)",
    };

    private static Device.BuildCheckResult Result(Device.CheckStatus s) => new() { Id = "x", Status = s };

    [Fact]
    public void Shows_links_and_hides_empty_or_unsafe_ones()
    {
        var rule = new Device.BuildCheckRule
        {
            Id = "x",
            Actions =
            [
                new() { Id = "a", Label = "Atera", Kind = "link", Link = "atera" },
                new() { Id = "s", Label = "S1", Kind = "link", Link = "sentinelone" },
                new() { Id = "b", Label = "Bad", Kind = "link", Link = "bad" },
                new() { Id = "w", Label = "Windows Update", Kind = "url", Url = "ms-settings:windowsupdate" },
            ],
        };
        var v = Device.BuildActions.Visible(rule, Result(Device.CheckStatus.Fail), new Device.DeviceInfo(), [], Links);
        Assert.Equal(["a", "w"], v.Select(x => x.Id).ToList());
        Assert.Equal("https://app.atera.com/", v[0].Target);
    }

    [Fact]
    public void Installs_only_show_for_the_right_manufacturer_and_when_missing()
    {
        var rule = new Device.BuildCheckRule
        {
            Id = "x",
            Actions =
            [
                new() { Id = "dcu", Label = "Install DCU", Kind = "winget", WingetId = "Dell.CommandUpdate.Universal", Manufacturer = "Dell" },
                new() { Id = "lsu", Label = "Install LSU", Kind = "winget", WingetId = "Lenovo.SystemUpdate", Manufacturer = "Lenovo" },
                new() { Id = "7z", Label = "Install 7-Zip", Kind = "winget", WingetId = "7zip.7zip", IfAppMissing = ["7-Zip"] },
                new() { Id = "tab", Label = "Apps", Kind = "tab", Tab = "apps-review", OnlyWhenNotOk = true },
            ],
        };
        var lenovo = new Device.DeviceInfo { Manufacturer = "LENOVO" };
        var apps = new List<InstalledItem> { new() { Name = "7-Zip 26.05 (x64)", Source = ItemSource.Registry } };
        var v = Device.BuildActions.Visible(rule, Result(Device.CheckStatus.Fail), lenovo, apps, Links);
        Assert.Equal(["lsu", "tab"], v.Select(x => x.Id).ToList());

        // Installs and tab-only-when-not-OK are hidden once the step passes.
        Assert.Empty(Device.BuildActions.Visible(rule, Result(Device.CheckStatus.Pass), lenovo, apps, Links));
    }

    [Fact]
    public void Programs_must_be_in_trusted_folders()
    {
        Assert.False(Device.BuildActions.IsSafeProgram(@"C:\Users\bob\AppData\Local\Temp\evil.exe"));
        Assert.False(Device.BuildActions.IsSafeUrl("file:///C:/evil.exe"));
        Assert.True(Device.BuildActions.IsSafeUrl("https://cloud.gravityzone.bitdefender.com/"));
        Assert.True(Device.BuildActions.IsSafeUrl("windowsdefender:"));
    }

    [Fact]
    public void Catalogue_actions_parse_and_reference_valid_packages()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "rules", "eol-rules.json");
        var catalog = File.Exists(path) ? Rules.RuleCatalogLoader.Parse(File.ReadAllText(path)) : Rules.RuleCatalogLoader.LoadEmbedded();
        var actions = catalog.BuildChecklist.SelectMany(r => r.Actions).ToList();
        Assert.True(actions.Count > 20);
        Assert.True(actions.Where(a => a.Kind == "winget").All(a => Updates.WingetClient.IsValidId(a.WingetId!)));
        Assert.True(actions.Where(a => a.Kind == "link").All(a => catalog.Links.ContainsKey(a.Link!)));
        Assert.True(actions.Where(a => a.Kind == "url").All(a => Device.BuildActions.IsSafeUrl(a.Url)));
        Assert.True(actions.All(a => a.Kind is "url" or "link" or "open" or "run" or "winget" or "tab"));
    }

    [Fact]
    public void Handover_counts_signed_off_steps_as_done()
    {
        var checks = new List<Device.BuildCheckResult>
        {
            new() { Step = 1, Id = "a", Title = "A", Status = Device.CheckStatus.Pass },
            new() { Step = 2, Id = "b", Title = "B", Status = Device.CheckStatus.Fail },
            new() { Step = 3, Id = "c", Title = "C", Status = Device.CheckStatus.Manual },
            new() { Step = 4, Id = "d", Title = "D", Status = Device.CheckStatus.Warn },
        };
        var file = new Device.BuildSignoffFile();
        file.Steps["c"] = new Device.BuildSignoff { Status = Device.SignoffStatus.Checked, By = "ADM\\ross" };
        file.Steps["d"] = new Device.BuildSignoff { Status = Device.SignoffStatus.NotRequired, By = "ADM\\ross", Note = "customer uses Sophos" };
        Device.BuildSignoffStore.Apply(checks, file);
        var h = Device.BuildSignoffStore.Summarise(checks, "ADM\\ross", null);
        Assert.Equal(1, h.StepsOk);
        Assert.Equal(2, h.StepsSignedOff);
        Assert.Equal(1, h.StepsOutstanding);
        Assert.Equal(["2. B"], h.Outstanding);
    }
}

public class OemToolTests
{
    private static List<InstalledItem> Apps(params (string Name, string Version)[] apps) =>
        apps.Select(a => new InstalledItem { Name = a.Name, Version = a.Version, Source = ItemSource.Registry }).ToList();

    [Fact]
    public void ThinkPad_expects_Commercial_Vantage_and_flags_System_Update_as_older()
    {
        var d = new Device.DeviceInfo { Manufacturer = "LENOVO", Model = "21C3001UUK", ProductName = "ThinkPad L15 Gen 3" };
        var t = Device.DeviceCollector.DetectOemTools(d, Apps(("Lenovo System Update", "5.08.04.85"))).Single(x => x.Vendor == "Lenovo");
        Assert.Equal("Lenovo Commercial Vantage", t.Tool);
        Assert.False(t.Installed);
        Assert.Equal("Lenovo System Update", t.LegacyInstalled);

        d.OemTools = [t];
        var rule = new Device.BuildCheckRule { Id = "oem", Type = "builtin", Check = "oemTools" };
        var r = Device.BuildChecklist.Evaluate([rule], d, [], new DateOnly(2026, 11, 6)).Single();
        Assert.Equal(Device.CheckStatus.Warn, r.Status);
        Assert.Contains("Commercial Vantage is the tool for this model", r.Detail);
    }

    [Fact]
    public void Dell_business_and_consumer_models_get_different_tools()
    {
        var latitude = new Device.DeviceInfo { Manufacturer = "Dell Inc.", Model = "Latitude 5550" };
        var inspiron = new Device.DeviceInfo { Manufacturer = "Dell Inc.", Model = "Inspiron 15 3530" };
        Assert.Equal("Dell Command | Update", Device.DeviceCollector.DetectOemTools(latitude, []).Single(x => x.Vendor == "Dell").Tool);
        Assert.Equal("Dell SupportAssist", Device.DeviceCollector.DetectOemTools(inspiron, []).Single(x => x.Vendor == "Dell").Tool);
    }

    [Fact]
    public void Old_Dell_Command_Update_is_flagged_and_offered_an_update()
    {
        var d = new Device.DeviceInfo { Manufacturer = "Dell Inc.", Model = "OptiPlex 7090" };
        var apps = Apps(("Dell Command | Update for Windows Universal", "4.3.0"));
        d.OemTools = Device.DeviceCollector.DetectOemTools(d, apps);
        var tool = d.OemTools.Single(x => x.Vendor == "Dell");
        tool.LastActivity = DateTimeOffset.Now;
        var catalog = Rules.RuleCatalogLoader.LoadEmbedded();
        var rule = catalog.BuildChecklist.Single(r => r.Id == "oem-tool");
        var r = Device.BuildChecklist.Evaluate([rule], d, apps, DateOnly.FromDateTime(DateTime.Now), catalog.Links).Single();
        Assert.Equal(Device.CheckStatus.Warn, r.Status);
        var ids = r.Actions.Select(a => a.Id).ToList();
        Assert.Contains("update-dcu", ids);
        Assert.False(ids.Contains("install-dcu"));
        Assert.False(ids.Any(i => i.Contains("cv") || i.Contains("sa")));
    }
}

public class HpAndSurfaceToolTests
{
    [Fact]
    public void HP_business_uses_Image_Assistant_and_consumer_uses_Support_Assistant()
    {
        var elite = new Device.DeviceInfo { Manufacturer = "HP", Model = "HP EliteBook 840 G10 Notebook PC" };
        var pavilion = new Device.DeviceInfo { Manufacturer = "HP", Model = "HP Pavilion Laptop 15-eg3xxx" };
        Assert.Equal("HP Image Assistant", Device.DeviceCollector.DetectOemTools(elite, []).Single(x => x.Vendor == "HP").Tool);
        Assert.Equal("HP Support Assistant", Device.DeviceCollector.DetectOemTools(pavilion, []).Single(x => x.Vendor == "HP").Tool);

        var catalog = Rules.RuleCatalogLoader.LoadEmbedded();
        var rule = catalog.BuildChecklist.Single(r => r.Id == "oem-tool");
        elite.OemTools = Device.DeviceCollector.DetectOemTools(elite, []);
        var r = Device.BuildChecklist.Evaluate([rule], elite, [], new DateOnly(2026, 11, 6), catalog.Links).Single();
        Assert.Equal(Device.CheckStatus.Fail, r.Status);
        var install = r.Actions.Single(a => a.Id == "install-hpia");
        Assert.Equal("HP.ImageAssistant", install.Target);
        Assert.False(r.Actions.Any(a => a.Id.Contains("hpsa") || a.Id.Contains("dcu") || a.Id.Contains("cv")));
        Assert.True(catalog.BuildChecklist.SelectMany(x => x.Actions).Where(a => a.WingetLocation is not null).All(a => a.WingetLocation!.StartsWith("%ProgramFiles%")));
    }

    [Fact]
    public void Surface_needs_no_manufacturer_tool()
    {
        var d = new Device.DeviceInfo { Manufacturer = "Microsoft Corporation", Model = "Surface Laptop 7" };
        d.OemTools = Device.DeviceCollector.DetectOemTools(d, []);
        var rule = new Device.BuildCheckRule { Id = "oem", Type = "builtin", Check = "oemTools" };
        var r = Device.BuildChecklist.Evaluate([rule], d, [], new DateOnly(2026, 11, 6)).Single();
        Assert.Equal(Device.CheckStatus.Pass, r.Status);
        Assert.Contains("Windows Update", r.Detail);
    }
}
