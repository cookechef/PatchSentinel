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
