using System.Text.RegularExpressions;
using PatchSentinel.Core.Inventory;
using PatchSentinel.Core.Rules;

namespace PatchSentinel.Core.Remediation;

/// <summary>Works out which apps depend on a finding and which concrete steps would fix it.</summary>
public static class RemediationPlanner
{
    public static void Plan(Finding f, EolRule? rule, IReadOnlyList<InstalledItem> inventory, IReadOnlyList<RuntimeConfigReference> refs, bool wingetAvailable)
    {
        var isDotNet = f.Items.Count > 0 && f.Items.All(i => i.Source is ItemSource.DotNetSharedFramework or ItemSource.DotNetSdk);
        if (isDotNet)
        {
            f.Dependents = FindDependents(f.Items, inventory, refs);
            PlanDotNet(f, rule, inventory, wingetAvailable);
        }
        else if (f.Items.All(i => i.Source == ItemSource.Registry))
        {
            PlanRegistry(f, rule, wingetAvailable);
        }
        // .NET Framework 4.x is part of Windows: advice only (upgrade via Windows Update).

        if (f.BreakingDependents > 0)
        {
            var names = string.Join(", ", f.Dependents.Where(d => d.WouldBreak).Select(d => Path.GetFileName(d.AppPath)).Distinct().Take(5));
            f.Advice = $"{f.BreakingDependents} application(s) still need this runtime ({names}). Ask the vendor for a build on a supported .NET release. " +
                       "As a tested stop-gap, setting \"rollForward\": \"Major\" in the app's runtimeconfig.json lets it run on a newer runtime. " + f.Advice;
        }
    }

    // ---------- dependents ----------

    public static List<Dependent> FindDependents(IReadOnlyList<InstalledItem> removing, IReadOnlyList<InstalledItem> inventory, IReadOnlyList<RuntimeConfigReference> refs)
    {
        var removingShared = removing.Where(i => i.Source == ItemSource.DotNetSharedFramework).ToList();
        if (removingShared.Count == 0) return [];
        var removingKeys = removingShared.Select(i => i.Key).ToHashSet();
        var deps = new Dictionary<(string, string), Dependent>();

        foreach (var r in refs)
        {
            var same = removingShared.Where(i => i.Name == r.Framework && i.Architecture == r.Architecture).Select(i => i.Version!).ToList();
            if (same.Count == 0 || !RollForwardResolver.CanResolve(r.Version, r.RollForward, same)) continue;
            var remaining = inventory
                .Where(i => i.Source == ItemSource.DotNetSharedFramework && i.Name == r.Framework && i.Architecture == r.Architecture && !removingKeys.Contains(i.Key))
                .Select(i => i.Version!);
            var d = new Dependent
            {
                AppPath = r.AppPath, Framework = r.Framework, RequestedVersion = r.Version,
                RollForward = r.RollForward, Architecture = r.Architecture,
                WouldBreak = !RollForwardResolver.CanResolve(r.Version, r.RollForward, remaining),
            };
            var key = (r.AppPath.ToLowerInvariant(), r.Framework);
            if (!deps.TryGetValue(key, out var existing) || (d.WouldBreak && !existing.WouldBreak)) deps[key] = d;
        }
        return deps.Values.OrderByDescending(d => d.WouldBreak).ThenBy(d => d.AppPath, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ---------- .NET ----------

    private static void PlanDotNet(Finding f, EolRule? rule, IReadOnlyList<InstalledItem> inventory, bool winget)
    {
        var registry = inventory.Where(i => i.Source == ItemSource.Registry && i.Scope == InstallScope.Machine).ToList();
        var notes = new List<string>();

        if (f.Kind == FindingKind.OutdatedPatch)
        {
            var actions = new List<RemediationAction>();
            var template = rule?.WingetIdTemplate;
            if (winget && template is not null)
            {
                var ids = f.Items.Select(i => VersionUtil.ApplyTemplate(template, i.Version)).Distinct().ToList();
                var steps = ids.Select(id => new RemediationStep { Kind = StepKind.WingetInstall, Target = id, Description = $"Install the latest {id} patch with winget" }).ToList();
                foreach (var g in f.Items.GroupBy(i => (i.Name, i.Architecture, VersionUtil.Major(i.Version), VersionUtil.Minor(i.Version))))
                {
                    var highest = g.OrderByDescending(i => i.Version, Comparer<string?>.Create(VersionUtil.Compare)).First();
                    steps.Add(new RemediationStep { Kind = StepKind.VerifyDotNetNewer, Target = highest.InstallLocation ?? "", Description = $"Check a newer {g.Key.Name} {g.Key.Item3}.{g.Key.Item4} patch is now present ({g.Key.Architecture})" });
                }
                steps.AddRange(DotNetRemovalSteps(f.Items, registry, notes));
                actions.Add(new RemediationAction
                {
                    Id = "upgrade", Kind = ActionKind.UpgradeInPlace, Recommended = true,
                    Label = $"Install the latest patch, then remove the old patch versions",
                    Description = "Apps keep working: .NET automatically uses the newest patch of the same major.minor release. The old folders are only removed once the newer patch is confirmed on disk.",
                    Steps = steps,
                });
            }

            var superseded = f.Items.Where(i => inventory.Any(o => o.Source == i.Source && o.Name == i.Name && o.Architecture == i.Architecture
                                                                  && VersionUtil.SameMajorMinor(o.Version, i.Version) && VersionUtil.Compare(o.Version, i.Version) > 0)).ToList();
            if (superseded.Count > 0)
            {
                actions.Add(new RemediationAction
                {
                    Id = "remove-superseded", Kind = ActionKind.RemoveSupersededPatches, Recommended = actions.Count == 0,
                    Label = $"Remove {superseded.Count} superseded patch version(s) only",
                    Description = "Safe: a newer patch of the same release is already installed, so nothing loses its runtime. " +
                                  string.Join("; ", superseded.Select(i => $"{i.Name} {i.Version} ({i.Architecture})")),
                    Steps = DotNetRemovalSteps(superseded, registry, notes),
                });
            }
            f.Actions = actions;
        }
        else
        {
            var removal = DotNetRemovalSteps(f.Items, registry, notes);
            var breaking = f.BreakingDependents;
            var warn = breaking > 0
                ? $"{breaking} application(s) listed above would stop working after removal."
                : null;
            const string scope = " The dependency check covers Program Files and per-user Programs folders; test line-of-business apps afterwards.";
            var actions = new List<RemediationAction>
            {
                new()
                {
                    Id = "remove", Kind = ActionKind.Remove, Recommended = breaking == 0,
                    Label = f.Dependents.Count == 0 ? $"Remove {f.Title} (no installed apps found that use it)" : $"Remove {f.Title}",
                    Description = $"Uninstalls {f.Items.Count} installation(s) and deletes any leftover runtime folders that scanners still detect." + scope,
                    Warning = warn, Steps = removal,
                },
            };
            if (winget && rule?.ReplacementWingetId is { } repl)
            {
                var install = new RemediationStep { Kind = StepKind.WingetInstall, Target = repl, Description = $"Install {rule.Replacement ?? repl} with winget" };
                actions.Insert(0, new RemediationAction
                {
                    Id = "replace-and-remove", Kind = ActionKind.ReplaceAndRemove,
                    Label = $"Install {rule.Replacement ?? repl}, then remove {f.Title}",
                    Description = "Use when your apps have been updated to (or can roll forward to) the supported release." + scope,
                    Warning = warn, Steps = [install, .. removal],
                });
                actions.Add(new RemediationAction
                {
                    Id = "install-replacement", Kind = ActionKind.InstallReplacement,
                    Label = $"Only install {rule.Replacement ?? repl}",
                    Description = "Installs the supported release side by side without removing anything. The finding stays open until the old version is removed.",
                    Steps = [install],
                });
            }
            f.Actions = actions;
        }

        if (notes.Count > 0) f.Advice = string.Join(" ", notes.Distinct()) + (f.Advice is null ? "" : " " + f.Advice);
    }

    /// <summary>Uninstall via the registered installer where possible, then delete any folder still left behind.</summary>
    public static List<RemediationStep> DotNetRemovalSteps(IEnumerable<InstalledItem> items, IReadOnlyList<InstalledItem> registry, List<string> notes)
    {
        var steps = new List<RemediationStep>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var folderSteps = new List<RemediationStep>();

        foreach (var item in items)
        {
            var token = new Regex($@"(?<![\d.]){Regex.Escape(item.Version ?? "")}(?![\d.])", RegexOptions.CultureInvariant);
            var matches = registry.Where(r => r.Name.Contains(".NET", StringComparison.OrdinalIgnoreCase)
                                              && token.IsMatch(r.Name)
                                              && (r.Architecture is null || r.Architecture == item.Architecture)
                                              && (item.Source == ItemSource.DotNetSdk ? r.Name.Contains("SDK", StringComparison.OrdinalIgnoreCase) : MatchesFramework(r.Name, item.Name)))
                                  .ToList();

            if (matches.Any(m => m.Name.Contains("from Visual Studio", StringComparison.OrdinalIgnoreCase)))
                notes.Add("Some of these were installed by Visual Studio; use Visual Studio Installer > Modify > 'Remove out-of-support components' or they may be reinstalled.");
            if (matches.Any(m => m.Name.Contains("Windows Server Hosting", StringComparison.OrdinalIgnoreCase)))
                notes.Add("This includes an ASP.NET Core Hosting Bundle used by IIS; install the supported Hosting Bundle first on web servers.");

            var bundles = matches.Where(m => !m.IsSystemComponent && (m.QuietUninstallString ?? m.UninstallString) is { } u && IsBurnBundle(u)).ToList();
            if (bundles.Count > 0)
            {
                foreach (var b in bundles)
                {
                    var cmd = BundleQuietUninstall(b);
                    if (seen.Add(cmd)) steps.Add(new RemediationStep { Kind = StepKind.CommandUninstall, Target = cmd, Description = $"Uninstall '{b.Name}'" });
                }
            }
            else
            {
                foreach (var m in matches.Where(m => m.ProductCode is not null))
                    if (seen.Add(m.ProductCode!)) steps.Add(new RemediationStep { Kind = StepKind.MsiUninstall, Target = m.ProductCode!, Description = $"Uninstall '{m.Name}' (MSI)" });
            }

            if (!string.IsNullOrEmpty(item.InstallLocation) && seen.Add(item.InstallLocation))
                folderSteps.Add(new RemediationStep
                {
                    Kind = StepKind.DeleteDotNetFolder, Target = item.InstallLocation,
                    Description = matches.Count > 0
                        ? $"Delete leftover folder {item.InstallLocation} if the uninstaller leaves it"
                        : $"Delete orphaned folder {item.InstallLocation} (no installer is registered for it)",
                });
        }
        steps.AddRange(folderSteps);
        return steps;
    }

    private static bool MatchesFramework(string displayName, string framework)
    {
        bool Has(string s) => displayName.Contains(s, StringComparison.OrdinalIgnoreCase);
        return framework switch
        {
            "Microsoft.NETCore.App" => (Has("Runtime") && !Has("Desktop") && !Has("ASP.NET")) || Has("Windows Server Hosting"),
            "Microsoft.AspNetCore.App" or "Microsoft.AspNetCore.All" => Has("ASP.NET Core") || Has("Windows Server Hosting"),
            "Microsoft.WindowsDesktop.App" => Has("Windows Desktop Runtime"),
            _ => false,
        };
    }

    private static bool IsBurnBundle(string command)
    {
        var (file, _) = CommandLine.Split(command);
        return file.Contains(@"\Package Cache\", StringComparison.OrdinalIgnoreCase) && file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
    }

    private static string BundleQuietUninstall(InstalledItem b)
    {
        if (!string.IsNullOrEmpty(b.QuietUninstallString)) return b.QuietUninstallString!;
        var (file, args) = CommandLine.Split(b.UninstallString!);
        if (!args.Contains("/uninstall", StringComparison.OrdinalIgnoreCase)) args = ("/uninstall " + args).Trim();
        if (!args.Contains("/quiet", StringComparison.OrdinalIgnoreCase)) args += " /quiet";
        if (!args.Contains("/norestart", StringComparison.OrdinalIgnoreCase)) args += " /norestart";
        return $"\"{file}\" {args}";
    }

    // ---------- Add/Remove Programs items ----------

    private static void PlanRegistry(Finding f, EolRule? rule, bool winget)
    {
        var actions = new List<RemediationAction>();

        if (f.Kind == FindingKind.OutdatedPatch)
        {
            if (winget && rule?.WingetIdTemplate is { } template)
            {
                actions.Add(new RemediationAction
                {
                    Id = "upgrade", Kind = ActionKind.UpgradeInPlace, Recommended = true,
                    Label = "Upgrade to the latest patch with winget",
                    Steps = f.Items.Select(i => new RemediationStep
                    {
                        Kind = StepKind.WingetUpgrade, Target = VersionUtil.ApplyTemplate(template, RuleEngine.EffectiveVersion(i, rule)),
                        Description = $"Upgrade {i.Name}", RequiresUserContext = i.Scope == InstallScope.User, UserSid = i.UserSid,
                    }).DistinctBy(s => s.Target + s.UserSid).ToList(),
                });
            }
            f.Actions = actions;
            return;
        }

        var removal = f.Items.SelectMany(RegistryUninstallSteps).ToList();
        var cannot = f.Items.Count - f.Items.Count(i => RegistryUninstallSteps(i).Any());
        string? warning = rule?.Category == "Runtime"
            ? "Shared runtimes are often required by other applications. Check with the vendor of any app that installed it, and test afterwards."
            : null;
        if (cannot > 0) warning = $"{cannot} item(s) have no usable uninstaller and must be removed manually. " + warning;

        if (removal.Count > 0)
            actions.Add(new RemediationAction
            {
                Id = "remove", Kind = ActionKind.Remove, Recommended = warning is null,
                Label = $"Uninstall {f.Title}",
                Description = $"Runs the registered uninstaller for {f.Items.Count} item(s).",
                Warning = warning, Steps = removal,
            });

        if (winget && rule?.ReplacementWingetId is { } repl)
        {
            var install = new RemediationStep { Kind = StepKind.WingetInstall, Target = repl, Description = $"Install {rule.Replacement ?? repl} with winget" };
            if (removal.Count > 0)
                actions.Insert(0, new RemediationAction
                {
                    Id = "replace-and-remove", Kind = ActionKind.ReplaceAndRemove, Recommended = warning is null,
                    Label = $"Install {rule.Replacement ?? repl}, then uninstall {f.Title}",
                    Warning = warning, Steps = [install, .. removal],
                });
            actions.Add(new RemediationAction
            {
                Id = "install-replacement", Kind = ActionKind.InstallReplacement,
                Label = $"Only install {rule.Replacement ?? repl}", Steps = [install],
            });
        }

        // Only one recommendation.
        var first = actions.FindIndex(a => a.Recommended);
        for (var i = 0; i < actions.Count; i++)
            if (i != first && actions[i].Recommended) actions[i] = actions[i] with { Recommended = false };
        f.Actions = actions;
    }

    public static List<RemediationStep> RegistryUninstallSteps(InstalledItem item)
    {
        var user = item.Scope == InstallScope.User;
        if (item.ProductCode is not null)
            return [new() { Kind = StepKind.MsiUninstall, Target = item.ProductCode, Description = $"Uninstall '{item.Name}' (MSI)", RequiresUserContext = user, UserSid = item.UserSid }];

        if (!string.IsNullOrWhiteSpace(item.QuietUninstallString))
        {
            var (file, _) = CommandLine.Split(item.QuietUninstallString);
            return [new() { Kind = StepKind.CommandUninstall, Target = item.QuietUninstallString, Description = $"Uninstall '{item.Name}' silently",
                            RequiresUserContext = user || !CommandLine.IsTrustedSystemPath(Environment.ExpandEnvironmentVariables(file)), UserSid = item.UserSid }];
        }

        if (!string.IsNullOrWhiteSpace(item.UninstallString))
        {
            var (file, args) = CommandLine.Split(item.UninstallString);
            if (CommandLine.IsMsiExec(file) && CommandLine.MsiGuid.Match(args) is { Success: true } g)
                return [new() { Kind = StepKind.MsiUninstall, Target = g.Value.ToUpperInvariant(), Description = $"Uninstall '{item.Name}' (MSI)", RequiresUserContext = user, UserSid = item.UserSid }];
            // No silent switch is known, so the uninstaller's own UI is shown to the logged-on user.
            return [new() { Kind = StepKind.InteractiveUninstall, Target = item.UninstallString, Description = $"Open the uninstaller for '{item.Name}'", RequiresUserContext = true, UserSid = item.UserSid }];
        }
        return [];
    }
}
