using System.Text.Json;
using PatchSentinel.Core;
using PatchSentinel.Core.Config;
using PatchSentinel.Core.Ipc;
using PatchSentinel.Core.Remediation;
using PatchSentinel.Core.Reporting;
using PatchSentinel.Core.Rules;
using PatchSentinel.Core.Updates;

namespace PatchSentinel.Agent;

/// <summary>Command line for RMM tools (Atera, Action1, NinjaOne...) and admins. Exit codes are documented in README.</summary>
internal static class Cli
{
    public const int ExitClean = 0, ExitError = 1, ExitUsage = 2, ExitEol = 10, ExitNeedsAttention = 11, ExitUpdatesPending = 12;

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is "help" or "--help" or "-h" or "/?") { PrintHelp(); return args.Length == 0 ? ExitUsage : ExitClean; }

        var cmd = args[0].ToLowerInvariant();
        if (cmd == "service") return ServiceHost.Run();

        AppLog.Initialize(Platform.IsElevated ? AppPaths.LogDir : Path.Combine(Path.GetTempPath(), "PatchSentinel"), echoToConsole: Has(args, "--verbose"));
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            return cmd switch
            {
                "version" or "--version" => Print($"PatchSentinel {AppPaths.Version}"),
                "scan" => await ScanAsync(args, cts.Token),
                "updates" => await UpdatesAsync(args, cts.Token),
                "fix" => await FixAsync(args, cts.Token),
                "uninstall" => await UninstallAsync(args, cts.Token),
                "inventory" => await InventoryAsync(args, cts.Token),
                "device" => await DeviceAsync(args, cts.Token),
                "extensions" => await ExtensionsAsync(args, cts.Token),
                "rules" => await RulesAsync(args, cts.Token),
                "self-update" => await SelfUpdateAsync(args, cts.Token),
                "run" => await RunConsoleAsync(cts.Token),
                _ => Usage($"Unknown command '{args[0]}'."),
            };
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("Cancelled."); return ExitError; }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            AppLog.Error("CLI failure", ex);
            return ExitError;
        }
    }

    private static void PrintHelp() => Console.WriteLine($"""
        PatchSentinel {AppPaths.Version} - winget patching plus end-of-life software detection and remediation

        Usage: psentinel <command> [options]

          scan                         Scan for EOL/legacy software, missing runtime patches and app updates
            --json                     Write the full result as JSON to stdout (for RMM parsing)
            --out <file.json>          Save JSON   --html <file.html>  Save HTML report   --csv <file.csv>  Save CSV
            --no-updates               Skip the winget update check
            --no-deps                  Skip the application dependency scan
            --offline                  Do not contact endoflife.date (use built-in/cached dates)
            --inventory                Include the full software inventory in JSON output
            --no-device                Skip device details and the build checklist
            --no-extensions            Skip the browser extension check

          updates list                 List available winget upgrades (exclusions applied)
          updates install --all        Install every non-excluded upgrade
          updates install --id <id>    Install specific package(s); repeat --id as needed

          fix list                     List findings and their fix actions
          fix <findingId> <actionId>   Run one fix action (e.g. fix dotnet-runtime:6:EndOfLife remove)
          fix --safe                   Remove superseded .NET patch versions and patch supported runtimes
          fix --remove-unused-eol      Remove EOL .NET runtimes that no installed application uses
            --yes                      Do not prompt (required when run non-interactively)

          self-update [--check]        Check GitHub for a newer PatchSentinel and install it
            --repo <owner/repo>        Override the repository to update from

          device                       Device details, security status and the build checklist
            --json | --html <file> | --xlsx <file> | --csv <file>
            --no-public-ip             Do not look up the public IP address

          extensions                   Check Chrome, Edge, Brave and Firefox extensions (all users when elevated)
            --json | --xlsx <file> | --html <file> | --csv <file>
            --review                   Only show extensions that need attention
            --offline                  Do not contact the extension stores
          extensions block --browser <chrome|edge|brave|firefox> --id <extensionId>
                                       Block an extension by machine policy (applied at the browser's next start)
          extensions uninstall --browser <...> --id <extensionId>
                                       Uninstall for every user at the browser's next start (the service
                                       takes the policy off again once it has gone)
          extensions unblock --browser <...> --id <extensionId>   Unblock or cancel an uninstall

          inventory                    List installed apps with category and security advisory
            --xlsx <file> --html <file> --csv <file>   Export the list
            --review                   Only show apps that need a security review

          uninstall --key <regkey>     Uninstall app(s) by their Add/Remove Programs key (repeatable)
          uninstall --winget-id <id>   Uninstall app(s) with winget (repeatable)
            --name <text>              Uninstall the single app whose name matches exactly
            --result <file.json>       Write the outcome as JSON (used by the tray app)
            --yes                      Do not prompt

          rules update [--url <url>]   Download the latest EOL rules catalogue
          rules show                   Show the rules catalogue in use

          run                          Run the background agent in this console (debugging)
          service                      Entry point used by the Windows service

        Exit codes: 0 clean, 10 end-of-life software found, 11 nearing EOL / unpatched runtimes,
                    12 only app updates pending, 1 error, 2 usage.
        """);

    private static async Task<ScanResult> DoScanAsync(string[] args, bool includeUpdates, CancellationToken ct)
    {
        var eff = SettingsStore.LoadEffective(AppPaths.SettingsFile);
        return await Scanner.ScanAsync(eff, new ScanOptions
        {
            IncludeUpdates = includeUpdates && !Has(args, "--no-updates"),
            AllowNetwork = !Has(args, "--offline"),
            ScanDependencies = !Has(args, "--no-deps"),
            CollectDevice = includeUpdates && !Has(args, "--no-device"),
            CheckExtensions = includeUpdates && !Has(args, "--no-extensions"),
        }, ct);
    }

    private static async Task<int> ScanAsync(string[] args, CancellationToken ct)
    {
        var json = Has(args, "--json");
        if (!json) Console.WriteLine("Scanning this device...");
        var r = await DoScanAsync(args, includeUpdates: true, ct);

        if (Value(args, "--out") is { } outFile) await File.WriteAllTextAsync(outFile, ReportWriter.ToJson(r, Has(args, "--inventory")), ct);
        if (Value(args, "--html") is { } html) await File.WriteAllTextAsync(html, ReportWriter.ToHtml(r), ct);
        if (Value(args, "--csv") is { } csv) await File.WriteAllTextAsync(csv, ReportWriter.ToCsv(r), ct);

        if (json) Console.WriteLine(ReportWriter.ToJson(r, Has(args, "--inventory")));
        else PrintSummary(r);

        var c = r.Counts;
        return c.EndOfLife > 0 ? ExitEol : c.NearingEndOfLife + c.OutdatedPatch > 0 ? ExitNeedsAttention : c.UpdatesAvailable > 0 ? ExitUpdatesPending : ExitClean;
    }

    private static void PrintSummary(ScanResult r)
    {
        var today = DateOnly.FromDateTime(DateTime.Now);
        var c = r.Counts;
        Console.WriteLine();
        Console.WriteLine($"{r.ComputerName}: {c.EndOfLife} end-of-life, {c.NearingEndOfLife} nearing end of life, {c.OutdatedPatch} unpatched, {c.UpdatesAvailable} app update(s) ({c.UpdatesExcluded} excluded)");
        Console.WriteLine($"Rules {r.RulesVersion}{(r.OnlineEolData ? " + endoflife.date" : " (offline dates)")}, context {r.ScanContext}");
        foreach (var f in r.Findings)
        {
            Console.WriteLine();
            Console.WriteLine($"[{f.Severity}] {f.Title} - {f.StatusText(today)}");
            Console.WriteLine($"  id: {f.Id}");
            foreach (var i in f.Items) Console.WriteLine($"    {i.Describe()}");
            foreach (var d in f.Dependents.Take(10)) Console.WriteLine($"    used by: {d.AppPath}{(d.WouldBreak ? "  <-- would break" : "")}");
            foreach (var a in f.Actions) Console.WriteLine($"  fix: {a.Id,-20} {a.Label}{(a.Recommended ? "  (recommended)" : "")}");
        }
        if (r.Updates.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("App updates:");
            foreach (var u in r.Updates) Console.WriteLine($"  {(u.Excluded ? "[excluded] " : "")}{u.Name} ({u.Id}) {u.InstalledVersion} -> {u.AvailableVersion}");
        }
        foreach (var w in r.Warnings) Console.WriteLine($"note: {w}");
    }

    private static async Task<int> UpdatesAsync(string[] args, CancellationToken ct)
    {
        var sub = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
        var eff = SettingsStore.LoadEffective(AppPaths.SettingsFile);
        var winget = WingetClient.TryCreate(Platform.IsSystem) ?? throw new InvalidOperationException("winget (App Installer) was not found on this device.");
        var updates = ExclusionMatcher.Apply(await winget.ListUpgradesAsync(ct), eff.Settings.ExcludedPackageIds, eff.PolicyExcludedPackageIds);

        if (sub == "list")
        {
            foreach (var u in updates)
                Console.WriteLine($"{(u.Excluded ? "[excluded] " : u.RequiresExplicit ? "[pinned]   " : "")}{u.Name} | {u.Id} | {u.InstalledVersion} -> {u.AvailableVersion}");
            Console.WriteLine($"{updates.Count(u => u.Installable)} installable, {updates.Count(u => u.Excluded)} excluded.");
            return updates.Any(u => u.Installable) ? ExitUpdatesPending : ExitClean;
        }
        if (sub != "install") return Usage("Use 'updates list' or 'updates install --all | --id <id>'.");

        var ids = Values(args, "--id");
        if (!Has(args, "--all") && ids.Count == 0) return Usage("Specify --all or one or more --id values.");
        var targets = updates.Where(u => u.Installable && (Has(args, "--all") || ids.Contains(u.Id, StringComparer.OrdinalIgnoreCase))).ToList();
        var failed = 0;
        foreach (var u in targets)
        {
            Console.Write($"Updating {u.Name} {u.InstalledVersion} -> {u.AvailableVersion} ... ");
            var res = await winget.UpgradeAsync(u.Id, u.Name, ct);
            Console.WriteLine(res.Message);
            if (!res.Success) failed++;
        }
        Console.WriteLine($"{targets.Count - failed} of {targets.Count} update(s) installed.");
        return failed > 0 ? ExitError : ExitClean;
    }

    private static async Task<int> FixAsync(string[] args, CancellationToken ct)
    {
        var positional = args.Skip(1).Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToList();
        var r = await DoScanAsync(args, includeUpdates: false, ct);

        if (positional.FirstOrDefault()?.Equals("list", StringComparison.OrdinalIgnoreCase) == true)
        {
            PrintSummary(r);
            return ExitClean;
        }

        var plan = new List<(Finding F, RemediationAction A)>();
        if (Has(args, "--safe"))
        {
            foreach (var f in r.Findings.Where(f => f.Kind == FindingKind.OutdatedPatch && f.Items.All(i => i.Source == ItemSource.DotNetSharedFramework)))
            {
                var a = f.Actions.FirstOrDefault(x => x.Kind == ActionKind.UpgradeInPlace) ?? f.Actions.FirstOrDefault(x => x.Kind == ActionKind.RemoveSupersededPatches);
                if (a is not null) plan.Add((f, a));
            }
        }
        if (Has(args, "--remove-unused-eol"))
        {
            foreach (var f in r.Findings.Where(f => f.Kind == FindingKind.EndOfLife && f.Dependents.Count == 0
                                                    && f.Items.All(i => i.Source is ItemSource.DotNetSharedFramework or ItemSource.DotNetSdk)))
            {
                var a = f.Actions.FirstOrDefault(x => x.Kind == ActionKind.Remove);
                if (a is not null) plan.Add((f, a));
            }
        }
        if (positional.Count == 2)
        {
            var f = r.Findings.FirstOrDefault(x => x.Id.Equals(positional[0], StringComparison.OrdinalIgnoreCase));
            var a = f?.Actions.FirstOrDefault(x => x.Id.Equals(positional[1], StringComparison.OrdinalIgnoreCase));
            if (f is null || a is null) return Usage($"Finding/action not found. Run 'psentinel fix list' to see ids.");
            plan.Add((f, a));
        }
        if (plan.Count == 0)
        {
            if (positional.Count != 2 && !Has(args, "--safe") && !Has(args, "--remove-unused-eol"))
                return Usage("Specify '<findingId> <actionId>', --safe or --remove-unused-eol.");
            Console.WriteLine("Nothing to fix.");
            return ExitClean;
        }

        if (!Platform.IsElevated) { Console.Error.WriteLine("Fixes need administrator rights: run from an elevated prompt or as SYSTEM via your RMM."); return ExitError; }

        Console.WriteLine("Planned:");
        foreach (var (f, a) in plan)
        {
            Console.WriteLine($"  {f.Title}: {a.Label}");
            foreach (var s in a.Steps) Console.WriteLine($"     - {s.Description}{(s.RequiresUserContext ? " [skipped: needs the user's session]" : "")}");
            if (a.Warning is not null) Console.WriteLine($"     ! {a.Warning}");
        }
        if (!Has(args, "--yes"))
        {
            if (Console.IsInputRedirected) { Console.Error.WriteLine("Add --yes to run non-interactively."); return ExitUsage; }
            Console.Write("Proceed? [y/N] ");
            if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase)) return ExitClean;
        }

        var executor = new RemediationExecutor(WingetClient.TryCreate(Platform.IsSystem), Platform.IsSystem);
        var allOk = true;
        foreach (var (f, a) in plan)
        {
            var res = await executor.ExecuteAsync(f, a, s => !s.RequiresUserContext, ct);
            Console.WriteLine($"{f.Title}: {res.Summary}");
            foreach (var s in res.Steps) Console.WriteLine($"   {(s.Success ? "OK  " : "FAIL")} {s.Description}: {s.Message}");
            allOk &= res.Success;
        }
        return allOk ? ExitClean : ExitError;
    }

    /// <summary>
    /// Uninstalls apps. Machine-wide apps need administrator rights, so the tray app runs this elevated (UAC prompt)
    /// rather than asking the SYSTEM service; that way a standard user cannot remove software without an admin.
    /// The uninstall command is always read from this machine's registry, never taken from the caller.
    /// </summary>
    private static async Task<int> UninstallAsync(string[] args, CancellationToken ct)
    {
        var keys = Values(args, "--key");
        var wingetIds = Values(args, "--winget-id");
        var name = Value(args, "--name");
        var resultFile = Value(args, "--result");
        if (keys.Count == 0 && wingetIds.Count == 0 && name is null) return Usage("Specify --key, --winget-id or --name.");
        if (wingetIds.Any(i => !WingetClient.IsValidId(i))) return Usage("Invalid winget id.");
        if (!Platform.IsElevated) { Console.Error.WriteLine("Uninstalling needs administrator rights: run from an elevated prompt."); return ExitError; }

        var warnings = new List<string>();
        var inventory = Core.Inventory.RegistryInventory.Collect(allLoadedUserHives: Platform.IsSystem, Platform.CurrentUserSid, warnings);
        var items = inventory.Where(i => (i.RegistryKey is not null && keys.Contains(i.RegistryKey, StringComparer.OrdinalIgnoreCase))
                                         || (name is not null && i.Name.Equals(name, StringComparison.OrdinalIgnoreCase))).ToList();

        var plan = new List<(string Name, string? Version, List<RemediationStep> Steps)>();
        foreach (var i in items)
            plan.Add((i.Name, i.Version, RemediationPlanner.RegistryUninstallSteps(i)
                .Select(s => s with { RequiresUserContext = false }).ToList())); // already running as the elevated user
        foreach (var id in wingetIds)
            plan.Add((id, null, [new RemediationStep { Kind = StepKind.WingetUninstall, Target = id, Description = $"Uninstall {id} with winget" }]));
        foreach (var k in keys.Where(k => !items.Any(i => string.Equals(i.RegistryKey, k, StringComparison.OrdinalIgnoreCase))))
            Console.WriteLine($"Not found (already removed?): {k}");

        if (plan.Count == 0) { WriteResult(resultFile, new UninstallResultFile()); Console.WriteLine("Nothing to uninstall."); return ExitClean; }

        Console.WriteLine("PatchSentinel will uninstall:");
        foreach (var p in plan) Console.WriteLine($"  {p.Name} {p.Version}{(p.Steps.Count == 0 ? "  (no uninstaller registered - skipped)" : "")}");
        if (!Has(args, "--yes"))
        {
            if (Console.IsInputRedirected) { Console.Error.WriteLine("Add --yes to run non-interactively."); return ExitUsage; }
            Console.Write("Proceed? [y/N] ");
            if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase)) return ExitClean;
        }

        var executor = new RemediationExecutor(WingetClient.TryCreate(Platform.IsSystem), Platform.IsSystem);
        var outcome = new UninstallResultFile();
        foreach (var p in plan)
        {
            if (p.Steps.Count == 0) { outcome.Results.Add(new UninstallRecord(p.Name, p.Version, false, "No uninstaller is registered; remove it manually.")); continue; }
            Console.Write($"Uninstalling {p.Name}... ");
            var finding = new Finding { Id = "uninstall", Title = p.Name };
            var action = new RemediationAction { Id = "uninstall", Label = $"Uninstall {p.Name}", Steps = p.Steps };
            var res = await executor.ExecuteAsync(finding, action, _ => true, ct);
            var msg = string.Join("; ", res.Steps.Select(s => s.Message));
            Console.WriteLine(res.Success ? "done" : $"failed: {msg}");
            outcome.Results.Add(new UninstallRecord(p.Name, p.Version, res.Success, res.Success ? (res.RebootRequired ? "Uninstalled (restart required)" : "Uninstalled") : msg));
            outcome.RebootRequired |= res.RebootRequired;
        }
        WriteResult(resultFile, outcome);
        return outcome.Results.All(r => r.Success) ? ExitClean : ExitError;
    }

    private static void WriteResult(string? path, UninstallResultFile result)
    {
        if (path is null) return;
        try { File.WriteAllText(path, JsonSerializer.Serialize(result, Json.Options)); }
        catch (Exception ex) { Console.Error.WriteLine($"Could not write result file: {ex.Message}"); }
    }

    private static async Task<int> RulesAsync(string[] args, CancellationToken ct)
    {
        var sub = args.Length > 1 ? args[1].ToLowerInvariant() : "show";
        if (sub == "update")
        {
            if (!Platform.IsElevated) { Console.Error.WriteLine("Run elevated to update the shared rules catalogue."); return ExitError; }
            var url = Value(args, "--url") ?? SettingsStore.LoadEffective(AppPaths.SettingsFile).EffectiveRulesUrl
                      ?? throw new InvalidOperationException("No rules URL configured. Use --url or set RulesUrl in policy/settings.");
            Directory.CreateDirectory(AppPaths.RulesDir);
            Console.WriteLine(await RuleCatalogLoader.UpdateFromUrlAsync(url, AppPaths.RulesDir, ct));
            return ExitClean;
        }
        var warnings = new List<string>();
        var catalog = RuleCatalogLoader.Load(AppPaths.RulesDir, warnings);
        Console.WriteLine($"Rules catalogue {catalog.CatalogVersion} ({catalog.Rules.Count} rules)");
        foreach (var rule in catalog.Rules) Console.WriteLine($"  {rule.Id,-28} {rule.Product}{(rule.Disabled ? " (disabled)" : "")}");
        foreach (var w in warnings) Console.WriteLine($"note: {w}");
        return ExitClean;
    }

    private static async Task<int> DeviceAsync(string[] args, CancellationToken ct)
    {
        var warnings = new List<string>();
        var catalog = RuleCatalogLoader.Load(AppPaths.RulesDir, warnings);
        var inventory = new SoftwareClassifier(catalog.Categories, warnings).Apply(
            Core.Inventory.RegistryInventory.Collect(allLoadedUserHives: Platform.IsSystem, Platform.CurrentUserSid, warnings));
        var today = DateOnly.FromDateTime(DateTime.Now);
        var device = await Core.Device.DeviceCollector.CollectAsync(inventory, !Has(args, "--no-public-ip"), today, ct);
        var checks = Core.Device.BuildChecklist.Evaluate(catalog.BuildChecklist, device, inventory, today, catalog.Links);
        var signoffs = Core.Device.BuildSignoffStore.Load();
        Core.Device.BuildSignoffStore.Apply(checks, signoffs);
        var computer = device.ComputerName;
        var apps = inventory.Where(i => !i.IsSystemComponent).ToList();

        if (Value(args, "--xlsx") is { } xlsx) { await using var f = File.Create(xlsx); InventoryExporter.WriteXlsx(apps, computer, f, device, checks, handover: signoffs.Handover); }
        if (Value(args, "--html") is { } html) await File.WriteAllTextAsync(html, InventoryExporter.ToHtml(apps, computer, device, checks, handover: signoffs.Handover), ct);
        if (Value(args, "--csv") is { } csv) await File.WriteAllTextAsync(csv, DeviceReport.ToCsv(device, checks, signoffs.Handover), ct);
        if (Has(args, "--json"))
        {
            Console.WriteLine(JsonSerializer.Serialize(new { device, buildChecks = checks, buildHandover = signoffs.Handover }, Json.Options));
        }
        else
        {
            foreach (var g in DeviceReport.Rows(device).GroupBy(r => r.Section))
            {
                Console.WriteLine();
                Console.WriteLine(g.Key.ToUpperInvariant());
                foreach (var r in g) Console.WriteLine($"  {r.Field,-28} {r.Value}{(r.Status is { } s ? $"  [{DeviceReport.StatusText(s)}]" : "")}");
            }
            Console.WriteLine();
            Console.WriteLine("BUILD CHECKLIST");
            foreach (var c in checks)
                Console.WriteLine($"  {c.Step,2}. [{DeviceReport.StatusText(c.Status),-13}] {c.Title} - {c.Detail}{(c.Signoff is { } so ? $"  ({so.Text})" : "")}");
            Console.WriteLine(signoffs.Handover is { } h ? $"  {h.Text}" : "  Build not signed off yet.");
        }
        var failed = checks.Count(c => c.Status == Core.Device.CheckStatus.Fail);
        return failed > 0 ? ExitNeedsAttention : ExitClean;
    }

    private static async Task<int> ExtensionsAsync(string[] args, CancellationToken ct)
    {
        var sub = args.Length > 1 && !args[1].StartsWith("--", StringComparison.Ordinal) ? args[1].ToLowerInvariant() : "list";
        if (sub is "block" or "unblock" or "uninstall")
        {
            if (!Platform.IsElevated) { Console.Error.WriteLine("Run elevated: blocking an extension writes a machine policy."); return ExitError; }
            if (!Enum.TryParse<Core.Browsers.Browser>(Value(args, "--browser"), true, out var browser)) return Usage("--browser must be chrome, edge, brave or firefox.");
            var ids = Values(args, "--id");
            if (ids.Count == 0) return Usage("--id is required.");
            var failed = false;
            foreach (var id in ids)
            {
                try
                {
                    Console.WriteLine(sub switch
                    {
                        "block" => Core.Browsers.ExtensionPolicy.Block(browser, id),
                        "uninstall" => Core.Browsers.ExtensionPolicy.Uninstall(browser, id, id, Environment.UserName),
                        _ => Core.Browsers.ExtensionPolicy.Unblock(browser, id),
                    });
                }
                catch (Exception ex) { Console.Error.WriteLine($"{id}: {ex.Message}"); failed = true; }
            }
            return failed ? ExitError : ExitClean;
        }
        if (sub != "list") return Usage($"Unknown extensions command '{sub}'.");

        var warnings = new List<string>();
        var s = SettingsStore.LoadEffective(AppPaths.SettingsFile).Settings;
        var list = await Scanner.ScanExtensionsAsync(s.ExtensionStoreLookup && !Has(args, "--offline"), Platform.IsSystem, warnings, ct);
        foreach (var done in Scanner.LastCompletedRemovals) Console.WriteLine($"Uninstalled: {done.Name} ({done.Browser}) - uninstall policy taken off.");
        var computer = Environment.MachineName;
        if (Value(args, "--xlsx") is { } xlsx) { await using var f = File.Create(xlsx); Core.Reporting.ExtensionExporter.WriteXlsx(list, computer, f); }
        if (Value(args, "--html") is { } html) await File.WriteAllTextAsync(html, Core.Reporting.ExtensionExporter.ToHtml(list, computer), ct);
        if (Value(args, "--csv") is { } csv) await File.WriteAllTextAsync(csv, Core.Reporting.ExtensionExporter.ToCsv(list, computer), ct);
        var review = list.Count(e => e.Concern != Core.Rules.Concern.Info);
        if (Has(args, "--json"))
            Console.WriteLine(JsonSerializer.Serialize(new { extensions = list, warnings }, Json.Options));
        else
        {
            foreach (var e in Has(args, "--review") ? list.Where(e => e.Concern != Core.Rules.Concern.Info) : list)
                Console.WriteLine($"[{InventoryExporter.ConcernText(e.Concern),-18}] {e.BrowserName,-15} {e.UserName}/{e.Profile}: {e.Name} {e.Version} - {e.StatusText}");
            foreach (var w in warnings) Console.WriteLine($"note: {w}");
            Console.WriteLine($"{list.Count} extensions, {review} need attention.");
        }
        return review > 0 ? ExitNeedsAttention : ExitClean;
    }

    private static async Task<int> InventoryAsync(string[] args, CancellationToken ct)
    {
        var warnings = new List<string>();
        var catalog = Core.Rules.RuleCatalogLoader.Load(AppPaths.RulesDir, warnings);
        var items = new Core.Rules.SoftwareClassifier(catalog.Categories, warnings).Apply(
            Core.Inventory.RegistryInventory.Collect(allLoadedUserHives: Platform.IsSystem, Platform.CurrentUserSid, warnings))
            .Where(i => !i.IsSystemComponent).ToList();
        var computer = Environment.MachineName;
        if (Value(args, "--xlsx") is { } xlsx) { await using var f = File.Create(xlsx); InventoryExporter.WriteXlsx(items, computer, f); }
        if (Value(args, "--html") is { } html) await File.WriteAllTextAsync(html, InventoryExporter.ToHtml(items, computer), ct);
        if (Value(args, "--csv") is { } csv) await File.WriteAllTextAsync(csv, InventoryExporter.ToCsv(items, computer), ct);

        var shown = Has(args, "--review") ? items.Where(i => i.Classification?.Concern is Core.Rules.Concern.Review or Core.Rules.Concern.High).ToList() : items;
        foreach (var i in shown.OrderByDescending(i => i.Classification?.Concern ?? (Core.Rules.Concern)(-1)).ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase))
            Console.WriteLine($"{(i.Classification is { } c ? $"[{InventoryExporter.ConcernText(c.Concern)}] {c.Category}: " : "")}{i.Name} {i.Version}");
        var review = items.Count(i => i.Classification?.Concern is Core.Rules.Concern.Review or Core.Rules.Concern.High);
        Console.WriteLine($"{items.Count} apps, {review} need a security review.");
        return review > 0 ? ExitNeedsAttention : ExitClean;
    }

    private static async Task<int> SelfUpdateAsync(string[] args, CancellationToken ct)
    {
        var repo = Value(args, "--repo") ?? SettingsStore.LoadEffective(AppPaths.SettingsFile).EffectiveUpdateRepo;
        if (!SelfUpdater.IsValidRepo(repo)) { Console.Error.WriteLine("No update repository configured (use --repo owner/repo)."); return ExitError; }
        var latest = await SelfUpdater.GetLatestAsync(repo!, ct);
        if (latest is null) { Console.WriteLine($"No published release found in {repo}."); return ExitClean; }
        Console.WriteLine($"Installed {AppPaths.Version}, latest release {latest.Version} ({latest.PageUrl})");
        if (!SelfUpdater.IsNewer(latest.Version, AppPaths.Version)) { Console.WriteLine("PatchSentinel is up to date."); return ExitClean; }
        if (Has(args, "--check")) return ExitUpdatesPending;
        if (!Platform.IsElevated) { Console.Error.WriteLine("Run elevated to install the update."); return ExitError; }
        Console.WriteLine($"Downloading {latest.MsiName} and checking its SHA-256...");
        var msi = await SelfUpdater.DownloadAndVerifyAsync(latest, ct);
        Console.WriteLine("Verified. Starting silent upgrade (the PatchSentinel service will restart).");
        SelfUpdater.LaunchInstaller(msi);
        return ExitClean;
    }

    private static async Task<int> RunConsoleAsync(CancellationToken ct)
    {
        if (!Platform.IsElevated) { Console.Error.WriteLine("Run elevated (the agent needs administrator rights)."); return ExitError; }
        AppLog.EchoToConsole = true;
        Console.WriteLine("Agent running in console. Press Ctrl+C to stop.");
        await new AgentEngine().RunAsync(ct);
        return ExitClean;
    }

    private static int Print(string s) { Console.WriteLine(s); return ExitClean; }
    private static int Usage(string msg) { Console.Error.WriteLine(msg); Console.Error.WriteLine("Run 'psentinel help' for usage."); return ExitUsage; }
    private static bool Has(string[] args, string flag) => args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));

    private static string? Value(string[] args, string flag)
    {
        var i = Array.FindIndex(args, a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static List<string> Values(string[] args, string flag) =>
        args.Select((a, i) => (a, i)).Where(x => x.a.Equals(flag, StringComparison.OrdinalIgnoreCase) && x.i + 1 < args.Length).Select(x => args[x.i + 1]).ToList();
}
