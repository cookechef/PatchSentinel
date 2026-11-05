using System.Text.Json;
using PatchSentinel.Core;
using PatchSentinel.Core.Config;
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
                "rules" => await RulesAsync(args, cts.Token),
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

          updates list                 List available winget upgrades (exclusions applied)
          updates install --all        Install every non-excluded upgrade
          updates install --id <id>    Install specific package(s); repeat --id as needed

          fix list                     List findings and their fix actions
          fix <findingId> <actionId>   Run one fix action (e.g. fix dotnet-runtime:6:EndOfLife remove)
          fix --safe                   Remove superseded .NET patch versions and patch supported runtimes
          fix --remove-unused-eol      Remove EOL .NET runtimes that no installed application uses
            --yes                      Do not prompt (required when run non-interactively)

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
