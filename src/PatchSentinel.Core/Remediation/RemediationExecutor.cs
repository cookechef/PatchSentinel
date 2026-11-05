using PatchSentinel.Core.Inventory;
using PatchSentinel.Core.Updates;

namespace PatchSentinel.Core.Remediation;

public sealed record StepResult(string Description, bool Success, string Message);

public sealed record RemediationResult(string FindingId, string ActionId, bool Success, bool RebootRequired, List<StepResult> Steps)
{
    public string Summary => Success
        ? $"Completed {Steps.Count} step(s){(RebootRequired ? "; a restart is required to finish" : "")}."
        : $"Stopped: {Steps.LastOrDefault(s => !s.Success)?.Message ?? "a step failed"}";
}

/// <summary>Runs remediation steps. The same code runs in the SYSTEM service (machine steps) and in the tray (per-user steps).</summary>
public sealed class RemediationExecutor(WingetClient? winget, bool runningAsSystem)
{
    private static readonly TimeSpan UninstallTimeout = TimeSpan.FromMinutes(30);

    public async Task<RemediationResult> ExecuteAsync(Finding finding, RemediationAction action, Func<RemediationStep, bool> include, CancellationToken ct)
    {
        var results = new List<StepResult>();
        var reboot = false;
        foreach (var step in action.Steps.Where(include))
        {
            StepResult r;
            try
            {
                AppLog.Info($"Remediation {finding.Id}/{action.Id}: {step.Kind} {step.Target}");
                (r, var needsReboot) = await ExecuteStepAsync(step, ct);
                reboot |= needsReboot;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { r = new StepResult(step.Description, false, ex.Message); }
            results.Add(r);
            AppLog.Info($"  -> {(r.Success ? "OK" : "FAILED")}: {r.Message}");
            if (!r.Success) break; // never carry on removing things after a failed step
        }
        return new RemediationResult(finding.Id, action.Id, results.All(r => r.Success), reboot, results);
    }

    private async Task<(StepResult, bool reboot)> ExecuteStepAsync(RemediationStep step, CancellationToken ct)
    {
        if (runningAsSystem && step.RequiresUserContext)
            return (new StepResult(step.Description, false, "This step must run in the user's session (open PatchSentinel from the tray)."), false);

        switch (step.Kind)
        {
            case StepKind.MsiUninstall:
            {
                if (!CommandLine.MsiGuid.IsMatch(step.Target) || step.Target.Length != 38)
                    return (Fail(step, "Invalid MSI product code."), false);
                var msiexec = Path.Combine(Environment.SystemDirectory, "msiexec.exe");
                var r = await ProcessRunner.RunAsync(msiexec, $"/x {step.Target} /qn /norestart", UninstallTimeout, ct);
                return r.ExitCode switch
                {
                    0 => (Ok(step, "Uninstalled"), false),
                    3010 or 1641 => (Ok(step, "Uninstalled (restart required)"), true),
                    1605 => (Ok(step, "Already removed"), false),
                    1618 => (Fail(step, "Another installation is in progress; try again shortly."), false),
                    _ => (Fail(step, r.TimedOut ? "Uninstaller timed out." : $"msiexec returned {r.ExitCode}."), false),
                };
            }

            case StepKind.CommandUninstall:
            {
                var (file, args) = CommandLine.Split(step.Target);
                file = Environment.ExpandEnvironmentVariables(file);
                if (!File.Exists(file)) return (Ok(step, "Uninstaller not found - the product appears to be removed already"), false);
                if (runningAsSystem && !CommandLine.IsTrustedSystemPath(file))
                    return (Fail(step, $"Refusing to run {file} as SYSTEM because it is in a user-writable location."), false);
                var r = await ProcessRunner.RunAsync(file, args, UninstallTimeout, ct);
                return r.ExitCode switch
                {
                    0 => (Ok(step, "Uninstalled"), false),
                    3010 or 1641 => (Ok(step, "Uninstalled (restart required)"), true),
                    _ => (Fail(step, r.TimedOut ? "Uninstaller timed out." : $"Uninstaller returned {r.ExitCode}."), false),
                };
            }

            case StepKind.InteractiveUninstall:
            {
                var (file, args) = CommandLine.Split(step.Target);
                file = Environment.ExpandEnvironmentVariables(file);
                if (!File.Exists(file)) return (Ok(step, "Uninstaller not found - the product appears to be removed already"), false);
                var code = await ProcessRunner.RunInteractiveAsync(file, args, ct);
                return code is 0 or 3010 or 1641
                    ? (Ok(step, "Uninstaller finished"), code != 0)
                    : (Fail(step, $"Uninstaller returned {code} (it may have been cancelled)."), false);
            }

            case StepKind.WingetInstall:
            case StepKind.WingetUpgrade:
            case StepKind.WingetUninstall:
            {
                if (winget is null) return (Fail(step, "winget (App Installer) is not available on this device."), false);
                var r = step.Kind switch
                {
                    StepKind.WingetInstall => await winget.InstallAsync(step.Target, ct),
                    StepKind.WingetUpgrade => await winget.UpgradeAsync(step.Target, step.Target, ct),
                    _ => await winget.UninstallAsync(step.Target, ct),
                };
                return (new StepResult(step.Description, r.Success, r.Message), false);
            }

            case StepKind.VerifyDotNetNewer:
            {
                var dir = Path.GetDirectoryName(step.Target);
                var ver = Path.GetFileName(step.Target);
                if (dir is null || !Directory.Exists(dir)) return (Fail(step, "Runtime folder not found."), false);
                var newer = Directory.GetDirectories(dir).Select(Path.GetFileName)
                    .FirstOrDefault(v => v is not null && DotNetInventory.VersionFolder.IsMatch(v) && VersionUtil.SameMajorMinor(v, ver) && VersionUtil.Compare(v, ver) > 0);
                return newer is null
                    ? (Fail(step, $"No newer patch than {ver} is installed, so the old version was kept to avoid breaking apps."), false)
                    : (Ok(step, $"{newer} is installed"), false);
            }

            case StepKind.DeleteDotNetFolder:
            {
                if (!Directory.Exists(step.Target)) return (Ok(step, "Already removed"), false);
                if (!DotNetPathValidator.IsDeletable(step.Target, DotNetInventory.GetRoots().Select(r => r.Root), out var why))
                    return (Fail(step, why), false);
                try
                {
                    Directory.Delete(step.Target, recursive: true);
                    return (Ok(step, "Folder deleted"), false);
                }
                catch (UnauthorizedAccessException) when (!runningAsSystem && !Platform.IsElevated)
                {
                    return (Fail(step, "Administrator rights are required."), false);
                }
                catch (IOException ex)
                {
                    return (Fail(step, $"Files are in use ({ex.Message}). Close apps using this runtime or restart, then try again."), false);
                }
            }
        }
        return (Fail(step, "Unknown step."), false);
    }

    private static StepResult Ok(RemediationStep s, string m) => new(s.Description, true, m);
    private static StepResult Fail(RemediationStep s, string m) => new(s.Description, false, m);
}

/// <summary>Only ever allows deleting dotnet\shared\&lt;fw&gt;\&lt;version&gt; or dotnet\sdk\&lt;version&gt; under a known root, with no junctions in the path.</summary>
public static class DotNetPathValidator
{
    public static bool IsDeletable(string path, IEnumerable<string> dotnetRoots, out string reason)
    {
        reason = "Path is not a .NET runtime or SDK version folder.";
        string full;
        try { full = Path.GetFullPath(path).TrimEnd('\\', '/'); } catch { return false; }

        foreach (var root in dotnetRoots)
        {
            var rootFull = Path.GetFullPath(root).TrimEnd('\\', '/');
            if (!full.StartsWith(rootFull + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue;
            var parts = Path.GetRelativePath(rootFull, full).Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var shape = (parts.Length == 3 && parts[0].Equals("shared", StringComparison.OrdinalIgnoreCase)
                            && DotNetInventory.FrameworkFolder.IsMatch(parts[1]) && DotNetInventory.VersionFolder.IsMatch(parts[2]))
                        || (parts.Length == 2 && parts[0].Equals("sdk", StringComparison.OrdinalIgnoreCase) && DotNetInventory.VersionFolder.IsMatch(parts[1]));
            if (!shape) continue;

            // Refuse if any directory between the root and the target is a junction/symlink.
            for (var d = new DirectoryInfo(full); d is not null && d.FullName.TrimEnd('\\', '/').Length >= rootFull.Length; d = d.Parent)
            {
                if (d.Exists && d.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    reason = $"Refusing to delete through a junction or symbolic link ({d.FullName}).";
                    return false;
                }
            }
            reason = "";
            return true;
        }
        return false;
    }
}
