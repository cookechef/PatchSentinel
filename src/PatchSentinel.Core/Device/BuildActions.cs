using System.Text.RegularExpressions;

namespace PatchSentinel.Core.Device;

/// <summary>
/// A button on a build checklist step, defined in the rules catalogue. The agent only ever runs actions from its own
/// catalogue (the tray sends the step and action IDs, never a command), and programs must live under Program Files or
/// Windows\System32.
/// </summary>
public sealed class BuildAction
{
    public string Id { get; set; } = "";
    public string Label { get; set; } = "";
    /// <summary>
    /// url (open a web page, ms-settings: or windowsdefender: link), link (a named portal link from the catalogue's
    /// links section), open (start a program for the signed-in user), winget (install a package as SYSTEM),
    /// run (run a program as SYSTEM and wait), tab (switch to a tab in the app).
    /// </summary>
    public string Kind { get; set; } = "url";
    public string? Url { get; set; }
    public string? Link { get; set; }
    public string? WingetId { get; set; }
    public List<string> Paths { get; set; } = [];
    public string? Args { get; set; }
    /// <summary>open: ask for administrator approval.</summary>
    public bool Elevate { get; set; }
    public string? Tab { get; set; }
    public List<int> OkExitCodes { get; set; } = [0];
    public int TimeoutMinutes { get; set; } = 60;
    public string? Description { get; set; }

    /// <summary>Regex on the device manufacturer (e.g. "Dell", "Lenovo", "HP|Hewlett").</summary>
    public string? Manufacturer { get; set; }
    /// <summary>Regex on the processor name (e.g. "Intel").</summary>
    public string? Processor { get; set; }
    /// <summary>Only show when one of these files exists (defaults to Paths for open/run).</summary>
    public List<string> IfInstalled { get; set; } = [];
    /// <summary>Only show when none of these files exist.</summary>
    public List<string> IfMissing { get; set; } = [];
    /// <summary>Only show when no installed app name matches (regex fragments).</summary>
    public List<string> IfAppMissing { get; set; } = [];
    /// <summary>Only show when the step is not OK (default for winget and run).</summary>
    public bool? OnlyWhenNotOk { get; set; }
}

/// <summary>What the tray needs to show and start an action.</summary>
public sealed class BuildActionView
{
    public string Id { get; set; } = "";
    public string Label { get; set; } = "";
    public string Kind { get; set; } = "";
    public string? Target { get; set; }
    public string? Args { get; set; }
    public bool Elevate { get; set; }
    public string? Description { get; set; }
    /// <summary>Runs through the agent (winget or run as SYSTEM).</summary>
    public bool ViaAgent => Kind is "winget" or "run";
}

public static class BuildActions
{
    private static readonly string[] AllowedSchemes = ["https://", "ms-settings:", "windowsdefender:"];

    public static string Expand(string path) => Environment.ExpandEnvironmentVariables(path.Replace("%ProgramFiles(x86)%", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase));

    /// <summary>Programs may only be started from Program Files or Windows\System32, so a catalogue entry cannot point at a user-writable folder.</summary>
    public static bool IsSafeProgram(string fullPath)
    {
        try
        {
            var p = Path.GetFullPath(fullPath);
            var roots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.System),
            }.Where(r => !string.IsNullOrEmpty(r)).Select(r => r.TrimEnd('\\') + "\\");
            return roots.Any(r => p.StartsWith(r, StringComparison.OrdinalIgnoreCase)) && !p.Contains("..", StringComparison.Ordinal);
        }
        catch { return false; }
    }

    public static bool IsSafeUrl(string? url) => url is not null && AllowedSchemes.Any(s => url.StartsWith(s, StringComparison.OrdinalIgnoreCase)) && !url.Any(char.IsControl);

    public static string? FirstExisting(IEnumerable<string> paths) =>
        paths.Select(Expand).FirstOrDefault(p => File.Exists(p) && IsSafeProgram(p));

    public static string? ResolveUrl(BuildAction a, IReadOnlyDictionary<string, string> links)
    {
        var url = a.Kind == "link" ? (a.Link is not null && links.TryGetValue(a.Link, out var l) ? l : null) : a.Url;
        return IsSafeUrl(url) ? url : null;
    }

    /// <summary>The actions that apply to this device and this step's current result.</summary>
    public static List<BuildActionView> Visible(BuildCheckRule rule, BuildCheckResult result, DeviceInfo d, IReadOnlyList<InstalledItem> apps,
        IReadOnlyDictionary<string, string> links)
    {
        var list = new List<BuildActionView>();
        foreach (var a in rule.Actions)
        {
            try
            {
                if (a.Manufacturer is { Length: > 0 } m && !Regex.IsMatch(d.Manufacturer ?? "", m, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100))) continue;
                if (a.Processor is { Length: > 0 } pr && !Regex.IsMatch(d.CpuName ?? "", pr, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100))) continue;
                var onlyNotOk = a.OnlyWhenNotOk ?? a.Kind is "winget" or "run";
                if (onlyNotOk && result.Status == CheckStatus.Pass) continue;
                if (a.IfMissing.Count > 0 && a.IfMissing.Select(Expand).Any(File.Exists)) continue;
                var mustExist = a.IfInstalled.Count > 0 ? a.IfInstalled : a.Kind is "open" or "run" ? a.Paths : [];
                if (mustExist.Count > 0 && !mustExist.Select(Expand).Any(File.Exists)) continue;
                if (a.IfAppMissing.Count > 0)
                {
                    var rx = new Regex(@"(?<![A-Za-z0-9])(?:" + string.Join("|", a.IfAppMissing) + ")", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
                    if (apps.Any(i => rx.IsMatch(i.Name))) continue;
                }

                var v = new BuildActionView { Id = a.Id, Label = a.Label, Kind = a.Kind, Description = a.Description, Elevate = a.Elevate, Args = a.Args };
                switch (a.Kind)
                {
                    case "url":
                    case "link":
                        v.Kind = "url";
                        v.Target = ResolveUrl(a, links);
                        if (v.Target is null) continue; // e.g. a portal link that hasn't been filled in
                        break;
                    case "open":
                    case "run":
                        v.Target = FirstExisting(a.Paths);
                        if (v.Target is null) continue;
                        break;
                    case "winget":
                        if (a.WingetId is null || !Updates.WingetClient.IsValidId(a.WingetId)) continue;
                        v.Target = a.WingetId;
                        break;
                    case "tab":
                        v.Target = a.Tab;
                        break;
                    default:
                        continue;
                }
                list.Add(v);
            }
            catch { /* skip a bad catalogue entry */ }
        }
        return list;
    }
}
