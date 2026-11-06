using System.Diagnostics;
using System.Text.Json;

namespace PatchSentinel.Core.Remediation;

public sealed record RuntimeConfigReference(string ConfigPath, string AppPath, string Framework, string Version, string RollForward, string Architecture, bool Implicit);

/// <summary>
/// Finds framework-dependent .NET applications by their *.runtimeconfig.json so we can tell the user
/// which apps would stop working if a runtime were removed.
/// </summary>
public static class DotNetDependencyScanner
{
    public static List<string> DefaultRoots(bool allUsers, IEnumerable<string>? extra = null)
    {
        var roots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };
        if (allUsers)
        {
            foreach (var profile in Browsers.ExtensionInventory.UserProfileFolders())
                roots.Add(Path.Combine(profile, "AppData", "Local", "Programs"));
        }
        else
        {
            roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"));
        }
        if (extra is not null) roots.AddRange(extra);
        return roots.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static List<RuntimeConfigReference> Scan(IEnumerable<string> roots, IReadOnlyCollection<string> dotnetRoots, TimeSpan budget, List<string> warnings, CancellationToken ct)
    {
        var results = new List<RuntimeConfigReference>();
        var sw = Stopwatch.StartNew();
        var opts = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            MaxRecursionDepth = 8,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline,
        };
        var globalRollForward = Environment.GetEnvironmentVariable("DOTNET_ROLL_FORWARD", EnvironmentVariableTarget.Machine);

        foreach (var root in roots.Where(Directory.Exists))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.runtimeconfig.json", opts))
                {
                    ct.ThrowIfCancellationRequested();
                    if (sw.Elapsed > budget)
                    {
                        warnings.Add($"Application dependency scan stopped after {budget.TotalSeconds:0}s; the list of affected apps may be incomplete.");
                        return results;
                    }
                    if (dotnetRoots.Any(d => file.StartsWith(d.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))) continue;
                    if (file.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase)) continue;
                    results.AddRange(ParseFile(file, globalRollForward));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { warnings.Add($"Dependency scan of {root} failed: {ex.Message}"); }
        }
        return results;
    }

    public static IEnumerable<RuntimeConfigReference> ParseFile(string file, string? globalRollForward = null)
    {
        try
        {
            var info = new FileInfo(file);
            if (info.Length > 256 * 1024) return [];
            return Parse(File.ReadAllText(file), file, globalRollForward);
        }
        catch { return []; }
    }

    public static List<RuntimeConfigReference> Parse(string json, string configPath, string? globalRollForward = null)
    {
        var list = new List<RuntimeConfigReference>();
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        if (!doc.RootElement.TryGetProperty("runtimeOptions", out var ro)) return list;
        if (ro.TryGetProperty("includedFrameworks", out _)) return list; // self-contained app - unaffected

        var rollForward = ro.TryGetProperty("rollForward", out var rf) && rf.ValueKind == JsonValueKind.String
            ? rf.GetString()!
            : ro.TryGetProperty("rollForwardOnNoCandidateFx", out var legacy) && legacy.ValueKind == JsonValueKind.Number
                ? legacy.GetInt32() switch { 0 => "LatestPatch", 2 => "Major", _ => "Minor" }
                : globalRollForward ?? "Minor";

        var appBase = configPath.EndsWith(".runtimeconfig.json", StringComparison.OrdinalIgnoreCase)
            ? configPath[..^".runtimeconfig.json".Length]
            : configPath;
        var exe = appBase + ".exe";
        var appPath = File.Exists(exe) ? exe : appBase + ".dll";
        var arch = File.Exists(exe) ? PeArchitecture(exe) ?? Platform.NativeArchitecture : Platform.NativeArchitecture;

        var frameworks = new List<JsonElement>();
        if (ro.TryGetProperty("framework", out var single) && single.ValueKind == JsonValueKind.Object) frameworks.Add(single);
        if (ro.TryGetProperty("frameworks", out var many) && many.ValueKind == JsonValueKind.Array) frameworks.AddRange(many.EnumerateArray());

        foreach (var fw in frameworks)
        {
            var name = fw.TryGetProperty("name", out var n) ? n.GetString() : null;
            var version = fw.TryGetProperty("version", out var v) ? v.GetString() : null;
            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(version)) continue;
            list.Add(new RuntimeConfigReference(configPath, appPath, name, version, rollForward, arch, false));
            // ASP.NET Core and Windows Desktop are layered on Microsoft.NETCore.App of the same version.
            if (name is "Microsoft.AspNetCore.App" or "Microsoft.WindowsDesktop.App" or "Microsoft.AspNetCore.All")
                list.Add(new RuntimeConfigReference(configPath, appPath, "Microsoft.NETCore.App", version, rollForward, arch, true));
        }
        return list;
    }

    /// <summary>Reads the machine type from a PE header.</summary>
    public static string? PeArchitecture(string exePath)
    {
        try
        {
            using var fs = File.OpenRead(exePath);
            using var br = new BinaryReader(fs);
            if (fs.Length < 0x40) return null;
            fs.Position = 0x3C;
            var peOffset = br.ReadInt32();
            if (peOffset <= 0 || peOffset > fs.Length - 6) return null;
            fs.Position = peOffset;
            if (br.ReadUInt32() != 0x00004550) return null; // "PE\0\0"
            return br.ReadUInt16() switch
            {
                0x8664 => "x64",
                0x014C => "x86",
                0xAA64 => "arm64",
                _ => null,
            };
        }
        catch { return null; }
    }
}

/// <summary>Implements the .NET host's roll-forward rules closely enough to predict breakage.</summary>
public static class RollForwardResolver
{
    public static bool CanResolve(string requested, string? policy, IEnumerable<string> available)
    {
        var req = VersionUtil.Parse(requested);
        if (req.Length == 0) return true;
        int rMaj = req[0], rMin = req.Length > 1 ? req[1] : 0, rPatch = req.Length > 2 ? req[2] : 0;
        var p = (policy ?? "Minor").Trim();

        foreach (var a in available)
        {
            var v = VersionUtil.Parse(a);
            if (v.Length == 0) continue;
            int maj = v[0], min = v.Length > 1 ? v[1] : 0, patch = v.Length > 2 ? v[2] : 0;
            var ok = p.ToLowerInvariant() switch
            {
                "disable" => maj == rMaj && min == rMin && patch == rPatch,
                "latestpatch" => maj == rMaj && min == rMin && patch >= rPatch,
                "minor" or "latestminor" => maj == rMaj && (min > rMin || (min == rMin && patch >= rPatch)),
                "major" or "latestmajor" => maj > rMaj || (maj == rMaj && (min > rMin || (min == rMin && patch >= rPatch))),
                _ => maj == rMaj && (min > rMin || (min == rMin && patch >= rPatch)),
            };
            if (ok) return true;
        }
        return false;
    }
}
