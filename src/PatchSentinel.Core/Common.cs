using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace PatchSentinel.Core;

public static class Json
{
    public static readonly JsonSerializerOptions Options = Create(indented: true);
    public static readonly JsonSerializerOptions Compact = Create(indented: false);

    private static JsonSerializerOptions Create(bool indented)
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = indented,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
        };
        o.Converters.Add(new JsonStringEnumConverter());
        return o;
    }
}

public static class AppPaths
{
    public const string PipeName = "PatchSentinel.Agent.v1";
    public const string ServiceName = "PatchSentinelAgent";

    public static string DataRoot { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "PatchSentinel");

    public static string StateDir => Path.Combine(DataRoot, "state");
    public static string CacheDir => Path.Combine(DataRoot, "cache");
    public static string LogDir => Path.Combine(DataRoot, "logs");
    public static string RulesDir => Path.Combine(DataRoot, "rules");
    public static string SettingsFile => Path.Combine(DataRoot, "settings.json");
    public static string LastScanFile => Path.Combine(StateDir, "last-scan.json");
    public static string AgentStateFile => Path.Combine(StateDir, "agent-state.json");

    public static string Version =>
        typeof(AppPaths).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0]
        ?? typeof(AppPaths).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    /// <summary>Rules URL baked in at build time (CI points it at the GitHub repo hosting this project).</summary>
    public static string? BuiltInRulesUrl
    {
        get
        {
            var v = typeof(AppPaths).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                .FirstOrDefault(a => a.Key == "DefaultRulesUrl")?.Value;
            return string.IsNullOrWhiteSpace(v) ? null : v;
        }
    }
}

public static class Platform
{
    public static bool IsSystem
    {
        get { try { using var id = WindowsIdentity.GetCurrent(); return id.IsSystem; } catch { return false; } }
    }

    public static bool IsElevated
    {
        get
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return id.IsSystem || new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    public static string? CurrentUserSid
    {
        get { try { using var id = WindowsIdentity.GetCurrent(); return id.User?.Value; } catch { return null; } }
    }

    public static string NativeArchitecture => RuntimeInformation.OSArchitecture switch
    {
        Architecture.Arm64 => "arm64",
        Architecture.X86 => "x86",
        _ => "x64",
    };
}

public static class VersionUtil
{
    private static readonly Regex Leading = new(@"(\d+(?:\.\d+)*)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    public static int[] Parse(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return [];
        var m = Leading.Match(v);
        if (!m.Success) return [];
        var parts = m.Groups[1].Value.Split('.');
        var r = new int[parts.Length];
        for (var i = 0; i < parts.Length; i++)
            r[i] = int.TryParse(parts[i], out var n) ? n : int.MaxValue;
        return r;
    }

    public static int Compare(string? a, string? b)
    {
        var x = Parse(a);
        var y = Parse(b);
        var len = Math.Max(x.Length, y.Length);
        for (var i = 0; i < len; i++)
        {
            var xi = i < x.Length ? x[i] : 0;
            var yi = i < y.Length ? y[i] : 0;
            if (xi != yi) return xi.CompareTo(yi);
        }
        return 0;
    }

    /// <summary>True when every component of <paramref name="cycle"/> equals the same component of <paramref name="version"/> (so 3.1 matches 3.1.32 but not 3.10.0).</summary>
    public static bool MatchesCycle(string? version, string cycle)
    {
        var v = Parse(version);
        var c = Parse(cycle);
        if (c.Length == 0 || v.Length == 0) return false;
        for (var i = 0; i < c.Length; i++)
        {
            var vi = i < v.Length ? v[i] : 0;
            if (vi != c[i]) return false;
        }
        return true;
    }

    public static int Major(string? v) { var p = Parse(v); return p.Length > 0 ? p[0] : 0; }
    public static int Minor(string? v) { var p = Parse(v); return p.Length > 1 ? p[1] : 0; }

    public static bool SameMajorMinor(string? a, string? b) => Major(a) == Major(b) && Minor(a) == Minor(b);

    /// <summary>Expands {major} and {minor} in a winget id template.</summary>
    public static string ApplyTemplate(string template, string? version) =>
        template.Replace("{major}", Major(version).ToString()).Replace("{minor}", Minor(version).ToString());
}

public static class CommandLine
{
    /// <summary>Splits an uninstall command line into executable and arguments, coping with unquoted paths containing spaces.</summary>
    public static (string File, string Args) Split(string commandLine)
    {
        var s = commandLine.Trim();
        if (s.Length == 0) return ("", "");
        if (s[0] == '"')
        {
            var end = s.IndexOf('"', 1);
            if (end > 0) return (s[1..end], s[(end + 1)..].Trim());
            return (s.Trim('"'), "");
        }
        var idx = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (idx > 0) return (s[..(idx + 4)], s[(idx + 4)..].Trim());
        var sp = s.IndexOf(' ');
        return sp < 0 ? (s, "") : (s[..sp], s[(sp + 1)..].Trim());
    }

    public static readonly Regex MsiGuid = new(@"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}", RegexOptions.Compiled);

    public static bool IsMsiExec(string file) =>
        Path.GetFileName(file).Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase) ||
        Path.GetFileName(file).Equals("msiexec", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Executables that are safe to launch as SYSTEM: only locations ordinary users cannot write to.
    /// Anything else (e.g. an uninstaller under C:\Users) must be run in the user's own context.
    /// </summary>
    public static bool IsTrustedSystemPath(string file)
    {
        if (string.IsNullOrWhiteSpace(file) || !Path.IsPathFullyQualified(file)) return false;
        string full;
        try { full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(file)); } catch { return false; }
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Package Cache"),
        };
        return roots.Where(r => !string.IsNullOrEmpty(r))
            .Any(r => full.StartsWith(r.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase));
    }
}

public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr, bool TimedOut);

public static class ProcessRunner
{
    public static async Task<ProcessResult> RunAsync(string file, string args, TimeSpan timeout, CancellationToken ct, Encoding? encoding = null)
    {
        var psi = new ProcessStartInfo(file, args)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = encoding ?? Encoding.UTF8,
            StandardErrorEncoding = encoding ?? Encoding.UTF8,
        };
        using var p = new Process { StartInfo = psi };
        p.Start();
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        var stderr = p.StandardError.ReadToEndAsync(ct);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await p.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); } catch { /* ignore */ }
            return new ProcessResult(-1, await SafeAsync(stdout), await SafeAsync(stderr), TimedOut: !ct.IsCancellationRequested);
        }
        return new ProcessResult(p.ExitCode, await SafeAsync(stdout), await SafeAsync(stderr), false);
    }

    /// <summary>Runs a program visibly (ShellExecute) so it can show UI or raise a UAC prompt. User context only.</summary>
    public static async Task<int> RunInteractiveAsync(string file, string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(file, args) { UseShellExecute = true };
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Could not start {file}");
        await p.WaitForExitAsync(ct);
        return p.ExitCode;
    }

    private static async Task<string> SafeAsync(Task<string> t)
    {
        try { return await t; } catch { return ""; }
    }
}

public static class AppLog
{
    private static readonly object Gate = new();
    private static string? _dir;
    public static bool EchoToConsole { get; set; }

    public static void Initialize(string dir, bool echoToConsole = false)
    {
        EchoToConsole = echoToConsole;
        try
        {
            Directory.CreateDirectory(dir);
            _dir = dir;
            foreach (var f in Directory.GetFiles(dir, "*.log").Where(f => File.GetLastWriteTimeUtc(f) < DateTime.UtcNow.AddDays(-14)))
                File.Delete(f);
        }
        catch { _dir = null; }
    }

    public static void Info(string msg) => Write("INFO", msg);
    public static void Warn(string msg) => Write("WARN", msg);
    public static void Error(string msg, Exception? ex = null) => Write("ERROR", ex is null ? msg : $"{msg}: {ex}");

    private static void Write(string level, string msg)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {msg}";
        if (EchoToConsole) Console.Error.WriteLine(line);
        if (_dir is null) return;
        lock (Gate)
        {
            try { File.AppendAllText(Path.Combine(_dir, $"patchsentinel-{DateTime.Now:yyyyMMdd}.log"), line + Environment.NewLine); }
            catch (Exception ex)
            {
                // Logging must never break the agent, but say why it stopped where it can still be seen.
                if (EchoToConsole) Console.Error.WriteLine($"(log write failed: {ex.Message})");
                try { System.Diagnostics.Trace.WriteLine($"PatchSentinel log write failed: {ex}"); } catch { /* ignore */ }
            }
        }
    }
}

public static class FileUtil
{
    public static void WriteAllTextAtomic(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content, new UTF8Encoding(false));
        File.Move(tmp, path, overwrite: true);
    }
}
