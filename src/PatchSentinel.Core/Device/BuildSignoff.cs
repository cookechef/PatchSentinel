using System.Text.Json;

namespace PatchSentinel.Core.Device;

public enum SignoffStatus { Checked, NotRequired }

/// <summary>A technician confirming a build step. Kept on the device and recorded in the history for auditing.</summary>
public sealed class BuildSignoff
{
    public SignoffStatus Status { get; set; }
    public string By { get; set; } = "";
    public DateTimeOffset At { get; set; }
    public string? Note { get; set; }
    /// <summary>What PatchSentinel showed for the step when it was signed off.</summary>
    public CheckStatus StepStatusAtSignoff { get; set; }

    public string Text => $"{(Status == SignoffStatus.Checked ? "Checked" : "Not required")} by {By}, {At.LocalDateTime:dd MMM yyyy HH:mm}{(string.IsNullOrWhiteSpace(Note) ? "" : $" - {Note}")}";
}

/// <summary>Sign-off of the whole build: the device is ready to hand over.</summary>
public sealed class BuildHandover
{
    public string By { get; set; } = "";
    public DateTimeOffset At { get; set; }
    public string? Note { get; set; }
    public int StepsOk { get; set; }
    public int StepsSignedOff { get; set; }
    public int StepsOutstanding { get; set; }
    public List<string> Outstanding { get; set; } = [];

    public string Text => $"Build signed off by {By}, {At.LocalDateTime:dd MMM yyyy HH:mm}: {StepsOk} OK, {StepsSignedOff} signed off, {StepsOutstanding} outstanding{(string.IsNullOrWhiteSpace(Note) ? "" : $" - {Note}")}";
}

public sealed class BuildSignoffFile
{
    public Dictionary<string, BuildSignoff> Steps { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public BuildHandover? Handover { get; set; }
}

public static class BuildSignoffStore
{
    public static string FilePath => Path.Combine(AppPaths.StateDir, "build-signoff.json");

    public static BuildSignoffFile Load(string? path = null)
    {
        try
        {
            path ??= FilePath;
            if (File.Exists(path) && JsonSerializer.Deserialize<BuildSignoffFile>(File.ReadAllText(path), Json.Options) is { } f)
            {
                f.Steps = new Dictionary<string, BuildSignoff>(f.Steps, StringComparer.OrdinalIgnoreCase);
                return f;
            }
        }
        catch { /* start again */ }
        return new BuildSignoffFile();
    }

    public static void Save(BuildSignoffFile f, string? path = null)
    {
        path ??= FilePath;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        FileUtil.WriteAllTextAtomic(path, JsonSerializer.Serialize(f, Json.Options));
    }

    /// <summary>Copies stored sign-offs onto the checklist results.</summary>
    public static void Apply(IEnumerable<BuildCheckResult> checks, BuildSignoffFile f)
    {
        foreach (var c in checks) c.Signoff = f.Steps.GetValueOrDefault(c.Id);
    }

    /// <summary>A step is done if PatchSentinel shows it OK or Info, or a technician has signed it off.</summary>
    public static bool IsDone(BuildCheckResult c) => c.Signoff is not null || c.Status is CheckStatus.Pass or CheckStatus.Info;

    public static BuildHandover Summarise(IReadOnlyList<BuildCheckResult> checks, string by, string? note) => new()
    {
        By = by,
        At = DateTimeOffset.Now,
        Note = note,
        StepsOk = checks.Count(c => c.Signoff is null && c.Status is CheckStatus.Pass or CheckStatus.Info),
        StepsSignedOff = checks.Count(c => c.Signoff is not null),
        StepsOutstanding = checks.Count(c => !IsDone(c)),
        Outstanding = checks.Where(c => !IsDone(c)).Select(c => $"{c.Step}. {c.Title}").ToList(),
    };
}
