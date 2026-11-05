using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using PatchSentinel.Core.Config;
using PatchSentinel.Core.Remediation;

namespace PatchSentinel.Core.Ipc;

/// <summary>One JSON line in, one JSON line out, over a local named pipe.</summary>
public sealed class PipeRequest
{
    public string Command { get; set; } = "";
    public JsonElement? Payload { get; set; }
}

public sealed class PipeResponse
{
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public JsonElement? Data { get; set; }

    public static PipeResponse Success(object? data = null) =>
        new() { Ok = true, Data = data is null ? null : JsonSerializer.SerializeToElement(data, Json.Compact) };

    public static PipeResponse Fail(string error) => new() { Ok = false, Error = error };

    public T? As<T>() => Data is { } d ? d.Deserialize<T>(Json.Compact) : default;
}

public static class Commands
{
    public const string Status = "status";
    public const string GetScan = "get-scan";
    public const string Scan = "scan";
    public const string InstallUpdates = "install-updates";
    public const string Remediate = "remediate";
    public const string GetSettings = "get-settings";
    public const string SetExclusions = "set-exclusions";
    public const string SetSchedule = "set-schedule";
    public const string Defer = "defer";
}

public sealed class JobInfo
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Kind { get; set; } = "";
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public List<string> Details { get; set; } = [];
    public RemediationResult? Remediation { get; set; }
}

public sealed class AgentStatus
{
    public string Version { get; set; } = "";
    /// <summary>Newer PatchSentinel release found on GitHub, if any.</summary>
    public string? AvailableVersion { get; set; }
    public string? BusyWith { get; set; }
    public DateTimeOffset? LastScanAt { get; set; }
    public DateTimeOffset? NextScanAt { get; set; }
    public DateTimeOffset? NextUpdateAt { get; set; }
    public DateTimeOffset? DeferredUntil { get; set; }
    public bool CanDefer { get; set; }
    public int DeferralsLeft { get; set; }
    public ScanCounts Counts { get; set; } = new();
    public JobInfo? LastJob { get; set; }
    public bool AllowUserExclusions { get; set; }
    public bool AllowUserRemediation { get; set; }
    public bool ScheduleLocked { get; set; }
    public int NotifyMinutesBefore { get; set; }
}

public sealed class SettingsView
{
    public UpdateSchedule Schedule { get; set; } = new();
    public List<string> ExcludedPackageIds { get; set; } = [];
    public List<string> PolicyExcludedPackageIds { get; set; } = [];
    public bool ScheduleLocked { get; set; }
    public bool AllowUserExclusions { get; set; }
    public bool AllowUserRemediation { get; set; }
    public bool AllowUserDeferral { get; set; }
    public bool ManagedByPolicy { get; set; }
}

public sealed record RemediateRequest(string FindingId, string ActionId);
public sealed record InstallUpdatesRequest(List<string>? Ids);
public sealed record ExclusionsRequest(List<string> Ids);
public sealed record DeferRequest(int Minutes);
public sealed record JobStarted(string JobId);

public sealed class AgentPipeClient
{
    public async Task<PipeResponse> SendAsync(string command, object? payload = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(15));
        await using var pipe = new NamedPipeClientStream(".", AppPaths.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(cts.Token);

        var req = new PipeRequest { Command = command, Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, Json.Compact) };
        var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        await writer.WriteLineAsync(JsonSerializer.Serialize(req, Json.Compact).AsMemory(), cts.Token);
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, leaveOpen: true);
        var line = await reader.ReadLineAsync(cts.Token) ?? throw new IOException("The agent closed the connection.");
        return JsonSerializer.Deserialize<PipeResponse>(line, Json.Compact) ?? PipeResponse.Fail("Empty response.");
    }

    public async Task<T?> GetAsync<T>(string command, object? payload = null, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        var r = await SendAsync(command, payload, timeout, ct);
        if (!r.Ok) throw new InvalidOperationException(r.Error ?? "The agent reported an error.");
        return r.As<T>();
    }
}
