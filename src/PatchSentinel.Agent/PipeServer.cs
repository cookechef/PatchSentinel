using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using PatchSentinel.Core;
using PatchSentinel.Core.Ipc;

namespace PatchSentinel.Agent;

internal sealed record PipeCaller(string Name, bool IsAdmin);

/// <summary>Local-only named pipe. Authenticated users may connect; only SYSTEM can create pipe instances.</summary>
internal sealed class PipeServer(Func<PipeRequest, PipeCaller, Task<PipeResponse>> handler)
{
    private const int MaxRequestChars = 64 * 1024;

    public async Task RunAsync(CancellationToken ct)
    {
        var first = true;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream server;
            try
            {
                server = Create(first);
                first = false;
            }
            catch (Exception ex)
            {
                AppLog.Error("Could not create the agent pipe", ex);
                try { await Task.Delay(TimeSpan.FromSeconds(10), ct); } catch (OperationCanceledException) { return; }
                continue;
            }

            try { await server.WaitForConnectionAsync(ct); }
            catch (OperationCanceledException) { await server.DisposeAsync(); return; }
            catch (Exception ex) { AppLog.Warn($"Pipe connection failed: {ex.Message}"); await server.DisposeAsync(); continue; }

            _ = Task.Run(() => HandleClientAsync(server, ct), CancellationToken.None);
        }
    }

    private static NamedPipeServerStream Create(bool first)
    {
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        // Deny network logons: this API is for the local tray app only.
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
        return NamedPipeServerStreamAcl.Create(AppPaths.PipeName, PipeDirection.InOut, 8, PipeTransmissionMode.Byte, options, 0, 0, sec);
    }

    private async Task HandleClientAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        await using (server)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(30));
                using var reader = new StreamReader(server, Encoding.UTF8, false, 4096, leaveOpen: true);
                var line = await ReadBoundedLineAsync(reader, cts.Token);

                PipeResponse response;
                if (line is null) response = PipeResponse.Fail("Request too large or empty.");
                else
                {
                    var req = JsonSerializer.Deserialize<PipeRequest>(line, Json.Compact);
                    response = req is null ? PipeResponse.Fail("Bad request.") : await handler(req, Identify(server));
                }

                var writer = new StreamWriter(server, new UTF8Encoding(false), 65536, leaveOpen: true) { AutoFlush = true };
                await writer.WriteLineAsync(JsonSerializer.Serialize(response, Json.Compact).AsMemory(), cts.Token);
                server.WaitForPipeDrain();
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or JsonException)
            {
                AppLog.Warn($"Pipe client error: {ex.Message}");
            }
        }
    }

    private static async Task<string?> ReadBoundedLineAsync(StreamReader reader, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buf = new char[1];
        while (await reader.ReadAsync(buf.AsMemory(), ct) == 1)
        {
            if (buf[0] == '\n') return sb.ToString().TrimEnd('\r');
            sb.Append(buf[0]);
            if (sb.Length > MaxRequestChars) return null;
        }
        return sb.Length > 0 ? sb.ToString() : null;
    }

    private static PipeCaller Identify(NamedPipeServerStream server)
    {
        try
        {
            string name = "unknown";
            var admin = false;
            server.RunAsClient(() =>
            {
                using var id = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
                name = id.Name;
                admin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            });
            return new PipeCaller(name, admin);
        }
        catch
        {
            return new PipeCaller("unknown", false);
        }
    }
}
