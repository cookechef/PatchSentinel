using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using PatchSentinel.Core;

namespace PatchSentinel.Agent;

internal sealed record ReleaseInfo(string Version, string MsiName, string MsiUrl, string Sha256, string PageUrl);

/// <summary>
/// Keeps PatchSentinel itself up to date from the GitHub repository it was built from.
/// The MSI is only accepted from that repository's latest release and only if its SHA-256 matches
/// the digest GitHub publishes for the asset (or the release's SHA256SUMS.txt).
/// </summary>
internal static class SelfUpdater
{
    private static readonly Regex RepoPattern = new(@"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$", RegexOptions.Compiled);
    private static readonly Regex VersionPattern = new(@"^\d+\.\d+\.\d+$", RegexOptions.Compiled);
    private static readonly Regex Sha256Hex = new(@"^[0-9a-fA-F]{64}$", RegexOptions.Compiled);
    private const long MaxMsiBytes = 400L * 1024 * 1024;

    public static bool IsValidRepo(string? repo) => repo is not null && RepoPattern.IsMatch(repo);

    public static bool IsNewer(string candidate, string current) => VersionUtil.Compare(candidate, current) > 0;

    private static HttpClient NewClient(TimeSpan timeout)
    {
        var http = new HttpClient { Timeout = timeout };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"PatchSentinel/{AppPaths.Version}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return http;
    }

    public static async Task<ReleaseInfo?> GetLatestAsync(string repo, CancellationToken ct)
    {
        if (!IsValidRepo(repo)) throw new ArgumentException($"Invalid update repository '{repo}'.");
        using var http = NewClient(TimeSpan.FromSeconds(30));
        using var resp = await http.GetAsync($"https://api.github.com/repos/{repo}/releases/latest", ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotFound) return null; // no releases yet
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var root = doc.RootElement;
        if (root.TryGetProperty("draft", out var d) && d.GetBoolean()) return null;
        if (root.TryGetProperty("prerelease", out var p) && p.GetBoolean()) return null;

        var version = (root.GetProperty("tag_name").GetString() ?? "").TrimStart('v', 'V');
        if (!VersionPattern.IsMatch(version)) return null;
        var page = root.TryGetProperty("html_url", out var h) ? h.GetString() ?? "" : "";
        var msiName = $"PatchSentinel-{version}-x64.msi";

        string? msiUrl = null, sha = null, sumsUrl = null;
        foreach (var a in root.GetProperty("assets").EnumerateArray())
        {
            var name = a.GetProperty("name").GetString();
            var url = a.GetProperty("browser_download_url").GetString();
            if (name == msiName)
            {
                msiUrl = url;
                if (a.TryGetProperty("digest", out var dg) && dg.GetString() is { } digest && digest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase))
                    sha = digest[7..];
            }
            else if (name == "SHA256SUMS.txt") sumsUrl = url;
        }
        if (msiUrl is null) return null;

        if (sha is null && sumsUrl is not null)
        {
            var sums = await http.GetStringAsync(sumsUrl, ct);
            sha = sums.Split('\n').Select(l => l.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries))
                      .FirstOrDefault(parts => parts.Length >= 2 && parts[^1].TrimStart('*') == msiName)?[0];
        }
        if (sha is null || !Sha256Hex.IsMatch(sha)) throw new InvalidDataException($"Release {version} has no SHA-256 for {msiName}; refusing to update.");
        return new ReleaseInfo(version, msiName, msiUrl, sha.ToLowerInvariant(), page);
    }

    /// <summary>Downloads into the admin-only ProgramData folder and verifies the hash before returning the path.</summary>
    public static async Task<string> DownloadAndVerifyAsync(ReleaseInfo r, CancellationToken ct)
    {
        if (!Uri.TryCreate(r.MsiUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || uri.Host != "github.com")
            throw new InvalidDataException($"Unexpected download location {r.MsiUrl}.");

        var dir = Path.Combine(AppPaths.DataRoot, "updates");
        Directory.CreateDirectory(dir);
        foreach (var old in Directory.GetFiles(dir, "*.msi")) { try { File.Delete(old); } catch { /* in use */ } }
        var target = Path.Combine(dir, r.MsiName);
        var tmp = target + ".download";

        using var http = NewClient(TimeSpan.FromMinutes(20));
        using (var resp = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            resp.EnsureSuccessStatusCode();
            if (resp.RequestMessage?.RequestUri is { } final && final.Scheme != Uri.UriSchemeHttps)
                throw new InvalidDataException("Download was redirected to a non-HTTPS location.");
            await using var src = await resp.Content.ReadAsStreamAsync(ct);
            await using var dst = File.Create(tmp);
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buf = new byte[81920];
            long total = 0;
            int n;
            while ((n = await src.ReadAsync(buf, ct)) > 0)
            {
                total += n;
                if (total > MaxMsiBytes) throw new InvalidDataException("Download is larger than expected.");
                sha.AppendData(buf, 0, n);
                await dst.WriteAsync(buf.AsMemory(0, n), ct);
            }
            var actual = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            if (actual != r.Sha256)
            {
                dst.Close();
                File.Delete(tmp);
                throw new InvalidDataException($"SHA-256 mismatch for {r.MsiName} (expected {r.Sha256}, got {actual}); update refused.");
            }
        }
        File.Move(tmp, target, overwrite: true);
        return target;
    }

    /// <summary>Starts a silent upgrade. msiexec stops and restarts this service itself, so it must outlive us.</summary>
    public static void LaunchInstaller(string msiPath)
    {
        var log = Path.Combine(AppPaths.LogDir, $"self-update-{DateTime.Now:yyyyMMdd-HHmmss}.log");
        var msiexec = Path.Combine(Environment.SystemDirectory, "msiexec.exe");
        var psi = new ProcessStartInfo(msiexec, $"/i \"{msiPath}\" /qn /norestart REBOOT=ReallySuppress /l*v \"{log}\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        Process.Start(psi);
    }
}
