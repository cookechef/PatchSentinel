using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using PatchSentinel.Core.Rules;

namespace PatchSentinel.Core.Browsers;

public enum ExtensionStore { None, ChromeWebStore, EdgeAddons, FirefoxAddons }

/// <summary>Result of asking a store about one extension.</summary>
public sealed class StoreInfo
{
    public bool Listed { get; set; }
    public string? Version { get; set; }
    public string? Url { get; set; }
    public DateTimeOffset Checked { get; set; }
}

/// <summary>
/// Looks extensions up in the Chrome Web Store, Edge Add-ons and addons.mozilla.org (only extension IDs are sent),
/// then decides a status, concern level and advice for each one.
/// </summary>
public static class ExtensionChecker
{
    private const string ChromeUpdate = "https://clients2.google.com/service/update2/crx";
    private const string EdgeUpdate = "https://edge.microsoft.com/extensionwebstorebase/v1/crx";
    private static readonly TimeSpan CacheFor = TimeSpan.FromHours(24);

    public static string CacheDir { get; set; } = AppPaths.CacheDir;
    private static string CacheFile => Path.Combine(CacheDir, "extension-store.json");

    public static ExtensionStore StoreFor(BrowserExtension e)
    {
        if (e.Browser == Browser.Firefox)
            return e.InstallSource == "Store" ? ExtensionStore.FirefoxAddons : ExtensionStore.None;
        var u = e.UpdateUrl ?? "";
        if (u.Contains("clients2.google.com", StringComparison.OrdinalIgnoreCase)) return ExtensionStore.ChromeWebStore;
        if (u.Contains("edge.microsoft.com", StringComparison.OrdinalIgnoreCase)) return ExtensionStore.EdgeAddons;
        if (e.InstallSource.StartsWith("Store", StringComparison.Ordinal))
            return e.Browser == Browser.Edge ? ExtensionStore.EdgeAddons : ExtensionStore.ChromeWebStore;
        return ExtensionStore.None;
    }

    public static string? StorePage(ExtensionStore s, string id, string? slug = null) => s switch
    {
        ExtensionStore.ChromeWebStore => $"https://chromewebstore.google.com/detail/{id}",
        ExtensionStore.EdgeAddons => $"https://microsoftedge.microsoft.com/addons/detail/{id}",
        ExtensionStore.FirefoxAddons => $"https://addons.mozilla.org/firefox/addon/{Uri.EscapeDataString(slug ?? id)}/",
        _ => null,
    };

    /// <summary>Checks the stores (unless <paramref name="online"/> is false) and fills in Status, Concern, Advice and StoreUrl.</summary>
    public static async Task CheckAsync(List<BrowserExtension> list, bool online, List<string> warnings, CancellationToken ct = default)
    {
        var cache = LoadCache();
        if (online)
        {
            var wanted = list.Select(e => (Store: StoreFor(e), e.Id)).Where(x => x.Store != ExtensionStore.None)
                .Distinct().Where(x => !cache.TryGetValue(Key(x.Store, x.Id), out var c) || DateTimeOffset.UtcNow - c.Checked > CacheFor).ToList();
            if (wanted.Count > 0)
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20), MaxResponseContentBufferSize = 4 * 1024 * 1024 };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("PatchSentinel/1.0");
                foreach (var group in wanted.GroupBy(w => w.Store))
                {
                    try
                    {
                        var ids = group.Select(g => g.Id).ToList();
                        var found = group.Key == ExtensionStore.FirefoxAddons
                            ? await QueryAmoAsync(http, ids, ct)
                            : await QueryOmahaAsync(http, group.Key == ExtensionStore.EdgeAddons ? EdgeUpdate : ChromeUpdate, ids, ct);
                        foreach (var (id, info) in found) cache[Key(group.Key, id)] = info;
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
                    {
                        warnings.Add($"Could not reach {Describe(group.Key)}: {ex.Message}");
                    }
                }
                SaveCache(cache);
            }
        }

        foreach (var e in list)
        {
            var store = StoreFor(e);
            StoreInfo? info = null;
            if (store != ExtensionStore.None) cache.TryGetValue(Key(store, e.Id), out info);
            Assess(e, store, info);
        }
    }

    public static string Describe(ExtensionStore s) => s switch
    {
        ExtensionStore.ChromeWebStore => "the Chrome Web Store",
        ExtensionStore.EdgeAddons => "Microsoft Edge Add-ons",
        ExtensionStore.FirefoxAddons => "addons.mozilla.org",
        _ => "the store",
    };

    /// <summary>Works out status, concern and advice. Public so it can be unit tested.</summary>
    public static void Assess(BrowserExtension e, ExtensionStore store, StoreInfo? info)
    {
        e.StoreUrl = info?.Url ?? StorePage(store, e.Id);
        e.LatestVersion = info?.Listed == true ? info.Version : null;
        var risky = e.BroadAccess && e.SensitivePermissions.Count > 0;
        var access = e.BroadAccess ? $" It can read and change data on every website{(e.SensitivePermissions.Count > 0 ? " and access " + string.Join(", ", e.SensitivePermissions) : "")}." : "";
        var chromium = e.Browser != Browser.Firefox;

        if (e.Browser == Browser.Firefox && e.FirefoxBlocklisted)
        {
            Set(e, ExtensionStatus.Blocklisted, Concern.High,
                "Mozilla has blocklisted this add-on, usually because it is malicious or seriously broken. Remove it from Firefox and check the device.");
        }
        else if (store != ExtensionStore.None && info is { Listed: false })
        {
            Set(e, ExtensionStatus.RemovedFromStore, Concern.High,
                $"No longer available from {Describe(store)}. Extensions are usually taken down for malware, policy breaches or because the developer abandoned them, and it will never be updated again. Remove it and find a supported replacement.{access}");
        }
        else if (chromium && e.ManifestVersion is 2)
        {
            Set(e, ExtensionStatus.RetiredManifestV2, Concern.Review,
                $"Built on Manifest V2, which {e.BrowserName} no longer supports. It has been, or soon will be, switched off by the browser and gets no security fixes. Remove it and install a current version or an alternative.{access}");
        }
        else if (e.InstallSource is "Sideloaded" or "Developer")
        {
            Set(e, ExtensionStatus.NotFromStore, risky ? Concern.High : Concern.Review,
                (e.InstallSource == "Developer" ? "Loaded in developer mode from a local folder. " : "Installed from outside the store. ")
                + "It is not reviewed by the store and does not update itself. Confirm where it came from and that it is approved, otherwise remove it." + access);
        }
        else if (e.Browser == Browser.Firefox && e.FirefoxUnsigned)
        {
            Set(e, ExtensionStatus.NotFromStore, Concern.Review, "This add-on is not signed by Mozilla. Confirm it is approved, otherwise remove it." + access);
        }
        else if (e.LatestVersion is not null && e.Version is not null && VersionUtil.Compare(e.Version, e.LatestVersion) < 0)
        {
            Set(e, ExtensionStatus.UpdateAvailable, Concern.Review,
                $"Version {e.Version} is installed but {e.LatestVersion} is available. Browsers update extensions themselves every few hours, so if this stays out of date restart the browser, or open the extensions page, turn on developer mode and click Update.{access}");
        }
        else if (info is { Listed: true })
        {
            Set(e, ExtensionStatus.UpToDate, risky ? Concern.Review : Concern.Info,
                risky ? $"Up to date.{access} Make sure it is an approved extension." : "Up to date.");
        }
        else
        {
            Set(e, ExtensionStatus.Unknown, risky ? Concern.Review : Concern.Info,
                (e.InstallSource == "Policy" ? "Installed by policy from a private source, so it can't be checked against a public store." : "Could not be checked against the store.") + access);
        }

        if (!e.Enabled) e.Advice += " It is currently turned off; remove it if it is no longer needed.";
        if (e.BlockedByPolicy) { e.Advice = "Blocked by policy: the browser turns it off (Firefox uninstalls it) at the next start and it can't be turned back on. " + e.Advice; e.Concern = Concern.Info; }
    }

    private static void Set(BrowserExtension e, ExtensionStatus s, Concern c, string advice) { e.Status = s; e.Concern = c; e.Advice = advice; }

    // ---------------- Omaha (Chrome / Edge) ----------------

    private static async Task<Dictionary<string, StoreInfo>> QueryOmahaAsync(HttpClient http, string baseUrl, List<string> ids, CancellationToken ct)
    {
        var result = new Dictionary<string, StoreInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var chunk in ids.Chunk(25))
        {
            var url = baseUrl + "?response=updatecheck&acceptformat=crx3&prodversion=140.0.0.0"
                      + string.Concat(chunk.Select(id => "&x=" + Uri.EscapeDataString($"id={id}&uc")));
            var xml = await http.GetStringAsync(url, ct);
            foreach (var (id, info) in ParseOmaha(xml)) result[id] = info;
            foreach (var id in chunk.Where(i => !result.ContainsKey(i))) result[id] = new StoreInfo { Listed = false, Checked = DateTimeOffset.UtcNow };
        }
        return result;
    }

    /// <summary>Parses an Omaha update check response. An app with a version is listed; "noupdate" or an error status for an unversioned request means it is no longer available.</summary>
    public static Dictionary<string, StoreInfo> ParseOmaha(string xml)
    {
        var r = new Dictionary<string, StoreInfo>(StringComparer.OrdinalIgnoreCase);
        var doc = XDocument.Parse(xml);
        foreach (var app in doc.Descendants().Where(x => x.Name.LocalName == "app"))
        {
            var id = (string?)app.Attribute("appid");
            if (string.IsNullOrEmpty(id)) continue;
            var uc = app.Elements().FirstOrDefault(x => x.Name.LocalName == "updatecheck");
            var version = (string?)uc?.Attribute("version");
            var status = (string?)uc?.Attribute("status") ?? (string?)app.Attribute("status");
            r[id] = new StoreInfo
            {
                Listed = !string.IsNullOrEmpty(version) && (status is null or "ok"),
                Version = string.IsNullOrEmpty(version) ? null : version,
                Checked = DateTimeOffset.UtcNow,
            };
        }
        return r;
    }

    // ---------------- addons.mozilla.org ----------------

    private static async Task<Dictionary<string, StoreInfo>> QueryAmoAsync(HttpClient http, List<string> ids, CancellationToken ct)
    {
        var result = new Dictionary<string, StoreInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in ids)
        {
            using var resp = await http.GetAsync($"https://addons.mozilla.org/api/v5/addons/addon/{Uri.EscapeDataString(id)}/", ct);
            if ((int)resp.StatusCode is 404 or 401 or 403)
            {
                result[id] = new StoreInfo { Listed = false, Checked = DateTimeOffset.UtcNow };
                continue;
            }
            resp.EnsureSuccessStatusCode();
            result[id] = ParseAmo(await resp.Content.ReadAsStringAsync(ct), id);
        }
        return result;
    }

    public static StoreInfo ParseAmo(string json, string id)
    {
        var n = JsonNode.Parse(json);
        var status = n?["status"]?.GetValue<string>();
        var disabled = n?["is_disabled"]?.GetValue<bool>() == true;
        var slug = n?["slug"]?.GetValue<string>();
        return new StoreInfo
        {
            Listed = !disabled && status is null or "public",
            Version = n?["current_version"]?["version"]?.GetValue<string>(),
            Url = n?["url"]?.GetValue<string>() ?? StorePage(ExtensionStore.FirefoxAddons, id, slug),
            Checked = DateTimeOffset.UtcNow,
        };
    }

    // ---------------- cache ----------------

    private static string Key(ExtensionStore s, string id) => $"{s}:{id}";

    private static Dictionary<string, StoreInfo> LoadCache()
    {
        try
        {
            if (File.Exists(CacheFile))
                return JsonSerializer.Deserialize<Dictionary<string, StoreInfo>>(File.ReadAllText(CacheFile), Json.Options)
                       is { } d ? new Dictionary<string, StoreInfo>(d, StringComparer.OrdinalIgnoreCase) : new(StringComparer.OrdinalIgnoreCase);
        }
        catch { /* rebuild */ }
        return new(StringComparer.OrdinalIgnoreCase);
    }

    private static void SaveCache(Dictionary<string, StoreInfo> cache)
    {
        try
        {
            Directory.CreateDirectory(CacheDir);
            var keep = cache.Where(kv => DateTimeOffset.UtcNow - kv.Value.Checked < TimeSpan.FromDays(30)).ToDictionary();
            File.WriteAllText(CacheFile, JsonSerializer.Serialize(keep, Json.Options));
        }
        catch { /* best effort */ }
    }
}
