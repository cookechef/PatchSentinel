using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32;

namespace PatchSentinel.Core.Browsers;

/// <summary>
/// Finds installed browser extensions for every user profile: Chromium browsers (Chrome, Edge, Brave) from the
/// profile's Extensions folder plus its preferences, and Firefox from extensions.json.
/// </summary>
public static class ExtensionInventory
{
    private static readonly (Browser Browser, string Path)[] Chromium =
    [
        (Browser.Chrome, @"Google\Chrome\User Data"),
        (Browser.Edge, @"Microsoft\Edge\User Data"),
        (Browser.Brave, @"BraveSoftware\Brave-Browser\User Data"),
    ];

    /// <summary>Default apps and components that ship with the browser itself.</summary>
    private static readonly HashSet<string> BuiltInIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "nmmhkkegccagdldgiimedpiccmgmieda", "pkedcjkdefgpdelpbcmbmeomcjbeemfm", "mhjfbmdgcfjbbpaeojofohoefgiehjai",
        "aapocclcgogkmnckokdopfmhonfmgoek", "felcaaldnbdncclmgdcncolpebgiejap", "apdfllckaahabafndbhieahigkjlhalf",
        "aohghmighlieiainnegkcijnfilokake", "blpcfgokakmgnkcojhhkbfbldkacnbeo", "pjkljhegncpnkpknbcohdijeoejaedia",
        "coobgpohoikkiipiblmjeljniedjpjpf", "neajdppkdcdipfabeoofebfddakdcjhd", "jmjflgjpcpepeafmmgdpfkogkghcpiha",
        "ncbjelpjchkpbikbpkcchkhkblodoama", "iglcjdemknebjbklcgkfaebgojjphkec", "mnjggcdmjocbbbhaepdhchncahnbgone",
    };

    private static readonly Dictionary<string, string> Sensitive = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cookies"] = "cookies", ["history"] = "browsing history", ["webRequest"] = "network traffic", ["webRequestBlocking"] = "network traffic",
        ["debugger"] = "debugger", ["nativeMessaging"] = "local programs", ["proxy"] = "proxy settings", ["management"] = "other extensions",
        ["clipboardRead"] = "clipboard", ["downloads"] = "downloads", ["desktopCapture"] = "screen capture", ["tabCapture"] = "screen capture",
        ["privacy"] = "privacy settings", ["browsingData"] = "browsing data", ["webNavigation"] = "pages visited",
    };

    public static List<BrowserExtension> Collect(bool allUsers, List<string> warnings)
    {
        var list = new List<BrowserExtension>();
        foreach (var (user, home) in Profiles(allUsers))
        {
            var local = Path.Combine(home, "AppData", "Local");
            var roaming = Path.Combine(home, "AppData", "Roaming");
            foreach (var (browser, rel) in Chromium)
            {
                var userData = Path.Combine(local, rel);
                if (!Directory.Exists(userData)) continue;
                try { list.AddRange(ReadChromium(browser, user, userData)); }
                catch (Exception ex) { warnings.Add($"Could not read {browser} extensions for {user}: {ex.Message}"); }
            }
            var ff = Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(ff))
            {
                try { list.AddRange(ReadFirefox(user, ff)); }
                catch (Exception ex) { warnings.Add($"Could not read Firefox add-ons for {user}: {ex.Message}"); }
            }
        }
        MarkPolicyBlocked(list);
        return list;
    }

    private static IEnumerable<(string User, string Home)> Profiles(bool allUsers)
    {
        if (!allUsers)
        {
            yield return (Environment.UserName, Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            yield break;
        }
        var root = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments)) ?? @"C:\Users";
        string[] dirs;
        try { dirs = Directory.GetDirectories(root); } catch { yield break; }
        foreach (var d in dirs)
        {
            var name = Path.GetFileName(d);
            if (name is "Public" or "Default" or "Default User" or "All Users" || name.StartsWith("defaultuser", StringComparison.OrdinalIgnoreCase)) continue;
            yield return (name, d);
        }
    }

    // ---------------- Chromium ----------------

    private static JsonDocumentOptions JsonOpts => new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    private static JsonNode? ReadJson(string path)
    {
        if (!File.Exists(path)) return null;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sr = new StreamReader(fs);
            return JsonNode.Parse(sr.ReadToEnd(), documentOptions: JsonOpts);
        }
        catch { return null; }
    }

    public static IEnumerable<BrowserExtension> ReadChromium(Browser browser, string user, string userData)
    {
        var localState = ReadJson(Path.Combine(userData, "Local State"));
        var profileNames = localState?["profile"]?["info_cache"] as JsonObject;

        foreach (var profileDir in Directory.GetDirectories(userData))
        {
            var dirName = Path.GetFileName(profileDir);
            if (!(dirName == "Default" || dirName.StartsWith("Profile ", StringComparison.Ordinal))) continue;
            var profileName = profileNames?[dirName]?["name"]?.GetValue<string>() ?? dirName;

            var settings = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
            foreach (var prefFile in new[] { "Preferences", "Secure Preferences" }) // Secure Preferences wins
                if (ReadJson(Path.Combine(profileDir, prefFile))?["extensions"]?["settings"] is JsonObject s)
                    foreach (var (id, node) in s)
                        if (node is JsonObject o) settings[id] = o;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var extRoot = Path.Combine(profileDir, "Extensions");
            if (Directory.Exists(extRoot))
            {
                foreach (var idDir in Directory.GetDirectories(extRoot))
                {
                    var id = Path.GetFileName(idDir);
                    if (id.Length != 32 || BuiltInIds.Contains(id)) continue;
                    var versionDir = Directory.GetDirectories(idDir)
                        .OrderByDescending(v => Path.GetFileName(v), Comparer<string>.Create(VersionUtil.Compare)).FirstOrDefault();
                    if (versionDir is null) continue;
                    settings.TryGetValue(id, out var pref);
                    var ext = FromManifest(browser, user, profileName, profileDir, id, versionDir, pref);
                    if (ext is not null && seen.Add(id)) yield return ext;
                }
            }

            // Developer-mode (unpacked) extensions live wherever they were loaded from.
            foreach (var (id, pref) in settings)
            {
                if (seen.Contains(id) || pref["location"]?.GetValue<int>() != 4) continue;
                var path = pref["path"]?.GetValue<string>();
                if (string.IsNullOrEmpty(path) || !Directory.Exists(path)) continue;
                var ext = FromManifest(browser, user, profileName, profileDir, id, path, pref);
                if (ext is not null && seen.Add(id)) yield return ext;
            }
        }
    }

    private static BrowserExtension? FromManifest(Browser browser, string user, string profile, string profileDir, string id, string dir, JsonObject? pref)
    {
        var manifest = ReadJson(Path.Combine(dir, "manifest.json")) as JsonObject;
        if (manifest is null) return null;
        if (manifest["theme"] is not null) return null; // themes are not extensions

        var location = Int(pref?["location"]);
        if (location is 5 or 10) return null; // component / built in
        var updateUrl = Str(manifest["update_url"]);
        var fromStore = pref?["from_webstore"]?.GetValue<bool>() == true || IsStoreUrl(updateUrl);
        var source = location switch
        {
            4 or 8 => "Developer",
            7 or 9 => "Policy",
            2 or 3 or 6 => fromStore ? "Store (installed by another program)" : "Sideloaded",
            _ => fromStore ? "Store" : "Sideloaded",
        };

        var perms = Strings(manifest["permissions"]);
        var hosts = Strings(manifest["host_permissions"]);
        // MV2 mixes host patterns into "permissions".
        hosts.AddRange(perms.Where(p => p.Contains("://") || p == "<all_urls>"));
        perms = perms.Where(p => !p.Contains("://") && p != "<all_urls>").ToList();
        if (manifest["content_scripts"] is JsonArray cs)
            foreach (var c in cs) hosts.AddRange(Strings(c?["matches"]));

        var disableReasons = pref?["disable_reasons"];
        var disabled = Int(pref?["state"]) == 0
                       || (disableReasons is JsonValue dv && dv.TryGetValue<int>(out var dr) && dr != 0)
                       || (disableReasons is JsonArray da && da.Count > 0);

        return new BrowserExtension
        {
            Browser = browser,
            UserName = user,
            Profile = profile,
            ProfilePath = profileDir,
            Id = id,
            Name = Localise(Str(manifest["name"]) ?? id, manifest, dir),
            Version = Str(manifest["version"]),
            ManifestVersion = Int(manifest["manifest_version"]),
            Enabled = !disabled,
            InstallSource = source,
            UpdateUrl = updateUrl,
            InstallDate = FileTime(Str(pref?["install_time"]) ?? Str(pref?["first_install_time"])),
            Permissions = perms.Distinct().ToList(),
            HostPermissions = hosts.Distinct().ToList(),
            BroadAccess = hosts.Any(IsBroad),
            SensitivePermissions = perms.Where(Sensitive.ContainsKey).Select(p => Sensitive[p]).Distinct().ToList(),
        };
    }

    public static bool IsStoreUrl(string? url) =>
        url is not null && (url.Contains("clients2.google.com", StringComparison.OrdinalIgnoreCase)
                            || url.Contains("edge.microsoft.com", StringComparison.OrdinalIgnoreCase));

    public static bool IsBroad(string pattern) =>
        pattern is "<all_urls>" or "*://*/*" or "http://*/*" or "https://*/*" or "*://*/" or "https://*/" or "http://*/" or "file:///*";

    private static string Localise(string name, JsonObject manifest, string dir)
    {
        if (!name.StartsWith("__MSG_", StringComparison.Ordinal) || !name.EndsWith("__", StringComparison.Ordinal)) return name;
        var key = name[6..^2];
        var locales = new[] { Str(manifest["default_locale"]), "en_GB", "en", "en_US" }.Where(l => l is not null).Distinct();
        foreach (var loc in locales)
        {
            if (ReadJson(Path.Combine(dir, "_locales", loc!, "messages.json")) is not JsonObject msgs) continue;
            foreach (var (k, v) in msgs)
                if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase) && Str(v?["message"]) is { Length: > 0 } m) return m;
        }
        return name;
    }

    private static DateTimeOffset? FileTime(string? microsSince1601)
    {
        if (!long.TryParse(microsSince1601, out var us) || us <= 0) return null;
        try { return DateTimeOffset.FromFileTime(us * 10); } catch { return null; }
    }

    // ---------------- Firefox ----------------

    public static IEnumerable<BrowserExtension> ReadFirefox(string user, string profilesRoot)
    {
        foreach (var profileDir in Directory.GetDirectories(profilesRoot))
        {
            if (ReadJson(Path.Combine(profileDir, "extensions.json"))?["addons"] is not JsonArray addons) continue;
            var dirName = Path.GetFileName(profileDir);
            var profile = dirName.Contains('.') ? dirName[(dirName.IndexOf('.') + 1)..] : dirName;
            foreach (var a in addons.OfType<JsonObject>())
            {
                if (Str(a["type"]) != "extension") continue;
                var location = Str(a["location"]) ?? "";
                if (location is "app-builtin" or "app-system-defaults" or "app-system-addons" or "app-builtin-addons" || a["isSystem"]?.GetValue<bool>() == true || a["isBuiltin"]?.GetValue<bool>() == true) continue;
                var perms = Strings(a["userPermissions"]?["permissions"]);
                var origins = Strings(a["userPermissions"]?["origins"]);
                var blocklist = Int(a["blocklistState"]) ?? 0;
                var installMs = a["installDate"] is JsonValue iv && iv.TryGetValue<long>(out var ms) ? ms : 0;
                yield return new BrowserExtension
                {
                    Browser = Browser.Firefox,
                    UserName = user,
                    Profile = profile,
                    ProfilePath = profileDir,
                    Id = Str(a["id"]) ?? "",
                    Name = Str(a["defaultLocale"]?["name"]) ?? Str(a["id"]) ?? "",
                    Version = Str(a["version"]),
                    ManifestVersion = Int(a["manifestVersion"]),
                    Enabled = a["active"]?.GetValue<bool>() == true,
                    InstallSource = location == "app-temporary" ? "Developer" : location is "app-profile" or "app-global" or "app-system-share" or "app-system-user"
                        ? (Str(a["sourceURI"])?.Contains("addons.mozilla.org", StringComparison.OrdinalIgnoreCase) == true || Str(a["updateURL"]) is null ? "Store" : "Sideloaded")
                        : location,
                    UpdateUrl = Str(a["updateURL"]),
                    InstallDate = installMs > 0 ? DateTimeOffset.FromUnixTimeMilliseconds(installMs) : null,
                    Permissions = perms,
                    HostPermissions = origins,
                    BroadAccess = origins.Any(IsBroad),
                    SensitivePermissions = perms.Where(Sensitive.ContainsKey).Select(p => Sensitive[p]).Distinct().ToList(),
                    FirefoxBlocklisted = blocklist >= 2,
                    FirefoxUnsigned = Int(a["signedState"]) is < 0,
                };
            }
        }
    }

    // ---------------- policy ----------------

    public static string? PolicyKey(Browser b) => b switch
    {
        Browser.Chrome => @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist",
        Browser.Edge => @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist",
        Browser.Brave => @"SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallBlocklist",
        _ => null,
    };

    private static void MarkPolicyBlocked(List<BrowserExtension> list)
    {
        foreach (var b in new[] { Browser.Chrome, Browser.Edge, Browser.Brave })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(PolicyKey(b)!);
                if (k is null) continue;
                var ids = k.GetValueNames().Select(n => k.GetValue(n) as string).Where(v => v is not null).ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var e in list.Where(e => e.Browser == b && (ids.Contains(e.Id) || ids.Contains("*")))) e.BlockedByPolicy = true;
            }
            catch { /* ignore */ }
        }
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Mozilla\Firefox");
            if (k?.GetValue("ExtensionSettings") is { } raw && JsonNode.Parse(raw is string[] parts ? string.Join("", parts) : raw.ToString()!) is JsonObject es)
                foreach (var e in list.Where(e => e.Browser == Browser.Firefox))
                    if (Str(es[e.Id]?["installation_mode"]) == "blocked") e.BlockedByPolicy = true;
        }
        catch { /* ignore */ }
    }

    // ---------------- helpers ----------------

    private static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    private static int? Int(JsonNode? n)
    {
        if (n is not JsonValue v) return null;
        if (v.TryGetValue<int>(out var i)) return i;
        if (v.TryGetValue<string>(out var s) && int.TryParse(s, out i)) return i;
        return null;
    }

    private static List<string> Strings(JsonNode? n) =>
        n is JsonArray a ? a.Select(x => x is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).Where(s => s is not null).Cast<string>().ToList() : [];
}
