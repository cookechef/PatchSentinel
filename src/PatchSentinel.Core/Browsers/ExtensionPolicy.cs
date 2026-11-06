using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32;

namespace PatchSentinel.Core.Browsers;

/// <summary>An uninstall PatchSentinel asked a browser to do, waiting for the browser to carry it out.</summary>
public sealed class PendingRemoval
{
    public Browser Browser { get; set; }
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string By { get; set; } = "";
    public DateTimeOffset RequestedAt { get; set; }
}

/// <summary>
/// Blocks and uninstalls extensions with the browsers' own machine policies (needs administrator rights, HKLM).
/// Block: Chrome, Edge and Brave switch the extension off for good at their next start (ExtensionInstallBlocklist);
/// Firefox uninstalls it. Uninstall: ExtensionSettings installation_mode "removed" (Chrome, Edge, Brave) or "blocked"
/// (Firefox) makes the browser remove it at its next start. PatchSentinel takes the uninstall entry off again once the
/// extension has gone from every profile, so it can be reinstalled later if needed.
/// </summary>
public static class ExtensionPolicy
{
    private const string FirefoxKey = @"SOFTWARE\Policies\Mozilla\Firefox";

    public static string StateFile => Path.Combine(AppPaths.StateDir, "extension-removals.json");

    public static string? VendorKey(Browser b) => b switch
    {
        Browser.Chrome => @"SOFTWARE\Policies\Google\Chrome",
        Browser.Edge => @"SOFTWARE\Policies\Microsoft\Edge",
        Browser.Brave => @"SOFTWARE\Policies\BraveSoftware\Brave",
        Browser.Firefox => FirefoxKey,
        _ => null,
    };

    public static string Block(Browser browser, string id) => ChangeBlocklist(browser, id, block: true);

    public static string Unblock(Browser browser, string id)
    {
        var wasPending = LoadPending().Any(p => p.Browser == browser && p.Id.Equals(id.Trim(), StringComparison.OrdinalIgnoreCase));
        // Clears the blocklist entry and any ExtensionSettings "blocked"/"removed" entry (a pending uninstall blocks reinstalling too).
        var msg = ChangeBlocklist(browser, id, block: false);
        if (wasPending) { RemovePending(browser, id.Trim()); msg = $"Cancelled the pending uninstall of {id} in {Display(browser)}."; }
        return msg;
    }

    /// <summary>Asks the browser to uninstall the extension for every user at its next start.</summary>
    public static string Uninstall(Browser browser, string id, string name, string by)
    {
        Validate(browser, id);
        var mode = browser == Browser.Firefox ? "blocked" : "removed";
        SetMode(browser, id, mode, out var others);
        var pending = LoadPending();
        pending.RemoveAll(p => p.Browser == browser && p.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        pending.Add(new PendingRemoval { Browser = browser, Id = id, Name = name, By = by, RequestedAt = DateTimeOffset.Now });
        SavePending(pending);
        var msg = $"{name}: {Display(browser)} will uninstall it for every user when it next starts.";
        if (others > 0)
            msg += $" Note: {Display(browser)}'s extension policy already had {others} other entr{(others == 1 ? "y" : "ies")}, probably from Group Policy or Intune. If they manage this browser, Group Policy will overwrite this change at its next refresh, so make the change there instead.";
        return msg;
    }

    /// <summary>
    /// Takes the uninstall policy off extensions that have now gone from every profile. Returns the ones completed.
    /// Call after a full (all users) extension scan.
    /// </summary>
    public static List<PendingRemoval> CompletePendingRemovals(IReadOnlyCollection<BrowserExtension> found)
    {
        var pending = LoadPending();
        if (pending.Count == 0) return [];
        var done = pending.Where(p => !found.Any(e => e.Browser == p.Browser && e.Id.Equals(p.Id, StringComparison.OrdinalIgnoreCase))).ToList();
        foreach (var p in done)
        {
            try { SetMode(p.Browser, p.Id, null, out _); }
            catch (Exception ex) { AppLog.Warn($"Could not clear the uninstall policy for {p.Id}: {ex.Message}"); }
        }
        if (done.Count > 0) SavePending(pending.Except(done).ToList());
        foreach (var e in found)
            if (pending.Except(done).Any(p => p.Browser == e.Browser && p.Id.Equals(e.Id, StringComparison.OrdinalIgnoreCase))) e.PendingRemoval = true;
        return done;
    }

    public static List<PendingRemoval> LoadPending()
    {
        try
        {
            if (File.Exists(StateFile)) return JsonSerializer.Deserialize<List<PendingRemoval>>(File.ReadAllText(StateFile), Json.Options) ?? [];
        }
        catch { /* start again */ }
        return [];
    }

    private static void SavePending(List<PendingRemoval> list)
    {
        Directory.CreateDirectory(AppPaths.StateDir);
        FileUtil.WriteAllTextAtomic(StateFile, JsonSerializer.Serialize(list, Json.Options));
    }

    private static void RemovePending(Browser b, string id)
    {
        var list = LoadPending();
        if (list.RemoveAll(p => p.Browser == b && p.Id.Equals(id, StringComparison.OrdinalIgnoreCase)) > 0) SavePending(list);
    }

    private static string Display(Browser b) => b switch { Browser.Chrome => "Chrome", Browser.Edge => "Edge", Browser.Brave => "Brave", _ => "Firefox" };

    private static void Validate(Browser browser, string id)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Trim() == "*") throw new ArgumentException("A specific extension ID is required.");
        if (browser != Browser.Firefox && (id.Length != 32 || !id.All(c => c is >= 'a' and <= 'p')))
            throw new ArgumentException($"'{id}' is not a Chrome/Edge extension ID.");
        if (browser == Browser.Firefox && (id.Length > 200 || id.Any(char.IsControl))) throw new ArgumentException($"'{id}' is not a Firefox add-on ID.");
    }

    /// <summary>Sets (or with null clears) an extension's installation_mode in ExtensionSettings. Returns true if anything changed.</summary>
    private static bool SetMode(Browser browser, string id, string? mode, out int otherEntries)
    {
        id = id.Trim();
        Validate(browser, id);
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var k = mode is null ? hklm.OpenSubKey(VendorKey(browser)!, writable: true) : hklm.CreateSubKey(VendorKey(browser)!, writable: true);
        otherEntries = 0;
        if (k is null) return false;
        var raw = k.GetValue("ExtensionSettings");
        var text = raw is string[] parts ? string.Join("\n", parts) : raw as string;
        var settings = (string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text) as JsonObject) ?? new JsonObject();
        otherEntries = settings.Count(kv => !kv.Key.Equals(id, StringComparison.OrdinalIgnoreCase));
        var existingKey = settings.Select(kv => kv.Key).FirstOrDefault(key => key.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (mode is null)
        {
            // Only take off an entry PatchSentinel would have written.
            var current = existingKey is null ? null : settings[existingKey]?["installation_mode"]?.GetValue<string>();
            if (existingKey is null || current is not ("removed" or "blocked")) return false;
            settings.Remove(existingKey);
        }
        else
        {
            if (existingKey is not null) settings.Remove(existingKey);
            settings[id] = new JsonObject { ["installation_mode"] = mode };
        }
        if (settings.Count == 0) k.DeleteValue("ExtensionSettings", false);
        else k.SetValue("ExtensionSettings", settings.ToJsonString(), RegistryValueKind.String);
        return true;
    }

    private static string ChangeBlocklist(Browser browser, string id, bool block)
    {
        id = id.Trim();
        Validate(browser, id);
        if (browser == Browser.Firefox)
        {
            var changed = SetMode(browser, id, block ? "blocked" : null, out _);
            return block ? $"Blocked {id} in Firefox. Firefox uninstalls it at its next start." : changed ? $"Unblocked {id} in Firefox." : $"{id} was not blocked in Firefox.";
        }

        // ExtensionSettings takes priority over the older blocklist in Chromium, so write both.
        if (block) SetMode(browser, id, "blocked", out _);
        else SetMode(browser, id, null, out _);

        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var k = hklm.CreateSubKey(ExtensionInventory.PolicyKey(browser)!, writable: true);
        var existing = k.GetValueNames().Where(n => string.Equals(k.GetValue(n) as string, id, StringComparison.OrdinalIgnoreCase)).ToList();
        if (block)
        {
            if (existing.Count > 0) return $"{id} is already blocked in {browser}.";
            var next = 1;
            var used = k.GetValueNames().Select(n => int.TryParse(n, out var i) ? i : 0).ToHashSet();
            while (used.Contains(next)) next++;
            k.SetValue(next.ToString(), id, RegistryValueKind.String);
            return $"Blocked {id} in {browser}. {browser} turns it off at its next start and users can't turn it back on.";
        }
        foreach (var n in existing) k.DeleteValue(n, false);
        return existing.Count > 0 ? $"Unblocked {id} in {browser}." : $"{id} was not blocked in {browser}.";
    }
}
