using System.Text.Json.Nodes;
using Microsoft.Win32;

namespace PatchSentinel.Core.Browsers;

/// <summary>
/// Blocks extensions with the browsers' own machine policies. Chrome, Edge and Brave switch a blocked extension
/// off for good at their next start; Firefox uninstalls it. Needs administrator rights (HKLM).
/// </summary>
public static class ExtensionPolicy
{
    private const string FirefoxKey = @"SOFTWARE\Policies\Mozilla\Firefox";

    public static string Block(Browser browser, string id) => Change(browser, id, block: true);

    public static string Unblock(Browser browser, string id) => Change(browser, id, block: false);

    private static string Change(Browser browser, string id, bool block)
    {
        id = id.Trim();
        if (id.Length == 0 || id == "*") throw new ArgumentException("A specific extension ID is required.");
        if (browser == Browser.Firefox) return ChangeFirefox(id, block);
        if (id.Length != 32 || !id.All(c => c is >= 'a' and <= 'p')) throw new ArgumentException($"'{id}' is not a Chrome/Edge extension ID.");

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

    private static string ChangeFirefox(string id, bool block)
    {
        using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var k = hklm.CreateSubKey(FirefoxKey, writable: true);
        var raw = k.GetValue("ExtensionSettings");
        var text = raw is string[] parts ? string.Join("\n", parts) : raw as string;
        var settings = (string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text) as JsonObject) ?? new JsonObject();
        if (block)
        {
            if (settings[id]?["installation_mode"]?.GetValue<string>() == "blocked") return $"{id} is already blocked in Firefox.";
            settings[id] = new JsonObject { ["installation_mode"] = "blocked" };
        }
        else
        {
            if (settings[id] is null) return $"{id} was not blocked in Firefox.";
            settings.Remove(id);
        }
        // Firefox reads ExtensionSettings as a REG_MULTI_SZ or REG_SZ holding JSON.
        k.SetValue("ExtensionSettings", settings.ToJsonString(), RegistryValueKind.String);
        return block ? $"Blocked {id} in Firefox. Firefox uninstalls it at its next start." : $"Unblocked {id} in Firefox.";
    }
}
