using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PatchSentinel.Core.Inventory;

/// <summary>Reads Add/Remove Programs entries from HKLM (64 and 32-bit views) and from user hives.</summary>
public static class RegistryInventory
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private static readonly Regex ArchRegex = new(@"\((x64|x86|arm64|64-bit|32-bit)\)|-(x64|x86|arm64)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex GuidKey = new(@"^\{[0-9A-Fa-f\-]{36}\}$", RegexOptions.Compiled);

    /// <param name="allLoadedUserHives">When running as SYSTEM, read HKEY_USERS\&lt;SID&gt; for every logged-on user.</param>
    public static List<InstalledItem> Collect(bool allLoadedUserHives, string? currentUserSid, List<string> warnings)
    {
        var items = new List<InstalledItem>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                Read(hklm, InstallScope.Machine, null, view == RegistryView.Registry32 ? @"HKLM\WOW6432Node" : "HKLM", items);
            }
            catch (Exception ex) { warnings.Add($"Could not read HKLM ({view}): {ex.Message}"); }
        }

        try
        {
            if (allLoadedUserHives)
            {
                using var hku = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Default);
                foreach (var sid in hku.GetSubKeyNames())
                {
                    if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase)) continue;
                    using var root = hku.OpenSubKey(sid);
                    if (root is not null) Read(root, InstallScope.User, sid, $@"HKU\{sid}", items);
                }
            }
            else
            {
                using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                Read(hkcu, InstallScope.User, currentUserSid, "HKCU", items);
            }
        }
        catch (Exception ex) { warnings.Add($"Could not read user uninstall entries: {ex.Message}"); }

        return items.GroupBy(i => (i.Key, i.ProductCode)).Select(g => g.First()).ToList();
    }

    private static void Read(RegistryKey baseKey, InstallScope scope, string? sid, string label, List<InstalledItem> items)
    {
        using var uninstall = baseKey.OpenSubKey(UninstallPath);
        if (uninstall is null) return;
        foreach (var name in uninstall.GetSubKeyNames())
        {
            try
            {
                using var k = uninstall.OpenSubKey(name);
                if (k is null) continue;
                var displayName = (k.GetValue("DisplayName") as string)?.Trim();
                if (string.IsNullOrEmpty(displayName)) continue;
                // Skip patches/hotfixes that hang off a parent product.
                if (k.GetValue("ParentKeyName") is string) continue;
                var releaseType = k.GetValue("ReleaseType") as string;
                if (releaseType is "Update" or "Hotfix" or "Security Update") continue;

                var isMsi = GetInt(k, "WindowsInstaller") == 1;
                var archMatch = ArchRegex.Match(displayName);
                string? arch = null;
                if (archMatch.Success)
                {
                    var a = (archMatch.Groups[1].Success ? archMatch.Groups[1].Value : archMatch.Groups[2].Value).ToLowerInvariant();
                    arch = a switch { "64-bit" => "x64", "32-bit" => "x86", _ => a };
                }

                items.Add(new InstalledItem
                {
                    Name = displayName,
                    Version = (k.GetValue("DisplayVersion") as string)?.Trim(),
                    Publisher = (k.GetValue("Publisher") as string)?.Trim(),
                    Source = ItemSource.Registry,
                    Scope = scope,
                    UserSid = sid,
                    Architecture = arch,
                    InstallLocation = (k.GetValue("InstallLocation") as string)?.Trim(),
                    UninstallString = (k.GetValue("UninstallString") as string)?.Trim(),
                    QuietUninstallString = (k.GetValue("QuietUninstallString") as string)?.Trim(),
                    ProductCode = isMsi && GuidKey.IsMatch(name) ? name.ToUpperInvariant() : null,
                    RegistryKey = $@"{label}\{UninstallPath}\{name}",
                    IsSystemComponent = GetInt(k, "SystemComponent") == 1,
                });
            }
            catch
            {
                // One bad key must not stop the inventory.
            }
        }
    }

    private static int GetInt(RegistryKey k, string name) => k.GetValue(name) switch
    {
        int i => i,
        string s when int.TryParse(s, out var i) => i,
        _ => 0,
    };
}
