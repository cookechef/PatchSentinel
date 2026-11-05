using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PatchSentinel.Core.Inventory;

/// <summary>
/// Finds .NET (Core) runtimes and SDKs by folder, exactly as vulnerability scanners do. This catches
/// side-by-side patch versions and orphaned folders that never appear in Add/Remove Programs.
/// </summary>
public static class DotNetInventory
{
    public static readonly Regex VersionFolder = new(@"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$", RegexOptions.Compiled);
    public static readonly Regex FrameworkFolder = new(@"^Microsoft\.[A-Za-z][A-Za-z.]*$", RegexOptions.Compiled);

    public const string SdkItemName = "Microsoft .NET SDK";
    public const string NetFrameworkItemName = ".NET Framework";

    public static IReadOnlyList<(string Root, string Arch)> GetRoots()
    {
        var list = new List<(string, string)>();
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var native = Platform.NativeArchitecture;
        if (!string.IsNullOrEmpty(pf))
        {
            list.Add((Path.Combine(pf, "dotnet"), native));
            if (native == "arm64") list.Add((Path.Combine(pf, "dotnet", "x64"), "x64"));
        }
        if (!string.IsNullOrEmpty(pf86) && !string.Equals(pf86, pf, StringComparison.OrdinalIgnoreCase))
            list.Add((Path.Combine(pf86, "dotnet"), "x86"));
        return list;
    }

    public static List<InstalledItem> Collect(List<string> warnings)
    {
        var items = new List<InstalledItem>();
        foreach (var (root, arch) in GetRoots())
        {
            try
            {
                var shared = Path.Combine(root, "shared");
                if (Directory.Exists(shared))
                {
                    foreach (var fwDir in Directory.GetDirectories(shared))
                    {
                        var fw = Path.GetFileName(fwDir);
                        if (!FrameworkFolder.IsMatch(fw)) continue;
                        foreach (var verDir in Directory.GetDirectories(fwDir))
                        {
                            var ver = Path.GetFileName(verDir);
                            if (!VersionFolder.IsMatch(ver)) continue;
                            items.Add(new InstalledItem
                            {
                                Name = fw, Version = ver, Source = ItemSource.DotNetSharedFramework,
                                Architecture = arch, InstallLocation = verDir, Publisher = "Microsoft Corporation",
                            });
                        }
                    }
                }

                var sdk = Path.Combine(root, "sdk");
                if (Directory.Exists(sdk))
                {
                    foreach (var verDir in Directory.GetDirectories(sdk))
                    {
                        var ver = Path.GetFileName(verDir);
                        if (!VersionFolder.IsMatch(ver)) continue;
                        items.Add(new InstalledItem
                        {
                            Name = SdkItemName, Version = ver, Source = ItemSource.DotNetSdk,
                            Architecture = arch, InstallLocation = verDir, Publisher = "Microsoft Corporation",
                        });
                    }
                }
            }
            catch (Exception ex) { warnings.Add($"Could not read {root}: {ex.Message}"); }
        }

        var fx = CollectNetFramework();
        if (fx is not null) items.Add(fx);
        return items;
    }

    public static InstalledItem? CollectNetFramework()
    {
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var k = hklm.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full");
            if (k?.GetValue("Release") is not int release) return null;
            return new InstalledItem
            {
                Name = NetFrameworkItemName,
                Version = MapRelease(release),
                Source = ItemSource.DotNetFramework,
                Publisher = "Microsoft Corporation",
            };
        }
        catch { return null; }
    }

    /// <summary>Maps the NDP v4 Release DWORD to a version (documented by Microsoft).</summary>
    public static string MapRelease(int release) => release switch
    {
        >= 533320 => "4.8.1",
        >= 528040 => "4.8",
        >= 461808 => "4.7.2",
        >= 461308 => "4.7.1",
        >= 460798 => "4.7",
        >= 394802 => "4.6.2",
        >= 394254 => "4.6.1",
        >= 393295 => "4.6",
        >= 379893 => "4.5.2",
        >= 378675 => "4.5.1",
        _ => "4.5",
    };
}
