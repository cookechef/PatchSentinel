using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using PatchSentinel.Core;

namespace PatchSentinel.Tray;

public enum AppTheme { System, Light, Dark }

/// <summary>
/// Light/dark appearance. Standard controls use WPF's Fluent theme (Application.ThemeMode); PatchSentinel's own
/// colours come from the palette below, referenced as DynamicResource so open windows switch immediately.
/// The choice is saved per user.
/// </summary>
public static class ThemeManager
{
    private sealed class TraySettings { public AppTheme Theme { get; set; } = AppTheme.System; }

    private static readonly string SettingsFile =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PatchSentinel", "tray-settings.json");

    private static readonly Dictionary<string, (string Light, string Dark)> Palette = new()
    {
        ["WindowBg"] = ("#F7F7F7", "#1E1E1E"),
        ["SurfaceBg"] = ("#FFFFFF", "#2A2A2A"),
        ["SurfaceBorder"] = ("#E0E0E0", "#3D3D3D"),
        ["GridLine"] = ("#E6E6E6", "#383838"),
        ["StatusBarBg"] = ("#ECECEC", "#252525"),
        ["CodeBg"] = ("#FAFAFA", "#232323"),
        ["Muted"] = ("#5F6368", "#A9ADB3"),
        ["Accent"] = ("#005FB8", "#5AA9FF"),
        ["Critical"] = ("#C42B1C", "#FF7B72"),
        ["Warning"] = ("#9D5D00", "#F2B84B"),
        ["StatusEol"] = ("#B42318", "#FF8A80"),
        ["StatusWarn"] = ("#B54708", "#F2B84B"),
        ["OkText"] = ("#067647", "#5BD98B"),
        ["FailText"] = ("#B42318", "#FF7B72"),
        ["BannerBg"] = ("#FFF4E5", "#3A2D17"),
        ["BannerBorder"] = ("#F0C27B", "#7A5A22"),
        ["PrimaryBg"] = ("#005FB8", "#2F7FE0"),
        ["PrimaryBorder"] = ("#004C93", "#2F7FE0"),
    };

    public static AppTheme Current { get; private set; } = AppTheme.System;
    public static bool IsDark { get; private set; }
    public static event EventHandler? Changed;

    public static void Initialize(Application app)
    {
        Current = Load();
        Apply(app);
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (Current == AppTheme.System && e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color)
                app.Dispatcher.InvokeAsync(() => Apply(app));
        };
    }

    public static void Set(Application app, AppTheme theme)
    {
        Current = theme;
        Save(theme);
        Apply(app);
    }

    private static bool SystemUsesDarkApps()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch { return false; }
    }

    private static void Apply(Application app)
    {
        var dark = Current == AppTheme.Dark || (Current == AppTheme.System && SystemUsesDarkApps());
        IsDark = dark;
        try
        {
#pragma warning disable WPF0001 // ThemeMode (Fluent theme) is marked experimental in WPF
            app.ThemeMode = dark ? ThemeMode.Dark : ThemeMode.Light;
#pragma warning restore WPF0001
        }
        catch (Exception ex) { AppLog.Warn($"Could not switch the window theme: {ex.Message}"); }

        foreach (var (key, colours) in Palette)
        {
            var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(dark ? colours.Dark : colours.Light));
            brush.Freeze();
            app.Resources[key] = brush;
        }

        // Rebuild our button/check box tweaks on top of whatever the active theme provides.
        app.Resources.Remove(typeof(Button));
        app.Resources.Remove(typeof(CheckBox));
        var baseButton = app.TryFindResource(typeof(Button)) as Style;
        var button = new Style(typeof(Button), baseButton);
        button.Setters.Add(new Setter(FrameworkElement.MarginProperty, new Thickness(0, 0, 8, 8)));
        button.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(14, 6, 14, 6)));
        button.Setters.Add(new Setter(FrameworkElement.MinWidthProperty, 90.0));
        app.Resources[typeof(Button)] = button;

        var primary = new Style(typeof(Button), button);
        primary.Setters.Add(new Setter(Control.BackgroundProperty, app.Resources["PrimaryBg"]));
        primary.Setters.Add(new Setter(Control.BorderBrushProperty, app.Resources["PrimaryBorder"]));
        primary.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.White));
        app.Resources["Primary"] = primary;

        // The Fluent theme gives check boxes a large minimum width, which clips the tick columns in lists.
        var baseCheck = app.TryFindResource(typeof(CheckBox)) as Style;
        var check = new Style(typeof(CheckBox), baseCheck);
        check.Setters.Add(new Setter(FrameworkElement.MinWidthProperty, 0.0));
        app.Resources[typeof(CheckBox)] = check;

        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static AppTheme Load()
    {
        try
        {
            if (File.Exists(SettingsFile))
                return JsonSerializer.Deserialize<TraySettings>(File.ReadAllText(SettingsFile), Json.Options)?.Theme ?? AppTheme.System;
        }
        catch { /* defaults */ }
        return AppTheme.System;
    }

    private static void Save(AppTheme theme)
    {
        try { FileUtil.WriteAllTextAtomic(SettingsFile, JsonSerializer.Serialize(new TraySettings { Theme = theme }, Json.Options)); }
        catch (Exception ex) { AppLog.Warn($"Could not save the theme choice: {ex.Message}"); }
    }
}
