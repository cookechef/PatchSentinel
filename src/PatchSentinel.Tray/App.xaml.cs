using System;
using System.Threading;
using System.Windows;
using PatchSentinel.Core;

namespace PatchSentinel.Tray;

public partial class App : Application
{
    private const string MutexName = @"Local\PatchSentinel.Tray";
    private const string ShowEventName = @"Local\PatchSentinel.Tray.Show";

    private Mutex? _mutex;
    private bool _ownsMutex;
    private EventWaitHandle? _showEvent;
    private TrayController? _tray;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        AppLog.Initialize(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PatchSentinel", "logs"));

        _mutex = new Mutex(true, MutexName, out _ownsMutex);
        if (!_ownsMutex)
        {
            // Already running: ask the existing instance to open its window.
            try { EventWaitHandle.OpenExisting(ShowEventName).Set(); } catch { /* ignore */ }
            Shutdown();
            return;
        }

        DispatcherUnhandledException += (_, args) =>
        {
            AppLog.Error("Unhandled UI exception", args.Exception);
            MessageBox.Show(args.Exception.Message, "PatchSentinel", MessageBoxButton.OK, MessageBoxImage.Warning);
            args.Handled = true;
        };

        ThemeManager.Initialize(this);
        _tray = new TrayController(this);
        _tray.Start();

        _showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEventName);
        var listener = new Thread(() =>
        {
            while (_showEvent.WaitOne())
                Dispatcher.InvokeAsync(() => _tray?.ShowMainWindow(null));
        }) { IsBackground = true, Name = "ShowListener" };
        listener.Start();

        if (Array.Exists(e.Args, a => a.Equals("--show", StringComparison.OrdinalIgnoreCase)))
            _tray.ShowMainWindow(null);
    }

    /// <summary>After a self-update replaced the exe on disk, start the new version and exit this one.</summary>
    internal void RestartIntoNewVersion()
    {
        var path = Environment.ProcessPath;
        if (path is null) return;
        _tray?.Dispose();
        _tray = null;
        if (_ownsMutex)
        {
            try { _mutex?.ReleaseMutex(); } catch { /* ignore */ }
            _ownsMutex = false;
        }
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(path) { UseShellExecute = true }); }
        catch (Exception ex) { AppLog.Error("Could not restart the tray app after an update", ex); }
        Shutdown();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        if (_ownsMutex)
        {
            try { _mutex?.ReleaseMutex(); } catch { /* ignore */ }
        }
        _mutex?.Dispose();
        base.OnExit(e);
    }
}
