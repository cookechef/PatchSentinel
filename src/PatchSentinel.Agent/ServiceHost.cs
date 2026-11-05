using System.ComponentModel;
using System.Runtime.InteropServices;
using PatchSentinel.Core;

namespace PatchSentinel.Agent;

/// <summary>
/// Minimal Windows Service Control Manager integration via advapi32, so the agent has no third-party
/// dependencies. Started by the SCM as "psentinel.exe service".
/// </summary>
internal static class ServiceHost
{
    private const int SERVICE_WIN32_OWN_PROCESS = 0x10;
    private const int SERVICE_STOPPED = 1, SERVICE_START_PENDING = 2, SERVICE_STOP_PENDING = 3, SERVICE_RUNNING = 4;
    private const int SERVICE_ACCEPT_STOP = 0x1, SERVICE_ACCEPT_SHUTDOWN = 0x4;
    private const int SERVICE_CONTROL_STOP = 1, SERVICE_CONTROL_INTERROGATE = 4, SERVICE_CONTROL_SHUTDOWN = 5;
    private const int NO_ERROR = 0, ERROR_CALL_NOT_IMPLEMENTED = 120;
    private const int ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063;

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public int dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SERVICE_TABLE_ENTRY
    {
        public string? lpServiceName;
        public IntPtr lpServiceProc;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainProc(int argc, IntPtr argv);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int HandlerExProc(int control, int eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "StartServiceCtrlDispatcherW")]
    private static extern bool StartServiceCtrlDispatcher([In] SERVICE_TABLE_ENTRY[] table);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegisterServiceCtrlHandlerExW")]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(string serviceName, HandlerExProc handler, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetServiceStatus(IntPtr handle, ref SERVICE_STATUS status);

    // Delegates must stay referenced for the lifetime of the process.
    private static ServiceMainProc? _main;
    private static HandlerExProc? _handler;
    private static IntPtr _statusHandle;
    private static SERVICE_STATUS _status;
    private static readonly CancellationTokenSource Stop = new();
    private static Task? _engineTask;
    private static readonly ManualResetEventSlim Finished = new(false);

    public static int Run()
    {
        _main = ServiceMain;
        var table = new[]
        {
            new SERVICE_TABLE_ENTRY { lpServiceName = AppPaths.ServiceName, lpServiceProc = Marshal.GetFunctionPointerForDelegate(_main) },
            new SERVICE_TABLE_ENTRY { lpServiceName = null, lpServiceProc = IntPtr.Zero },
        };
        if (!StartServiceCtrlDispatcher(table))
        {
            var err = Marshal.GetLastWin32Error();
            if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            {
                Console.Error.WriteLine("'service' is used by the Windows Service Control Manager. To run the agent in this console use: psentinel run");
                return 2;
            }
            throw new Win32Exception(err);
        }
        Finished.Wait(TimeSpan.FromSeconds(30));
        return 0;
    }

    private static void ServiceMain(int argc, IntPtr argv)
    {
        _handler = Handler;
        _statusHandle = RegisterServiceCtrlHandlerEx(AppPaths.ServiceName, _handler, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero) return;

        _status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        Report(SERVICE_START_PENDING, waitHint: 10000);

        var engine = new AgentEngine();
        _engineTask = Task.Run(async () =>
        {
            try { await engine.RunAsync(Stop.Token); }
            catch (Exception ex) { AppLog.Error("Agent engine crashed", ex); _status.dwWin32ExitCode = 1; }
            finally
            {
                Report(SERVICE_STOPPED);
                Finished.Set();
            }
        });
        Report(SERVICE_RUNNING);
    }

    private static int Handler(int control, int eventType, IntPtr eventData, IntPtr context)
    {
        switch (control)
        {
            case SERVICE_CONTROL_STOP:
            case SERVICE_CONTROL_SHUTDOWN:
                Report(SERVICE_STOP_PENDING, waitHint: 20000);
                Stop.Cancel();
                return NO_ERROR;
            case SERVICE_CONTROL_INTERROGATE:
                SetServiceStatus(_statusHandle, ref _status);
                return NO_ERROR;
            default:
                return ERROR_CALL_NOT_IMPLEMENTED;
        }
    }

    private static void Report(int state, int waitHint = 0)
    {
        _status.dwCurrentState = state;
        _status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
        _status.dwWaitHint = waitHint;
        _status.dwCheckPoint = state is SERVICE_RUNNING or SERVICE_STOPPED ? 0 : _status.dwCheckPoint + 1;
        if (state != SERVICE_STOPPED) _status.dwWin32ExitCode = NO_ERROR;
        SetServiceStatus(_statusHandle, ref _status);
    }
}
