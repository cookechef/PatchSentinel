using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using PatchSentinel.Core;

namespace PatchSentinel.Agent;

/// <summary>
/// Starts the tray app in signed-in users' desktop sessions. A silent MSI upgrade closes the running tray app
/// and does not reopen it, so the agent does this after it starts on a new version.
/// </summary>
internal static class SessionLauncher
{
    private const int WTSActive = 0;
    private const uint TOKEN_ALL_ACCESS = 0xF01FF;
    private const int SecurityImpersonation = 2;
    private const int TokenPrimary = 1;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint NORMAL_PRIORITY_CLASS = 0x00000020;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int sessionId, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attributes, int impersonationLevel, int tokenType, out IntPtr newToken);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateProcessAsUserW")]
    private static extern bool CreateProcessAsUser(IntPtr token, string? application, string commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint creationFlags, IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>Starts the tray app in every active session that is not already running it. Returns the number started.</summary>
    public static int StartTrayInActiveSessions()
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "PatchSentinel.Tray.exe");
        if (!File.Exists(exe)) { AppLog.Warn($"Tray app not found at {exe}."); return 0; }

        var running = Process.GetProcessesByName("PatchSentinel.Tray").Select(p => { try { return p.SessionId; } catch { return -1; } }).ToHashSet();
        var started = 0;
        foreach (var session in ActiveSessions())
        {
            if (running.Contains(session)) continue;
            try
            {
                StartInSession(session, exe);
                started++;
                AppLog.Info($"Started the tray app in session {session}.");
            }
            catch (Exception ex) { AppLog.Warn($"Could not start the tray app in session {session}: {ex.Message}"); }
        }
        return started;
    }

    private static List<int> ActiveSessions()
    {
        var list = new List<int>();
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out var info, out var count)) return list;
        try
        {
            var size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (var i = 0; i < count; i++)
            {
                var s = Marshal.PtrToStructure<WTS_SESSION_INFO>(info + i * size);
                if (s.State == WTSActive && s.SessionId != 0) list.Add(s.SessionId);
            }
        }
        finally { WTSFreeMemory(info); }
        return list;
    }

    private static void StartInSession(int sessionId, string exe)
    {
        IntPtr userToken = IntPtr.Zero, primary = IntPtr.Zero, env = IntPtr.Zero;
        try
        {
            if (!WTSQueryUserToken(sessionId, out userToken)) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out primary))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!CreateEnvironmentBlock(out env, primary, false)) env = IntPtr.Zero;

            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            if (!CreateProcessAsUser(primary, exe, $"\"{exe}\"", IntPtr.Zero, IntPtr.Zero, false,
                    NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT, env, Path.GetDirectoryName(exe), ref si, out var pi))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        finally
        {
            if (env != IntPtr.Zero) DestroyEnvironmentBlock(env);
            if (primary != IntPtr.Zero) CloseHandle(primary);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }
}
