using System.Text.Json;
using PatchSentinel.Core;
using PatchSentinel.Core.Ipc;

namespace PatchSentinel.Agent;

/// <summary>
/// Remembers apps whose automatic updates keep failing (so scheduled runs stop retrying them and the user is told
/// to update them by hand) and keeps a history of updates and fixes for the tray app and for audit evidence.
/// </summary>
internal sealed class UpdateTracker
{
    /// <summary>Failures in a row before an app is flagged for manual updating.</summary>
    public const int FailuresBeforeManual = 2;
    private const int MaxHistory = 1000;

    private readonly object _gate = new();
    private readonly string _manualFile = Path.Combine(AppPaths.StateDir, "manual-updates.json");
    private readonly string _historyFile = Path.Combine(AppPaths.StateDir, "history.json");
    private readonly Dictionary<string, ManualUpdateEntry> _manual;
    private readonly List<HistoryEntry> _history;

    public UpdateTracker()
    {
        _manual = (Load<List<ManualUpdateEntry>>(_manualFile) ?? []).ToDictionary(e => e.Id, StringComparer.OrdinalIgnoreCase);
        _history = Load<List<HistoryEntry>>(_historyFile) ?? [];
    }

    public int FlaggedCount { get { lock (_gate) return _manual.Values.Count(m => m.Flagged); } }

    public HistoryView View()
    {
        lock (_gate)
            return new HistoryView
            {
                Entries = _history.OrderByDescending(h => h.At).ToList(),
                ManualUpdates = _manual.Values.Where(m => m.Flagged).OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            };
    }

    /// <summary>Marks update candidates that need manual updating.</summary>
    public List<UpdateCandidate> Annotate(IEnumerable<UpdateCandidate> updates)
    {
        lock (_gate)
            return updates.Select(u =>
            {
                if (!_manual.TryGetValue(u.Id, out var m)) return u;
                var attempt = $"Failed {m.LastFailedAt.LocalDateTime:dd MMM HH:mm}" +
                              (m.Flagged ? $" ({m.Failures} times)" : $" (attempt {m.Failures} of {FailuresBeforeManual})") + $": {m.LastError}";
                return m.Flagged
                    ? u with { NeedsManualUpdate = true, ManualReason = m.LastError, LastAttempt = attempt, VendorUrl = m.VendorUrl, InstallerUrl = m.InstallerUrl }
                    : u with { LastAttempt = attempt };
            }).ToList();
    }

    public bool IsFlagged(string id) { lock (_gate) return _manual.TryGetValue(id, out var m) && m.Flagged; }

    public void RecordSuccess(UpdateCandidate u, string trigger)
    {
        lock (_gate)
        {
            _manual.Remove(u.Id);
            Add(new HistoryEntry { At = DateTimeOffset.Now, Kind = "Update", Name = u.Name, Id = u.Id, From = u.InstalledVersion, To = u.AvailableVersion, Success = true, Message = "Updated", Trigger = trigger });
            Save();
        }
    }

    /// <summary>Records a failure; returns true if this failure flagged the app for manual updating.</summary>
    public bool RecordFailure(UpdateCandidate u, string error, string trigger)
    {
        lock (_gate)
        {
            if (!_manual.TryGetValue(u.Id, out var m))
                _manual[u.Id] = m = new ManualUpdateEntry { Id = u.Id, Name = u.Name, FirstFailedAt = DateTimeOffset.Now };
            m.Failures++;
            m.LastError = error;
            m.LastFailedAt = DateTimeOffset.Now;
            m.InstalledVersion = u.InstalledVersion;
            m.AvailableVersion = u.AvailableVersion;
            var newlyFlagged = !m.Flagged && m.Failures >= FailuresBeforeManual;
            m.Flagged |= newlyFlagged;
            Add(new HistoryEntry { At = DateTimeOffset.Now, Kind = "Update", Name = u.Name, Id = u.Id, From = u.InstalledVersion, To = u.AvailableVersion, Success = false, Message = error, Trigger = trigger });
            Save();
            return newlyFlagged;
        }
    }

    /// <summary>Flagged apps whose vendor links have not been looked up in the last day.</summary>
    public List<string> NeedingLinks()
    {
        lock (_gate)
            return _manual.Values.Where(m => m.Flagged && m.VendorUrl is null && (m.LinksCheckedAt is null || DateTimeOffset.Now - m.LinksCheckedAt > TimeSpan.FromDays(1)))
                          .Select(m => m.Id).ToList();
    }

    public void SetLinks(string id, string? vendorUrl, string? installerUrl)
    {
        lock (_gate)
        {
            if (!_manual.TryGetValue(id, out var m)) return;
            m.VendorUrl = vendorUrl;
            m.InstallerUrl = installerUrl;
            m.LinksCheckedAt = DateTimeOffset.Now;
            Save();
        }
    }

    public void ClearManual(string id)
    {
        lock (_gate)
        {
            if (_manual.Remove(id)) Save();
        }
    }

    /// <summary>Drops manual flags for apps that no longer have an update pending (e.g. the user updated them by hand).</summary>
    public void Reconcile(IEnumerable<UpdateCandidate> pending)
    {
        lock (_gate)
        {
            var ids = pending.Select(p => p.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var gone = _manual.Keys.Where(k => !ids.Contains(k)).ToList();
            foreach (var id in gone)
            {
                var m = _manual[id];
                _manual.Remove(id);
                if (m.Flagged)
                    Add(new HistoryEntry { At = DateTimeOffset.Now, Kind = "Update", Name = m.Name, Id = id, From = m.InstalledVersion, To = m.AvailableVersion, Success = true, Message = "No longer pending (updated outside PatchSentinel)", Trigger = "Detected" });
            }
            if (gone.Count > 0) Save();
        }
    }

    public void RecordEvent(HistoryEntry e)
    {
        lock (_gate) { Add(e); Save(); }
    }

    private void Add(HistoryEntry e)
    {
        _history.Add(e);
        if (_history.Count > MaxHistory) _history.RemoveRange(0, _history.Count - MaxHistory);
    }

    private void Save()
    {
        try
        {
            FileUtil.WriteAllTextAtomic(_manualFile, JsonSerializer.Serialize(_manual.Values.ToList(), Json.Options));
            FileUtil.WriteAllTextAtomic(_historyFile, JsonSerializer.Serialize(_history, Json.Options));
        }
        catch (Exception ex) { AppLog.Warn($"Could not save update history: {ex.Message}"); }
    }

    private static T? Load<T>(string path) where T : class
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<T>(File.ReadAllText(path), Json.Options) : null; }
        catch { return null; }
    }
}
