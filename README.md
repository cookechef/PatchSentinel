# PatchSentinel

**Patch management and legacy software remediation for Windows, built on winget.**

Most patching tools (RMM patching, Action1, Patch My PC, UniGet UI and others) are good at *updating* applications, but they don't deal with what vulnerability scanners such as Qualys flag in a Cyber Essentials Plus assessment:

- **End-of-life runtimes left side by side**, e.g. *"EOL/Obsolete Software: Microsoft .NET Version 6 Detected"*. .NET runtimes are never removed when the app that needed them is uninstalled.
- **Old patch levels still on disk**, e.g. *"Microsoft .NET Security Update for June 2026"*, even though a newer patch is installed alongside.
- **Orphaned runtime folders** that no longer appear in Add/Remove Programs but are still detected by scanners.
- **Legacy redistributables** such as the Microsoft Access Database Engine 2016, old Visual C++ runtimes, Office 2013/2016/2019, Python, Node.js, PowerShell 7, Java 6/7, Flash and Silverlight.

PatchSentinel covers both jobs. It installs app updates with winget on a schedule the user (or IT) chooses, with per-app exclusions. It also **finds EOL software the way the scanners do, shows which applications still depend on it, and removes or upgrades it with one click**.

---

## Features

| | |
|---|---|
| **Scheduled winget updates** | Daily or weekly at a chosen time, random start delay for fleets, reminder before the run, postpone (limited number of times), and catch-up if the PC was off. |
| **Manual updates list** | Apps whose automatic update fails twice in a row (e.g. VPN clients with drivers) are flagged as "update manually", skipped by scheduled runs and listed with the error. Each one gets a **Download page** link to the vendor's site (taken from its winget manifest), and you can copy the direct installer link. They leave the list once they're up to date. Framework packages that Windows updates itself (Windows App Runtime, VCLibs and so on) are hidden from the list. |
| **Installed apps** | A searchable list of everything in Add/Remove Programs for all users: version, publisher, install date, size, scope and uninstall method. You can export it to CSV, copy from it, and tick several apps to uninstall them in one go. Machine-wide uninstalls ask for administrator approval through UAC, so standard users cannot remove software on their own. |
| **Software purpose and security advisories** | Each installed app is tagged with what it is for (time tracking or employee monitoring, remote access, RMM agent, network scanner, consumer VPN, peer-to-peer, bundled "PC optimiser", keylogger, crypto-miner, security software, password manager, cloud sync and so on) and how much of a concern it is (Info, Review, High), with plain-English advice. For example, memtime and Clockify are flagged as monitoring tools to confirm are approved and disclosed to staff. The categories live in `rules/eol-rules.json` under `categories` and update with the rules. |
| **History** | Every update, fix and self-update is recorded with versions, result, error and who started it. It can be copied or exported to CSV as patching evidence. |
| **Exclusions** | Users can tick apps to exclude (wildcards such as `Adobe.*` are supported). Admins can enforce exclusions by policy, which users cannot override. |
| **EOL / legacy detection** | Reads `dotnet\shared\*` and `dotnet\sdk\*` folders (x64, x86 and arm64) as well as Add/Remove Programs for all users. EOL dates and latest patch versions come from [endoflife.date](https://endoflife.date), with built-in dates as an offline fallback. |
| **Advance warning** | Flags software approaching end of life (90 days by default). For example, **.NET 8 and .NET 9 reach end of support on 10 November 2026**. |
| **Dependency check** | Finds framework-dependent .NET apps from their `*.runtimeconfig.json` and applies the .NET roll-forward rules to work out whether each one **would break** if a runtime were removed. |
| **One-click remediation** | Uninstall via the registered installer, then delete leftover folders the scanner still sees. You can also install the supported replacement (e.g. .NET 10) with winget, or remove only superseded patch versions (always safe). |
| **Light and dark mode** | Match Windows, Light or Dark. Choose it on the Overview tab or from the tray icon's Appearance menu; the choice is saved per user. |
| **Notifications** | Windows tray notifications when legacy software is found, before scheduled updates, and when jobs finish. |
| **Reports** | HTML / CSV / JSON exports to use as CE+ remediation evidence. |
| **RMM-friendly CLI** | `psentinel.exe scan --json` with exit codes your monitors can alert on, plus `fix --safe` and `fix --remove-unused-eol` for unattended clean-up. |
| **Central control** | Group Policy / Intune / RMM registry settings under `HKLM\SOFTWARE\Policies\PatchSentinel`. |

## How it fits together

```
 PatchSentinel.Tray.exe (user)  ──named pipe──►  psentinel.exe service (SYSTEM)
   tray icon, notifications                        scheduler, winget, scans,
   exclusions, schedule, Fix...                    machine-wide remediation
                                                     │
 psentinel.exe scan/fix (RMM, SYSTEM) ───────────────┘ same engine (PatchSentinel.Core)
```

- **PatchSentinel.Core**: inventory, rules engine, endoflife.date client, dependency scanner, remediation planner/executor, winget wrapper and reports. It has no third-party dependencies.
- **psentinel.exe**: the Windows service (`PatchSentinelAgent`, LocalSystem) and the command line.
- **PatchSentinel.Tray.exe**: a WPF tray app that runs as the signed-in user. Per-user installs are fixed in the user's own context, and everything machine-wide is done by the service.

## Installing

Download `PatchSentinel-x.y.z-x64.msi` from the [Releases](../../releases) page.

```powershell
# Interactive
msiexec /i PatchSentinel-1.0.0-x64.msi

# Silent (RMM / Intune)
msiexec /i PatchSentinel-1.0.0-x64.msi /qn /norestart

# Uninstall
msiexec /x PatchSentinel-1.0.0-x64.msi /qn
```

The MSI installs to `C:\Program Files\PatchSentinel`, registers and starts the **PatchSentinel Agent** service, adds `psentinel.exe` to the system PATH, and starts the tray app at every sign-in. The first scan runs about two minutes after the service starts.

**Requirements:** Windows 10 1809+ / Windows 11 / Windows Server 2019+ (x64). App updates need **winget (App Installer)**. EOL detection and remediation work without it, but installing replacements needs it. There is no .NET prerequisite: the binaries are self-contained, so PatchSentinel does not add yet another runtime to the machine.

## Automatic updates

From v0.1.4, PatchSentinel keeps itself up to date:

- The agent checks your repository's **latest GitHub Release** every 6 hours, and whenever you click **Check for PatchSentinel updates** on the tray app's Overview tab.
- When a newer version is found, the tray shows a notification with an **Install update now** button. In the default *Automatic* mode it installs by itself 15 minutes later (`SelfUpdateGraceMinutes`). In *NotifyOnly* mode it waits for someone to click Install.
- If there is a newer version, it downloads the MSI into `C:\ProgramData\PatchSentinel\updates`. It only installs it if the file's SHA-256 matches GitHub's published digest for that asset (or the release's `SHA256SUMS.txt`). It then runs a silent upgrade. The service restarts on the new version and reopens the tray app for everyone who is signed in. Settings and history are kept.
- Drafts and pre-releases are ignored, so mark a release as **pre-release** on GitHub to keep it off devices while you test it.
- To roll out a release on demand, run `psentinel self-update` (elevated). Use `psentinel self-update --check` to just report whether an update is available (exit code 12 if so).
- To turn it off or point devices at another repo, set `AutoUpdateAgent` = 0 or `UpdateRepo` = `owner/repo` in the policy key.

Because devices install whatever you publish as the latest release, protect the GitHub account with two-factor authentication and, ideally, sign the releases.

## Command line (RMM)

```powershell
psentinel scan                                   # human-readable summary
psentinel scan --json > result.json              # full result for parsing
psentinel scan --html C:\Reports\%COMPUTERNAME%.html --csv C:\Reports\%COMPUTERNAME%.csv
psentinel updates list
psentinel updates install --all                  # respects exclusions
psentinel updates install --id 7zip.7zip --id Notepad++.Notepad++
psentinel inventory --review                     # apps that need a security review
psentinel inventory --xlsx C:\Reports\apps.xlsx --html C:\Reports\apps.html
psentinel uninstall --name "DrayTek Smart VPN Client" --yes
psentinel uninstall --winget-id DrayTek.SmartVPN --yes
psentinel fix list                               # findings and their fix ids
psentinel fix dotnet-runtime:6:EndOfLife remove --yes
psentinel fix --safe --yes                       # patch supported runtimes + remove superseded patch folders
psentinel fix --remove-unused-eol --yes          # remove EOL .NET runtimes no installed app uses
psentinel rules update
psentinel self-update --check                    # is a newer PatchSentinel release available?
```

| Exit code | Meaning |
|---|---|
| 0 | Clean |
| 10 | End-of-life software present |
| 11 | Software nearing end of life, or runtimes missing patches |
| 12 | Only app updates pending |
| 1 / 2 | Error / bad arguments |

A typical **Atera / Action1 / NinjaOne** monitoring script:

```powershell
& "$env:ProgramFiles\PatchSentinel\psentinel.exe" scan --no-updates --html "$env:ProgramData\PatchSentinel\last-report.html"
exit $LASTEXITCODE   # alert on 10
```

## Policy settings (GPO, Intune or RMM)

Create values under `HKLM\SOFTWARE\Policies\PatchSentinel`. Any `Schedule*` value locks the schedule in the tray app.

| Value | Type | Example | Effect |
|---|---|---|---|
| `ScheduleEnabled` | DWORD | `1` | Automatic updates on/off |
| `ScheduleFrequency` | String | `Weekly` | `Daily` or `Weekly` |
| `ScheduleDays` | String | `Tue,Thu` | Days for weekly runs |
| `ScheduleTime` | String | `12:30` | Local time (24-hour) |
| `RandomDelayMinutes` | DWORD | `30` | Spread fleet start times |
| `NotifyMinutesBefore` | DWORD | `15` | Reminder before updates |
| `MaxDeferrals` | DWORD | `3` | How many times users may postpone |
| `ExcludedPackageIds` | Multi-string | `Adobe.*` `Zoom.Zoom` | Exclusions users cannot remove |
| `AllowUserExclusions` | DWORD | `0` | Stop users adding exclusions |
| `AllowUserRemediation` | DWORD | `0` | Report-only for standard users |
| `AllowUserDeferral` | DWORD | `0` | Stop users postponing |
| `NearingEolWarningDays` | DWORD | `120` | Early-warning window |
| `ScanIntervalHours` | DWORD | `12` | How often to rescan |
| `UseEndOfLifeApi` | DWORD | `0` | Use built-in dates only |
| `AutoUpdateRules` | DWORD | `1` | Fetch the rules catalogue daily |
| `SelfUpdateMode` | String | `NotifyOnly` | `Automatic` (default), `NotifyOnly` or `Off` |
| `SelfUpdateGraceMinutes` | DWORD | `15` | Delay between the notification and an automatic install |
| `AutoUpdateAgent` | DWORD | `0` | Legacy: same as `SelfUpdateMode` = `Off` |
| `UpdateRepo` | String | `cookechef/PatchSentinel` | Repository to take releases from |
| `RulesUrl` | String | `https://raw.githubusercontent.com/<org>/PatchSentinel/main/rules/eol-rules.json` | Your own catalogue |

Example (PowerShell, run as admin or SYSTEM):

```powershell
$k = 'HKLM:\SOFTWARE\Policies\PatchSentinel'
New-Item $k -Force | Out-Null
Set-ItemProperty $k ScheduleFrequency 'Weekly'
Set-ItemProperty $k ScheduleDays 'Wed'
Set-ItemProperty $k ScheduleTime '12:30'
New-ItemProperty $k ExcludedPackageIds -PropertyType MultiString -Value @('Adobe.*','Sage.*') -Force | Out-Null
```

## The EOL rules catalogue

Detection rules live in [`rules/eol-rules.json`](rules/eol-rules.json). They are compiled into the app, and the agent also downloads the file from your repository daily, so **you can add or correct a rule by committing to GitHub without shipping a new build**. The CI build sets the download URL to your repo automatically.

```jsonc
{
  "id": "access-database-engine-2016",
  "title": "Microsoft Access Database Engine 2016",
  "match": { "namePattern": "^Microsoft Access database engine 2016" },  // regex on the Add/Remove Programs name
  "eol": "2025-10-14",
  "replacement": "Microsoft 365 Access Runtime",
  "advice": "..."
}
```

Rules can also use `cycles` (per-version EOL dates), `endOfLifeProduct` (an endoflife.date slug for live dates and latest patch), `checkLatestPatch`, `versionFromName`, `wingetIdTemplate` (e.g. `Microsoft.DotNet.Runtime.{major}`) and `replacementWingetId`. When you bump `catalogVersion` (format `yyyy.MM.dd`), devices pick up the new file.

For rules specific to one site, put an `eol-rules.local.json` with the same schema in `C:\ProgramData\PatchSentinel\rules\`. Rules with the same `id` override the built-in ones.

## Publishing to GitHub

1. Create a repository (e.g. `PatchSentinel`) and push this folder to `main`.
2. GitHub Actions (`.github/workflows/build.yml`) runs the unit tests, publishes self-contained x64 binaries and builds the MSI on every push. The MSI and a portable zip are attached to the workflow run.
3. Tag a release to publish it:
   ```bash
   git tag v1.0.0 && git push origin v1.0.0
   ```
   The workflow creates a GitHub Release with the MSI and the zip.
4. **Code signing (recommended):** unsigned installers trigger SmartScreen and some EDR tools. Add `SIGNING_PFX_BASE64` and `SIGNING_PFX_PASSWORD` repository secrets and the workflow will sign the executables and the MSI. Azure Trusted Signing is a cheaper alternative and can replace the signtool step.

The MSI is built with WiX Toolset v5 (pinned to `5.0.2`).

## Security model

- The service runs as SYSTEM. The tray app talks to it over a local named pipe: authenticated local users can connect, network access is denied, and only SYSTEM can create pipe instances.
- Standard users can only trigger the fixes that the scan planned. Rules cannot contain commands: uninstall commands come from HKLM registry entries, and folder deletion is limited to `dotnet\shared\<framework>\<version>` / `dotnet\sdk\<version>`, with junctions refused.
- Uninstallers in user-writable locations, and all per-user (HKCU) uninstallers, are **never** run as SYSTEM. They run in the user's own session instead.
- `C:\ProgramData\PatchSentinel` is re-owned and locked to SYSTEM/Administrators at start-up, so a user cannot pre-create it to plant rules or settings.
- Remediation stops at the first failed step. Old .NET patch folders are only deleted after a newer patch has been confirmed on disk.
- Every action is logged to `C:\ProgramData\PatchSentinel\logs`, including which user requested it.

## Limitations and roadmap

- winget only manages apps that winget recognises. Anything else is reported but not updated. Chocolatey and Scoop providers are possible later additions.
- winget sometimes truncates long package ids in its output. Those apps are shown as "update manually" rather than guessed at.
- The dependency check looks in Program Files and per-user Programs folders. Services or apps installed elsewhere can be added with `ExtraDependencyScanPaths` in `settings.json`.
- Per-user apps for users who are not signed in are only seen once they sign in.
- Possible next steps: central reporting to a dashboard or Halo PSA, ARM64 build, Windows Update/driver status, more rules (Java 8 update levels, SQL Server Native Client, IIS modules).

## Building from source

```powershell
dotnet test tests/PatchSentinel.Core.Tests
dotnet publish src/PatchSentinel.Agent -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish/win-x64
dotnet publish src/PatchSentinel.Tray  -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o publish/win-x64
copy rules\eol-rules.json publish\win-x64\
dotnet build installer/PatchSentinel.Installer.wixproj -c Release -p:ProductVersion=1.0.0 -p:PublishDir=%CD%\publish\win-x64
```

To try the agent without installing the service, run `psentinel run` in an elevated prompt, then start `PatchSentinel.Tray.exe`.

## Licence

MIT. See [LICENSE](LICENSE).
