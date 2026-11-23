# Endpoint triage (Windows)

Read-only checks for a Windows PC after someone else has had remote control of it, typically a
"bank / Microsoft / IT support" scam over AnyDesk, TeamViewer, QuickAssist or similar. They answer:

- **Is there a way back in?** Accounts, remote-access tools, autostart entries, services, scheduled tasks, WMI, SSH keys, Defender exclusions, proxy, root certificates.
- **What happened during the session?** Who connected and from which IP, whether they had admin rights, when the screen was blacked out, what ran, what files appeared, which sign-in or passkey prompts were shown.

The checks run **on the endpoint** in Windows PowerShell 5.1 (nothing to install). Run them in an
elevated PowerShell there and keep the results in `.scratch_area/endpoint-cases/` (gitignored; it
holds client personal data).

## Layout

| Path | What it is |
|---|---|
| `ps/checks/NN-*.ps1` | One read-only check per file (table below). Each runs on its own and prints a text report. |
| `ps/TriageCommon.ps1` | Shared helpers: formatting, user hives, Prefetch parser, AnyDesk log parsers. |
| `ps/Invoke-EndpointTriage.ps1` | Runs the checks and saves each to a file, plus a manifest; optionally collects AnyDesk logs. |
| `scripts/test.sh`, `tests/` | Test suite (container, no endpoint needed). |

## The checks

| Script | Looks at | Needs |
|---|---|---|
| `01-Get-AccountsAndSessions.ps1` | Local users, Administrators and Remote Desktop Users, profiles, account create/enable/reset/group events, logged-on sessions, LAPS policy | `-Days` |
| `02-Get-RemoteAccessTools.ps1` | Installed programs (machine and users), remote-access/RMM services, processes, portable copies in Downloads/AppData/ProgramData with signer and SHA256, recent risky downloads | `-Expected` |
| `03-Get-AnyDeskActivity.ps1` | AnyDesk logs: remote ID and **remote public IP** per session, elevation (UAC), **privacy-mode (black screen) windows** with total, file transfers, unattended-access password | `-Path` (optional) |
| `04-Get-AutostartPersistence.ps1` | Run/RunOnce (machine and loaded users), Winlogon, AppInit, AppCertDlls, LSA, IFEO/SilentProcessExit, startup folders, non-system services with signer, service installs (7045), WMI subscriptions, SSH authorized keys, Defender status/exclusions/detections/changes, hosts, proxy, new root certificates | `-Since` |
| `05-Get-ScheduledTaskPersistence.ps1` | Task XML files (all non-Microsoft, plus recently changed Microsoft ones), hidden tasks in TaskCache, task registration events | `-Since` |
| `06-Get-ExecutionEvidence.ps1` | PowerShell logs, 4688/Sysmon process creation, **Prefetch run times**, BAM, Win+R history, typed paths, searches, console history files, log health and log clearing | `-From -To` |
| `07-Get-FileActivity.ps1` | Files created in the window, and executables/scripts/archives created or modified in it (with signer) | `-From -To` |
| `08-Get-CredentialPromptActivity.ps1` | Each "Windows Security" prompt matched to its cause: **passkey sign-ins (website, app, QR/phone, success)**, CredentialUIBroker and UAC run times, vault reads | `-From -To` |
| `09-Get-BrowserExtensions.ps1` | Extensions in Chrome, Edge, Brave, Vivaldi, Opera (all profiles) with resolved names and all-sites access; Firefox add-ons. Never opens history, cookies or saved passwords | |
| `10-Get-NetworkExposure.ps1` | Established connections and listeners with their program, RDP/WinRM/sshd state, custom inbound firewall rules, firewall rule changes | `-Since` |
| `11-Get-EventsAroundTime.ps1` | Every event in every log a few seconds either side of one moment, to explain something another check found | `-Time` |

All times are **local time on the endpoint**. Write the time zone next to any time you report.

## Running a triage

### 1. Agree the window

Ask the user when the call started and when it ended. Use generous edges (for example 30 minutes
before the first download). Check 03 gives exact AnyDesk times once you are in.

### 2. Run the checks

Copy `ps/` to the endpoint and start the runner from its text in an elevated PowerShell in that
folder. It runs each check from its text too (`[scriptblock]::Create`), not as a script file, so the
checks also run where Group Policy turns PowerShell scripts off, which `-ExecutionPolicy Bypass`
cannot lift:

```powershell
$env:ENDPOINT_TRIAGE_ROOT = "$PWD\ps"; & ([scriptblock]::Create([IO.File]::ReadAllText("$PWD\ps\Invoke-EndpointTriage.ps1"))) -From "2026-01-15 14:00" -To "2026-01-15 16:30" -Expected "Splashtop,Syncro" -CollectAnyDesk
```

It writes one `NN-*.txt` per check and `00-manifest.txt` (what ran, as whom, elevated or not, hashes
of collected files) to `C:\ProgramData\endpoint-triage\out\<computer>-<time>\`. Copy that folder to
`.scratch_area/endpoint-cases/`. To explain a single moment later, run it again with
`-Check 11 -Time "2026-01-15 14:22:05"`.

## Reading the results: things that look bad but are not

| Finding | Explanation |
|---|---|
| A local admin whose password is reset by SYSTEM / `COMPUTER$` about weekly (4724) | Windows LAPS or the RMM rotating it. Confirm with whoever manages the PC. |
| Two bare `S-1-12-1-...` SIDs in Administrators | Entra ID role groups (Global Administrator, device administrators). |
| `rundll32.exe` runs and `C:\Windows\appcompat\AIDD\Buffer\*.txt` files at the exact times privacy mode starts | AnyDesk's black-screen helper, not attacker tooling. |
| `gcapi.dll` in Downloads and Temp next to AnyDesk | Google Chrome offer DLL that AnyDesk drops. |
| PowerShell as SYSTEM from `C:\ProgramData\<RMM>\...ps1` or the RMM agent's host process | The RMM's own scheduled scripts. |
| `CredentialUIBroker.exe` ran during the session | A "Windows Security" prompt. Check 08 tells you whether it was a passkey sign-in (and to which website) or something else. |
| TaskCache "NOFILE" entries under `\Microsoft\Windows\` | Retired Windows tasks, normal on Windows 11. A non-Microsoft one, or any with no SD, is not. |
| WMI subscription `SCM Event Log Filter` / `SCM Event Log Consumer` | Windows default. |
| Defender 5007 events for `ServiceStartStates`, `WdConfigHash`, `EcsConfigs` | Routine service churn at start-up and update. |
| File History copies of the attacker's files in `AppData\Local\Microsoft\Windows\FileHistory` | The user's scheduled backup ran. Remove those copies with the originals. |

## What the results cannot tell you

- **Command contents.** Without process-creation auditing (4688 with command line) or Sysmon, you see *which* programs ran (Prefetch, BAM) but not their arguments, and nothing of what was typed into `cmd`.
- **Users without a session.** Their registry hives are not loaded, so their Run keys, Win+R history and proxy settings are not read. Check 04 lists which hives were covered.
- **Older runs.** Prefetch keeps the last 8 run times per program.
- **Browser activity.** History, cookies and saved passwords are deliberately not read. Ask before collecting a `History` file, and never collect `Login Data`, `Cookies` or `Local State`.
- **What was done in online accounts.** The bank, email and other providers' own logs are the only source. A remote session with the screen blacked out should be treated as full use of every signed-in website and every saved password.

## Pitfalls already hit

| Problem | Cause | Workaround |
|---|---|---|
| Multi-line PowerShell pasted through RustDesk arrived in reverse line order | Clipboard sync splits lines | Paste one-liners, or copy scripts over with file transfer |
| `The command line is too long` | `powershell -EncodedCommand` over cmd.exe is limited to 8191 characters | Copy the scripts over first and run them there |
| A `foreach` loop "cannot be piped" | `foreach` is a statement, not a pipeline command | Wrap it: `& { foreach (...) { ... } } \| ...` |
| `Could not compare ... to "[datetime]..."` | `Where-Object Prop -gt [datetime]'...'` (simplified syntax) treats the cast as a string | Use a script block: `Where-Object { $_.Prop -gt $date }` |
| Garbled text, odd parse errors on the endpoint | Windows PowerShell 5.1 reads BOM-less files as ANSI | Scripts are ASCII-only; the tests enforce it |
| `connection_trace.txt` reads as spaced-out letters | It is UTF-16 | `ConvertFrom-TriageAnyDeskConnectionTrace` detects the encoding |

## Tests

`scripts/test.sh` runs everything in the `m365-admin` container with no endpoint. Tags: `Static`, `Unit`.

- **Static:** every file parses, passes PSScriptAnalyzer including `PSUseCompatibleSyntax` for 5.1, is ASCII-only and avoids 7-only parameters. Checks and `TriageCommon.ps1` call nothing that changes the endpoint and never touch browser credential stores. Every check has help, follows the naming convention, is run by the runner and is listed in this README. Only documentation, private or loopback IPs appear in the folder.
- **Unit:** AnyDesk trace, config and connection-trace parsing (sessions, IPs, elevation, privacy windows, file events, unattended password), check 03 end to end on a folder of files, the Prefetch parser.

The Windows-only parts (event logs, registry, WMI, compressed Prefetch) can only be exercised on a
Windows machine: run them on a test PC after changing them.
