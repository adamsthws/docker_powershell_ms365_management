# Endpoint triage (Windows)

Read-only checks for a Windows PC after someone else has had remote control of it, typically a
"bank / Microsoft / IT support" scam over AnyDesk, TeamViewer, QuickAssist or similar. They answer:

- **Is there a way back in?** Accounts, remote-access tools, autostart entries, services, scheduled tasks, WMI, SSH keys, Defender exclusions, proxy, root certificates.
- **What happened during the session?** Who connected and from which IP, whether they had admin rights, when the screen was blacked out, what ran, what files appeared, which sign-in or passkey prompts were shown.

The checks run **on the endpoint** in Windows PowerShell 5.1 (nothing to install). You can run them
by hand at the console, or from this repo over SSH or WinRM with `scripts/triage.sh`, which copies
the results back into `.scratch_area/endpoint-cases/` (gitignored; it holds client personal data).

## Layout

| Path | What it is |
|---|---|
| `ps/checks/NN-*.ps1` | One read-only check per file (table below). Each runs on its own and prints a text report. |
| `ps/TriageCommon.ps1` | Shared helpers: formatting, user hives, Prefetch parser, AnyDesk log parsers. |
| `ps/Invoke-EndpointTriage.ps1` | Runs the checks and saves each to a file, plus a manifest; optionally collects AnyDesk logs. |
| `ps/setup/Set-TriageAccess.ps1` | **Changes the endpoint.** Turns remote PowerShell access on (SSH with your GitHub keys, else WinRM with a client certificate), shows it with `-Status`, and undoes it all with `-Remove`. |
| `scripts/new-winrm-cert.sh` | Makes your WinRM client certificate (the WinRM equivalent of an SSH key pair), outside any git repository. |
| `scripts/setup-command.sh` | Prints the one line to paste on the endpoint: downloads `Set-TriageAccess.ps1` from this repo, pinned to a commit, pointing at your GitHub keys and certificate Gist. |
| `scripts/triage.sh` | Runs everything over WinRM or SSH from Linux and copies the results back. |
| `scripts/winrm_client.py` | The WinRM client `triage.sh` uses (Python `pypsrp`, certificate login, TLS 1.2, thumbprint check). |
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

### 2. Get access

SSH needs nothing set up: the endpoint takes your public keys from `https://github.com/<you>.keys`.
For the WinRM fallback, once per machine of yours, make a client certificate and publish it (the
certificate only, never the key) as a Gist. WinRM cannot reuse the SSH key: Windows only accepts
X.509 client certificates with RSA or ECDSA keys, and your GitHub key is Ed25519.

```bash
endpoint-triage/scripts/new-winrm-cert.sh          # writes ~/.config/endpoint-triage/, never inside a git repository
gh gist create --desc "WinRM client certificate (public; CN=temp-local-admin, UPN temp-local-admin@localhost)" ~/.config/endpoint-triage/winrm-client.pem
echo <gist id> > ~/.config/endpoint-triage/winrm-gist
```

Then, for each endpoint:

1. On your machine, print the setup line. It is pinned to the commit `origin/main` points to, so
   run `git fetch` first; the script must already be pushed:

   ```bash
   endpoint-triage/scripts/setup-command.sh
   ```

   It uses the keys of the repository owner on GitHub (`-k USER` for someone else, `-i KEY.pub` for a
   local key), and the Gist's raw URL pinned to its current revision, after checking the Gist holds
   the same certificate as your `winrm-client.pem`. The line carries no key material.

2. Paste that **one line** into an elevated Windows PowerShell on the endpoint, through the
   remote-support session. It downloads `Set-TriageAccess.ps1` from GitHub and runs it in memory. Its
   general form is documented at the top of the script. If security software blocks download-and-run,
   copy the script and `winrm-client.cer` over with file transfer and run it with
   `-PublicKey '...' -ClientCertificate .\winrm-client.cer` instead. **Never copy `winrm-client.key`
   anywhere.**

   It downloads the keys and certificate first and shows their fingerprints, creates the temporary
   admin `temp-local-admin` with a random password nobody sees, then tries each method in turn until one works:

   | Order | Method | Time | Needs |
   |---|---|---|---|
   | 1 | **SSH** from the Win32-OpenSSH GitHub release (6 MB; `sshd.exe` must be validly signed by Microsoft) | seconds | `-GitHubUser` or `-PublicKey`, access to GitHub |
   | 2 | **WinRM**, built into Windows: HTTPS listener on 127.0.0.1, certificate login mapped to `temp-local-admin`. For when GitHub is blocked or security software stops the new sshd service | seconds | `-ClientCertificate` |
   | 3 | **SSH** from the Windows optional feature (Windows Update) | several minutes | `-GitHubUser` or `-PublicKey` |

   SSH comes first because it changes no security setting and the session is a full admin as it is.
   `-WinRM` or `-Ssh` limits it to those methods. An existing sshd is reused rather than reinstalled.
   Everything that was there before is recorded so `-Remove` can put it back. It ends by showing the
   status and the exact `triage.sh` command, including the WinRM server certificate thumbprint or
   the SSH host key fingerprint to check. Check again at any time with `-Status`.
3. In the remote-support tool, forward a local TCP port to the endpoint: local 2222 to
   `127.0.0.1:22` for SSH, or local 5986 to `127.0.0.1:5986` for WinRM.

Why the temporary account: Windows cannot do key or certificate logins for **Entra ID (AzureAD)
accounts**, and typing the user's password over a session you suspect is compromised adds risk.

What WinRM changes that SSH does not: it sets **`LocalAccountTokenFilterPolicy` = 1**, without which
a local admin logging in remotely gets a non-admin token and the checks see little. Attackers set it
too, so some security tools alert on it; `-Remove` puts it back. It also trusts your client
certificate in the machine's Root store for the session. The certificate is CA:FALSE, so it cannot
be used to issue other certificates, and `-Remove` removes it.

Exposure: sshd listens on 127.0.0.1 only. The WinRM listener only answers on 127.0.0.1, but Windows'
HTTP service opens the port on all addresses, so it is the Windows Firewall (no inbound rule is
added) that keeps it off the network. `-Status` names any inbound rule that would expose it.

### 3. Run the checks

```bash
endpoint-triage/scripts/triage.sh -F <server thumbprint> -- \
    -From "2026-01-15 14:00" -To "2026-01-15 16:30" -Expected "Splashtop,Syncro" -CollectAnyDesk
```

`triage.sh` finds the tunnel itself: it tries local port 2222, then 5986, and tells WinRM from SSH
by whether the port sends an SSH banner. Use `-t winrm|ssh` and `-p PORT` to choose. The first WinRM
run creates a Python virtual environment with `pypsrp` in `.scratch_area/venv-winrm/`.

It asks before copying anything, then saves to `.scratch_area/endpoint-cases/<date>-<computer>/<run>/`:
one `NN-*.txt` per check, `00-manifest.txt` (what ran, as whom, elevated or not, hashes of collected
files) and `run-info.txt` (how it connected, and the server certificate thumbprint or host key). To
explain a single moment later:

```bash
endpoint-triage/scripts/triage.sh -- -Check 11 -Time "2026-01-15 14:22:05"
```

`triage.sh` runs the runner, and the runner runs each check, from the script text
(`[scriptblock]::Create`), not as script files. So the checks also run where Group Policy turns
PowerShell scripts off, which `-ExecutionPolicy Bypass` cannot lift. On such a PC `Set-TriageAccess.ps1`
skips the GitHub SSH route (Microsoft's installer is a script file) and goes on to WinRM.

Without remote access, copy `ps/` to the endpoint and start the runner from its text in an elevated
PowerShell in that folder:

```powershell
$env:ENDPOINT_TRIAGE_ROOT = "$PWD\ps"; & ([scriptblock]::Create([IO.File]::ReadAllText("$PWD\ps\Invoke-EndpointTriage.ps1"))) -From "2026-01-15 14:00" -To "2026-01-15 16:30"
```

It writes to `C:\ProgramData\endpoint-triage\out\<computer>-<time>\`; copy that folder back yourself.

### 4. Remove the access

Collect everything first. Then at the endpoint's console (or through the remote-support tool, not
over the remote session you are removing), in an elevated PowerShell, paste the line from
`setup-command.sh -m remove` (or run `.\Set-TriageAccess.ps1 -Remove`; `-WhatIf` shows the plan).

It undoes whichever method was used:
- **WinRM:** removes the listener, the certificate mapping, the temporary server certificate and your
  trusted client certificate, and puts certificate authentication, `LocalAccountTokenFilterPolicy`
  and the WinRM service back as they were.
- **SSH:** restores or deletes `administrators_authorized_keys` and `sshd_config`, and uninstalls
  OpenSSH if it installed it (GitHub copy, including the machine `PATH` entry its installer adds, or
  Windows feature), otherwise restores the sshd service. `-KeepOpenSsh` leaves OpenSSH installed.
- **Both:** deletes `temp-local-admin` and its profile, and `C:\ProgramData\endpoint-triage`.

If `temp-local-admin` still has programs running (a session still open), it stops and says so; close the
session and run `-Remove` again. Windows often keeps a profile loaded for a while after the last
logoff, even with nothing running: then it deletes the account at once (that ends the access) and
asks you to restart the PC and run `-Remove` again to delete the profile folder.

Record what you added and removed in the case notes so it is not mistaken for attacker activity.

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
| `ssh: remote username contains invalid characters` | OpenSSH refuses `DOMAIN\user` on the command line | `triage.sh` writes it to a config file, which is allowed |
| `Permission denied` for an Entra ID account with a valid key | Key auth needs S4U, unsupported for cloud accounts | Temporary local admin from `Set-TriageAccess.ps1` |
| `Too many authentication failures` | ssh-agent offers every key first | `IdentitiesOnly yes` in the generated config |
| `The command line is too long` | `powershell -EncodedCommand` over cmd.exe is limited to 8191 characters | Copy the scripts over first and run them there |
| A `foreach` loop "cannot be piped" | `foreach` is a statement, not a pipeline command | Wrap it: `& { foreach (...) { ... } } \| ...` |
| `Could not compare ... to "[datetime]..."` | `Where-Object Prop -gt [datetime]'...'` (simplified syntax) treats the cast as a string | Use a script block: `Where-Object { $_.Prop -gt $date }` |
| Garbled text, odd parse errors on the endpoint | Windows PowerShell 5.1 reads BOM-less files as ANSI | Scripts are ASCII-only; the tests enforce it |
| `connection_trace.txt` reads as spaced-out letters | It is UTF-16 | `ConvertFrom-TriageAnyDeskConnectionTrace` detects the encoding |
| OpenSSH Server took many minutes to install | The Windows optional feature downloads from Windows Update | `Set-TriageAccess.ps1` tries the GitHub release of Win32-OpenSSH first, then WinRM, and only then the Windows feature |
| WinRM certificate login fails under TLS 1.3 | Windows asks for the client certificate after the handshake, which Python's TLS client does not support under TLS 1.3 | `winrm_client.py` caps TLS at 1.2 |
| Two endpoints behind the same tunnel port trigger a host-key warning | Both appear as `127.0.0.1:2222` | `triage.sh` uses a fresh known_hosts per run and records the key in `run-info.txt` |

## Tests

`scripts/test.sh` runs everything in the `m365-admin` container with no endpoint. Tags: `Static`, `Unit`, `Scripts`.

- **Static:** every file parses, passes PSScriptAnalyzer including `PSUseCompatibleSyntax` for 5.1, is ASCII-only and avoids 7-only parameters. Checks and `TriageCommon.ps1` call nothing that changes the endpoint and never touch browser credential stores. Every check has help, follows the naming convention, is run by the runner and is listed in this README. Setup scripts support `-WhatIf` and confirm. Only documentation, private or loopback IPs appear in the folder.
- **Unit:** AnyDesk trace, config and connection-trace parsing (sessions, IPs, elevation, privacy windows, file events, unattended password), check 03 end to end on a folder of files, the Prefetch parser.
- **Scripts:** `triage.sh` syntax, argument validation and port detection; `setup-command.sh` prints one pinned line matching the command documented in `Set-TriageAccess.ps1`, with no key material by default (`-GitHubUser`), a local key quoted correctly with `-i`, WinRM only with a valid Gist ID, and refuses a private key; `new-winrm-cert.sh` refuses to write inside a git repository and makes a client-authentication, CA:FALSE certificate with the right UPN and a private key only you can read. `test.sh` also syntax-checks `winrm_client.py` on the host (the container has no Python).

The Windows-only parts (event logs, registry, WMI, compressed Prefetch, and everything
`Set-TriageAccess.ps1` does) can only be exercised on a Windows machine: run them on a test PC after
changing them, including `Set-TriageAccess.ps1` with each of `-WinRM` and `-Ssh` followed by `-Remove`.
