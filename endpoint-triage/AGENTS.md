# AGENTS.md: endpoint triage

Guidance for AI agents (and people) extending these scripts or helping an operator triage a Windows endpoint.
Read [README.md](README.md) first.

## Rules

- **Read-only during a live triage unless the operator says otherwise.** Run only the checks. Anything that changes the endpoint (installing, deleting, disabling, creating accounts, changing settings) needs the operator's explicit approval for that one change.
- **Checks never change the endpoint.** A check may read files, the registry, event logs, WMI and network state. It may not write, delete, start or stop anything. `tests/Static.Tests.ps1` enforces this with a list of state-changing commands; extend the list rather than the exceptions.
- **Never collect credentials.** Do not read or copy browser `Login Data`, `Cookies`, `Local State`, `Web Data`, Firefox `key4.db` / `logins.json`, Credential Manager vaults or DPAPI keys. Browser `History` only with the operator's approval, as a file copy, never by opening it in place.
- **Windows PowerShell 5.1 and ASCII.** The checks run on a stock Windows. No PowerShell 7-only syntax or parameters (`??`, ternary, `-Parallel`, `-AsHashtable`, three-argument `Join-Path`). No characters above 127, including in comments.
- **Case data stays out of git.** Results go to `.scratch_area/endpoint-cases/` (gitignored). Use documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and made-up names in docs, tests and examples.
- **Times are local to the endpoint.** Say so, with the time zone, whenever you report one. Microsoft 365 logs are UTC.
- **Do not overclaim.** "No sign of X" is about what the logs cover: say which logs, which period and which users' hives were checked.

## Adding a check

1. `ps/checks/NN-Verb-Noun.ps1` with comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`). Put "what normal looks like" in the description.
2. Start with `if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }` and `Write-TriageElevationWarning`. The runner loads `TriageCommon.ps1` and runs each check from its text (`[scriptblock]::Create`), not as a file, so an execution policy set by Group Policy cannot stop it; there `$PSScriptRoot` is empty and the line above does nothing. Do not use `$PSScriptRoot` anywhere else in a check.
3. Print sections with `Write-TriageSection` and tables with `Format-TriageTable` / `Format-TriageList`, so empty results say `(none)`.
4. Add it to `$plan` in `ps/Invoke-EndpointTriage.ps1` and to the checks table in README.md.
5. Put parsing logic in `TriageCommon.ps1` as a function and unit-test it with synthetic data in `tests/Unit.Tests.ps1`.
6. Run `scripts/test.sh`. It must pass. Then run the check on a real Windows PC: the tests cannot reach the event log, registry or WMI.

## Interpreting results

See "Reading the results" and "What the results cannot tell you" in README.md. In short:

- `Logged in from <ip>` in an AnyDesk trace is the **remote party's** public IP. Mobile carrier addresses are shared (CGNAT): only the carrier, with IP + port + time, and the remote-access vendor, with the remote ID, can identify the person, and only for police.
- Elevated session + long privacy-mode windows = assume every signed-in website and saved password was available to the attacker.
- A passkey sign-in during the session (check 08) means the attacker had an authenticated session on that website.
