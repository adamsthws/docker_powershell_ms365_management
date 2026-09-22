# AGENTS.md: business email compromise recovery

Guidance for AI coding agents (and people) working in this folder, either extending the tooling or helping an operator run a live BEC case.

## What this is

A runbook plus PowerShell helpers for recovering a compromised Microsoft 365 mailbox. It is tenant-generic: nothing client-specific belongs in the repo. The operator works in the `m365-admin` Docker container from the repo root, and every case has its own folder in `.scratch_area/bec-cases/` at the repo root (gitignored), mounted into the container at `/case`.

Start with [README.md](README.md) for the layout and the procedure order, then the numbered files in [procedures/](procedures/).

## Running a case

1. `scripts/new-case.sh <client> <upn> [known-good-ip-prefix ...]` creates the case folder and `case.json`.
2. `scripts/bec-shell.sh graph <case-dir>`: Graph session (`BecGraph.ps1`) for containment, identity review and sign-in logs.
3. `scripts/bec-shell.sh exo <case-dir>`: Exchange session (`BecExchange.ps1`) for everything mailbox-related.
4. Work through procedures 01-11 in order. If the mailbox is actively sending, contain (02) before intake.

When helping an operator mid-case, an agent usually sees pasted PowerShell output rather than running commands itself. Read the output against the "look for" tables in the procedure for that step and say what is attacker activity and what is normal.

## Rules

- **Every step is gated.** Each step command calls `Confirm-BecStep` first. It describes the step, lists any tenant changes and the files it writes, asks `Proceed? [y/N]`, and logs the answer to `actions.log`. The shell scripts do the same. Keep this for every new step. `-Force` skips the prompt and is only for calls made from inside another gated step (for example `Invoke-BecTenantSweep` calling `Get-BecAuditLog -Force`). Never pass `-Force` on the operator's behalf. Pure local analysis of data already retrieved (`Get-BecSubjectSummary`, `Get-BecUnknownIpActivity`, `Import-BecSentTrace`, case.json helpers) is not gated.
- **Preserve before you remove.** `Save-BecMailboxSnapshot` and `Set-BecRetention` (03) come before rule removal (04) or anything that changes the mailbox. `Remove-BecInboxRule` refuses to run without a snapshot. Keep that guard.
- **Revoking sessions is not optional.** A password reset alone leaves refresh tokens valid. MFA methods, registered devices and OAuth consents survive both. Check them every time.
- **Case data stays out of git.** Case folders contain client personal data and evidence. They live in `.scratch_area/`, which the root `.gitignore` excludes; do not weaken that or move cases anywhere tracked. Archive closed cases elsewhere and delete them from `.scratch_area/`.
- **Keep everything tenant-generic.** Use placeholder values in docs and examples: `contoso.com`, `user@contoso.com`, IPs from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32. Never real client names, addresses, IPs or rule IDs.
- **Times:** audit logs, message trace and sign-in logs are UTC, and the container runs with `TZ=UTC`. Users give local time. Write the timezone next to every time in notes and reports.
- **Do not claim a step was done** in a report unless `actions.log` or the case files show it.

## Pitfalls already hit (keep the workarounds)

| Problem | Cause | Workaround in this folder |
|---|---|---|
| `Connect-MgGraph`: `Method not found ... WithLogging` | Exchange Online and Graph load conflicting MSAL versions in one pwsh process | Separate `exo` and `graph` containers via `bec-shell.sh` |
| `Get-RecoverableItems` "not recognized" | Needs the `Mailbox Import Export` role, which no one has by default | `Assert-BecRecoverableItemsCmdlets` prints the fix; procedure 08 |
| Audit search returns 5000 rows and misses older events | `MailItemsAccessed` floods the result; 5000-row page limit | Default operation list excludes it; `ReturnLargeSet` paging in `Get-BecAuditLog` |
| Message trace silently truncated | `Get-MessageTraceV2`: 5000 rows per query, 10-day window, 90 days of history | `Invoke-BecMessageTrace` queries a day at a time and splits windows that hit the cap |
| Audit `ClientIP` doesn't match sign-in IPs | Audit IPs carry a port (`192.0.2.10:56353`) | `ConvertTo-BecIp` strips it |
| Files in the case folder owned by root | Container runs as root by default | `bec-shell.sh` runs as the host UID/GID with `HOME=/tmp` |
| Deleted mail gone before recovery | Recoverable Items keeps 14 days by default | `Set-BecRetention -Days 30` in step 03 |
| BCC send rejected | Exchange Online allows 500 recipients per message | `New-BecRecipientList` batches at 450 |
| Reports garbled when pasted into Outlook on the web | Markdown and tables don't survive | Plain-text templates in `templates/` |
| Browser sign-in can't open inside the container | No browser in the image | The repo's `xdg-open` stub prints the URL; `-Device` / `-UseDeviceCode` as a fallback where device code isn't blocked |

## Attacker patterns to recognise

- Inbox rules with symbol-only names (`.`, `....`) that move all mail to **RSS Feeds**, **Conversation History** or **Archive**, mark it read and stop processing.
- A rule with a normal name hiding one supplier or customer: the likely target of payment fraud. Phone that contact.
- Keyword rules hiding notifications from a service the attacker is abusing with the account.
- A burst of hundreds of sends with one subject (a fake "shared document" or "sign your contract" lure) from a hosting or VPN IP, followed seconds later by hard deletion of the sent copies.
- `Re:` replies from the attacker IP to recipients who asked "is this genuine?". Those recipients are the highest priority to phone.
- First attacker action about a minute after the user was active from their normal IP: AiTM or device-code phishing at that moment. Sign-in logs (`AuthProtocol`, non-interactive sign-ins) tell them apart.
- A `UserLoginFailed` from an attacker IP just after containment: the lock-out working.

## Extending the tooling

- Put new functions in `ps/BecExchange.ps1` or `ps/BecGraph.ps1` by service, and shared helpers in `ps/BecCommon.ps1`. Never load Exchange and Graph cmdlets in the same file.
- Naming: `Verb-Bec<Noun>` with approved PowerShell verbs. Default `-Upn` from `case.json` via `Resolve-BecUpn`.
- Write output files with `Get-BecPath` (relative to the case folder) and record tenant changes with `Write-BecLog`.
- Start every step function with `if (-not (Confirm-BecStep -Force:$Force -Step '<NN name>' -Description '...' [-Changes ...] [-Writes ...])) { return }` and give it a `[switch]$Force` parameter. Put tenant changes in `-Changes` so they show in red.
- Anything that changes the tenant also gets `[CmdletBinding(SupportsShouldProcess)]` so `-WhatIf` works. Leave `ConfirmImpact` at its default so the admin isn't asked twice.
- Add the function to that file's `Show-BecHelp`, and document it in the matching procedure and the README table.
- A new Exchange or Graph cmdlet needs a stub in `tests/Stubs.ps1`, declaring every parameter you pass. A new Exchange cmdlet also goes in `$BecExchangeCmdlets` in `tests/TestTools.ps1`. The static tests fail until both are done.
- Add unit tests for new behaviour (mock the stubbed cmdlets and `Read-Host`): at minimum, "does nothing when declined" and "does X when approved".
- Run `scripts/test.sh` before committing. It must pass.

## Testing

`scripts/test.sh` runs everything in the container with no tenant and no sign-in. Pass tags to run a subset: `scripts/test.sh Static`, `scripts/test.sh Unit`, `scripts/test.sh Scripts`.

| Layer | File | What it proves |
|---|---|---|
| Static | `tests/Static.Tests.ps1` | Every file parses and passes PSScriptAnalyzer (`tests/PSScriptAnalyzerSettings.psd1`). Every command resolves: Graph cmdlets and parameters are checked against the installed modules; Exchange cmdlets must be in the known list (catches typos). Exchange and Graph never mix in one file. Stubs cover every cmdlet and parameter. **Gating:** every function that calls the tenant is gated or only called from gated steps; every gate is `if (-not (Confirm-BecStep -Force:$Force ...)) { return }`; every tenant change comes after the prompt, is listed in `-Changes`, and supports `-WhatIf`; steps call steps with `-Force`; every step is in `Show-BecHelp` and a procedure. **Docs:** every command and script named exists, no `-Force` advice, documentation IP ranges only. |
| Unit | `tests/Common.Tests.ps1`, `Exchange.Tests.ps1`, `Graph.Tests.ps1` | Behaviour with mocked cmdlets: prompt answers, declined steps change nothing, approved steps call the right cmdlet with the right arguments, `-WhatIf`, audit paging past 5000, message trace window splitting, recipient de-duplication and batching, rule detection, tenant sweep asks once. |
| Scripts | `tests/Scripts.Tests.ps1` | `bash -n`, plus `new-case.sh` and `bec-shell.sh` run for real against a temp folder (usage, decline, create, refuse overwrite). |
| Live, read-only | `Test-BecCommandSurface` | In a connected session: every cmdlet and named parameter the helpers use exists in that tenant's module version. Exchange cmdlets only exist after connecting, so this is the only check for Exchange parameter names. Splatted parameters are not checked. |

Exchange cmdlets can't be resolved offline. Their parameter names are covered only by the stubs, which we write ourselves, and by `Test-BecCommandSurface` against a real tenant. When Microsoft changes an Exchange cmdlet, the offline suite won't notice; run `Test-BecCommandSurface` after rebuilding the image.
