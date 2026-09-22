# Business email compromise (BEC) recovery: Microsoft 365

A repeatable runbook and tooling for responding to a compromised Microsoft 365 mailbox, built on the `m365-admin` container in this repo. It works for any tenant: everything client-specific lives in a case folder outside the repo.

## Quick start

```bash
# 1. Open a case (creates .scratch_area/bec-cases/<date>-<client>-<user>/)
business-email-compromise/scripts/new-case.sh contoso jane@contoso.com 203.0.113.

# 2. Containment: Graph session
business-email-compromise/scripts/bec-shell.sh graph .scratch_area/bec-cases/<case>
#    Connect-BecGraph; Invoke-BecContainment; Get-BecIdentityReview

# 3. Mailbox work: Exchange session (a second terminal is fine)
business-email-compromise/scripts/bec-shell.sh exo .scratch_area/bec-cases/<case>
#    Connect-BecExchange; Save-BecMailboxSnapshot; Set-BecRetention ...
```

Every session prints the available commands (`Show-BecHelp`) and the case details (`Show-BecCase`).

**Every step asks before it runs.** Each script and each `*-Bec*` step command first explains what it is about to do, whether it changes the tenant or only reads, and which case files it writes. It then asks `Proceed? [y/N]`. Anything other than `y` skips the step. Each answer is recorded in the case's `actions.log`.

## Procedures, in priority order

| # | Procedure | Session | Key commands |
|---|---|---|---|
| 01 | [Intake and triage](procedures/01-intake.md): interview the user about the email they interacted with | host | `new-case.sh` |
| 02 | [Contain the identity](procedures/02-contain.md): block sign-in, revoke sessions, reset password, remove attacker MFA, devices and apps | graph | `Invoke-BecContainment`, `Get-BecIdentityReview`, `Enable-BecSignIn` |
| 03 | [Preserve evidence](procedures/03-preserve.md): snapshot the mailbox, extend retention | exo | `Save-BecMailboxSnapshot`, `Set-BecRetention` |
| 04 | [Remove mailbox persistence](procedures/04-mailbox-persistence.md): rules, forwarding, delegates, devices | exo | `Get-BecInboxRuleReport`, `Remove-BecInboxRule`, `Get-BecMailboxAccess` |
| 05 | [Investigate access](procedures/05-investigate.md): attacker IPs, timeline, initial access, the lure | exo + graph | `Get-BecAuditLog`, `Get-BecUnknownIpActivity`, `Get-BecSignIns`, `Find-BecLureMessage` |
| 06 | [Outbound impact](procedures/06-outbound-impact.md): what was sent and to whom | exo | `Get-BecSentTrace`, `Get-BecSubjectSummary`, `New-BecRecipientList` |
| 07 | [Notify recipients](procedures/07-notify.md): warning email in BCC batches, phone calls | exo | `Get-BecSendingStatus` |
| 08 | [Recover mail](procedures/08-recover-mail.md): hidden and deleted mail | exo | `Get-BecDeletedItems`, `Restore-BecDeletedItems` |
| 09 | [Tenant sweep](procedures/09-tenant-sweep.md): check every other mailbox | exo | `Invoke-BecTenantSweep` |
| 10 | [Harden](procedures/10-harden.md): stop it happening again | portal | n/a |
| 11 | [Report](procedures/11-report.md): executive and technical, plain text for Outlook | n/a | templates |

If the mailbox is still sending phishing when you are called, do 02 immediately and the intake while it runs.

After connecting in either session, run `Test-BecCommandSurface`. It is read-only and checks that every cmdlet and parameter the helpers use exists in that tenant's module version, before you rely on them.

## Testing

```bash
business-email-compromise/scripts/test.sh            # everything (static, unit, scripts); no tenant needed
business-email-compromise/scripts/test.sh Static     # or Unit, or Scripts
```

These tests cover syntax, linting, the cmdlet and parameter names, the rule that every step asks first and that every tenant change sits behind that prompt, and the behaviour of each helper against mocked Exchange and Graph cmdlets. [AGENTS.md](AGENTS.md#testing) lists what each layer proves. A first run without Pester in the image downloads it once into `.scratch_area/ps-test-modules/`.

## Layout

```
business-email-compromise/
├── AGENTS.md            Guidance for AI agents and new team members working on this folder
├── README.md            This file
├── procedures/          One markdown runbook per step (01-11)
├── ps/
│   ├── BecCommon.ps1    Case folder, case.json, logging and IP helpers (loaded by both sessions)
│   ├── BecExchange.ps1  Exchange Online functions (steps 03-09)
│   └── BecGraph.ps1     Microsoft Graph functions (steps 02, 05)
├── scripts/
│   ├── new-case.sh      Create a case folder
│   ├── bec-shell.sh     Start an exo or graph session with the case mounted at /case
│   └── test.sh          Run the test suite (no tenant needed)
├── templates/           Intake questionnaire, recipient warning, report templates
└── tests/               Pester tests: static analysis, unit tests with mocked cmdlets, script tests
```

## Case folder

```
.scratch_area/bec-cases/20250101-contoso-jane/
├── case.json            upn, known-good IP prefixes, attacker IPs, phishing subjects, key times
├── intake.md            Answers from the user interview
├── actions.log          Every change made to the tenant, with UTC times (written by the helpers)
├── evidence/            Snapshots, audit/sign-in exports, message traces, identity review
├── notification/        affected_recipients.txt, bcc_batch_N.txt, priority/internal recipients
├── report/              Report drafts
└── tenant_sweep-*/      Sweep results
```

The case folder is mounted into the container, so files are written straight to the host. Cases live in `.scratch_area/bec-cases/` at the repo root. The root `.gitignore` excludes all of `.scratch_area/`, because case folders hold client evidence and personal data. `BEC_CASES_DIR` changes the location.

## Requirements

- The `m365-admin-pwsh:local` image (`docker compose build` in the repo root; `bec-shell.sh` builds it if it is missing)
- An admin account in the client tenant with Exchange Administrator, plus User Administrator or Privileged Authentication Administrator to reset passwords and MFA
- Entra ID P1 or P2 to read sign-in logs through Graph (otherwise use the portal)
- The `Mailbox Import Export` role for mail recovery (step 08 explains how to assign it)
