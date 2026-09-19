# 11 Report

**Goal:** two reports, both plain text so they paste cleanly into Outlook on the web.

| Report | Reader | Template | Times |
|---|---|---|---|
| Executive summary | Client owner or management | [templates/executive-report.txt](../templates/executive-report.txt) | Local time, say which |
| Technical report | Our records, the client's IT contact, insurers | [templates/technical-report.txt](../templates/technical-report.txt) | UTC, with the local offset stated |

Save drafts in the case's `report/` folder.

## Where each section comes from

| Section | Source in the case folder |
|---|---|
| Summary, scope | `case.json`, `intake.md` |
| Indicators of compromise | `case.json` (attackerIps, phishingSubjects), `evidence/snapshot-*/inbox_rules.txt`, `Find-BecLureMessage` output |
| Timeline | `evidence/audit-*.csv` (rule creation, sends, deletes, failed logins), `evidence/signins-*.csv`, `evidence/sent_trace.csv` (first and last phishing send per IP), `actions.log` (our actions) |
| Malicious rules | `evidence/snapshot-*/inbox_rules.txt` plus audit attribution |
| Outbound analysis | `Get-BecSubjectSummary`, `notification/*` counts |
| Containment | `actions.log`, `evidence/identity-*/` |
| Tenant sweep | `tenant_sweep-*/` |
| Notification | `notification/` file counts, the message sent, `actions.log` |
| Mail recovery | `evidence/deleted_since_compromise.csv`, `actions.log` |
| Open items | Anything from procedures 02-10 not done, and the hardening the client has not yet agreed |

## Writing rules

- Executive summary: no IPs, no cmdlets, no jargon. Lead with what happened and that it is contained. Impact, a short timeline, how we responded, then what is left to do.
- Technical report: exact UTC times, IPs, rule identities, counts, and the commands used. State unconfirmed things as unconfirmed, with the evidence for each possibility.
- Mark nothing as done that the case files do not show as done.
- Plain text only: no tables, bold or checkboxes. Use `-` for lists and `1.` for steps, and indent commands by four spaces.

## Close the case

- [ ] Both reports sent
- [ ] Case folder archived: zip `.scratch_area/bec-cases/<case>/`, store it per the client's retention requirements, then delete it from `.scratch_area/`. It holds personal data, so never commit it to this repo.
- [ ] `Mailbox Import Export` role removed from the admin account if it was only added for this case:
  `Get-ManagementRoleAssignment -Role 'Mailbox Import Export' -RoleAssignee <admin> | Remove-ManagementRoleAssignment`
