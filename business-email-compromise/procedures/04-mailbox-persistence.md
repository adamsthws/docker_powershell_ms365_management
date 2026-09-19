# 04 Remove mailbox persistence

**Goal:** find and remove everything the attacker set up inside the mailbox: rules, forwarding, delegates, mobile devices.

Exchange session. Take the snapshot in [03](03-preserve.md) first.

## 1. Inbox rules

```powershell
Get-BecInboxRuleReport | Format-List
```

The `Findings` column flags the patterns attackers use:

| Finding | Typical attacker rule |
|---|---|
| symbol-only name | Rules named `.`, `..`, `....`, `,` |
| matches all mail + marks read and moves | Hides everything so the user sees no replies or bounces |
| moves to RSS / Conversation History / Archive / Deleted | Folders users never open |
| keyword filter | Hides mail mentioning invoice, payment, bank, or a specific service the attacker is abusing |
| forwards or redirects | Exfiltration to an outside address |
| deletes | Destroys evidence |

A rule from a single sender with a normal-looking name can still be the attacker's: it is often hiding a supplier or customer they are running payment fraud with. Check attribution in the audit log ([05](05-investigate.md): `New-InboxRule` / `UpdateInboxRules` from attacker IPs) before you decide.

Remove the attacker's rules:

```powershell
Remove-BecInboxRule -RuleIdentity <RuleIdentity>, <RuleIdentity>
Get-BecInboxRuleReport          # confirm
```

## 2. Forwarding, delegates, devices, transport rules

```powershell
Get-BecMailboxAccess
```

| Check | Attacker sign | Fix |
|---|---|---|
| `ForwardingSmtpAddress` / `ForwardingAddress` | Any external address | `Set-Mailbox <upn> -ForwardingSmtpAddress $null -ForwardingAddress $null` |
| Mailbox permissions / Send As | A user or account nobody recognises | `Remove-MailboxPermission` / `Remove-RecipientPermission` |
| Mobile devices | A device with `FirstSyncTime` in the compromise window | `Remove-MobileDevice` |
| Transport rules | New rules redirecting or BCC'ing mail | `Remove-TransportRule` |

Log anything you change by hand:

```powershell
Write-BecLog 'Removed external forwarding to x@example.com from user@tenant.com'
```

## Done when

- [ ] All attacker rules removed and the report shows only legitimate rules
- [ ] No unknown forwarding, permissions, mobile devices or transport rules
