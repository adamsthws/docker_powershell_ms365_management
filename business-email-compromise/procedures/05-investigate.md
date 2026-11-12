# 05 Investigate access

**Goal:** establish when the attacker got in, from where, how, and what they did. The result is a list of attacker IPs and a timeline.

## 1. Mailbox audit log (Exchange session)

```powershell
$audit = Get-BecAuditLog -Days 90
Get-BecUnknownIpActivity $audit | Format-Table -AutoSize -Wrap
```

`Get-BecAuditLog` leaves out `MailItemsAccessed` by default. That operation produces thousands of rows and would push the useful ones past the result limit. Add it with `-Operations ($BecDefaultAuditOperations + 'MailItemsAccessed')` when you need to show what the attacker read.

Read the output like this:

- The user's own IPs appear on every working day at regular hours. Add them to `knownGoodIpPrefixes` if you have not already, then rerun `Get-BecUnknownIpActivity`.
- Blank `ClientIP` on `MailItemsAccessed` is usually background sync and is normal.
- **Attacker IPs** typically show `New-InboxRule`, a burst of `Send`, then `HardDelete`/`SoftDelete`/`MoveToDeletedItems`, often from hosting or VPN ranges.
- The first `New-InboxRule` from an unknown IP is usually the attacker's first action. If it comes about a minute after the user was active from their normal IP, the user was most likely phished at that moment.

Record the attacker IPs:

```powershell
Add-BecCaseValue attackerIps '198.51.100.23', '192.0.2.77'
Set-BecCaseValue compromiseStartUtc '2025-01-06T08:05:52Z'
```

To see who did the deleting, filter the rows: `$audit | Where-Object Operation -match 'Delete' | Format-Table DateUtc, Operation, ClientIP, KnownGood, Detail -Wrap`.

## 2. Sign-in logs (Graph session)

With Entra ID P1 or P2 (see `Get-BecTenantCapabilities` in [02](02-contain.md)):

```powershell
$signins = Get-BecSignIns -Days 30 -IncludeNonInteractive
```

**Without P1 or P2**, Graph refuses (`Authentication_RequestFromNonPremiumTenantOrB2CTenant`) and `Get-BecSignIns` prints these steps instead. The portal still shows the last **7 days**, so export them on the first day of the case:

1. Entra admin centre → **Monitoring & health → Sign-in logs**, Date: last 7 days.
2. **Download → JSON**, on both the **User sign-ins (interactive)** and **User sign-ins (non-interactive)** tabs. The download covers every user; the import keeps only the case mailbox.
3. Copy the files into the case's `evidence/` folder. The container only sees the case folder.
4. Import them:

```powershell
$signins = Import-BecSignInExport evidence/InteractiveSignIns_*.json, evidence/NonInteractiveSignIns_*.json
```

Both commands save a CSV in `evidence/` and print the same summary (`Show-BecSignInSummary $signins` reprints it):

- **Device code warning** if any sign-in used the device code flow.
- **Containment taking effect:** the first and last sign-in refused because the account was disabled (`50057`) or because an old session was revoked or the password changed (`50173`, `50133`). The first `50057` is a good source for `containedUtc`. Any **successful sign-ins after containment** are listed by IP and device: confirm they are the user with the new password.
- **Unknown networks**, grouped by network (ASN) and country rather than by IP, because home and mobile IPv6 addresses change constantly. Hosting providers (cloud ASNs) stand out; a mail app's servers (for example a parcel-tracking app with a mail consent) look the same, so match them against the consents in `Get-BecIdentityReview`.

| Pattern | Meaning |
|---|---|
| `AuthProtocol` = `deviceCode` from an unknown IP | Device-code phishing: the user typed a code on microsoft.com/devicelogin |
| Successful interactive sign-in from an unknown IP seconds after the user's own, MFA satisfied | AiTM phishing: a proxy page relayed password and MFA |
| Only non-interactive sign-ins from the unknown IP | Stolen token replay (often AiTM) |
| Many failures, then a success | Password spray or guessing |

Add any new attacker IPs to `case.json` with `Add-BecCaseValue`. The Exchange audit log in section 1 also records sign-ins (`UserLoggedIn`, `UserLoginFailed`) and keeps them longer than the free portal, so use it for anything older than the export.

## 3. Find the lure (Exchange session)

Use the intake answers:

```powershell
Find-BecLureMessage -Start '2025-01-05' -End '2025-01-07' -SenderAddress 'sender@example.com'
Find-BecLureMessage -Start '2025-01-05' -End '2025-01-07' -Subject 'sign your contract'
```

Record the sender, subject and MessageId in the technical report. Then:

- Search the tenant for the same lure: `Invoke-BecMessageTrace -Start <date> -Filter @{ SenderAddress = '<sender>' }` shows who else received it.
- If the sender is a real supplier or customer, their mailbox is probably compromised too. Phone them.
- Ask the user to report it to Microsoft (Report phishing button) or submit it in Defender → Submissions.

## Done when

- [ ] Attacker IPs in `case.json`, compromise start time set
- [ ] Initial access method identified, or recorded as unconfirmed with the evidence for each possibility
- [ ] Lure message found (or recorded as not found)
