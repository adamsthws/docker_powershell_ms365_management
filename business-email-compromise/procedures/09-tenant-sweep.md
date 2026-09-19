# 09 Check the rest of the tenant

**Goal:** confirm no other account is compromised. Attackers move sideways by phishing colleagues from the first account.

Exchange session, with `attackerIps` already in `case.json`:

```powershell
Invoke-BecTenantSweep -Days 10
```

Results go to `tenant_sweep-<timestamp>/`.

| Check | Clean result | Investigate if |
|---|---|---|
| 1. Attacker IPs across the tenant (90 days) | Only the compromised mailbox | Any other user appears: treat them as compromised and start a case |
| 2. Restricted senders | Empty | Any account is blocked for spam |
| 3. Send volume per mailbox | Normal counts, everyday subjects, the office's own IPs | A spike, one subject repeated hundreds of times, or an unknown sending IP |
| 4. Suspicious inbox rules | Only the rules already removed | Any rule flagged on another mailbox |
| 5. Mailbox forwarding | None | Any external forwarding |

Then by hand:

- **Staff who received the phishing email** (`notification/internal_recipients.txt`): ask each whether they clicked it, and check their sign-ins for the attacker IPs or device-code logins (`Get-BecSignIns -Upn <them>` in a Graph session).
- **The lure sender**, if they are a real supplier or customer: tell them by phone that their account is probably compromised.
- **Admin accounts with Full Access** to the compromised mailbox: check their sign-ins too.

IPv6 addresses from one office share a /64 prefix and rotate their endings. An unfamiliar ending under the office prefix is normal.

## Done when

- [ ] Sweep run and every finding explained
- [ ] Internal recipients of the phishing email checked
