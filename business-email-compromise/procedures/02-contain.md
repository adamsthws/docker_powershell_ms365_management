# 02 Contain the identity

**Goal:** cut off every way the attacker can use the account, as fast as possible.

Run this in a **Graph** session:

```bash
business-email-compromise/scripts/bec-shell.sh graph <case-dir>
```
```powershell
Connect-BecGraph            # add -Device only if browser sign-in fails and device code is allowed
```

## 1. Block sign-in and revoke sessions

```powershell
Invoke-BecContainment
```

This does two things and logs both to `actions.log`:

1. **Blocks sign-in** (`AccountEnabled = false`), so no new sign-ins succeed while you work.
2. **Revokes all sign-in sessions.** This invalidates every refresh token and session cookie, however it was obtained (browser, mobile app, device code, AiTM token replay), plus PRTs on any device the attacker registered.

Access tokens the attacker already holds can work for up to about an hour. Exchange Online supports Continuous Access Evaluation, so mailbox access usually stops within minutes.

## 2. Reset the password

In the Entra admin centre: **Users → the user → Reset password**. Give the new password to the user by phone, not email. Note the time; it goes in `case.json` as `containedUtc`.

A password reset on its own does **not** end existing sessions. Always revoke as well.

## 3. Review what the attacker may have added

```powershell
Get-BecIdentityReview
```

Saves to `evidence/identity-<timestamp>/` and shows:

| Item | What to look for | Remove in |
|---|---|---|
| Authentication methods | Phone numbers or authenticator apps the user does not recognise; `CreatedUtc` in the compromise window | Entra: user → Authentication methods |
| Devices | Registrations during the compromise window (device-code phishing often registers one) | Entra: Devices → delete |
| OAuth consents | Apps the user did not knowingly consent to, especially with `Mail.*`, `offline_access` | Entra: Enterprise apps → the app → Permissions, or delete the service principal |
| App assignments | Unfamiliar enterprise apps | Entra: Enterprise apps |

Revoking sessions does **not** remove any of these. A malicious OAuth app keeps working after a password reset.

## 4. Re-enable sign-in

When the password is reset and nothing unfamiliar remains:

```powershell
Enable-BecSignIn
```

Then have the user sign in, confirm MFA works, and sign out of Outlook on every device so cached sessions use the new password.

## If Graph will not connect

- `Method not found ... WithLogging`: Exchange Online was loaded in the same pwsh session. Use a separate `bec-shell.sh graph` container.
- No tooling at all: do it in the portal. **Entra admin centre → Users → user → Block sign-in, Revoke sessions, Reset password, Authentication methods, Devices, Applications.**

## Done when

- [ ] Sign-in blocked, sessions revoked, password reset (time recorded as `containedUtc`)
- [ ] MFA methods, devices, OAuth consents and app assignments reviewed and cleaned
- [ ] Sign-in re-enabled and the user signed in with the new password
