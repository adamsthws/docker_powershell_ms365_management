# 01 Intake and triage

**Goal:** open a case, find out what the user interacted with, and decide how urgent containment is.

## 1. Triage first (2 minutes)

Ask one question before anything else: **is the mailbox sending mail or behaving oddly right now?**

- Contacts reporting strange emails from the user today, bounce-backs arriving, or the account locked by Microsoft for spam: go straight to [02 Contain](02-contain.md) and do this intake while it runs.
- Otherwise, spend 10 minutes on intake first. The answers make every later trace faster.

## 2. Open the case

```bash
business-email-compromise/scripts/new-case.sh <client-slug> <user@tenant.com> [known-good-ip-prefix ...]
```

After you confirm, this creates `.scratch_area/bec-cases/<yyyymmdd>-<client>-<user>/` in the repo (gitignored) with `case.json`, `intake.md`, `actions.log` and folders for evidence, notification and report. Known-good prefixes are the office and home broadband ranges (for example `2001:db8:1234:5678:` or `203.0.113.`). You can add them later in `case.json`.

## 3. Interview the user

Work through `intake.md` (copied from [templates/intake-questionnaire.md](../templates/intake-questionnaire.md)) on the phone. The answers that drive the investigation are:

| Answer | Used in |
|---|---|
| Date, time, sender and subject of the email they interacted with | `Find-BecLureMessage` in [05](05-investigate.md), to find the lure in the message trace |
| Whether they entered a password, approved MFA, or typed a code on a devicelogin page | Tells you AiTM phishing (password + MFA proxied) vs device-code phishing; see [05](05-investigate.md) |
| When they did it | Start of the sign-in log and audit window |
| Their normal locations (office, home, mobile network) | `knownGoodIpPrefixes` in `case.json`, used to separate their activity from the attacker's |
| Payment or bank-detail conversations in progress | Contacts to phone in [07](07-notify.md); the attacker often targets these |
| Password reuse | Other accounts the user must change |

Write times with a timezone. Users usually give local time; audit logs and message trace are UTC.

## 4. Record what you know

```powershell
Set-BecCaseValue compromiseStartUtc '2025-01-06T08:00:00Z'   # best estimate; refine in 05
Add-BecCaseValue knownGoodIpPrefixes '2001:db8:1234:5678:'
```

## Done when

- [ ] Case folder created and `intake.md` filled in
- [ ] Known-good IP prefixes recorded (or noted as unknown)
- [ ] Containment started (next step)
