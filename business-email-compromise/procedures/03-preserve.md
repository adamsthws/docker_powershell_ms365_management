# 03 Preserve evidence

**Goal:** capture the mailbox's state and stop deleted mail from expiring, before you change anything in the mailbox.

Run in an **Exchange** session:

```bash
business-email-compromise/scripts/bec-shell.sh exo <case-dir>
```
```powershell
Connect-BecExchange
```

## 1. Snapshot the mailbox

```powershell
Save-BecMailboxSnapshot
```

Saves to `evidence/snapshot-<timestamp>/`:

- `inbox_rules.txt` / `.xml`: every rule, including hidden system rules (`-IncludeHidden`)
- `mailbox.txt`: all mailbox properties, including forwarding and retention
- `mailbox_permissions.txt`, `recipient_permissions.txt`: Full Access and Send As
- `folder_statistics.csv`: item counts and newest/oldest dates per folder (shows emptied or overflowing folders)
- `mobile_devices.txt`: ActiveSync/Outlook mobile partnerships
- `transport_rules.txt`: tenant-wide mail flow rules

`Remove-BecInboxRule` refuses to run until a snapshot exists.

## 2. Stop deleted mail expiring

Attackers hard-delete replies, bounces and sent copies. These sit in Recoverable Items for **14 days by default**, then are gone.

```powershell
Set-BecRetention -Days 30                   # maximum
Set-BecRetention -Days 30 -LitigationHold   # if licensed (Exchange Online Plan 2, Business Premium, E3/E5)
```

## 3. Read the folder statistics

Open `folder_statistics.csv` and look for:

- **RSS Feeds, Conversation History, Archive** with recent items, or emptied while the inbox is quiet: the usual hiding places.
- **Recoverable Items / Purges** with items dated in the compromise window: hard deletion, often starting seconds after a phishing send.
- **Deletions** with recent items: soft deletion.

## Done when

- [ ] Snapshot saved
- [ ] Retention set to 30 days (and a hold, if licensed)
