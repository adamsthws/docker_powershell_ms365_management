# 08 Recover hidden and deleted mail

**Goal:** give the user back the mail the attacker hid or deleted.

## 1. Mail that was moved, not deleted

Hiding rules move mail to RSS Feeds, Conversation History, Archive and similar folders. Check `folder_statistics.csv` from [03](03-preserve.md) for counts.

The quickest fix is Outlook on the web, as an admin with Full Access (or as the user):

1. **Open another mailbox** → the user's mailbox.
2. Open each hiding folder. Select everything received since the compromise started, then **Move to Inbox**.
3. Optionally mark it unread. The rules marked it read, so the user has never seen it.

Leave older items in Archive alone, as they were archived on purpose.

## 2. Mail that was deleted

This needs the **Mailbox Import Export** role, which no one has by default, not even Global Admins. Without it, `Get-RecoverableItems` is reported as "not recognized".

```powershell
New-ManagementRoleAssignment -Role 'Mailbox Import Export' -User <admin upn>
# wait 15-60 minutes
Disconnect-ExchangeOnline -Confirm:$false; Connect-BecExchange
```

Then list what was deleted since the compromise:

```powershell
$deleted = Get-BecDeletedItems -Since '2025-01-06T08:00:00'
```

This saves to `evidence/deleted_since_compromise.csv`, grouped by source and original folder:

- `LastParentPath` of RSS Feeds or another hiding folder: mail the rule hid that the attacker then deleted. Restore it.
- `LastParentPath` of Sent Items: copies of the phishing email. No need to restore.
- Deleted Items in the window: may be the user's own deletions. Ask before restoring.

Use the audit log ([05](05-investigate.md)) to tell attacker deletions from user deletions by IP.

Restore:

```powershell
Restore-BecDeletedItems -Since '2025-01-06T08:00:00'                     # RecoverableItems + PurgedItems
Restore-BecDeletedItems -Since '2025-01-06T08:00:00' -SubjectContains 'Invoice'
```

Items go back to the folder they were deleted from, which is often RSS Feeds. Then move them to the Inbox as in step 1.

If `-SourceFolder PurgedItems` is rejected, the ExchangeOnlineManagement module is too old: rebuild the image (`docker compose build --no-cache`). Alternatively, use a Purview Content Search export.

Warn the user that recovered mail includes replies to the phishing email and bounces, some with links. They shouldn't click anything in them.

## Done when

- [ ] Hidden mail moved back to the Inbox
- [ ] Attacker-deleted mail restored (or recorded as unrecoverable)
