# 06 Outbound impact and recipient list

**Goal:** find everything the attacker sent and build the list of people to warn.

Exchange session.

## 1. Trace everything sent since the compromise started

```powershell
$trace = Get-BecSentTrace -Start '2025-01-06'
```

This queries a day at a time and splits any window that hits the 5000-row cap, so nothing is silently dropped. Results go to `evidence/sent_trace.csv`. Message trace only covers the last 90 days. To reload the trace in a later session, run `$trace = Import-BecSentTrace`.

## 2. Identify the phishing subjects

```powershell
Get-BecSubjectSummary $trace | Format-Table -AutoSize -Wrap
```

Phishing stands out as one or two subjects with hundreds of messages, and `UnknownIPs` showing attacker addresses. Also look for:

- `Re:` / `RE:` versions of the phishing subject sent **from an attacker IP**. The attacker was replying to recipients who asked "is this genuine?", and those recipients are the most likely to have clicked.
- `RE:` versions sent from the **user's** IP. These are the user's own replies, often to the lure itself, and are useful for the timeline.

## 3. Build the recipient list

```powershell
New-BecRecipientList $trace -Subject 'PHISHING SUBJECT 1', 'Phishing subject 2', 'Re: PHISHING SUBJECT 1'
```

This writes to `notification/`:

| File | Contents |
|---|---|
| `affected_recipients.txt` | Unique recipients, one per line, lower-cased, Failed deliveries excluded |
| `bcc_batch_N.txt` | Semicolon-separated batches of 450, ready to paste into Outlook BCC (Exchange Online allows 500 recipients per message) |
| `priority_recipients.csv` | Recipients of `RE:`/`FW:` messages in the phishing thread: **phone these** |
| `internal_recipients.txt` | Staff who received the phishing email: check them in [09](09-tenant-sweep.md) |

It also saves the subjects to `case.json`. If you can't tell phishing from genuine mail, use `-AllRecipients` instead. Over-warning does no harm.

## Done when

- [ ] `sent_trace.csv` saved
- [ ] Phishing subjects identified and recorded
- [ ] Recipient files built; priority and internal recipients reviewed
