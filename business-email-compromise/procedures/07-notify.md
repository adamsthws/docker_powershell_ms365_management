# 07 Notify recipients

**Goal:** warn everyone who received the phishing email, without looking like a second phishing email.

## 1. Check the mailbox can send

```powershell
Get-BecSendingStatus
```

After a bulk send, Microsoft often adds the account to the restricted senders list. Unblock it with `Remove-BlockedSenderAddress -SenderAddress <upn>`, or send the warning from another mailbox in the same organisation.

## 2. Write the message

Start from [templates/recipient-warning.txt](../templates/recipient-warning.txt). Rules:

- **The first sentence is the warning:** do not open, do not click, delete. Name the exact phishing subjects and the date range.
- Say briefly what happened and that it is resolved.
- Say what to do if they already clicked (change password, tell their IT).
- **No links, no attachments, no signature banner with links.** Recipients have just been phished and should be suspicious of anything clickable.
- Give a phone number to verify, and ask them to call rather than reply.

## 3. Send

1. Put the mailbox's own address in **To**.
2. Paste `notification/bcc_batch_1.txt` into **BCC**, then send.
3. Repeat for each batch, a few minutes apart. A sudden burst right after a compromise can get the account restricted again.
4. Log it:
   ```powershell
   Write-BecLog 'Warning email sent to batches 1-2 (N recipients)'
   ```

## 4. Phone calls

Call these contacts rather than relying on the email:

- Everyone in `priority_recipients.csv`. The attacker replied to them, so they probably engaged.
- Any supplier or customer whose mail an inbox rule was hiding.
- Anyone with a payment or bank-detail conversation in progress (from the intake). Confirm no change of bank details was requested from our side.

## Done when

- [ ] Every batch sent and logged
- [ ] Priority contacts and targeted suppliers or customers phoned
