# Intake: compromised mailbox

Fill this in with the user before (or while) you work. Times matter: write the timezone next to every time.

## Case

- Client / tenant:
- Compromised mailbox (UPN):
- User's name and best phone number:
- Who reported it, and how (user noticed, contact complained, bounce-backs, Microsoft alert):
- Reported at (date, time, timezone):
- Is the mailbox still sending mail right now? (If yes, contain first: procedures/02-contain.md)

## The email they interacted with

- Date and approximate time it arrived:
- Sender name and address as shown in Outlook:
- Subject:
- Was it from someone they know (a supplier, customer, colleague)?
- Is it still in the mailbox? Which folder? (Do not let the user forward it; we trace it ourselves.)
- What did it ask them to do (open a document, sign a contract, view an invoice, voicemail, shared file)?

## What they did

- Clicked a link? Opened an attachment? Which?
- Did a Microsoft sign-in page appear? Did they enter their password?
- Did they approve an MFA prompt, type an MFA code, or enter a code on a "microsoft.com/devicelogin" page?
- Anything odd afterwards (second sign-in prompt, page went blank, error, redirect to a real document)?
- Approximately when (date, time, timezone)?

## Since then

- Have they noticed missing mail, mail marked read they had not opened, replies they did not send?
- Have any contacts called or replied asking about an email?
- Any payment, invoice or bank-detail conversations in progress with suppliers or customers?
- Do they use the same password anywhere else (other accounts, banking, personal email)?
- Devices they use for this mailbox (work PC, phone, home PC, tablet):

## Normal locations (to tell their sign-ins from the attacker's)

- Office broadband provider / public IP (if known):
- Home broadband provider:
- Mobile network:
- Travelling recently? Where?

Add the known office/home IP prefixes to `knownGoodIpPrefixes` in case.json.

## Notes
