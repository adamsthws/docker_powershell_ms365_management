# 10 Harden

**Goal:** make the same attack harder next time. Agree these with the client. Do not apply tenant-wide policy changes without their approval.

| Control | Why | Where |
|---|---|---|
| Block device code flow with Conditional Access | Device-code phishing gets past MFA. Few businesses need the device code flow. | Entra → Conditional Access → new policy → Conditions → Authentication flows → Device code flow → Block. Exclude break-glass accounts and any admin tooling that still needs device code. |
| Phishing-resistant MFA (passkeys, FIDO2, Windows Hello) for finance and admin users | AiTM proxies relay passwords and push or SMS MFA, but cannot relay passkeys | Entra → Authentication methods → Passkey (FIDO2); CA authentication strength "Phishing-resistant MFA" |
| Block automatic external forwarding | Stops silent exfiltration by inbox rule or mailbox forwarding | Defender → Policies → Anti-spam → Outbound policy → Automatic forwarding: Off |
| Alert on suspicious inbox rules and forwarding | Earlier detection | Defender → Alert policies (built-in "Suspicious email forwarding activity", "Suspicious inbox manipulation rule") with notifications to the IT contact |
| Mailbox auditing on and audit log searchable | Needed for every step in [05](05-investigate.md) | `Get-OrganizationConfig \| Format-List AuditDisabled`; `Get-AdminAuditLogConfig \| Format-List UnifiedAuditLogIngestionEnabled` |
| Restrict user consent to apps | Stops consent phishing | Entra → Enterprise apps → Consent and permissions → allow verified publishers only, or admin consent workflow |
| User awareness | The lure worked once | Short briefing on fake "shared document", "sign your contract", voicemail and invoice emails, and on calling to confirm any bank-detail change |

Record what the client agreed to and what was applied in the technical report's open items.
