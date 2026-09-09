# Exchange Online helpers for BEC response. Load in an Exchange-only session:
#   scripts/bec-shell.sh exo <case-dir>
# Do not load Microsoft.Graph in the same session: both ship MSAL and the second to load
# fails with "Method not found ... WithLogging". Use scripts/bec-shell.sh graph instead.
#
# Every step function starts with Confirm-BecStep, which describes the step and asks the
# admin to proceed. -Force skips that prompt; it is meant for calls from inside another step.

. (Join-Path $PSScriptRoot 'BecCommon.ps1')

$global:BecDefaultAuditOperations = @(
    'New-InboxRule', 'Set-InboxRule', 'Enable-InboxRule', 'Disable-InboxRule', 'Remove-InboxRule', 'UpdateInboxRules',
    'Send', 'SendAs', 'SendOnBehalf',
    'HardDelete', 'SoftDelete', 'MoveToDeletedItems', 'Move',
    'Add-MailboxPermission', 'Add-RecipientPermission', 'Set-Mailbox', 'Set-MailboxJunkEmailConfiguration',
    'New-TransportRule', 'Set-TransportRule',
    'UserLoggedIn', 'UserLoginFailed'
)

# Folders attackers use to hide mail from the user.
$global:BecHidingFolderPattern = 'RSS|Conversation History|Archive|Deleted|Junk|Notes|Clutter'
$global:BecRuleKeywordPattern = 'invoice|payment|bank|remit|wire|transfer|account|paypal|amazon|docusign|password|security|phish|hack|spam|virus|compromis|fraud|scam'

function Connect-BecExchange {
    param([string]$AdminUpn, [switch]$Device, [switch]$Force)
    $how = if ($Device) { 'device code sign-in (enter a code at microsoft.com/devicelogin)' } else { 'browser sign-in (open the printed URL in your host browser)' }
    if (-not (Confirm-BecStep -Force:$Force -Step 'Connect to Exchange Online' `
            -Description "Signs in to Exchange Online$(if ($AdminUpn) { " as $AdminUpn" }) using $how. Use an admin account in the client's tenant.")) { return }

    $params = @{ ShowBanner = $false }
    if ($AdminUpn) { $params.UserPrincipalName = $AdminUpn }
    if ($Device) { $params.Device = $true }
    Connect-ExchangeOnline @params
    Write-BecLog "Connected to Exchange Online as $((Get-ConnectionInformation | Select-Object -First 1).UserPrincipalName)"
}

#region 03 - Preserve evidence

function Save-BecMailboxSnapshot {
    param([string]$Upn, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    $dir = "evidence/snapshot-$(Get-BecTimestamp)"
    if (-not (Confirm-BecStep -Force:$Force -Step "03 Snapshot mailbox $Upn" `
            -Description 'Captures the current state of the mailbox before anything is changed: inbox rules (including hidden), mailbox properties, permissions, folder statistics, mobile devices and tenant transport rules.' `
            -Writes "$dir/")) { return }

    Get-InboxRule -Mailbox $Upn -IncludeHidden | Format-List * | Out-File (Get-BecPath "$dir/inbox_rules.txt")
    Get-InboxRule -Mailbox $Upn -IncludeHidden | Export-Clixml (Get-BecPath "$dir/inbox_rules.xml")
    Get-Mailbox $Upn | Format-List * | Out-File (Get-BecPath "$dir/mailbox.txt")
    Get-MailboxPermission $Upn | Format-Table -AutoSize -Wrap | Out-File (Get-BecPath "$dir/mailbox_permissions.txt")
    Get-RecipientPermission $Upn | Format-Table -AutoSize -Wrap | Out-File (Get-BecPath "$dir/recipient_permissions.txt")
    Get-MailboxFolderStatistics $Upn -IncludeOldestAndNewestItems |
        Select-Object Name, FolderPath, ItemsInFolder, OldestItemReceivedDate, NewestItemReceivedDate |
        Export-Csv (Get-BecPath "$dir/folder_statistics.csv") -NoTypeInformation
    Get-MobileDevice -Mailbox $Upn -ErrorAction SilentlyContinue | Format-List * | Out-File (Get-BecPath "$dir/mobile_devices.txt")
    Get-TransportRule | Format-List Name, State, Priority, Description | Out-File (Get-BecPath "$dir/transport_rules.txt")

    Write-BecLog "Mailbox snapshot of $Upn saved to $dir"
}

function Set-BecRetention {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Upn, [ValidateRange(14, 30)][int]$Days = 30, [switch]$LitigationHold, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    $changes = @("Set-Mailbox $Upn -RetainDeletedItemsFor $Days")
    if ($LitigationHold) { $changes += "Set-Mailbox $Upn -LitigationHoldEnabled `$true (needs Exchange Online Plan 2 or equivalent)" }
    if (-not (Confirm-BecStep -Force:$Force -Step "03 Extend retention on $Upn" `
            -Description "Keeps deleted and purged mail for $Days days (default is 14) so the attacker's deletions can still be recovered. A litigation hold also stops anything being purged while the investigation runs." `
            -Changes $changes)) { return }

    if ($PSCmdlet.ShouldProcess($Upn, "RetainDeletedItemsFor $Days days")) {
        Set-Mailbox $Upn -RetainDeletedItemsFor $Days
        Write-BecLog "Set RetainDeletedItemsFor=$Days on $Upn"
    }
    if ($LitigationHold -and $PSCmdlet.ShouldProcess($Upn, 'Enable litigation hold')) {
        Set-Mailbox $Upn -LitigationHoldEnabled $true
        Write-BecLog "Enabled litigation hold on $Upn"
    }
    Get-Mailbox $Upn | Format-List RetainDeletedItemsFor, SingleItemRecoveryEnabled, LitigationHoldEnabled
}

#endregion

#region 04 - Mailbox persistence

function Get-BecRuleFindings {
    param([Parameter(Mandatory)]$Rule)
    $reasons = @()
    $conditions = @($Rule.From) + @($Rule.SubjectContainsWords) + @($Rule.BodyContainsWords) +
        @($Rule.SubjectOrBodyContainsWords) + @($Rule.FromAddressContainsWords) + @($Rule.HeaderContainsWords) |
        Where-Object { $_ }
    $folder = "$($Rule.MoveToFolder)"

    if ($Rule.Name -match '^[\W_]*$') { $reasons += 'symbol-only name' }
    if ($Rule.ForwardTo -or $Rule.ForwardAsAttachmentTo -or $Rule.RedirectTo) { $reasons += 'forwards or redirects' }
    if ($Rule.DeleteMessage -or $Rule.SoftDeleteMessage -or $Rule.PermanentDelete) { $reasons += 'deletes' }
    if ($folder -match $global:BecHidingFolderPattern) { $reasons += "moves to $folder" }
    if ($folder -and $Rule.MarkAsRead) { $reasons += 'marks read and moves (hides)' }
    if ($folder -and -not $conditions -and -not $Rule.SentTo -and -not $Rule.MyNameInToBox) { $reasons += 'matches all mail' }
    if (($conditions -join ' ') -match $global:BecRuleKeywordPattern) { $reasons += "keyword filter: $($conditions -join ', ')" }
    $reasons
}

function Get-BecInboxRuleReport {
    param([string]$Upn, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    if (-not (Confirm-BecStep -Force:$Force -Step "04 Inbox rule report for $Upn" `
            -Description 'Lists the inbox rules on the mailbox and flags attacker patterns (symbol-only names, hide-all rules, moves to RSS Feeds/Archive, forwarding, deletion, keyword filters).')) { return }

    Get-InboxRule -Mailbox $Upn | ForEach-Object {
        [pscustomobject]@{
            Priority     = $_.Priority
            Name         = $_.Name
            Enabled      = $_.Enabled
            RuleIdentity = $_.RuleIdentity
            Findings     = (Get-BecRuleFindings $_) -join '; '
            Description  = ($_.Description -replace '\s+', ' ').Trim()
        }
    }
}

function Remove-BecInboxRule {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Upn, [Parameter(Mandatory)][string[]]$RuleIdentity, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    if (-not (Get-ChildItem (Join-Path $global:BecCaseDir 'evidence') -Filter 'snapshot-*' -Directory -ErrorAction SilentlyContinue)) {
        throw 'No mailbox snapshot in evidence/. Run Save-BecMailboxSnapshot before removing rules.'
    }
    $rules = foreach ($id in $RuleIdentity) { Get-InboxRule -Mailbox $Upn -Identity $id }
    if (-not (Confirm-BecStep -Force:$Force -Step "04 Remove inbox rules from $Upn" `
            -Description 'Permanently deletes these inbox rules. They are already captured in the evidence snapshot.' `
            -Changes ($rules | ForEach-Object { "Remove-InboxRule '$($_.Name)' ($($_.RuleIdentity)): $(($_.Description -replace '\s+', ' ').Trim())" }))) { return }

    foreach ($rule in $rules) {
        if ($PSCmdlet.ShouldProcess("$Upn rule '$($rule.Name)' ($($rule.RuleIdentity))", 'Remove-InboxRule')) {
            Remove-InboxRule -Mailbox $Upn -Identity $rule.RuleIdentity -Confirm:$false
            Write-BecLog "Removed inbox rule '$($rule.Name)' ($($rule.RuleIdentity)) from $Upn"
        }
    }
}

function Get-BecMailboxAccess {
    param([string]$Upn, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    if (-not (Confirm-BecStep -Force:$Force -Step "04 Mailbox access review for $Upn" `
            -Description 'Shows mailbox forwarding, Full Access and Send As permissions, mobile device partnerships and tenant transport rules, so you can spot anything the attacker added.')) { return }

    Write-Host "`nForwarding" -ForegroundColor Yellow
    Get-Mailbox $Upn | Format-List ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
    Write-Host 'Mailbox permissions (excluding NT AUTHORITY)' -ForegroundColor Yellow
    Get-MailboxPermission $Upn | Where-Object { $_.User -notlike 'NT AUTHORITY*' } | Format-Table Identity, User, AccessRights, IsInherited -AutoSize
    Write-Host 'Send As' -ForegroundColor Yellow
    Get-RecipientPermission $Upn | Where-Object { $_.Trustee -notlike 'NT AUTHORITY*' } | Format-Table Identity, Trustee, AccessRights -AutoSize
    Write-Host 'Mobile devices' -ForegroundColor Yellow
    Get-MobileDevice -Mailbox $Upn -ErrorAction SilentlyContinue | Format-Table FriendlyName, DeviceModel, DeviceOS, FirstSyncTime, DeviceAccessState -AutoSize
    Write-Host 'Transport rules (tenant)' -ForegroundColor Yellow
    Get-TransportRule | Format-Table Name, State, Priority -AutoSize
}

#endregion

#region 05 - Investigate access

function Get-BecAuditDetail {
    param([Parameter(Mandatory)]$AuditData, [string]$Operation)
    switch -Regex ($Operation) {
        '^Send' { return "$($AuditData.Item.Subject)" }
        'InboxRule$' { return (@($AuditData.Parameters) | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ' }
        '^UpdateInboxRules$' { return (@($AuditData.OperationProperties) | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ' }
        'Delete' {
            $subjects = @($AuditData.AffectedItems.Subject | Select-Object -First 3) -join ' | '
            return "[$($AuditData.Folder.Path)] $subjects"
        }
        '^Move$' { return "$($AuditData.Folder.Path) -> $($AuditData.DestFolder.Path)" }
        default { return '' }
    }
}

function Get-BecAuditLog {
    param(
        [string]$Upn,
        [int]$Days = 90,
        [datetime]$Start,
        [datetime]$End = (Get-Date),
        [string[]]$Operations = $global:BecDefaultAuditOperations,
        [string[]]$IPAddresses,
        [switch]$Force
    )
    if (-not $Start) { $Start = (Get-Date).AddDays(-$Days) }
    $search = @{ StartDate = $Start; EndDate = $End; ResultSize = 5000; SessionCommand = 'ReturnLargeSet'; SessionId = [guid]::NewGuid().ToString() }
    if ($IPAddresses) { $search.IPAddresses = $IPAddresses; $scope = "activity from $($IPAddresses -join ', ') across the whole tenant" }
    else { $search.UserIds = (Resolve-BecUpn $Upn); $scope = "activity by $($search.UserIds)" }
    if ($Operations) { $search.Operations = $Operations }
    $file = "evidence/audit-$(Get-BecTimestamp).csv"

    if (-not (Confirm-BecStep -Force:$Force -Step '05 Search the unified audit log' `
            -Description "Searches the audit log for $scope from $($Start.ToString('u')) to $($End.ToString('u')), $(if ($Operations) { "limited to $(@($Operations).Count) operations (rules, sends, deletes, permissions, sign-ins)" } else { 'all operations' }). Large searches can take several minutes." `
            -Writes $file)) { return }

    # ReturnLargeSet pages through up to 50,000 records, 5000 per call, under one session id.
    $records = [System.Collections.Generic.List[object]]::new()
    do {
        $page = @(Search-UnifiedAuditLog @search)
        $records.AddRange($page)
    } while ($page.Count -eq 5000)

    $knownGood = Get-BecKnownGoodPrefixes
    $rows = $records | Sort-Object Identity -Unique | ForEach-Object {
        $data = $_.AuditData | ConvertFrom-Json
        $ip = ConvertTo-BecIp $data.ClientIP
        if (-not $ip) { $ip = ConvertTo-BecIp $data.ClientIPAddress }
        [pscustomobject]@{
            DateUtc   = $_.CreationDate
            User      = $_.UserIds
            Operation = $_.Operations
            ClientIP  = $ip
            KnownGood = Test-BecKnownGoodIp $ip $knownGood
            Detail    = Get-BecAuditDetail $data $_.Operations
        }
    } | Sort-Object DateUtc

    $rows | Export-Csv (Get-BecPath $file) -NoTypeInformation
    Write-Host "$(@($rows).Count) audit records saved to $file" -ForegroundColor Green
    $rows
}

# Local analysis of audit rows already retrieved; no tenant call, so no prompt.
function Get-BecUnknownIpActivity {
    param([Parameter(Mandatory)]$AuditRows)
    $AuditRows | Where-Object { $_.ClientIP -and -not $_.KnownGood } | Group-Object ClientIP | ForEach-Object {
        $first = $_.Group | Select-Object -First 1
        $last = $_.Group | Select-Object -Last 1
        [pscustomobject]@{
            ClientIP   = $_.Name
            Events     = $_.Count
            FirstUtc   = $first.DateUtc
            LastUtc    = $last.DateUtc
            Operations = ($_.Group | Group-Object Operation | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', '
        }
    } | Sort-Object FirstUtc
}

#endregion

#region Message trace

# Get-MessageTraceV2 caps each query at 5000 rows and a 10-day window. Query a day at a time
# and split any window that hits the cap.
function Get-BecTraceWindow {
    param([datetime]$Start, [datetime]$End, [hashtable]$Filter)
    $rows = @(Get-MessageTraceV2 @Filter -StartDate $Start -EndDate $End -ResultSize 5000)
    if ($rows.Count -lt 5000) { return $rows }
    if (($End - $Start).TotalMinutes -le 15) {
        Write-Warning "$Start to $End still returns 5000 rows; some messages are missing from this window."
        return $rows
    }
    $mid = $Start.AddTicks([long](($End - $Start).Ticks / 2))
    Get-BecTraceWindow -Start $Start -End $mid -Filter $Filter
    Get-BecTraceWindow -Start $mid -End $End -Filter $Filter
}

function Invoke-BecMessageTrace {
    param([Parameter(Mandatory)][datetime]$Start, [datetime]$End = (Get-Date), [hashtable]$Filter = @{}, [switch]$Force)
    $filterText = if ($Filter.Count) { ($Filter.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ' } else { 'no filter (all mail in the tenant)' }
    if (-not (Confirm-BecStep -Force:$Force -Step '05 Message trace' `
            -Description "Runs a message trace from $($Start.ToString('u')) to $($End.ToString('u')) with $filterText. Results are returned to the session, not saved.")) { return }

    if ($Start -lt (Get-Date).AddDays(-90)) { Write-Warning 'Message trace only covers the last 90 days; older messages will not be returned.' }
    $cursor = $Start
    $all = while ($cursor -lt $End) {
        $next = if ($cursor.AddDays(1) -lt $End) { $cursor.AddDays(1) } else { $End }
        Get-BecTraceWindow -Start $cursor -End $next -Filter $Filter
        $cursor = $next
    }
    @($all) | Sort-Object MessageTraceId, RecipientAddress -Unique | Sort-Object Received
}

function Find-BecLureMessage {
    param(
        [string]$Upn,
        [Parameter(Mandatory)][datetime]$Start,
        [datetime]$End = $Start.AddDays(2),
        [string]$SenderAddress,
        [string]$Subject,
        [switch]$Force
    )
    $filter = @{ RecipientAddress = (Resolve-BecUpn $Upn) }
    if ($SenderAddress) { $filter.SenderAddress = $SenderAddress }
    if ($Subject) { $filter.Subject = $Subject; $filter.SubjectFilterType = 'Contains' }
    $file = "evidence/lure_trace-$(Get-BecTimestamp).csv"
    if (-not (Confirm-BecStep -Force:$Force -Step '05 Find the lure email' `
            -Description "Traces mail received by $($filter.RecipientAddress) between $($Start.ToString('u')) and $($End.ToString('u'))$(if ($SenderAddress) { " from $SenderAddress" })$(if ($Subject) { " with '$Subject' in the subject" }), to find the email the user interacted with." `
            -Writes $file)) { return }

    $rows = Invoke-BecMessageTrace -Start $Start -End $End -Filter $filter -Force
    $rows | Export-Csv (Get-BecPath $file) -NoTypeInformation
    $rows | Select-Object Received, SenderAddress, Subject, Status, FromIP, MessageId
}

#endregion

#region 06 - Outbound impact

function Get-BecSentTrace {
    param([string]$Upn, [Parameter(Mandatory)][datetime]$Start, [datetime]$End = (Get-Date), [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    if (-not (Confirm-BecStep -Force:$Force -Step "06 Trace mail sent by $Upn" `
            -Description "Traces every message sent by $Upn from $($Start.ToString('u')) to $($End.ToString('u')), a day at a time, to find what the attacker sent and to whom." `
            -Writes 'evidence/sent_trace.csv (replaces any previous one)')) { return }

    $rows = Invoke-BecMessageTrace -Start $Start -End $End -Filter @{ SenderAddress = $Upn } -Force
    $rows | Export-Csv (Get-BecPath 'evidence/sent_trace.csv') -NoTypeInformation
    Write-BecLog "Sent trace for $Upn from $($Start.ToString('u')): $(@($rows).Count) rows saved to evidence/sent_trace.csv"
    $rows
}

# Local file read; no prompt.
function Import-BecSentTrace { Import-Csv (Get-BecPath 'evidence/sent_trace.csv') }

# Local analysis of a trace already retrieved; no tenant call, so no prompt.
function Get-BecSubjectSummary {
    param([Parameter(Mandatory)]$Trace, [int]$Top = 25)
    $knownGood = Get-BecKnownGoodPrefixes
    $Trace | Group-Object Subject | ForEach-Object {
        $ips = @($_.Group.FromIP | Where-Object { $_ } | Sort-Object -Unique)
        [pscustomobject]@{
            Count            = $_.Count
            UniqueRecipients = @($_.Group.RecipientAddress | Sort-Object -Unique).Count
            FirstUtc         = ($_.Group | Sort-Object { [datetime]$_.Received } | Select-Object -First 1).Received
            LastUtc          = ($_.Group | Sort-Object { [datetime]$_.Received } | Select-Object -Last 1).Received
            UnknownIPs       = ($ips | Where-Object { -not (Test-BecKnownGoodIp $_ $knownGood) }) -join ', '
            Subject          = $_.Name
        }
    } | Sort-Object Count -Descending | Select-Object -First $Top
}

function New-BecRecipientList {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes only local case files and is gated by Confirm-BecStep.')]
    param(
        [Parameter(Mandatory)]$Trace,
        [string[]]$Subject = (Get-BecCase).phishingSubjects,
        [int]$BatchSize = 450,
        [switch]$AllRecipients,
        [switch]$Force
    )
    if (-not $AllRecipients -and -not $Subject) { throw 'Pass -Subject (the phishing subjects) or -AllRecipients.' }

    $hits = $Trace | Where-Object { $_.Status -ne 'Failed' -and ($AllRecipients -or $_.Subject -in $Subject) }
    $recipients = @($hits | ForEach-Object { "$($_.RecipientAddress)".ToLower() } | Sort-Object -Unique)
    $batches = [math]::Ceiling($recipients.Count / $BatchSize)
    $dir = 'notification'

    $basis = if ($AllRecipients) { 'every recipient in the trace' } else { "recipients of: $(($Subject | ForEach-Object { "'$_'" }) -join ', ')" }
    if (-not (Confirm-BecStep -Force:$Force -Step '06 Build the recipient list' `
            -Description "Builds the warning list from $basis, excluding failed deliveries. Result: $($recipients.Count) unique recipients in $batches BCC batch(es) of up to $BatchSize. Also saves the subjects to case.json." `
            -Writes "$dir/affected_recipients.txt", "$dir/bcc_batch_N.txt (previous batch files are deleted)", "$dir/priority_recipients.csv", "$dir/internal_recipients.txt")) { return }

    if ($Subject) { Set-BecCaseValue phishingSubjects $Subject }
    $recipients | Out-File (Get-BecPath "$dir/affected_recipients.txt")
    Get-ChildItem (Join-Path $global:BecCaseDir $dir) -Filter 'bcc_batch_*.txt' -ErrorAction SilentlyContinue | Remove-Item
    $batch = 0
    for ($n = 0; $n -lt $recipients.Count; $n += $BatchSize) {
        $batch++
        $recipients[$n..([math]::Min($n + $BatchSize, $recipients.Count) - 1)] -join '; ' | Out-File (Get-BecPath "$dir/bcc_batch_$batch.txt")
    }

    # Recipients who got a reply ("RE:"/"FW:") in the phishing thread probably engaged with it: phone them.
    $hits | Where-Object { $_.Subject -match '^\s*(re|fw|fwd)\s*:' } |
        Select-Object Received, RecipientAddress, Subject, FromIP |
        Export-Csv (Get-BecPath "$dir/priority_recipients.csv") -NoTypeInformation

    $domain = ((Resolve-BecUpn) -split '@')[1]
    $recipients | Where-Object { $_ -like "*@$domain" } | Out-File (Get-BecPath "$dir/internal_recipients.txt")

    Write-BecLog "Recipient list: $($recipients.Count) unique recipients in $batch BCC batch(es) of up to $BatchSize"
    [pscustomobject]@{ UniqueRecipients = $recipients.Count; Batches = $batch; Folder = $dir }
}

#endregion

#region 07 - Notification

function Get-BecSendingStatus {
    param([string]$Upn, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    if (-not (Confirm-BecStep -Force:$Force -Step "07 Check $Upn can send" `
            -Description "Checks whether Microsoft has put $Upn on the restricted senders list after the bulk send. If it has, the warning email cannot go from this mailbox until it is unblocked.")) { return }

    $blocked = Get-BlockedSenderAddress | Where-Object { $_.SenderAddress -eq $Upn }
    if ($blocked) { Write-Warning "$Upn is on the restricted senders list. Unblock with: Remove-BlockedSenderAddress -SenderAddress $Upn" }
    else { Write-Host "$Upn is not blocked from sending." -ForegroundColor Green }
    $blocked
}

#endregion

#region 08 - Recover mail

function Assert-BecRecoverableItemsCmdlets {
    if (-not (Get-Command Get-RecoverableItems -ErrorAction SilentlyContinue)) {
        throw @'
Get-RecoverableItems is not available. Assign the role, wait 15-60 minutes, then reconnect:
  New-ManagementRoleAssignment -Role "Mailbox Import Export" -User <admin upn>
  Disconnect-ExchangeOnline -Confirm:$false; Connect-BecExchange
'@
    }
}

function Get-BecDeletedItems {
    param([string]$Upn, [Parameter(Mandatory)][datetime]$Since, [switch]$Force)
    Assert-BecRecoverableItemsCmdlets
    $Upn = Resolve-BecUpn $Upn
    if (-not (Confirm-BecStep -Force:$Force -Step "08 List mail deleted from $Upn" `
            -Description "Lists messages deleted since $($Since.ToString('u')) from Deleted Items, Recoverable Items and Purges, with the folder each was deleted from. Nothing is restored yet." `
            -Writes 'evidence/deleted_since_compromise.csv')) { return }

    $rows = foreach ($source in 'DeletedItems', 'RecoverableItems', 'PurgedItems') {
        try {
            Get-RecoverableItems -Identity $Upn -SourceFolder $source -FilterStartTime $Since -FilterItemType IPM.Note -ResultSize Unlimited |
                Select-Object @{ n = 'Source'; e = { $source } }, LastModifiedTime, Subject, LastParentPath, ItemClass
        } catch {
            Write-Warning "$source could not be searched: $($_.Exception.Message)"
        }
    }
    $rows | Export-Csv (Get-BecPath 'evidence/deleted_since_compromise.csv') -NoTypeInformation
    $rows | Group-Object Source, LastParentPath | Select-Object Count, Name | Format-Table -AutoSize | Out-Host
    $rows
}

function Restore-BecDeletedItems {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Upn,
        [Parameter(Mandatory)][datetime]$Since,
        [ValidateSet('DeletedItems', 'RecoverableItems', 'PurgedItems')][string[]]$SourceFolder = @('RecoverableItems', 'PurgedItems'),
        [string]$SubjectContains,
        [switch]$Force
    )
    Assert-BecRecoverableItemsCmdlets
    $Upn = Resolve-BecUpn $Upn
    if (-not (Confirm-BecStep -Force:$Force -Step "08 Restore deleted mail to $Upn" `
            -Description "Restores messages deleted since $($Since.ToString('u'))$(if ($SubjectContains) { " whose subject contains '$SubjectContains'" }) back to the folder they were deleted from (often RSS Feeds). Run Get-BecDeletedItems first and check the list." `
            -Changes ($SourceFolder | ForEach-Object { "Restore-RecoverableItems from $_ into $Upn" }))) { return }

    foreach ($source in $SourceFolder) {
        $params = @{ Identity = $Upn; SourceFolder = $source; FilterStartTime = $Since; FilterItemType = 'IPM.Note'; ResultSize = 'Unlimited' }
        if ($SubjectContains) { $params.SubjectContains = $SubjectContains }
        if ($PSCmdlet.ShouldProcess("$Upn $source since $($Since.ToString('u'))", 'Restore-RecoverableItems')) {
            $result = Restore-RecoverableItems @params
            Write-BecLog "Restored $(@($result).Count) item(s) from $source in $Upn (since $($Since.ToString('u')))"
        }
    }
}

#endregion

#region 09 - Tenant sweep

function Invoke-BecTenantSweep {
    param([int]$Days = 10, [string[]]$AttackerIps = (Get-BecAttackerIps), [switch]$Force)
    $dir = "tenant_sweep-$(Get-BecTimestamp)"
    if (-not (Confirm-BecStep -Force:$Force -Step '09 Sweep every mailbox in the tenant' `
            -Description @"
Checks all user and shared mailboxes for signs of compromise:
  1. Activity from the attacker IPs in the last 90 days ($(if ($AttackerIps) { $AttackerIps -join ', ' } else { 'none recorded in case.json; skipped' }))
  2. Accounts Microsoft has restricted from sending
  3. Mail sent per mailbox in the last $Days days (one message trace per mailbox; slow in large tenants)
  4. Suspicious inbox rules on every mailbox
  5. Mailbox forwarding
"@ `
            -Writes "$dir/send_volume.csv", "$dir/suspicious_rules.csv", "$dir/forwarding.csv", 'evidence/audit-*.csv (attacker IP search)')) { return }

    $mailboxes = Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox

    if ($AttackerIps) {
        Write-Host "`n[1/5] Attacker IPs across the tenant (90 days)" -ForegroundColor Yellow
        $ipRows = Get-BecAuditLog -IPAddresses $AttackerIps -Days 90 -Operations $null -Force
        $ipRows | Group-Object User | Select-Object Count, Name | Format-Table -AutoSize | Out-Host
    } else {
        Write-Warning '[1/5] No attackerIps in case.json; skipping the tenant-wide IP search.'
    }

    Write-Host '[2/5] Restricted senders' -ForegroundColor Yellow
    Get-BlockedSenderAddress | Tee-Object -Variable blocked | Format-Table -AutoSize | Out-Host
    if (-not $blocked) { Write-Host '  none' }

    Write-Host "[3/5] Send volume per mailbox ($Days days)" -ForegroundColor Yellow
    $volume = foreach ($m in $mailboxes) {
        $t = Invoke-BecMessageTrace -Start (Get-Date).AddDays(-$Days) -Filter @{ SenderAddress = $m.PrimarySmtpAddress } -Force
        [pscustomobject]@{
            Mailbox          = $m.PrimarySmtpAddress
            Sent             = @($t).Count
            UniqueRecipients = @($t.RecipientAddress | Sort-Object -Unique).Count
            TopSubject       = $t | Group-Object Subject | Sort-Object Count -Descending | Select-Object -First 1 | ForEach-Object { "$($_.Count)x $($_.Name)" }
            SendingIPs       = @($t.FromIP | Where-Object { $_ } | Sort-Object -Unique) -join ', '
        }
    }
    $volume | Sort-Object Sent -Descending | Export-Csv (Get-BecPath "$dir/send_volume.csv") -NoTypeInformation
    $volume | Sort-Object Sent -Descending | Format-Table -AutoSize -Wrap | Out-Host

    Write-Host '[4/5] Suspicious inbox rules' -ForegroundColor Yellow
    $rules = foreach ($m in $mailboxes) {
        Get-InboxRule -Mailbox $m.PrimarySmtpAddress -ErrorAction SilentlyContinue | ForEach-Object {
            $findings = Get-BecRuleFindings $_
            if ($findings) {
                [pscustomobject]@{ Mailbox = $m.PrimarySmtpAddress; Name = $_.Name; Enabled = $_.Enabled; RuleIdentity = $_.RuleIdentity; Findings = $findings -join '; ' }
            }
        }
    }
    $rules | Export-Csv (Get-BecPath "$dir/suspicious_rules.csv") -NoTypeInformation
    if ($rules) { $rules | Format-Table -AutoSize -Wrap | Out-Host } else { Write-Host '  none' }

    Write-Host '[5/5] Mailbox forwarding' -ForegroundColor Yellow
    $forwarding = $mailboxes | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |
        Select-Object PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
    $forwarding | Export-Csv (Get-BecPath "$dir/forwarding.csv") -NoTypeInformation
    if ($forwarding) { $forwarding | Format-Table -AutoSize | Out-Host } else { Write-Host '  none' }

    Write-BecLog "Tenant sweep of $(@($mailboxes).Count) mailboxes saved to $dir"
}

#endregion

function Show-BecHelp {
    @'

BEC Exchange session. Case folder: /case (on the host: the case directory you passed in).
Each step describes what it will do and asks "Proceed? [y/N]" before touching the tenant.

  Connect-BecExchange [-AdminUpn admin@tenant] [-Device]
  Test-BecCommandSurface               after connecting: check every cmdlet/parameter exists
  Show-BecCase | Set-BecCaseValue <name> <value> | Add-BecCaseValue attackerIps <ip>

  03 Save-BecMailboxSnapshot            Set-BecRetention [-LitigationHold]
  04 Get-BecInboxRuleReport             Get-BecMailboxAccess
     Remove-BecInboxRule -RuleIdentity <id>,<id>
  05 $audit = Get-BecAuditLog [-Days 90]
     Get-BecUnknownIpActivity $audit    Find-BecLureMessage -Start <date> [-SenderAddress] [-Subject]
     Invoke-BecMessageTrace -Start <date> -Filter @{ SenderAddress = '<lure sender>' }
  06 $trace = Get-BecSentTrace -Start <date>
     Get-BecSubjectSummary $trace       New-BecRecipientList $trace -Subject '<s1>','<s2>'
  07 Get-BecSendingStatus
  08 Get-BecDeletedItems -Since <date>  Restore-BecDeletedItems -Since <date>
  09 Invoke-BecTenantSweep [-Days 10]

Procedures: business-email-compromise/procedures/ in the repo.
'@ | Write-Host
}
