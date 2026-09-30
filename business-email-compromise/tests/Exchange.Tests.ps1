BeforeAll {
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    . (Join-Path $PSScriptRoot 'Stubs.ps1')
    . (Join-Path $BecTestRoot 'ps/BecExchange.ps1')
    Mock Write-Host {}

    function New-Rule([hashtable]$Props) {
        $base = [ordered]@{
            Name = 'Rule'; RuleIdentity = '1'; Enabled = $true; Priority = 1; Description = 'desc'
            From = $null; SubjectContainsWords = $null; BodyContainsWords = $null; SubjectOrBodyContainsWords = $null
            FromAddressContainsWords = $null; HeaderContainsWords = $null; SentTo = $null; MyNameInToBox = $false
            ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null
            DeleteMessage = $false; SoftDeleteMessage = $false; PermanentDelete = $false
            MoveToFolder = $null; MarkAsRead = $false
        }
        foreach ($k in $Props.Keys) { $base[$k] = $Props[$k] }
        [pscustomobject]$base
    }

    function New-TraceRow($To, $Subject = 'PHISH', $Status = 'Delivered', $Ip = '198.51.100.23') {
        [pscustomobject]@{ Received = Get-Date; RecipientAddress = $To; Subject = $Subject; Status = $Status; FromIP = $Ip; MessageTraceId = [guid]::NewGuid() }
    }
}

Describe 'Get-BecRuleFindings' -Tag Unit {
    It 'flags a hide-everything rule' {
        $f = Get-BecRuleFindings (New-Rule @{ Name = '....'; MoveToFolder = 'RSS Feeds'; MarkAsRead = $true })
        $f | Should -Contain 'symbol-only name'
        $f | Should -Contain 'matches all mail'
        $f | Should -Contain 'marks read and moves (hides)'
        $f | Should -Contain 'moves to RSS Feeds'
    }

    It 'flags a keyword filter' {
        (Get-BecRuleFindings (New-Rule @{ SubjectOrBodyContainsWords = @('invoice'); MoveToFolder = 'Archive' })) -join ';' | Should -Match 'keyword filter: invoice'
    }

    It 'flags forwarding and deletion' {
        Get-BecRuleFindings (New-Rule @{ ForwardTo = 'x@example.com' }) | Should -Contain 'forwards or redirects'
        Get-BecRuleFindings (New-Rule @{ DeleteMessage = $true }) | Should -Contain 'deletes'
    }

    It 'leaves an ordinary filing rule alone' {
        Get-BecRuleFindings (New-Rule @{ Name = 'Newsletters'; From = @('news@example.com'); MoveToFolder = 'Newsletters' }) | Should -BeNullOrEmpty
    }
}

Describe 'Remove-BecInboxRule' -Tag Unit {
    BeforeEach {
        New-TestCase | Out-Null
        Mock Get-InboxRule { New-Rule @{ Name = '....'; RuleIdentity = $Identity } }
        Mock Remove-InboxRule {}
    }

    It 'refuses to run without a snapshot' {
        Mock Read-Host { 'y' }
        { Remove-BecInboxRule -RuleIdentity 111 } | Should -Throw '*Save-BecMailboxSnapshot*'
        Should -Invoke Remove-InboxRule -Times 0
    }

    It 'removes nothing when declined' {
        New-Item -ItemType Directory (Join-Path $BecCaseDir 'evidence/snapshot-1') | Out-Null
        Mock Read-Host { 'n' }
        Remove-BecInboxRule -RuleIdentity 111, 222
        Should -Invoke Remove-InboxRule -Times 0
    }

    It 'removes each rule once when approved, and logs it' {
        New-Item -ItemType Directory (Join-Path $BecCaseDir 'evidence/snapshot-1') | Out-Null
        Mock Read-Host { 'y' }
        Remove-BecInboxRule -RuleIdentity 111, 222
        Should -Invoke Read-Host -Times 1 -Exactly
        Should -Invoke Remove-InboxRule -Times 1 -Exactly -ParameterFilter { $Identity -eq '111' -and $Mailbox -eq 'jane@contoso.com' }
        Should -Invoke Remove-InboxRule -Times 1 -Exactly -ParameterFilter { $Identity -eq '222' }
        [regex]::Matches((Get-TestLog), 'Removed inbox rule').Count | Should -Be 2
    }

    It 'changes nothing with -WhatIf' {
        New-Item -ItemType Directory (Join-Path $BecCaseDir 'evidence/snapshot-1') | Out-Null
        Mock Read-Host { 'y' }
        Remove-BecInboxRule -RuleIdentity 111 -WhatIf
        Should -Invoke Remove-InboxRule -Times 0
    }
}

Describe 'Set-BecRetention' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null; Mock Set-Mailbox {}; Mock Get-Mailbox { [pscustomobject]@{ RetainDeletedItemsFor = '30.00:00:00' } } }

    It 'sets 30 days and a hold when approved' {
        Mock Read-Host { 'y' }
        Set-BecRetention -LitigationHold | Out-Null
        Should -Invoke Set-Mailbox -Times 1 -Exactly -ParameterFilter { $RetainDeletedItemsFor -eq 30 }
        Should -Invoke Set-Mailbox -Times 1 -Exactly -ParameterFilter { $LitigationHoldEnabled -eq $true }
    }

    It 'changes nothing when declined or with -WhatIf' {
        Mock Read-Host { 'n' }
        Set-BecRetention | Out-Null
        Mock Read-Host { 'y' }
        Set-BecRetention -WhatIf | Out-Null
        Should -Invoke Set-Mailbox -Times 0
    }

    It 'rejects retention outside 14-30 days' {
        { Set-BecRetention -Days 60 -Force } | Should -Throw
    }
}

Describe 'Get-BecAuditLog' -Tag Unit {
    BeforeEach {
        New-TestCase | Out-Null
        $script:page = 0
        $script:attackerData = @{ ClientIP = '198.51.100.23:56353'; Item = @{ Subject = 'PHISH' } } | ConvertTo-Json -Compress
        $script:userData = @{ ClientIP = '203.0.113.9' } | ConvertTo-Json -Compress
        Mock Search-UnifiedAuditLog {
            $script:page++
            $count = if ($script:page -eq 1) { 5000 } else { 3 }
            1..$count | ForEach-Object {
                [pscustomobject]@{
                    Identity = "$($script:page)-$_"; CreationDate = (Get-Date).AddMinutes(-$_); UserIds = 'jane@contoso.com'; Operations = 'Send'
                    AuditData = if ($_ % 2) { $script:attackerData } else { $script:userData }
                }
            }
        }
    }

    It 'pages past 5000 records, strips ports and flags known-good IPs' {
        Mock Read-Host { 'y' }
        $rows = Get-BecAuditLog -Days 7
        Should -Invoke Search-UnifiedAuditLog -Times 2 -Exactly
        $rows.Count | Should -Be 5003
        ($rows | Where-Object ClientIP -eq '198.51.100.23').KnownGood | Sort-Object -Unique | Should -Be $false
        ($rows | Where-Object ClientIP -eq '203.0.113.9').KnownGood | Sort-Object -Unique | Should -Be $true
        ($rows | Where-Object ClientIP -eq '198.51.100.23' | Select-Object -First 1).Detail | Should -Be 'PHISH'
        Get-ChildItem (Join-Path $BecCaseDir 'evidence') -Filter 'audit-*.csv' | Should -HaveCount 1
    }

    It 'searches by IP across the tenant when -IPAddresses is given' {
        Mock Read-Host { 'y' }
        Get-BecAuditLog -IPAddresses '198.51.100.23' -Operations $null | Out-Null
        Should -Invoke Search-UnifiedAuditLog -ParameterFilter { $IPAddresses -contains '198.51.100.23' -and -not $UserIds -and -not $Operations }
    }

    It 'does not search when declined' {
        Mock Read-Host { 'n' }
        Get-BecAuditLog | Should -BeNullOrEmpty
        Should -Invoke Search-UnifiedAuditLog -Times 0
    }

    It 'Get-BecUnknownIpActivity groups only unknown IPs' {
        Mock Read-Host { 'y' }
        $summary = Get-BecUnknownIpActivity (Get-BecAuditLog -Days 7)
        $summary.ClientIP | Should -Be '198.51.100.23'
        $summary.Events | Should -Be 2502
    }
}

Describe 'Message trace windowing' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null }

    It 'splits a window that hits the 5000-row cap until it fits' {
        Mock Get-MessageTraceV2 {
            $n = if (($EndDate - $StartDate).TotalHours -gt 6) { 5000 } else { 10 }
            1..$n | ForEach-Object { [pscustomobject]@{ MessageTraceId = [guid]::NewGuid(); RecipientAddress = 'x@example.com'; Received = $StartDate } }
        }
        $start = Get-Date '2025-01-06T00:00:00'
        $rows = @(Get-BecTraceWindow -Start $start -End $start.AddDays(1) -Filter @{})
        $rows.Count | Should -Be 40
        Should -Invoke Get-MessageTraceV2 -Times 7 -Exactly
    }

    It 'warns instead of looping forever when 15 minutes still hits the cap' {
        Mock Get-MessageTraceV2 { 1..5000 | ForEach-Object { [pscustomobject]@{ MessageTraceId = $_ } } }
        $start = Get-Date '2025-01-06T00:00:00'
        @(Get-BecTraceWindow -Start $start -End $start.AddMinutes(15) -Filter @{} 3>$null).Count | Should -Be 5000
        Get-TestWarnings { Get-BecTraceWindow -Start $start -End $start.AddMinutes(15) -Filter @{} } | Should -Match 'some messages are missing'
    }

    It 'queries a day at a time and removes duplicates across windows' {
        Mock Read-Host { 'y' }
        Mock Get-MessageTraceV2 { [pscustomobject]@{ MessageTraceId = 'same'; RecipientAddress = 'x@example.com'; Received = $StartDate } }
        $start = (Get-Date).Date.AddDays(-3)
        $rows = @(Invoke-BecMessageTrace -Start $start -End $start.AddDays(3) -Filter @{ SenderAddress = 'jane@contoso.com' })
        Should -Invoke Get-MessageTraceV2 -Times 3 -Exactly -ParameterFilter { $SenderAddress -eq 'jane@contoso.com' }
        $rows.Count | Should -Be 1
    }

    It 'Get-BecSentTrace asks once, saves the trace and logs it' {
        Mock Read-Host { 'y' }
        Mock Get-MessageTraceV2 { New-TraceRow 'a@example.com' }
        Get-BecSentTrace -Start (Get-Date).AddDays(-1) | Out-Null
        Should -Invoke Read-Host -Times 1 -Exactly
        Join-Path $BecCaseDir 'evidence/sent_trace.csv' | Should -Exist
        Get-TestLog | Should -Match 'Sent trace for jane@contoso.com'
    }
}

Describe 'New-BecRecipientList' -Tag Unit {
    BeforeEach {
        New-TestCase | Out-Null
        $script:trace = @(
            1..1000 | ForEach-Object { New-TraceRow "user$_@example.com" }
            New-TraceRow 'USER1@EXAMPLE.COM'
            New-TraceRow 'failed@example.com' -Status 'Failed'
            New-TraceRow 'asked@example.com' -Subject 'Re: PHISH'
            New-TraceRow 'bob@contoso.com'
            New-TraceRow 'boss@example.com' -Subject 'Week 2 hours' -Ip '203.0.113.9'
        )
    }

    It 'builds de-duplicated, lower-cased BCC batches of 450 without failed or unrelated mail' {
        Mock Read-Host { 'y' }
        $result = New-BecRecipientList $trace -Subject 'PHISH', 'Re: PHISH'
        $result.UniqueRecipients | Should -Be 1002
        $result.Batches | Should -Be 3
        $dir = Join-Path $BecCaseDir 'notification'
        (Get-Content "$dir/bcc_batch_1.txt") -split '; ' | Should -HaveCount 450
        (Get-Content "$dir/bcc_batch_3.txt") -split '; ' | Should -HaveCount 102
        $all = Get-Content "$dir/affected_recipients.txt"
        $all | Should -Not -Contain 'failed@example.com'
        $all | Should -Not -Contain 'boss@example.com'
        $all | Should -Contain 'user1@example.com'
        (Import-Csv "$dir/priority_recipients.csv").RecipientAddress | Should -Be 'asked@example.com'
        Get-Content "$dir/internal_recipients.txt" | Should -Be 'bob@contoso.com'
        (Get-BecCase).phishingSubjects | Should -Be @('PHISH', 'Re: PHISH')
    }

    It 'writes nothing and leaves case.json alone when declined' {
        Mock Read-Host { 'n' }
        New-BecRecipientList $trace -Subject 'PHISH' | Out-Null
        Get-ChildItem (Join-Path $BecCaseDir 'notification') | Should -BeNullOrEmpty
        (Get-BecCase).phishingSubjects | Should -BeNullOrEmpty
    }

    It 'replaces old batch files when rebuilt with fewer recipients' {
        Mock Read-Host { 'y' }
        New-BecRecipientList $trace -Subject 'PHISH' | Out-Null
        New-BecRecipientList @(New-TraceRow 'one@example.com') -Subject 'PHISH' | Out-Null
        Get-ChildItem (Join-Path $BecCaseDir 'notification') -Filter 'bcc_batch_*.txt' | Should -HaveCount 1
    }

    It 'needs subjects or -AllRecipients' {
        { New-BecRecipientList $trace -Subject @() } | Should -Throw '*-AllRecipients*'
    }
}

Describe 'Recovery' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null }

    It 'explains the missing role when Get-RecoverableItems is unavailable' {
        Mock Get-Command { $null } -ParameterFilter { $Name -eq 'Get-RecoverableItems' }
        { Get-BecDeletedItems -Since (Get-Date) } | Should -Throw '*Mailbox Import Export*'
    }

    It 'keeps going when one source folder fails' {
        Mock Read-Host { 'y' }
        Mock Get-RecoverableItems {
            if ($SourceFolder -eq 'PurgedItems') { throw 'not supported' }
            [pscustomobject]@{ LastModifiedTime = Get-Date; Subject = 'Re: PHISH'; LastParentPath = 'RSS Feeds'; ItemClass = 'IPM.Note' }
        }
        $rows = @(Get-BecDeletedItems -Since (Get-Date).AddDays(-7) 3>$null)
        $rows.Count | Should -Be 2
        Join-Path $BecCaseDir 'evidence/deleted_since_compromise.csv' | Should -Exist
    }

    It 'restores only after approval' {
        Mock Restore-RecoverableItems { @(1, 2, 3) }
        Mock Read-Host { 'n' }
        Restore-BecDeletedItems -Since (Get-Date).AddDays(-7)
        Should -Invoke Restore-RecoverableItems -Times 0
        Mock Read-Host { 'y' }
        Restore-BecDeletedItems -Since (Get-Date).AddDays(-7) -SubjectContains 'Invoice'
        Should -Invoke Restore-RecoverableItems -Times 2 -Exactly -ParameterFilter { $SubjectContains -eq 'Invoice' }
        Get-TestLog | Should -Match 'Restored 3 item'
    }
}

Describe 'Invoke-BecTenantSweep' -Tag Unit {
    BeforeEach {
        New-TestCase -AttackerIps '198.51.100.23' | Out-Null
        Mock Get-Mailbox { @([pscustomobject]@{ PrimarySmtpAddress = 'jane@contoso.com' }, [pscustomobject]@{ PrimarySmtpAddress = 'bob@contoso.com'; ForwardingSmtpAddress = 'smtp:x@example.com' }) }
        Mock Search-UnifiedAuditLog { @() }
        Mock Get-BlockedSenderAddress { @() }
        Mock Get-MessageTraceV2 { @() }
        Mock Get-InboxRule { if ($Mailbox -eq 'bob@contoso.com') { New-Rule @{ Name = '.'; MoveToFolder = 'RSS Feeds'; MarkAsRead = $true } } }
    }

    It 'asks once, then runs every check without further prompts' {
        Mock Read-Host { 'y' }
        Invoke-BecTenantSweep -Days 2
        Should -Invoke Read-Host -Times 1 -Exactly
        Should -Invoke Search-UnifiedAuditLog -ParameterFilter { $IPAddresses -contains '198.51.100.23' }
        $dir = Get-ChildItem $BecCaseDir -Directory -Filter 'tenant_sweep-*'
        (Import-Csv (Join-Path $dir 'suspicious_rules.csv')).Mailbox | Should -Be 'bob@contoso.com'
        (Import-Csv (Join-Path $dir 'forwarding.csv')).PrimarySmtpAddress | Should -Be 'bob@contoso.com'
        (Import-Csv (Join-Path $dir 'send_volume.csv')) | Should -HaveCount 2
    }

    It 'does nothing when declined' {
        Mock Read-Host { 'n' }
        Invoke-BecTenantSweep
        Should -Invoke Get-Mailbox -Times 0
    }
}

Describe 'Get-BecSendingStatus' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null; Mock Read-Host { 'y' } }

    It 'warns when the mailbox is restricted' {
        Mock Get-BlockedSenderAddress { [pscustomobject]@{ SenderAddress = 'jane@contoso.com' } }
        Get-BecSendingStatus 3>$null | Should -Not -BeNullOrEmpty
        Get-TestWarnings { Get-BecSendingStatus } | Should -Match 'Remove-BlockedSenderAddress'
    }

    It 'returns nothing when the mailbox can send' {
        Mock Get-BlockedSenderAddress { [pscustomobject]@{ SenderAddress = 'other@contoso.com' } }
        Get-BecSendingStatus | Should -BeNullOrEmpty
    }
}
