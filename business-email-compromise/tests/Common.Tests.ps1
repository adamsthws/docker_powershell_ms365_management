BeforeAll {
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    . (Join-Path $BecTestRoot 'ps/BecCommon.ps1')
    Mock Write-Host {}
}

Describe 'Confirm-BecStep' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null }

    It 'proceeds on "<Answer>" and logs it' -ForEach @(
        @{ Answer = 'y' }, @{ Answer = 'Y' }, @{ Answer = 'yes' }, @{ Answer = ' YES ' }
    ) {
        Mock Read-Host { $Answer }
        Confirm-BecStep -Step 'Test step' -Description 'Does a thing' | Should -BeTrue
        Get-TestLog | Should -Match 'Proceeding: Test step'
    }

    It 'skips on "<Answer>" and logs it' -ForEach @(
        @{ Answer = '' }, @{ Answer = 'n' }, @{ Answer = 'no' }, @{ Answer = 'yy' }, @{ Answer = 'sure' }
    ) {
        Mock Read-Host { $Answer }
        Confirm-BecStep -Step 'Test step' -Description 'Does a thing' | Should -BeFalse
        Get-TestLog | Should -Match 'Declined: Test step'
    }

    It '-Force proceeds without asking or logging' {
        Mock Read-Host { 'n' }
        Confirm-BecStep -Step 'Test step' -Description 'Does a thing' -Force | Should -BeTrue
        Should -Invoke Read-Host -Times 0
        Get-TestLog | Should -BeNullOrEmpty
    }

    It 'shows tenant changes when there are any' {
        Mock Read-Host { 'n' }
        Confirm-BecStep -Step 'S' -Description 'D' -Changes 'Remove thing' | Out-Null
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'CHANGES the tenant' }
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'Remove thing' }
    }

    It 'says read-only when there are no changes' {
        Mock Read-Host { 'n' }
        Confirm-BecStep -Step 'S' -Description 'D' | Out-Null
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'Read-only' }
    }
}

Describe 'IP helpers' -Tag Unit {
    It 'ConvertTo-BecIp turns "<In>" into "<Out>"' -ForEach @(
        @{ In = '198.51.100.23:56353'; Out = '198.51.100.23' }
        @{ In = '198.51.100.23'; Out = '198.51.100.23' }
        @{ In = '[2001:db8::1]:443'; Out = '2001:db8::1' }
        @{ In = '2001:db8:1234::5'; Out = '2001:db8:1234::5' }
        @{ In = ''; Out = '' }
    ) {
        ConvertTo-BecIp $In | Should -Be $Out
    }

    It 'Test-BecKnownGoodIp matches by prefix' {
        Test-BecKnownGoodIp '2001:db8:1234::5' @('2001:db8:1234:') | Should -BeTrue
        Test-BecKnownGoodIp '203.0.113.9' @('203.0.113.') | Should -BeTrue
        Test-BecKnownGoodIp '198.51.100.23' @('203.0.113.', '2001:db8:1234:') | Should -BeFalse
        Test-BecKnownGoodIp '' @('203.0.113.') | Should -BeFalse
        Test-BecKnownGoodIp '203.0.113.9' @() | Should -BeFalse
    }
}

Describe 'Case file' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null }

    It 'Resolve-BecUpn falls back to case.json' {
        Resolve-BecUpn | Should -Be 'jane@contoso.com'
        Resolve-BecUpn 'other@contoso.com' | Should -Be 'other@contoso.com'
    }

    It 'Add-BecCaseValue appends without duplicates' {
        Add-BecCaseValue attackerIps '198.51.100.23', '192.0.2.77'
        Add-BecCaseValue attackerIps '198.51.100.23'
        (Get-BecCase).attackerIps | Should -Be @('198.51.100.23', '192.0.2.77')
    }

    It 'Set-BecCaseValue replaces and logs' {
        Set-BecCaseValue containedUtc '2025-01-07T13:10:00Z'
        (Get-BecCase).containedUtc | Should -Not -BeNullOrEmpty
        Get-TestLog | Should -Match 'case.containedUtc'
    }

    It 'Get-BecCase fails clearly without case.json' {
        $global:BecCaseDir = Join-Path $TestDrive 'nowhere'
        { Get-BecCase } | Should -Throw '*new-case.sh*'
    }
}
