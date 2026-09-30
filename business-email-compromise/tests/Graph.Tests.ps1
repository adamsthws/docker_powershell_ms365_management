BeforeAll {
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    . (Join-Path $PSScriptRoot 'Stubs.ps1')
    . (Join-Path $BecTestRoot 'ps/BecGraph.ps1')
    Mock Write-Host {}
}

Describe 'Invoke-BecContainment' -Tag Unit {
    BeforeEach {
        New-TestCase | Out-Null
        Mock Update-MgUser {}
        Mock Revoke-MgUserSignInSession { $true }
    }

    It 'changes nothing when declined' {
        Mock Read-Host { 'n' }
        Invoke-BecContainment
        Should -Invoke Update-MgUser -Times 0
        Should -Invoke Revoke-MgUserSignInSession -Times 0
        Get-TestLog | Should -Match 'Declined: 02 Contain'
    }

    It 'blocks sign-in and revokes sessions when approved, and logs both' {
        Mock Read-Host { 'y' }
        Invoke-BecContainment
        Should -Invoke Update-MgUser -Times 1 -Exactly -ParameterFilter { $UserId -eq 'jane@contoso.com' -and -not $AccountEnabled }
        Should -Invoke Revoke-MgUserSignInSession -Times 1 -Exactly -ParameterFilter { $UserId -eq 'jane@contoso.com' }
        Get-TestLog | Should -Match 'Blocked sign-in'
        Get-TestLog | Should -Match 'Revoked sign-in sessions'
    }

    It 'only revokes with -SkipBlock' {
        Mock Read-Host { 'y' }
        Invoke-BecContainment -SkipBlock
        Should -Invoke Update-MgUser -Times 0
        Should -Invoke Revoke-MgUserSignInSession -Times 1 -Exactly
    }

    It 'changes nothing with -WhatIf' {
        Mock Read-Host { 'y' }
        Invoke-BecContainment -WhatIf
        Should -Invoke Update-MgUser -Times 0
        Should -Invoke Revoke-MgUserSignInSession -Times 0
    }
}

Describe 'Enable-BecSignIn' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null; Mock Update-MgUser {} }

    It 're-enables only after approval' {
        Mock Read-Host { 'n' }
        Enable-BecSignIn
        Should -Invoke Update-MgUser -Times 0
        Mock Read-Host { 'y' }
        Enable-BecSignIn
        Should -Invoke Update-MgUser -Times 1 -Exactly -ParameterFilter { $AccountEnabled }
    }
}

Describe 'Connect-BecGraph' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null; Mock Connect-MgGraph {}; Mock Get-MgContext { [pscustomobject]@{ Account = 'admin@contoso.com'; TenantId = 'tid' } } }

    It 'does not sign in when declined' {
        Mock Read-Host { 'n' }
        Connect-BecGraph
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'requests the documented scopes and uses device code only when asked' {
        Mock Read-Host { 'y' }
        Connect-BecGraph -Device
        Should -Invoke Connect-MgGraph -ParameterFilter { $UseDeviceCode -and $Scopes -contains 'AuditLog.Read.All' }
    }
}

Describe 'Get-BecSignIns' -Tag Unit {
    BeforeEach {
        New-TestCase | Out-Null
        Mock Read-Host { 'y' }
        Mock Get-MgBetaAuditLogSignIn {
            [pscustomobject]@{ Id = '1'; CreatedDateTime = (Get-Date).AddHours(-2); IpAddress = '198.51.100.23'; AppDisplayName = 'Office 365 Exchange Online'
                AuthenticationProtocol = 'deviceCode'; IsInteractive = $true; Location = @{ CountryOrRegion = 'NL'; City = 'X' }; Status = @{ ErrorCode = 0 }; DeviceDetail = @{} }
            [pscustomobject]@{ Id = '2'; CreatedDateTime = (Get-Date).AddHours(-1); IpAddress = '203.0.113.9'; AppDisplayName = 'Outlook'
                AuthenticationProtocol = 'none'; IsInteractive = $true; Location = @{ CountryOrRegion = 'GB' }; Status = @{ ErrorCode = 0 }; DeviceDetail = @{} }
        }
    }

    It 'flags device code sign-ins and separates known-good IPs' {
        $rows = Get-BecSignIns -Days 7 3>$null
        Get-TestWarnings { Get-BecSignIns -Days 7 } | Should -Match 'device code'
        ($rows | Where-Object IpAddress -eq '203.0.113.9').KnownGood | Should -BeTrue
        ($rows | Where-Object IpAddress -eq '198.51.100.23').KnownGood | Should -BeFalse
        Should -Invoke Get-MgBetaAuditLogSignIn -ParameterFilter { $Filter -match "userPrincipalName eq 'jane@contoso.com'" }
    }

    It 'adds a non-interactive query and de-duplicates' {
        $rows = Get-BecSignIns -IncludeNonInteractive 3>$null
        Should -Invoke Get-MgBetaAuditLogSignIn -Times 2 -Exactly
        Should -Invoke Get-MgBetaAuditLogSignIn -Times 1 -Exactly -ParameterFilter { $Filter -match 'nonInteractiveUser' }
        $rows | Should -HaveCount 2
    }
}

Describe 'Get-BecIdentityReview' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null }

    It 'exports methods, devices, consents and app assignments' {
        Mock Read-Host { 'y' }
        Mock Get-MgUserAuthenticationMethod { [pscustomobject]@{ Id = 'm1'; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; phoneNumber = '+44 7700 900000' } } }
        Mock Get-MgUserRegisteredDevice { [pscustomobject]@{ Id = 'd1'; AdditionalProperties = @{ displayName = 'DESKTOP-1'; operatingSystem = 'Windows' } } }
        Mock Get-MgUserOwnedDevice { [pscustomobject]@{ Id = 'd1'; AdditionalProperties = @{ displayName = 'DESKTOP-1' } } }
        Mock Get-MgUserOauth2PermissionGrant { [pscustomobject]@{ Id = 'g1'; ClientId = 'sp1'; Scope = 'Mail.Read offline_access' } }
        Mock Get-MgServicePrincipal { [pscustomobject]@{ DisplayName = 'Suspicious App'; AppId = 'a1'; PublisherName = 'Unknown' } }
        Mock Get-MgUserAppRoleAssignment { @() }

        Get-BecIdentityReview
        $dir = Get-ChildItem (Join-Path $BecCaseDir 'evidence') -Directory -Filter 'identity-*'
        (Import-Csv (Join-Path $dir 'auth_methods.csv')).Type | Should -Be 'phoneAuthenticationMethod'
        Import-Csv (Join-Path $dir 'devices.csv') | Should -HaveCount 1
        (Import-Csv (Join-Path $dir 'oauth_grants.csv')).App | Should -Be 'Suspicious App'
    }

    It 'queries nothing when declined' {
        Mock Read-Host { 'n' }
        Mock Get-MgUserAuthenticationMethod {}
        Get-BecIdentityReview
        Should -Invoke Get-MgUserAuthenticationMethod -Times 0
    }
}
