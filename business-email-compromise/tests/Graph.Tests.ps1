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
    BeforeEach {
        New-TestCase | Out-Null
        Mock Connect-MgGraph {}
        Mock Get-MgContext { [pscustomobject]@{ Account = 'admin@contoso.com'; TenantId = 'tid-1' } }
        Mock Get-MgOrganization { [pscustomobject]@{ VerifiedDomains = @(@{ Name = 'contoso.com' }, @{ Name = 'contoso.onmicrosoft.com' }) } }
    }

    It 'does not sign in when declined' {
        Mock Read-Host { 'n' }
        Connect-BecGraph
        Should -Invoke Connect-MgGraph -Times 0
    }

    It 'requests the documented scopes and uses device code only when asked' {
        Mock Read-Host { 'y' }
        Connect-BecGraph -Device
        Should -Invoke Connect-MgGraph -ParameterFilter { $UseDeviceCode -and $Scopes -contains 'AuditLog.Read.All' -and -not $LoginHint }
    }

    It 'allows 15 minutes to sign in and takes tenant and admin from case.json' {
        Mock Read-Host { 'y' }
        Set-BecCaseValue tenant 'contoso.onmicrosoft.com'
        Set-BecCaseValue adminUpn 'admin@contoso.onmicrosoft.com'
        Connect-BecGraph
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter {
            $TenantId -eq 'contoso.onmicrosoft.com' -and $LoginHint -eq 'admin@contoso.onmicrosoft.com' -and $ClientTimeout -eq 900 -and -not $UseDeviceCode
        }
    }

    It '-Tenant overrides case.json' {
        Mock Read-Host { 'y' }
        Set-BecCaseValue tenant 'contoso.onmicrosoft.com'
        Connect-BecGraph -Tenant 'fabrikam.onmicrosoft.com'
        Should -Invoke Connect-MgGraph -ParameterFilter { $TenantId -eq 'fabrikam.onmicrosoft.com' }
    }

    It 'logs the connection and records the tenant ID when the tenant owns the mailbox domain' {
        Mock Read-Host { 'y' }
        Connect-BecGraph
        Get-TestLog | Should -Match 'Connected to Microsoft Graph as admin@contoso.com \(tenant tid-1\)'
        (Get-BecCase).tenantId | Should -Be 'tid-1'
    }

    It 'does not log "Connected" when the sign-in times out' {
        Mock Read-Host { 'y' }
        Mock Get-MgContext { $null }
        Get-TestWarnings { Connect-BecGraph } | Should -Match 'did not complete'
        Get-TestLog | Should -Not -Match 'Connected to'
        Get-TestLog | Should -Match 'did not complete'
    }

    It 'logs a failed sign-in instead of throwing' {
        Mock Read-Host { 'y' }
        Mock Connect-MgGraph { throw 'User canceled authentication' }
        { Connect-BecGraph 3>$null } | Should -Not -Throw
        Get-TestLog | Should -Match 'sign-in failed: User canceled'
    }

    It 'warns when the tenant does not own the mailbox domain' {
        Mock Read-Host { 'y' }
        Mock Get-MgOrganization { [pscustomobject]@{ VerifiedDomains = @(@{ Name = 'fabrikam.com' }) } }
        Get-TestWarnings { Connect-BecGraph } | Should -Match 'does not own contoso.com'
        (Get-BecCase).tenantId | Should -BeNullOrEmpty
    }

    It 'warns when the tenant differs from the one recorded in case.json' {
        Mock Read-Host { 'y' }
        Set-BecCaseValue tenantId 'tid-other'
        Get-TestWarnings { Connect-BecGraph } | Should -Match 'records tenant tid-other'
    }
}

Describe 'Get-BecTenantCapabilities' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null }

    It 'queries nothing when declined' {
        Mock Read-Host { 'n' }
        Mock Get-MgSubscribedSku {}
        Get-BecTenantCapabilities
        Should -Invoke Get-MgSubscribedSku -Times 0
    }

    It 'records <Level> for <Plans>' -ForEach @(
        @{ Plans = @('EXCHANGE_S_STANDARD'); Level = 'none' }
        @{ Plans = @('EXCHANGE_S_STANDARD', 'AAD_PREMIUM'); Level = 'P1' }
        @{ Plans = @('AAD_PREMIUM', 'AAD_PREMIUM_P2'); Level = 'P2' }
    ) {
        Mock Read-Host { 'y' }
        Mock Get-MgSubscribedSku {
            [pscustomobject]@{ CapabilityStatus = 'Enabled'; ServicePlans = @($Plans | ForEach-Object { [pscustomobject]@{ ServicePlanName = $_; ProvisioningStatus = 'Success' } }) }
        }
        Get-BecTenantCapabilities
        (Get-BecCase).entraPremium | Should -Be $Level
    }

    It 'ignores suspended subscriptions and disabled plans' {
        Mock Read-Host { 'y' }
        Mock Get-MgSubscribedSku {
            [pscustomobject]@{ CapabilityStatus = 'Suspended'; ServicePlans = @([pscustomobject]@{ ServicePlanName = 'AAD_PREMIUM_P2'; ProvisioningStatus = 'Success' }) }
            [pscustomobject]@{ CapabilityStatus = 'Enabled'; ServicePlans = @([pscustomobject]@{ ServicePlanName = 'AAD_PREMIUM'; ProvisioningStatus = 'Disabled' }) }
        }
        Get-BecTenantCapabilities
        (Get-BecCase).entraPremium | Should -Be 'none'
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

    It 'explains the portal export and saves nothing when the tenant has no P1/P2' {
        Mock Get-MgBetaAuditLogSignIn { throw "Tenant is not a B2C tenant and doesn't have premium license Status: 403 (Forbidden) ErrorCode: Authentication_RequestFromNonPremiumTenantOrB2CTenant" }
        Get-TestWarnings { Get-BecSignIns } | Should -Match 'no Entra ID P1 or P2'
        Get-ChildItem (Join-Path $BecCaseDir 'evidence') -Filter 'signins-*' | Should -BeNullOrEmpty
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'Import-BecSignInExport' }
        Get-TestLog | Should -Match 'not available through Graph'
    }

    It 'still throws other errors' {
        Mock Get-MgBetaAuditLogSignIn { throw 'Insufficient privileges to complete the operation.' }
        { Get-BecSignIns 3>$null } | Should -Throw '*Insufficient privileges*'
    }

    It 'does not query Graph when case.json records no P1/P2' {
        Set-BecCaseValue entraPremium 'none'
        Get-TestWarnings { Get-BecSignIns } | Should -Match 'no Entra ID P1/P2'
        Should -Invoke Get-MgBetaAuditLogSignIn -Times 0
        Should -Invoke Read-Host -Times 0
    }
}

Describe 'Import-BecSignInExport' -Tag Unit {
    BeforeAll {
        # The shape of the Entra admin centre's JSON download (camelCase), trimmed.
        function New-ExportRow([string]$Id, [string]$Upn, [string]$When, [string]$Ip, [int]$Code, [int]$Asn = 64500, [string]$Device = 'LAPTOP-1') {
            [ordered]@{
                id = $Id; createdDateTime = $When; userPrincipalName = $Upn; appDisplayName = 'Microsoft Office'; ipAddress = $Ip
                autonomousSystemNumber = $Asn; authenticationProtocol = 'none'; isInteractive = $false; clientAppUsed = 'Mobile Apps and Desktop clients'
                location = [ordered]@{ city = 'London'; countryOrRegion = 'GB' }; status = [ordered]@{ errorCode = $Code; failureReason = 'x' }
                deviceDetail = [ordered]@{ displayName = $Device; operatingSystem = 'Windows10'; browser = '' }; userAgent = ''
            }
        }
    }

    BeforeEach {
        $dir = New-TestCase
        @(
            New-ExportRow '1' 'jane@contoso.com' '2025-01-06T08:00:00Z' '2001:db8:1234::5' 0
            New-ExportRow '2' 'jane@contoso.com' '2025-01-06T09:00:00Z' '198.51.100.23' 0 64511 ''
            New-ExportRow '3' 'jane@contoso.com' '2025-01-06T20:00:00Z' '2001:db8:1234::5' 50057
            New-ExportRow '4' 'jane@contoso.com' '2025-01-07T09:00:00Z' '2001:db8:1234::6' 50173
            New-ExportRow '5' 'jane@contoso.com' '2025-01-07T10:00:00Z' '2001:db8:1234::7' 0 64500 'DESKTOP-2'
            New-ExportRow '6' 'bob@contoso.com' '2025-01-06T08:30:00Z' '192.0.2.10' 0
        ) | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $dir 'evidence/NonInteractiveSignIns_2025-01-01_2025-01-07.json')
        '[]' | Set-Content (Join-Path $dir 'evidence/InteractiveSignIns_2025-01-01_2025-01-07.json')
    }

    It 'reads nothing when declined' {
        Mock Read-Host { 'n' }
        Import-BecSignInExport 'evidence/*SignIns_*.json' | Should -BeNullOrEmpty
        Get-ChildItem (Join-Path $BecCaseDir 'evidence') -Filter 'signins-export-*' | Should -BeNullOrEmpty
    }

    It 'keeps only the case mailbox, converts the rows and saves a CSV' {
        Mock Read-Host { 'y' }
        $rows = Import-BecSignInExport 'evidence/InteractiveSignIns_*.json', 'evidence/NonInteractiveSignIns_*.json'
        $rows | Should -HaveCount 5
        $rows.User | Sort-Object -Unique | Should -Be 'jane@contoso.com'
        $rows[0].DateUtc | Should -Be '2025-01-06T08:00:00Z'
        $rows[0].KnownGood | Should -BeTrue
        ($rows | Where-Object IpAddress -eq '198.51.100.23').Asn | Should -Be 64511
        ($rows | Where-Object ErrorCode -eq 50057).Country | Should -Be 'GB'
        Get-ChildItem (Join-Path $BecCaseDir 'evidence') -Filter 'signins-export-*.csv' | Should -HaveCount 1
        Get-TestLog | Should -Match 'Imported 5 sign-ins for jane@contoso.com'
    }

    It 'warns and asks nothing when no file matches' {
        Mock Read-Host { 'y' }
        Get-TestWarnings { Import-BecSignInExport 'evidence/nothing-*.json' } | Should -Match 'No files match'
        Should -Invoke Read-Host -Times 0
    }

    It 'skips files that are not JSON' {
        Mock Read-Host { 'y' }
        'a,b' | Set-Content (Join-Path $BecCaseDir 'evidence/export.csv')
        Get-TestWarnings { Import-BecSignInExport 'evidence/export.csv' } | Should -Match 'only the portal''s JSON download'
    }
}

Describe 'Show-BecSignInSummary' -Tag Unit {
    BeforeEach { New-TestCase | Out-Null }

    It 'shows when containment took effect and the successful sign-ins after it' {
        $rows = @(
            [pscustomobject]@{ DateUtc = '2025-01-06T20:00:00Z'; IpAddress = '2001:db8:1234::5'; KnownGood = $true; ErrorCode = 50057; Asn = 64500; Country = 'GB'; App = 'Office'; Device = 'LAPTOP-1'; OS = 'Windows10'; AuthProtocol = 'none' }
            [pscustomobject]@{ DateUtc = '2025-01-07T09:00:00Z'; IpAddress = '2001:db8:1234::6'; KnownGood = $true; ErrorCode = 50173; Asn = 64500; Country = 'GB'; App = 'Office'; Device = 'LAPTOP-1'; OS = 'Windows10'; AuthProtocol = 'none' }
            [pscustomobject]@{ DateUtc = '2025-01-07T10:00:00Z'; IpAddress = '2001:db8:1234::7'; KnownGood = $true; ErrorCode = 0; Asn = 64500; Country = 'GB'; App = 'Windows Sign In'; Device = 'DESKTOP-2'; OS = 'Windows'; AuthProtocol = 'none' }
        )
        Show-BecSignInSummary $rows
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'Containment taking effect' }
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match '1 successful sign-in\(s\) after containment began \(2025-01-06T20:00:00Z\)' }
    }

    It 'warns about device code sign-ins' {
        $rows = @([pscustomobject]@{ DateUtc = '2025-01-06T08:00:00Z'; IpAddress = '198.51.100.23'; KnownGood = $false; ErrorCode = 0; Asn = 64511; Country = 'NL'; App = 'Office'; AuthProtocol = 'deviceCode' })
        Get-TestWarnings { Show-BecSignInSummary $rows } | Should -Match 'device code'
    }

    It 'copes with no rows' {
        { Show-BecSignInSummary @() } | Should -Not -Throw
    }
}

Describe 'Get-BecIdentityReview' -Tag Unit {
    BeforeEach {
        New-TestCase | Out-Null
        Mock Get-MgContext { [pscustomobject]@{ Account = 'admin@contoso.com'; TenantId = 'tid-1' } }
        Mock Get-MgUserAuthenticationMethod {
            [pscustomobject]@{ Id = 'm1'; CreatedDateTime = (Get-Date).AddDays(-2); AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; phoneNumber = '+44 7700 900000' } }
            [pscustomobject]@{ Id = 'm2'; CreatedDateTime = $null; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.emailAuthenticationMethod'; emailAddress = 'jane@example.net' } }
            [pscustomobject]@{ Id = 'm3'; CreatedDateTime = $null; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.softwareOathAuthenticationMethod'; createdDateTime = '2020-01-01T00:00:00Z' } }
        }
        Mock Get-MgUserRegisteredDevice { [pscustomobject]@{ Id = 'd1'; AdditionalProperties = @{ displayName = 'DESKTOP-1'; operatingSystem = 'Windows'; registrationDateTime = '2020-05-01T10:00:00Z' } } }
        Mock Get-MgUserOwnedDevice { [pscustomobject]@{ Id = 'd1'; AdditionalProperties = @{ displayName = 'DESKTOP-1' } } }
        Mock Get-MgUserOauth2PermissionGrant {
            [pscustomobject]@{ Id = 'g1'; ClientId = 'sp1'; Scope = ' Mail.Read offline_access'; ConsentType = 'Principal' }
            [pscustomobject]@{ Id = 'g2'; ClientId = 'sp2'; Scope = 'User.Read'; ConsentType = 'AllPrincipals' }
        }
        Mock Get-MgServicePrincipal -ParameterFilter { $ServicePrincipalId -eq 'sp1' } { [pscustomobject]@{ DisplayName = 'Suspicious App'; AppId = 'a1'; AppOwnerOrganizationId = 'other-tenant'; VerifiedPublisher = @{ DisplayName = $null } } }
        Mock Get-MgServicePrincipal -ParameterFilter { $ServicePrincipalId -eq 'sp2' } { [pscustomobject]@{ DisplayName = 'Office'; AppId = 'a2'; AppOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; VerifiedPublisher = @{ DisplayName = 'Microsoft Corporation' } } }
        Mock Get-MgUserAppRoleAssignment { @() }
    }

    It 'exports methods, devices, consents and app assignments, and flags what needs checking' {
        Mock Read-Host { 'y' }
        Get-BecIdentityReview
        $dir = Get-ChildItem (Join-Path $BecCaseDir 'evidence') -Directory -Filter 'identity-*'

        $methods = Import-Csv (Join-Path $dir 'auth_methods.csv')
        $phone = $methods | Where-Object Type -eq 'phoneAuthenticationMethod'
        $phone.CreatedUtc | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$'
        $phone.Flag | Should -Match 'added in the last 30 days'
        ($methods | Where-Object Type -eq 'emailAuthenticationMethod').Flag | Should -Match 'outside email'
        ($methods | Where-Object Type -eq 'softwareOathAuthenticationMethod').CreatedUtc | Should -Be '2020-01-01T00:00:00Z'

        $devices = Import-Csv (Join-Path $dir 'devices.csv')
        $devices | Should -HaveCount 1
        $devices.Flag | Should -BeNullOrEmpty

        $grants = Import-Csv (Join-Path $dir 'oauth_grants.csv')
        $suspicious = $grants | Where-Object App -eq 'Suspicious App'
        $suspicious.Owner | Should -Be 'third party'
        $suspicious.Flag | Should -Match 'can read mail'
        $suspicious.Scope | Should -Be 'Mail.Read offline_access'
        $office = $grants | Where-Object App -eq 'Office'
        $office.Owner | Should -Be 'Microsoft'
        $office.VerifiedPublisher | Should -Be 'Microsoft Corporation'
        $office.ConsentedFor | Should -Match 'admin consent'
        $office.Flag | Should -BeNullOrEmpty

        Get-TestLog | Should -Match '\(4 flagged\)'
    }

    It 'queries nothing when declined' {
        Mock Read-Host { 'n' }
        Get-BecIdentityReview
        Should -Invoke Get-MgUserAuthenticationMethod -Times 0
    }
}
