# Microsoft Graph helpers for BEC response: containment, identity review and sign-in logs.
# Load in a Graph-only session:
#   scripts/bec-shell.sh graph <case-dir>
# Never import ExchangeOnlineManagement into this session (MSAL version conflict).
#
# Every step function starts with Confirm-BecStep, which describes the step and asks the
# admin to proceed. -Force skips that prompt; it is meant for calls from inside another step.

. (Join-Path $PSScriptRoot 'BecCommon.ps1')

$global:BecGraphScopes = @(
    'User.ReadWrite.All',
    'UserAuthenticationMethod.ReadWrite.All',
    'Directory.Read.All',
    'AuditLog.Read.All',
    'Application.Read.All',
    'Policy.Read.All'
)

# -Tenant (a tenant ID or any of its domains, e.g. contoso.onmicrosoft.com) makes the sign-in land
# in the client's tenant even when the admin account is a guest or partner from elsewhere. Without
# it, Graph signs in to the admin account's home tenant. Both -Tenant and -AdminUpn default to
# "tenant" and "adminUpn" in case.json.
function Connect-BecGraph {
    param([string]$Tenant, [string]$AdminUpn, [int]$TimeoutSeconds = 900, [switch]$Device, [switch]$Force)
    $case = Get-BecCase
    if (-not $Tenant) { $Tenant = $case.tenant }
    if (-not $AdminUpn) { $AdminUpn = $case.adminUpn }
    $how = if ($Device) { 'device code sign-in (enter a code at microsoft.com/devicelogin)' } else { 'browser sign-in (open the printed URL in your host browser)' }
    $target = @(
        if ($Tenant) { "tenant $Tenant" } else { "the admin account's home tenant (pass -Tenant, or set ""tenant"" in case.json, for a client tenant)" }
        if ($AdminUpn) { "as $AdminUpn" }
    ) -join ' '
    if (-not (Confirm-BecStep -Force:$Force -Step 'Connect to Microsoft Graph' `
            -Description "Signs in to Microsoft Graph in $target using $how, allowing $TimeoutSeconds seconds to finish, and requests these delegated permissions (an admin may need to consent the first time): $($global:BecGraphScopes -join ', '). Afterwards it checks the case mailbox's domain belongs to the tenant it reached.")) { return }

    $params = @{ Scopes = $global:BecGraphScopes; NoWelcome = $true; ClientTimeout = $TimeoutSeconds }
    if ($Tenant) { $params.TenantId = $Tenant }
    if ($Device) { $params.UseDeviceCode = $true } elseif ($AdminUpn) { $params.LoginHint = $AdminUpn }
    try { Connect-MgGraph @params -ErrorAction Stop }
    catch { Write-BecLog "Microsoft Graph sign-in failed: $($_.Exception.Message)"; Write-Warning (Get-BecSignInRetryHint 'Connect-BecGraph' -HasTimeout); return }

    $ctx = Get-MgContext
    if (-not $ctx.Account) {
        Write-BecLog 'Microsoft Graph sign-in did not complete (timed out or cancelled)'
        Write-Warning (Get-BecSignInRetryHint 'Connect-BecGraph' -HasTimeout)
        return
    }
    Write-BecLog "Connected to Microsoft Graph as $($ctx.Account) (tenant $($ctx.TenantId))"

    # Wrong-tenant guard: the tenant must own the case mailbox's domain.
    $domain = ((Resolve-BecUpn) -split '@')[-1]
    $domains = @((Get-MgOrganization).VerifiedDomains.Name)
    if ($domain -notin $domains) {
        Write-BecLog "WARNING: tenant $($ctx.TenantId) does not own $domain"
        Write-Warning "This tenant ($($ctx.TenantId)) does not own $domain, so it is probably the wrong tenant. Run Disconnect-MgGraph, then Connect-BecGraph -Tenant <the client's tenant, e.g. contoso.onmicrosoft.com>."
    } elseif ($case.tenantId -and $case.tenantId -ne $ctx.TenantId) {
        Write-Warning "case.json records tenant $($case.tenantId), but this session is in $($ctx.TenantId)."
    } elseif (-not $case.tenantId) {
        Set-BecCaseValue tenantId $ctx.TenantId
    }
}

#region 02 - Contain

# Blocks sign-in and revokes every refresh token and session cookie (any flow, including
# device code). Reset the password in the Entra admin centre while sign-in is blocked.
function Invoke-BecContainment {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Upn, [switch]$SkipBlock, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    $changes = @()
    if (-not $SkipBlock) { $changes += "Block sign-in for $Upn (AccountEnabled = false): the user is also locked out until Enable-BecSignIn" }
    $changes += "Revoke all sign-in sessions for ${Upn}: every device and app, including the user's, must sign in again"
    if (-not (Confirm-BecStep -Force:$Force -Step "02 Contain $Upn" `
            -Description 'Cuts off the attacker: stops new sign-ins and invalidates every refresh token and session cookie, however it was obtained (browser, app, device code, stolen token).' `
            -Changes $changes)) { return }

    if (-not $SkipBlock -and $PSCmdlet.ShouldProcess($Upn, 'Block sign-in (AccountEnabled = false)')) {
        Update-MgUser -UserId $Upn -AccountEnabled:$false
        Write-BecLog "Blocked sign-in for $Upn"
    }
    if ($PSCmdlet.ShouldProcess($Upn, 'Revoke all sign-in sessions')) {
        Revoke-MgUserSignInSession -UserId $Upn | Out-Null
        Write-BecLog "Revoked sign-in sessions for $Upn"
    }
    Write-Host @"

Next, in the Entra admin centre:
  1. Reset the password for $Upn (Users > $Upn > Reset password).
  2. Run Get-BecIdentityReview and remove anything the attacker added.
  3. Re-enable sign-in with Enable-BecSignIn once the user is ready to sign in with the new password.
"@ -ForegroundColor Yellow
}

function Enable-BecSignIn {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Upn, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    if (-not (Confirm-BecStep -Force:$Force -Step "02 Re-enable sign-in for $Upn" `
            -Description 'Lets the user sign in again. Only do this once the password has been reset and the identity review found nothing left from the attacker.' `
            -Changes "Enable sign-in for $Upn (AccountEnabled = true)")) { return }

    if ($PSCmdlet.ShouldProcess($Upn, 'Enable sign-in (AccountEnabled = true)')) {
        Update-MgUser -UserId $Upn -AccountEnabled:$true
        Write-BecLog "Re-enabled sign-in for $Upn"
    }
}

#endregion

#region 02 - Identity review

# Tenants that own Microsoft's first-party apps.
$global:BecMicrosoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')
# Delegated scopes that let an app read or act on mail, files or contacts.
$global:BecSensitiveScopePattern = '(^|\s)(Mail\.|MailboxSettings\.|EAS\.|EWS\.|IMAP\.|POP\.|SMTP\.|Files\.|Sites\.|Contacts\.|Notes\.|full_access)'

function Get-BecIdentityReview {
    param([string]$Upn, [int]$RecentDays = 30, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    $dir = "evidence/identity-$(Get-BecTimestamp)"
    if (-not (Confirm-BecStep -Force:$Force -Step "02 Identity review for $Upn" `
            -Description "Lists the things that survive a password reset and session revoke: MFA methods, registered and owned devices, delegated OAuth app consents and enterprise app assignments, and flags anything added in the last $RecentDays days, outside password-reset emails and apps that can read mail or files. Remove anything unfamiliar in the Entra admin centre." `
            -Writes "$dir/")) { return }

    $domain = ($Upn -split '@')[-1]
    $tenantId = "$((Get-MgContext).TenantId)"
    $recent = (Get-Date).ToUniversalTime().AddDays(-$RecentDays)

    $methods = Get-MgUserAuthenticationMethod -UserId $Upn | ForEach-Object {
        $p = $_.AdditionalProperties
        $type = "$($p['@odata.type'])" -replace '#microsoft.graph.', ''
        # Current Graph modules return CreatedDateTime as a typed property; older ones in AdditionalProperties.
        $created = if ($_.CreatedDateTime) { $_.CreatedDateTime } else { $p.createdDateTime }
        $flags = @(
            if ($created -and [datetime]$created -ge $recent) { "added in the last $RecentDays days" }
            if ($p.emailAddress -and ($p.emailAddress -split '@')[-1] -ne $domain) { 'outside email address: it can reset the password' }
            if ($type -eq 'softwareOathAuthenticationMethod') { 'code app (TOTP): confirm the user set it up' }
        )
        [pscustomobject]@{
            Type       = $type
            Detail     = @($p.displayName, $p.phoneNumber, $p.emailAddress, $p.model, $p.deviceTag) | Where-Object { $_ } | Select-Object -First 1
            CreatedUtc = ConvertTo-BecUtc $created
            Flag       = $flags -join '; '
            Id         = $_.Id
        }
    }

    $devices = @(Get-MgUserRegisteredDevice -UserId $Upn -All) + @(Get-MgUserOwnedDevice -UserId $Upn -All) |
        Sort-Object Id -Unique | ForEach-Object {
            $p = $_.AdditionalProperties
            [pscustomobject]@{
                DisplayName     = $p.displayName
                OperatingSystem = "$($p.operatingSystem) $($p.operatingSystemVersion)"
                TrustType       = $p.trustType
                RegisteredUtc   = ConvertTo-BecUtc $p.registrationDateTime
                LastSignInUtc   = ConvertTo-BecUtc $p.approximateLastSignInDateTime
                Flag            = if ($p.registrationDateTime -and [datetime]$p.registrationDateTime -ge $recent) { "registered in the last $RecentDays days" } else { '' }
                Id              = $_.Id
            }
        }

    $grants = Get-MgUserOauth2PermissionGrant -UserId $Upn -All | ForEach-Object {
        $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId -ErrorAction SilentlyContinue
        $ownerId = "$($sp.AppOwnerOrganizationId)"
        $scope = @($_.Scope -split '\s+' | Where-Object { $_ }) -join ' '
        [pscustomobject]@{
            App               = $sp.DisplayName
            AppId             = $sp.AppId
            Owner             = if (-not $sp) { 'unknown (app not found)' } elseif ($ownerId -in $global:BecMicrosoftTenantIds) { 'Microsoft' } elseif ($ownerId -and $ownerId -eq $tenantId) { 'this tenant' } else { 'third party' }
            VerifiedPublisher = $sp.VerifiedPublisher.DisplayName
            ConsentedFor      = if ($_.ConsentType -eq 'AllPrincipals') { 'all users (admin consent)' } else { 'this user' }
            Flag              = if ($scope -match $global:BecSensitiveScopePattern) { 'can read mail or files: confirm the user uses it' } else { '' }
            Scope             = $scope
            GrantId           = $_.Id
        }
    }

    $appRoles = Get-MgUserAppRoleAssignment -UserId $Upn -All |
        Select-Object ResourceDisplayName, @{ n = 'CreatedUtc'; e = { ConvertTo-BecUtc $_.CreatedDateTime } }, PrincipalDisplayName, Id

    $methods | Export-Csv (Get-BecPath "$dir/auth_methods.csv") -NoTypeInformation
    $devices | Export-Csv (Get-BecPath "$dir/devices.csv") -NoTypeInformation
    $grants | Export-Csv (Get-BecPath "$dir/oauth_grants.csv") -NoTypeInformation
    $appRoles | Export-Csv (Get-BecPath "$dir/app_role_assignments.csv") -NoTypeInformation

    Write-Host "`nAuthentication methods (look for phones/apps the user does not recognise, recent CreatedUtc)" -ForegroundColor Yellow
    $methods | Format-Table Type, Detail, CreatedUtc -AutoSize | Out-String -Width 300 | Out-Host
    Write-Host 'Devices (look for registrations during the compromise window)' -ForegroundColor Yellow
    $devices | Sort-Object RegisteredUtc -Descending | Format-Table DisplayName, OperatingSystem, TrustType, RegisteredUtc, LastSignInUtc -AutoSize | Out-String -Width 300 | Out-Host
    Write-Host 'Delegated OAuth consents (an app keeps this access after a password reset)' -ForegroundColor Yellow
    $grants | Format-List App, Owner, VerifiedPublisher, ConsentedFor, Flag, Scope | Out-String -Width 300 | Out-Host
    Write-Host 'Enterprise app assignments' -ForegroundColor Yellow
    $appRoles | Sort-Object CreatedUtc -Descending | Format-Table -AutoSize | Out-String -Width 300 | Out-Host

    $flagged = @(@($methods) + @($devices) + @($grants) | Where-Object { $_.Flag })
    if ($flagged) {
        Write-Host "$($flagged.Count) item(s) flagged: confirm each one with the user." -ForegroundColor Yellow
        foreach ($item in $flagged) {
            $name = @($item.App, $item.DisplayName, $item.Detail, $item.Type) | Where-Object { $_ } | Select-Object -First 1
            Write-Host "  - ${name}: $($item.Flag)" -ForegroundColor Yellow
        }
    }
    Write-BecLog "Identity review of $Upn saved to $dir ($($flagged.Count) flagged)"
}

#endregion

#region 02 - Tenant capabilities

# Which checks work depends on the tenant's licences. Run once per case, after connecting.
function Get-BecTenantCapabilities {
    param([switch]$Force)
    if (-not (Confirm-BecStep -Force:$Force -Step '02 Tenant licences' `
            -Description 'Reads the tenant''s subscriptions to see which checks will work: Entra ID P1 or P2 lets Graph read sign-in logs (Get-BecSignIns), P2 adds sign-in risk. Records the result as "entraPremium" in case.json.' `
            -Writes 'case.json (entraPremium)')) { return }

    $plans = @(Get-MgSubscribedSku -All | Where-Object { $_.CapabilityStatus -in 'Enabled', 'Warning' } |
        ForEach-Object { $_.ServicePlans } | Where-Object { $_.ProvisioningStatus -eq 'Success' } | ForEach-Object { $_.ServicePlanName })
    $level = if ($plans -contains 'AAD_PREMIUM_P2') { 'P2' } elseif ($plans -contains 'AAD_PREMIUM') { 'P1' } else { 'none' }
    Set-BecCaseValue entraPremium $level

    $premium = $level -ne 'none'
    @(
        [pscustomobject]@{ Capability = 'Sign-in logs through Graph (Get-BecSignIns)'; Available = $premium; Otherwise = 'Export from the portal and use Import-BecSignInExport' }
        [pscustomobject]@{ Capability = 'Sign-in log history in the portal'; Available = if ($premium) { '30 days' } else { '7 days' }; Otherwise = 'Export it today; the Exchange audit log keeps sign-ins longer' }
        [pscustomobject]@{ Capability = 'Sign-in risk details'; Available = $level -eq 'P2'; Otherwise = 'Risk columns read "hidden"' }
    ) | Format-Table -AutoSize -Wrap | Out-String -Width 300 | Out-Host
    if (-not $premium) { Write-Host $global:BecPortalSignInExportHelp -ForegroundColor Yellow }
}

#endregion

#region 05 - Sign-in logs

# Entra error codes that show containment taking effect.
$global:BecContainmentErrorCodes = @{
    50057 = 'account disabled (sign-in blocked)'
    50173 = 'old session refused: tokens revoked or password changed'
    50133 = 'old session refused: password changed'
}

$global:BecPortalSignInExportHelp = @'
Without Entra ID P1 or P2, Graph cannot read sign-in logs, but the Entra admin centre shows the last 7 days. Export them now, before they age out:
  1. Entra admin centre > Monitoring & health > Sign-in logs, Date: last 7 days.
  2. Download > JSON, on both the "User sign-ins (interactive)" and "User sign-ins (non-interactive)" tabs.
  3. Copy the downloaded files into the case's evidence/ folder (the container only sees the case folder).
  4. $signins = Import-BecSignInExport evidence/InteractiveSignIns_*.json, evidence/NonInteractiveSignIns_*.json
The Exchange audit log (Get-BecAuditLog) also records sign-ins (UserLoggedIn, UserLoginFailed) and keeps them longer.
'@

# One row per sign-in, from Graph objects or the portal's JSON export (PowerShell property names
# are case-insensitive, so both shapes work).
function ConvertTo-BecSignInRow {
    param([Parameter(Mandatory, ValueFromPipeline)]$SignIn, [string[]]$KnownGood = @())
    process {
        $s = $SignIn
        [pscustomobject]@{
            DateUtc       = ConvertTo-BecUtc $s.CreatedDateTime
            User          = $s.UserPrincipalName
            IpAddress     = $s.IpAddress
            KnownGood     = Test-BecKnownGoodIp $s.IpAddress $KnownGood
            Country       = $s.Location.CountryOrRegion
            City          = $s.Location.City
            Asn           = $s.AutonomousSystemNumber
            App           = $s.AppDisplayName
            ClientApp     = $s.ClientAppUsed
            AuthProtocol  = $s.AuthenticationProtocol
            Interactive   = $s.IsInteractive
            ErrorCode     = [int]$s.Status.ErrorCode
            FailureReason = $s.Status.FailureReason
            Device        = $s.DeviceDetail.DisplayName
            Browser       = $s.DeviceDetail.Browser
            OS            = $s.DeviceDetail.OperatingSystem
            UserAgent     = $s.UserAgent
        }
    }
}

# Local analysis of sign-in rows already retrieved; no tenant call.
function Show-BecSignInSummary {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)
    if (-not $Rows) { Write-Host 'No sign-ins to summarise.'; return }
    $Rows = @($Rows | Sort-Object DateUtc)
    Write-Host "$($Rows.Count) sign-ins from $($Rows[0].DateUtc) to $($Rows[-1].DateUtc) (UTC)"

    $deviceCode = @($Rows | Where-Object { $_.AuthProtocol -match 'deviceCode' })
    if ($deviceCode) { Write-Warning "$($deviceCode.Count) sign-in(s) used the device code flow. Check whether the user expected these." }

    $refused = @($Rows | Where-Object { $_.ErrorCode -in $global:BecContainmentErrorCodes.Keys })
    if ($refused) {
        Write-Host "`nContainment taking effect" -ForegroundColor Yellow
        $refused | Group-Object ErrorCode | ForEach-Object {
            [pscustomobject]@{
                ErrorCode = $_.Name
                Meaning   = $global:BecContainmentErrorCodes[[int]$_.Name]
                Count     = $_.Count
                FirstUtc  = $_.Group[0].DateUtc
                LastUtc   = $_.Group[-1].DateUtc
            }
        } | Sort-Object FirstUtc | Format-Table -AutoSize | Out-String -Width 300 | Out-Host
        $since = $refused[0].DateUtc
        $after = @($Rows | Where-Object { $_.DateUtc -gt $since -and $_.ErrorCode -eq 0 })
        if ($after) {
            Write-Host "$($after.Count) successful sign-in(s) after containment began ($since). Confirm they are the user with the new password:" -ForegroundColor Yellow
            $after | Group-Object IpAddress | ForEach-Object {
                [pscustomobject]@{
                    IpAddress = $_.Name
                    KnownGood = $_.Group[0].KnownGood
                    FirstUtc  = $_.Group[0].DateUtc
                    Count     = $_.Count
                    Devices   = @($_.Group | ForEach-Object { if ($_.Device) { $_.Device } else { $_.OS } } | Sort-Object -Unique) -join ', '
                    Apps      = @($_.Group.App | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 -ExpandProperty Name) -join ', '
                }
            } | Format-Table -AutoSize | Out-String -Width 300 | Out-Host
        }
    }

    # IPv6 addresses rotate within a home or mobile connection, so group by network instead of by IP.
    Write-Host "`nSign-ins from unknown IPs, grouped by network (ASN) and country" -ForegroundColor Yellow
    $Rows | Where-Object { -not $_.KnownGood } | Group-Object { "$($_.Asn)|$($_.Country)" } | ForEach-Object {
        $g = $_.Group
        $ok = @($g | Where-Object { $_.ErrorCode -eq 0 }).Count
        [pscustomobject]@{
            Network  = if ($g[0].Asn) { "AS$($g[0].Asn)" } else { '-' }
            Country  = $g[0].Country
            IPs      = @($g.IpAddress | Sort-Object -Unique).Count
            Success  = $ok
            Failed   = $g.Count - $ok
            FirstUtc = $g[0].DateUtc
            LastUtc  = $g[-1].DateUtc
            Devices  = @($g | ForEach-Object { if ($_.Device) { $_.Device } else { $_.OS } } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 4) -join ', '
            Apps     = @($g.App | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 -ExpandProperty Name) -join ', '
        }
    } | Sort-Object FirstUtc | Format-Table -AutoSize | Out-String -Width 300 | Out-Host
    $good = @($Rows | Where-Object KnownGood).Count
    if ($good) { Write-Host "$good sign-in(s) from known-good networks not shown." }
}

# Sign-in logs through Graph need Entra ID P1 or P2. Without it, export them from the portal and
# use Import-BecSignInExport. This uses the beta API on purpose: v1.0 has no AuthenticationProtocol
# (device code detection), AutonomousSystemNumber or signInEventTypes (non-interactive sign-ins).
function Get-BecSignIns {
    param([string]$Upn, [int]$Days = 30, [switch]$IncludeNonInteractive, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    if ((Get-BecCase).entraPremium -eq 'none') {
        Write-Warning 'case.json records no Entra ID P1/P2 (Get-BecTenantCapabilities), so Graph cannot read sign-in logs.'
        Write-Host $global:BecPortalSignInExportHelp -ForegroundColor Yellow
        return
    }
    $file = "evidence/signins-$(Get-BecTimestamp).csv"
    if (-not (Confirm-BecStep -Force:$Force -Step "05 Sign-in logs for $Upn" `
            -Description "Pulls $Upn's sign-ins for the last $Days days$(if ($IncludeNonInteractive) { ', including non-interactive sign-ins (where stolen-token replay shows up)' }), flags device code sign-ins, shows when containment took effect and groups sign-ins from unknown networks. Needs Entra ID P1 or P2." `
            -Writes $file)) { return }

    $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $base = "userPrincipalName eq '$Upn' and createdDateTime ge $since"
    try {
        $raw = @(Get-MgBetaAuditLogSignIn -Filter $base -All -ErrorAction Stop)
        if ($IncludeNonInteractive) {
            # AiTM token replay usually shows up as non-interactive sign-ins.
            $raw += @(Get-MgBetaAuditLogSignIn -Filter "$base and signInEventTypes/any(t: t eq 'nonInteractiveUser')" -All -ErrorAction Stop)
        }
    } catch {
        if ("$_" -notmatch 'RequestFromNonPremiumTenant|premium license') { throw }
        Write-BecLog 'Sign-in logs not available through Graph: the tenant has no Entra ID P1/P2'
        Write-Warning 'This tenant has no Entra ID P1 or P2, so Graph cannot read its sign-in logs. Nothing was saved.'
        Write-Host $global:BecPortalSignInExportHelp -ForegroundColor Yellow
        return
    }

    $rows = @($raw | Sort-Object Id -Unique | ConvertTo-BecSignInRow -KnownGood (Get-BecKnownGoodPrefixes) | Sort-Object DateUtc)
    $rows | Export-Csv (Get-BecPath $file) -NoTypeInformation
    Write-Host "$($rows.Count) sign-ins saved to $file" -ForegroundColor Green
    Show-BecSignInSummary $rows
    $rows
}

# The portal's sign-in log download (JSON) for tenants without P1/P2, or for history Graph
# no longer returns. Exports cover every user in the tenant; only the case mailbox is kept.
function Import-BecSignInExport {
    param([Parameter(Mandatory)][string[]]$Path, [string]$Upn, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    $files = @(foreach ($p in $Path) {
            $full = if ([IO.Path]::IsPathRooted($p)) { $p } else { Join-Path $global:BecCaseDir $p }
            Get-ChildItem -Path $full -File -ErrorAction SilentlyContinue
        })
    if (-not $files) {
        Write-Warning "No files match $($Path -join ', '). Copy the portal's JSON downloads into the case's evidence/ folder first: the container only sees the case folder."
        return
    }
    $out = "evidence/signins-export-$(Get-BecTimestamp).csv"
    if (-not (Confirm-BecStep -Force:$Force -Step "05 Import sign-in log export for $Upn" `
            -Description "Reads $($files.Count) sign-in log download(s) from the Entra admin centre ($($files.Name -join ', ')), keeps $Upn's sign-ins and summarises them the same way as Get-BecSignIns. The tenant is not contacted." `
            -Writes $out)) { return }

    $raw = @(foreach ($f in $files) {
            if ($f.Extension -ne '.json') { Write-Warning "$($f.Name): only the portal's JSON download is supported (Download > JSON). Skipped."; continue }
            Get-Content $f.FullName -Raw | ConvertFrom-Json
        })
    $mine = @($raw | Where-Object { $_.userPrincipalName -eq $Upn })
    if ($raw.Count -gt $mine.Count) { Write-Host "Ignored $($raw.Count - $mine.Count) sign-in(s) by other users in the export." }

    $rows = @($mine | Sort-Object id -Unique | ConvertTo-BecSignInRow -KnownGood (Get-BecKnownGoodPrefixes) | Sort-Object DateUtc)
    $rows | Export-Csv (Get-BecPath $out) -NoTypeInformation
    Write-BecLog "Imported $($rows.Count) sign-ins for $Upn from $($files.Name -join ', ') into $out"
    Show-BecSignInSummary $rows
    $rows
}

#endregion

function Show-BecHelp {
    @'

BEC Graph session. Case folder: /case (on the host: the case directory you passed in).
Each step describes what it will do and asks "Proceed? [y/N]" before touching the tenant.

  Connect-BecGraph [-Tenant contoso.onmicrosoft.com] [-AdminUpn admin@tenant] [-Device]
  Test-BecCommandSurface               after connecting: check every cmdlet/parameter exists
  Show-BecCase | Set-BecCaseValue <name> <value> | Add-BecCaseValue attackerIps <ip>

  02 Get-BecTenantCapabilities         which checks this tenant's licences allow
     Invoke-BecContainment              Get-BecIdentityReview
     Enable-BecSignIn
  05 $signins = Get-BecSignIns [-Days 30] [-IncludeNonInteractive]       needs Entra ID P1/P2
     $signins = Import-BecSignInExport evidence/InteractiveSignIns_*.json, evidence/NonInteractiveSignIns_*.json
     Show-BecSignInSummary $signins

Procedures: business-email-compromise/procedures/ in the repo.
'@ | Write-Host
}
