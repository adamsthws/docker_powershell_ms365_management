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

function Connect-BecGraph {
    param([switch]$Device, [switch]$Force)
    $how = if ($Device) { 'device code sign-in (enter a code at microsoft.com/devicelogin)' } else { 'browser sign-in (open the printed URL in your host browser)' }
    if (-not (Confirm-BecStep -Force:$Force -Step 'Connect to Microsoft Graph' `
            -Description "Signs in to Microsoft Graph using $how and requests these delegated permissions (an admin may need to consent the first time): $($global:BecGraphScopes -join ', ').")) { return }

    $params = @{ Scopes = $global:BecGraphScopes; NoWelcome = $true }
    if ($Device) { $params.UseDeviceCode = $true }
    Connect-MgGraph @params
    $ctx = Get-MgContext
    Write-BecLog "Connected to Microsoft Graph as $($ctx.Account) (tenant $($ctx.TenantId))"
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

function Get-BecIdentityReview {
    param([string]$Upn, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    $dir = "evidence/identity-$(Get-BecTimestamp)"
    if (-not (Confirm-BecStep -Force:$Force -Step "02 Identity review for $Upn" `
            -Description 'Lists the things that survive a password reset and session revoke: MFA methods, registered and owned devices, delegated OAuth app consents and enterprise app assignments. Remove anything unfamiliar in the Entra admin centre.' `
            -Writes "$dir/")) { return }

    $methods = Get-MgUserAuthenticationMethod -UserId $Upn | ForEach-Object {
        $p = $_.AdditionalProperties
        [pscustomobject]@{
            Type        = "$($p['@odata.type'])" -replace '#microsoft.graph.', ''
            Detail      = @($p.displayName, $p.phoneNumber, $p.emailAddress, $p.model, $p.deviceTag) | Where-Object { $_ } | Select-Object -First 1
            CreatedUtc  = $p.createdDateTime
            Id          = $_.Id
        }
    }

    $devices = @(Get-MgUserRegisteredDevice -UserId $Upn -All) + @(Get-MgUserOwnedDevice -UserId $Upn -All) |
        Sort-Object Id -Unique | ForEach-Object {
            $p = $_.AdditionalProperties
            [pscustomobject]@{
                DisplayName     = $p.displayName
                OperatingSystem = "$($p.operatingSystem) $($p.operatingSystemVersion)"
                TrustType       = $p.trustType
                RegisteredUtc   = $p.registrationDateTime
                LastSignInUtc   = $p.approximateLastSignInDateTime
                Id              = $_.Id
            }
        }

    $grants = Get-MgUserOauth2PermissionGrant -UserId $Upn -All | ForEach-Object {
        $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId -ErrorAction SilentlyContinue
        [pscustomobject]@{ App = $sp.DisplayName; AppId = $sp.AppId; Publisher = $sp.PublisherName; Scope = $_.Scope; GrantId = $_.Id }
    }

    $appRoles = Get-MgUserAppRoleAssignment -UserId $Upn -All |
        Select-Object ResourceDisplayName, CreatedDateTime, PrincipalDisplayName, Id

    $methods | Export-Csv (Get-BecPath "$dir/auth_methods.csv") -NoTypeInformation
    $devices | Export-Csv (Get-BecPath "$dir/devices.csv") -NoTypeInformation
    $grants | Export-Csv (Get-BecPath "$dir/oauth_grants.csv") -NoTypeInformation
    $appRoles | Export-Csv (Get-BecPath "$dir/app_role_assignments.csv") -NoTypeInformation

    Write-Host "`nAuthentication methods (look for phones/apps the user does not recognise, recent CreatedUtc)" -ForegroundColor Yellow
    $methods | Format-Table -AutoSize | Out-Host
    Write-Host 'Devices (look for registrations during the compromise window)' -ForegroundColor Yellow
    $devices | Format-Table -AutoSize | Out-Host
    Write-Host 'Delegated OAuth consents' -ForegroundColor Yellow
    $grants | Format-Table -AutoSize -Wrap | Out-Host
    Write-Host 'Enterprise app assignments' -ForegroundColor Yellow
    $appRoles | Format-Table -AutoSize | Out-Host

    Write-BecLog "Identity review of $Upn saved to $dir"
}

#endregion

#region 05 - Sign-in logs

# Sign-in logs through Graph need Entra ID P1 or P2. Without it, export them from the portal.
function Get-BecSignIns {
    param([string]$Upn, [int]$Days = 30, [switch]$IncludeNonInteractive, [switch]$Force)
    $Upn = Resolve-BecUpn $Upn
    $file = "evidence/signins-$(Get-BecTimestamp).csv"
    if (-not (Confirm-BecStep -Force:$Force -Step "05 Sign-in logs for $Upn" `
            -Description "Pulls $Upn's sign-ins for the last $Days days$(if ($IncludeNonInteractive) { ', including non-interactive sign-ins (where stolen-token replay shows up)' }), flags device code sign-ins and groups sign-ins from unknown IPs. Needs Entra ID P1 or P2." `
            -Writes $file)) { return }

    $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $base = "userPrincipalName eq '$Upn' and createdDateTime ge $since"

    $raw = @(Get-MgBetaAuditLogSignIn -Filter $base -All)
    if ($IncludeNonInteractive) {
        # AiTM token replay usually shows up as non-interactive sign-ins.
        $raw += @(Get-MgBetaAuditLogSignIn -Filter "$base and signInEventTypes/any(t: t eq 'nonInteractiveUser')" -All)
    }

    $knownGood = Get-BecKnownGoodPrefixes
    $rows = $raw | Sort-Object Id -Unique | ForEach-Object {
        [pscustomobject]@{
            DateUtc        = $_.CreatedDateTime
            IpAddress      = $_.IpAddress
            KnownGood      = Test-BecKnownGoodIp $_.IpAddress $knownGood
            Country        = $_.Location.CountryOrRegion
            City           = $_.Location.City
            App            = $_.AppDisplayName
            ClientApp      = $_.ClientAppUsed
            AuthProtocol   = $_.AuthenticationProtocol
            Interactive    = $_.IsInteractive
            ErrorCode      = $_.Status.ErrorCode
            FailureReason  = $_.Status.FailureReason
            Browser        = $_.DeviceDetail.Browser
            OS             = $_.DeviceDetail.OperatingSystem
            UserAgent      = $_.UserAgent
        }
    } | Sort-Object DateUtc

    $rows | Export-Csv (Get-BecPath $file) -NoTypeInformation
    Write-Host "$(@($rows).Count) sign-ins saved to $file" -ForegroundColor Green

    $deviceCode = $rows | Where-Object { $_.AuthProtocol -match 'deviceCode' }
    if ($deviceCode) { Write-Warning "$(@($deviceCode).Count) sign-in(s) used the device code flow. Check whether the user expected these." }

    Write-Host "`nSign-ins from unknown IPs, grouped" -ForegroundColor Yellow
    $rows | Where-Object { -not $_.KnownGood } | Group-Object IpAddress | ForEach-Object {
        $ok = @($_.Group | Where-Object { $_.ErrorCode -eq 0 }).Count
        [pscustomobject]@{
            IpAddress = $_.Name
            Country   = ($_.Group | Select-Object -First 1).Country
            Success   = $ok
            Failed    = $_.Count - $ok
            FirstUtc  = ($_.Group | Select-Object -First 1).DateUtc
            LastUtc   = ($_.Group | Select-Object -Last 1).DateUtc
            Apps      = @($_.Group.App | Sort-Object -Unique) -join ', '
        }
    } | Sort-Object FirstUtc | Format-Table -AutoSize -Wrap | Out-Host

    $rows
}

#endregion

function Show-BecHelp {
    @'

BEC Graph session. Case folder: /case (on the host: the case directory you passed in).
Each step describes what it will do and asks "Proceed? [y/N]" before touching the tenant.

  Connect-BecGraph [-Device]
  Test-BecCommandSurface               after connecting: check every cmdlet/parameter exists
  Show-BecCase | Set-BecCaseValue <name> <value> | Add-BecCaseValue attackerIps <ip>

  02 Invoke-BecContainment              Get-BecIdentityReview
     Enable-BecSignIn
  05 $signins = Get-BecSignIns [-Days 30] [-IncludeNonInteractive]

Procedures: business-email-compromise/procedures/ in the repo.
'@ | Write-Host
}
