<#
.SYNOPSIS
    Local accounts, administrators, profiles, account-change events and current sessions.
.DESCRIPTION
    Read-only. Looks for accounts an attacker created, enabled or added to Administrators.
    Account events: 4720 created, 4722 enabled, 4724 password reset, 4728/4732/4756 added to a
    group, 4738 changed. A local account whose password is reset by SYSTEM (the computer account)
    about weekly is normally LAPS or an RMM rotating it.
.PARAMETER Days
    How far back to read account-change events from the Security log. Default 90.
.EXAMPLE
    .\01-Get-AccountsAndSessions.ps1 -Days 30
#>
[CmdletBinding()]
param([int]$Days = 90)

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning

Write-TriageSection 'Computer and time'
Get-CimInstance Win32_OperatingSystem | Select-Object CSName, Caption, Version, InstallDate, LastBootUpTime | Format-TriageList
"Now: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   Time zone: $((Get-TimeZone).Id)   UTC offset: $((Get-TimeZone).BaseUtcOffset)"

Write-TriageSection 'Local users'
Get-LocalUser | Select-Object Name, Enabled, SID, PasswordLastSet, LastLogon, Description | Format-TriageTable

Write-TriageSection 'Administrators group'
Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Select-Object ObjectClass, Name, PrincipalSource, SID | Format-TriageTable
'Note: Entra ID role groups appear as bare S-1-12-1-... SIDs (Global Administrator, device administrators).'

Write-TriageSection 'Remote Desktop Users group'
Get-LocalGroupMember -SID 'S-1-5-32-555' -ErrorAction SilentlyContinue | Select-Object ObjectClass, Name, PrincipalSource | Format-TriageTable

Write-TriageSection 'User profiles'
Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } |
    Select-Object LocalPath, SID, LastUseTime, Loaded | Sort-Object LastUseTime -Descending | Format-TriageTable

Write-TriageSection "Account changes in the Security log (last $Days days)"
$names = @{ 4720 = 'created'; 4722 = 'enabled'; 4724 = 'password reset'; 4725 = 'disabled'; 4726 = 'deleted'
    4728 = 'added to global group'; 4732 = 'added to local group'; 4756 = 'added to universal group'; 4738 = 'changed'; 4781 = 'renamed' }
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @($names.Keys); StartTime = (Get-Date).AddDays(-$Days) } -ErrorAction SilentlyContinue |
    ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        [pscustomobject]@{
            Time   = $_.TimeCreated
            Id     = $_.Id
            Action = $names[$_.Id]
            Target = if ($d.TargetUserName) { $d.TargetUserName } else { $d.MemberName }
            Group  = if ($_.Id -in 4728, 4732, 4756) { $d.TargetUserName } else { '' }
            By     = "$($d.SubjectDomainName)\$($d.SubjectUserName)"
        }
    } | Format-TriageTable

Write-TriageSection 'Logged-on sessions (quser)'
try { quser 2>&1 | Out-String } catch { '  quser not available' }

Write-TriageSection 'LAPS policy (if configured)'
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') {
    if (Test-Path $k) { "--- $k"; Get-ItemProperty $k | Select-Object * -ExcludeProperty PS* | Format-TriageList }
}
