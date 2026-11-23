<#
.SYNOPSIS
    Live network connections and listening ports with their programs, remote-access services, RDP settings and firewall rule changes.
.DESCRIPTION
    Read-only. Every established connection should map to a program you can explain (browser, Office,
    OneDrive, RMM agent, Defender). Anything else, or a listener on 0.0.0.0 you did not expect, needs a look.
.PARAMETER Since
    Firewall rule changes from this date are listed. Default 30 days ago.
.EXAMPLE
    .\10-Get-NetworkExposure.ps1 -Since '2026-01-15'
#>
[CmdletBinding()]
param([datetime]$Since = (Get-Date).AddDays(-30))

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning

$procs = @{}
Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
function Get-Owner([int]$ProcessId) {
    $p = $procs[$ProcessId]
    if ($p) { if ($p.ExecutablePath) { $p.ExecutablePath } else { $p.Name } } else { "pid $ProcessId" }
}

Write-TriageSection 'Established TCP connections to non-local addresses'
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0|::$)' } |
    ForEach-Object { [pscustomobject]@{ Remote = "$($_.RemoteAddress):$($_.RemotePort)"; Local = "$($_.LocalAddress):$($_.LocalPort)"; Pid = $_.OwningProcess; Program = Get-Owner $_.OwningProcess } } |
    Sort-Object Program, Remote -Unique | Format-TriageTable

Write-TriageSection 'Listening TCP ports'
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { [pscustomobject]@{ Listen = "$($_.LocalAddress):$($_.LocalPort)"; Pid = $_.OwningProcess; Program = Get-Owner $_.OwningProcess } } |
    Sort-Object Program, Listen -Unique | Format-TriageTable

Write-TriageSection 'Remote management services'
Get-Service TermService, WinRM, sshd, RemoteRegistry, SessionEnv, UmRdpService -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType | Format-TriageTable

Write-TriageSection 'Remote Desktop and Remote Assistance settings'
$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
$nla = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
$ra = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -ErrorAction SilentlyContinue
"RDP enabled: $($ts.fDenyTSConnections -eq 0)   NLA required: $($nla.UserAuthentication -eq 1)   RDP port: $($nla.PortNumber)   Remote Assistance allowed: $($ra.fAllowToGetHelp -eq 1)"

Write-TriageSection 'Enabled inbound allow rules that are not built-in Windows rules'
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction SilentlyContinue |
    Where-Object { -not $_.Group -or $_.Group -notmatch '^@' } | ForEach-Object {
        $app = ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
        $port = ($_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
        [pscustomobject]@{ Name = $_.DisplayName; Profile = $_.Profile; Program = $app; Protocol = $port.Protocol; LocalPort = ($port.LocalPort -join ',') }
    } | Format-TriageTable

Write-TriageSection "Firewall rule changes since $($Since.ToString('yyyy-MM-dd')) (2004 added, 2005 changed, 2006/2052 deleted, 2097 added)"
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; Id = 2004, 2005, 2006, 2052, 2071, 2097, 2099; StartTime = $Since } -ErrorAction SilentlyContinue |
    ForEach-Object {
        $x = [xml]$_.ToXml(); $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Rule = $d.RuleName; App = $d.ApplicationPath; ModifyingApp = $d.ModifyingApplication }
    } | Format-TriageTable
