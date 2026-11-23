<#
.SYNOPSIS
    AnyDesk sessions from the endpoint's own logs: who connected, from which IP, elevation, black-screen (privacy mode) windows and file activity.
.DESCRIPTION
    Read-only. Reads ad.trace / ad_svc.trace, connection_trace.txt and the .conf files from every
    profile's %APPDATA%\AnyDesk and from %ProgramData%\AnyDesk (installed service), or from -Path.
    Can also run on a copy of those files on another machine (PowerShell 7), e.g. collected evidence.

    What the output means:
    - "Logged in from <ip>:<port> on relay <id>" is the REMOTE party's public IP, not AnyDesk's server.
    - "Authenticated by local user (elevated)" plus "Opening UAC dialog": the user accepted UAC, so the
      remote session ran as administrator.
    - Privacy-mode windows: screen blacked out and local input blocked while the remote side worked.
      AnyDesk starts rundll32.exe and writes C:\Windows\appcompat\AIDD files at each start; those are
      AnyDesk, not attacker tools.
    - An unattended-access password in the .conf files is a way back in: treat it as persistence.
    Trace times are local time on the endpoint.
.PARAMETER Path
    Folders holding AnyDesk files (ad.trace, connection_trace.txt, *.conf). Default: all known locations.
.EXAMPLE
    .\03-Get-AnyDeskActivity.ps1
.EXAMPLE
    pwsh ./03-Get-AnyDeskActivity.ps1 -Path ./evidence/anydesk
#>
[CmdletBinding()]
param([string[]]$Path)

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it

if (-not $Path) {
    Write-TriageElevationWarning
    $Path = @(Join-Path $env:ProgramData 'AnyDesk')
    foreach ($p in Get-TriageLocalProfileFolder) { $Path += Join-Path $p.FullName 'AppData\Roaming\AnyDesk' }
}

$found = $false
foreach ($dir in $Path) {
    if (-not (Test-Path $dir)) { continue }
    $found = $true
    Write-TriageSection "AnyDesk folder: $dir"
    Get-ChildItem $dir -Recurse -Force -File -ErrorAction SilentlyContinue |
        Select-Object @{ n = 'File'; e = { $_.FullName.Substring($dir.Length).TrimStart('\', '/') } }, Length, CreationTime, LastWriteTime | Format-TriageTable

    $confs = @(Get-ChildItem $dir -Filter '*.conf' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    if ($confs) {
        Write-TriageSection 'Configuration'
        Get-TriageAnyDeskConfig -Path $confs | Format-TriageList
    }

    $ct = Join-Path $dir 'connection_trace.txt'
    if (Test-Path $ct) {
        Write-TriageSection 'connection_trace.txt (direction, time, how accepted, remote ID)'
        ConvertFrom-TriageAnyDeskConnectionTrace -Path $ct | Format-TriageTable
    }

    $traces = @(Get-ChildItem $dir -Filter '*.trace' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    if (-not $traces) { continue }
    $entries = @(ConvertFrom-TriageAnyDeskTrace -Path $traces)
    $s = Get-TriageAnyDeskSummary -Entry $entries

    Write-TriageSection 'Program runs (command lines AnyDesk logged)'
    $entries | Where-Object { $_.Message -match '^Command Line params:' } |
        Select-Object Time, Process, @{ n = 'CommandLine'; e = { $_.Message -replace '^Command Line params:\s*', '' } } | Format-TriageTable

    Write-TriageSection 'This endpoint''s external address as AnyDesk saw it'
    if ($s.ExternalAddresses) { $s.ExternalAddresses } else { '  (none)' }

    Write-TriageSection 'Incoming sessions (RemoteIp = the remote party''s public IP)'
    $s.Sessions | Format-TriageTable -Property Time, RemoteId, RemoteIp, RemotePort, Relay, Fingerprint, Accepted, Elevated
    if ($s.RemoteInfo) { $s.RemoteInfo | ForEach-Object { "  $_" } }

    Write-TriageSection 'Elevation (UAC accepted for the remote session)'
    $s.Elevations | Format-TriageTable

    Write-TriageSection ('Privacy mode: screen blacked out, local input blocked (total {0:hh\:mm\:ss})' -f $s.PrivacyTotal)
    $s.PrivacyWindows | Format-TriageTable

    Write-TriageSection 'File transfer / file clipboard events'
    $s.FileEvents | Format-TriageTable

    Write-TriageSection 'Other notable events'
    $s.Notable | Format-TriageTable
}
if (-not $found) { ''; 'No AnyDesk folders found.' }
