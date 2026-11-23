<#
.SYNOPSIS
    Every event in every log within a few seconds of a moment you want to explain.
.DESCRIPTION
    Read-only. Use it when another check shows something at a precise time (a prompt, a program run,
    a file) and you need the cause. Noisy logs that never explain anything are skipped unless -All.
.PARAMETER Time
    The moment to look around (local time).
.PARAMETER Seconds
    How many seconds either side. Default 30.
.PARAMETER All
    Include the noisy logs that are skipped by default.
.EXAMPLE
    .\11-Get-EventsAroundTime.ps1 -Time '2026-01-15 14:22:05' -Seconds 20
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][datetime]$Time,
    [int]$Seconds = 30,
    [switch]$All
)

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning

$from = $Time.AddSeconds(-$Seconds)
$to = $Time.AddSeconds($Seconds)
$noisyLogs = 'StorageManagement|Store/Operational|AppXDeployment|AppModel-Runtime|Application-Experience|Kernel-Power|Time-Service|DeviceSetupManager|UserPnp|Kernel-PnP|Diagnostics-Performance'
$noisyMessages = 'UserModePowerService|reset policy scheme'
"Events from $($from.ToString('yyyy-MM-dd HH:mm:ss')) to $($to.ToString('yyyy-MM-dd HH:mm:ss')) (local time)"

Write-TriageSection 'Events, all logs'
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 -and ($All -or $_.LogName -notmatch $noisyLogs) } | ForEach-Object {
    Get-WinEvent -FilterHashtable @{ LogName = $_.LogName; StartTime = $from; EndTime = $to } -ErrorAction SilentlyContinue
} | Where-Object { $All -or $_.ProviderName -notmatch $noisyMessages } | Sort-Object TimeCreated | ForEach-Object {
    $m = ($_.Message -replace '\s+', ' ')
    [pscustomobject]@{
        Time     = $_.TimeCreated.ToString('HH:mm:ss.fff')
        Log      = $_.LogName
        Id       = $_.Id
        Provider = $_.ProviderName -replace '^Microsoft-Windows-', ''
        Message  = $m.Substring(0, [math]::Min(220, $m.Length))
    }
} | Format-TriageTable
