<#
.SYNOPSIS
    What ran in a time window: PowerShell logs, process-creation events, Prefetch run times, BAM, Win+R history and PSReadLine history files.
.DESCRIPTION
    Read-only. Use the incident window (for example the remote session's start and end).
    - PowerShell: 4103/4104 (module and script-block logging), 40961/40962 (console start), 400/600/800
      (engine and pipeline). Identical repeated 600 events are collapsed. RMM agents (Syncro, NinjaOne
      and others) run PowerShell as SYSTEM all the time; check the HostApplication before worrying.
    - Prefetch keeps the last 8 run times per executable, so it shows cmd.exe, ipconfig.exe etc. even
      when no process auditing is enabled. rundll32.exe starting exactly when AnyDesk privacy mode
      starts is AnyDesk's own black-screen helper.
    - Console history files are listed (size and dates), not printed, unless -IncludeHistoryContent.
.PARAMETER From
    Start of the window (local time).
.PARAMETER To
    End of the window (local time).
.PARAMETER IncludeHistoryContent
    Also print the contents of PSReadLine ConsoleHost_history.txt files.
.EXAMPLE
    .\06-Get-ExecutionEvidence.ps1 -From '2026-01-15 14:00' -To '2026-01-15 16:30'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][datetime]$From,
    [Parameter(Mandatory)][datetime]$To,
    [switch]$IncludeHistoryContent
)

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning
"Window: $($From.ToString('yyyy-MM-dd HH:mm:ss')) to $($To.ToString('yyyy-MM-dd HH:mm:ss')) (local time)"

Write-TriageSection 'Event log health (a short or cleared log hides activity)'
& {
    foreach ($l in 'Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational') {
        $info = Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue
        $oldest = Get-WinEvent -LogName $l -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
        [pscustomobject]@{ Log = $l; Records = $info.RecordCount; MaxSizeMB = [math]::Round($info.MaximumSizeInBytes / 1MB); Oldest = $oldest.TimeCreated }
    }
} | Format-TriageTable
Write-TriageSection 'Log cleared events (Security 1102, System 104), any date'
& {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102 } -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Event = '1102 Security log cleared' } }
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104 } -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Event = "104 log cleared: $($_.Properties[1].Value)" } }
} | Format-TriageTable

Write-TriageSection 'PowerShell activity in the window'
& {
    $queries = @(
        @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4103, 4104, 4100, 40961, 40962 },
        @{ LogName = 'Windows PowerShell'; Id = 400, 403, 600, 800 }
    )
    foreach ($q in $queries) {
        $q.StartTime = $From; $q.EndTime = $To
        Get-WinEvent -FilterHashtable $q -ErrorAction SilentlyContinue | ForEach-Object {
            $m = $_.Message -replace '\s+', ' '
            if ($_.Id -in 400, 403, 600) { $m = (($m -replace '^.*HostApplication=', 'HostApplication=') -replace ' EngineVersion=.*$', '') }
            if ($_.Id -eq 4103) { $m = ($m -replace ' Context: .*Host Application = ', ' [host: ') -replace ' Engine Version = .*$', ']' }
            [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Detail = $m.Substring(0, [math]::Min(400, $m.Length)) }
        }
    }
} | Sort-Object Time | Group-Object Id, Detail | ForEach-Object {
    $first = $_.Group[0]
    [pscustomobject]@{ Time = $first.Time; Id = $first.Id; Count = $_.Count; Detail = $first.Detail }
} | Sort-Object Time | Format-TriageTable

Write-TriageSection 'Process creation in the window (Security 4688, Sysmon 1)'
$p4688 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $From; EndTime = $To } -ErrorAction SilentlyContinue)
if (-not $p4688) { '  No 4688 events: process-creation auditing is probably off, so rely on Prefetch and BAM below.' }
$p4688 | ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    [pscustomobject]@{ Time = $_.TimeCreated; User = $d.SubjectUserName; Process = $d.NewProcessName; Parent = $d.ParentProcessName; CommandLine = $d.CommandLine }
} | Format-TriageTable
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $From; EndTime = $To } -ErrorAction SilentlyContinue | ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    [pscustomobject]@{ Time = $_.TimeCreated; User = $d.User; Image = $d.Image; Parent = $d.ParentImage; CommandLine = $d.CommandLine }
} | Format-TriageTable

Write-TriageSection 'Prefetch: executables with a run time in the window'
$prefetchDir = Join-Path $env:SystemRoot 'Prefetch'
if (-not (Test-Path $prefetchDir)) { '  No Prefetch folder (disabled, or not elevated).' }
Get-ChildItem $prefetchDir -Filter '*.pf' -ErrorAction SilentlyContinue | ForEach-Object {
    try { $pf = ConvertFrom-TriagePrefetch -Path $_.FullName } catch { return }
    $inWindow = @($pf.RunTimes | Where-Object { $_ -ge $From -and $_ -le $To })
    if ($inWindow) {
        [pscustomobject]@{
            First      = $inWindow[0]
            Executable = $pf.Executable
            File       = $pf.File
            RunsInWin  = ($inWindow | ForEach-Object { $_.ToString('HH:mm:ss') }) -join ', '
            FirstEver  = $_.CreationTime
        }
    }
} | Sort-Object First | Format-TriageTable

Write-TriageSection 'BAM (Background Activity Moderator): last run per executable, within the window +/- 1 hour'
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' -ErrorAction SilentlyContinue | ForEach-Object {
    $sid = $_.PSChildName
    $key = Get-Item $_.PSPath
    foreach ($n in $key.GetValueNames()) {
        $v = $key.GetValue($n)
        if ($v -is [byte[]] -and $v.Length -ge 8) {
            $t = [datetime]::FromFileTime([BitConverter]::ToInt64($v, 0))
            if ($t -ge $From.AddHours(-1) -and $t -le $To.AddHours(1)) { [pscustomobject]@{ LastRun = $t; Sid = $sid; Executable = $n } }
        }
    }
} | Sort-Object LastRun | Format-TriageTable

Write-TriageSection 'Win+R history, Explorer typed paths and searches (loaded user hives; RunMRU entries end in \1)'
foreach ($h in (Get-TriageUserHive | Where-Object { $_.Loaded -and $_.ProfilePath })) {
    $base = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer"
    "--- $($h.ProfilePath)"
    $k = Get-Item "$base\RunMRU" -ErrorAction SilentlyContinue
    if ($k) { $order = $k.GetValue('MRUList'); foreach ($c in "$order".ToCharArray()) { "  Run ($c): $($k.GetValue([string]$c))" } }
    $tp = Get-ItemProperty "$base\TypedPaths" -ErrorAction SilentlyContinue
    if ($tp) { $tp.PSObject.Properties | Where-Object { $_.Name -like 'url*' } | ForEach-Object { "  Typed path: $($_.Value)" } }
    $w = Get-Item "$base\WordWheelQuery" -ErrorAction SilentlyContinue
    if ($w) {
        $list = $w.GetValue('MRUListEx')
        for ($i = 0; $i -lt [math]::Min(20, $list.Length / 4); $i++) {
            $n = [BitConverter]::ToInt32($list, $i * 4)
            if ($n -lt 0) { break }
            "  Search: $([Text.Encoding]::Unicode.GetString($w.GetValue([string]$n)).TrimEnd([char]0))"
        }
    }
}

Write-TriageSection 'PSReadLine console history files (a file recreated after the incident suggests the old one was deleted)'
foreach ($p in Get-TriageLocalProfileFolder) {
    $f = Join-Path $p.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (-not (Test-Path $f)) { continue }
    $item = Get-Item $f -Force
    "{0}  size={1}  created={2:yyyy-MM-dd HH:mm:ss}  modified={3:yyyy-MM-dd HH:mm:ss}  lines={4}" -f $f, $item.Length, $item.CreationTime, $item.LastWriteTime, @(Get-Content $f).Count
    if ($IncludeHistoryContent) { Get-Content $f | ForEach-Object { "    $_" } }
}
