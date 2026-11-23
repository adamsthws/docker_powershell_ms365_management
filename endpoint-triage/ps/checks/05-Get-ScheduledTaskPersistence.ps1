<#
.SYNOPSIS
    Scheduled tasks: every non-Microsoft task, Microsoft tasks changed recently, hidden tasks and task registration events.
.DESCRIPTION
    Read-only. Reads the task XML files in C:\Windows\System32\Tasks directly (works where
    Get-ScheduledTask hides tasks) and the TaskCache registry tree.
    "NOFILE" entries under \Microsoft\Windows\ are usually retired Windows tasks and are normal on
    Windows 11. A non-Microsoft entry with no file, or any entry with no SD value, is a hidden task.
.PARAMETER Since
    Microsoft tasks modified on or after this date, and task events from this date, are listed. Default 30 days ago.
.EXAMPLE
    .\05-Get-ScheduledTaskPersistence.ps1 -Since '2026-01-01'
#>
[CmdletBinding()]
param([datetime]$Since = (Get-Date).AddDays(-30))

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning

$taskRoot = Join-Path $env:SystemRoot 'System32\Tasks'
Write-TriageSection "Task files: all outside \Microsoft\, plus \Microsoft\ ones changed since $($Since.ToString('yyyy-MM-dd'))"
& {
    foreach ($f in (Get-ChildItem $taskRoot -Recurse -File -Force -ErrorAction SilentlyContinue)) {
        $rel = $f.FullName.Substring($taskRoot.Length)
        if ($rel -like '\Microsoft\*' -and $f.LastWriteTime -lt $Since) { continue }
        try { $x = [xml](Get-Content $f.FullName -Raw) } catch { [pscustomobject]@{ Task = $rel; Modified = $f.LastWriteTime; Action = '(unreadable XML)' }; continue }
        $actions = @($x.Task.Actions.Exec | ForEach-Object { "$($_.Command) $($_.Arguments)".Trim() }) +
        @($x.Task.Actions.ComHandler | ForEach-Object { "COM $($_.ClassId)" })
        [pscustomobject]@{
            Task     = $rel
            Modified = $f.LastWriteTime
            Created  = $f.CreationTime
            Author   = $x.Task.RegistrationInfo.Author
            RunAs    = $x.Task.Principals.Principal.UserId
            Triggers = ($x.Task.Triggers.ChildNodes | ForEach-Object { $_.Name }) -join ','
            Hidden   = $x.Task.Settings.Hidden
            Enabled  = $x.Task.Settings.Enabled
            Action   = $actions -join ' | '
        }
    }
} | Sort-Object Modified -Descending | Format-TriageList

Write-TriageSection 'TaskCache entries with no task file or no security descriptor (hidden-task technique)'
$tree = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
Get-ChildItem $tree -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $v = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if (-not $v.Id) { return }
    $rel = $_.Name -replace '^.*\\TaskCache\\Tree', ''
    $noFile = -not (Test-Path (Join-Path $taskRoot $rel.TrimStart('\')))
    $noSd = -not $v.SD
    if ($noFile -or $noSd) {
        [pscustomobject]@{
            Task    = $rel
            NoFile  = $noFile
            NoSD    = $noSd
            Verdict = if ($noSd -or $rel -notlike '\Microsoft\*') { 'REVIEW' } else { 'usually a retired Windows task' }
        }
    }
} | Sort-Object Verdict, Task | Format-TriageTable

Write-TriageSection "Task registered / updated / deleted since $($Since.ToString('yyyy-MM-dd')) (TaskScheduler 106/140/141)"
'Needs the Microsoft-Windows-TaskScheduler/Operational log enabled; it is off by default on many builds.'
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 106, 140, 141; StartTime = $Since } -ErrorAction SilentlyContinue |
    ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Task = $_.Properties[0].Value; User = $_.Properties[1].Value } } | Format-TriageTable
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698, 4699, 4702; StartTime = $Since } -ErrorAction SilentlyContinue |
    ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Task = $_.Properties[4].Value; By = $_.Properties[1].Value } } | Format-TriageTable
