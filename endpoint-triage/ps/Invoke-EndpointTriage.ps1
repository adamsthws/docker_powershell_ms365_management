<#
.SYNOPSIS
    Runs the endpoint triage checks and saves each one's output to a folder on the endpoint.
.DESCRIPTION
    Read-only towards the endpoint: the checks only read. The only things written are this run's
    output folder and, with -CollectAnyDesk, copies of AnyDesk's log and config files (the originals
    are not touched).
    Window checks (06, 07, 08) need -From and -To; they are skipped without them.
    Check 11 (events around a moment) needs -Time and is only run when -Time is given.
.PARAMETER From
    Start of the incident window (local time on the endpoint).
.PARAMETER To
    End of the incident window (local time on the endpoint).
.PARAMETER Since
    Start of the period for "recent changes" in checks 01, 04, 05 and 10. Default: 30 days before -From, or 30 days ago.
.PARAMETER Check
    Run only these checks, by number (e.g. 03,06). Default: all.
.PARAMETER Expected
    Remote-access tools the organisation uses, passed to check 02 so they are labelled 'expected'.
.PARAMETER Time
    A moment to explain with check 11 (events in all logs around it).
.PARAMETER OutputDirectory
    Where to save the results. Default: C:\ProgramData\endpoint-triage\out\<computer>-<yyyyMMdd-HHmmss>.
.PARAMETER CollectAnyDesk
    Also copy AnyDesk trace, connection_trace and .conf files into <OutputDirectory>\evidence\anydesk.
.EXAMPLE
    .\Invoke-EndpointTriage.ps1 -From '2026-01-15 14:00' -To '2026-01-15 16:30' -Expected 'Splashtop','Syncro' -CollectAnyDesk
.EXAMPLE
    .\Invoke-EndpointTriage.ps1 -Check 11 -Time '2026-01-15 14:22:05'
#>
[CmdletBinding()]
param(
    [datetime]$From,
    [datetime]$To,
    [datetime]$Since,
    [string[]]$Check,
    [string[]]$Expected = @(),
    [datetime]$Time,
    [string]$OutputDirectory,
    [switch]$CollectAnyDesk
)

# Everything is loaded as text and run as script blocks, not as script files, so an execution policy
# against scripts (even one set by Group Policy, which -ExecutionPolicy Bypass cannot lift) does not
# stop it. Run that way there is no $PSScriptRoot: the folder comes from ENDPOINT_TRIAGE_ROOT, else
# C:\ProgramData\endpoint-triage\ps.
$triageRoot = if ($PSScriptRoot) { $PSScriptRoot } elseif ($env:ENDPOINT_TRIAGE_ROOT) { $env:ENDPOINT_TRIAGE_ROOT } else { Join-Path $env:ProgramData 'endpoint-triage\ps' }
function Get-TriageScriptBlock([string]$Path) { [scriptblock]::Create([IO.File]::ReadAllText($Path)) }
. (Get-TriageScriptBlock (Join-Path $triageRoot 'TriageCommon.ps1'))

if (($From -and -not $To) -or ($To -and -not $From)) { throw 'Give both -From and -To, or neither.' }
if ($From -and $To -lt $From) { throw '-To is before -From.' }
if (-not $Since) { $Since = if ($From) { $From.AddDays(-30) } else { (Get-Date).AddDays(-30) } }
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $env:ProgramData ("endpoint-triage\out\{0}-{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
# powershell.exe -File passes 'a,b' as one string, so accept comma-separated lists as well as arrays.
$Check = @($Check -split ',' | Where-Object { $_ } | ForEach-Object { '{0:D2}' -f [int]$_ })
$Expected = @($Expected -split ',' | Where-Object { $_ })
[void](New-Item -ItemType Directory -Path $OutputDirectory -Force)

$checksDir = Join-Path $triageRoot 'checks'
$plan = @(
    @{ N = '01'; Args = @{ Days = [int]((Get-Date) - $Since).TotalDays + 1 } },
    @{ N = '02'; Args = @{ Expected = $Expected } },
    @{ N = '03'; Args = @{} },
    @{ N = '04'; Args = @{ Since = $Since } },
    @{ N = '05'; Args = @{ Since = $Since } },
    @{ N = '06'; Args = @{ From = $From; To = $To }; Window = $true },
    @{ N = '07'; Args = @{ From = $From; To = $To }; Window = $true },
    @{ N = '08'; Args = @{ From = $From; To = $To }; Window = $true },
    @{ N = '09'; Args = @{} },
    @{ N = '10'; Args = @{ Since = $Since } },
    @{ N = '11'; Args = @{ Time = $Time }; NeedsTime = $true }
)

$manifest = @(
    "Endpoint triage run",
    "Computer:   $env:COMPUTERNAME",
    "Run by:     $([Security.Principal.WindowsIdentity]::GetCurrent().Name)   elevated: $(Test-TriageElevated)",
    "Started:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') local, $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC   time zone: $((Get-TimeZone).Id)",
    "Window:     $(if ($From) { "$($From.ToString('yyyy-MM-dd HH:mm:ss')) to $($To.ToString('yyyy-MM-dd HH:mm:ss')) local" } else { '(none given)' })",
    "Since:      $($Since.ToString('yyyy-MM-dd HH:mm:ss')) local",
    ''
)

foreach ($step in $plan) {
    if ($Check -and $step.N -notin $Check) { continue }
    $script = Get-ChildItem $checksDir -Filter "$($step.N)-*.ps1" | Select-Object -First 1
    if (-not $script) { $manifest += "$($step.N) not found"; continue }
    if ($step.Window -and -not $From) { $manifest += "$($script.BaseName): skipped (needs -From and -To)"; continue }
    if ($step.NeedsTime -and -not $Time) { if ($Check) { $manifest += "$($script.BaseName): skipped (needs -Time)" }; continue }
    $out = Join-Path $OutputDirectory "$($script.BaseName).txt"
    Write-Host "Running $($script.BaseName) ..." -ForegroundColor Cyan
    $args2 = $step.Args
    $started = Get-Date
    try {
        & (Get-TriageScriptBlock $script.FullName) @args2 2>&1 | ForEach-Object { if ($_ -is [Management.Automation.ErrorRecord]) { "ERROR: $_" } else { $_ } } |
            Out-String -Width 300 | Set-Content -Path $out -Encoding UTF8
        $manifest += "{0}: done in {1:N0}s -> {2}" -f $script.BaseName, ((Get-Date) - $started).TotalSeconds, (Split-Path $out -Leaf)
    }
    catch {
        $manifest += "$($script.BaseName): FAILED $_"
    }
}

if ($CollectAnyDesk) {
    $dest = Join-Path $OutputDirectory 'evidence\anydesk'
    $sources = @(Join-Path $env:ProgramData 'AnyDesk')
    foreach ($p in Get-TriageLocalProfileFolder) { $sources += Join-Path $p.FullName 'AppData\Roaming\AnyDesk' }
    foreach ($src in $sources) {
        if (-not (Test-Path $src)) { continue }
        $label = if ($src -like "$env:ProgramData*") { 'ProgramData' } else { Split-Path (Split-Path (Split-Path (Split-Path $src -Parent) -Parent) -Parent) -Leaf }
        $target = Join-Path $dest $label
        [void](New-Item -ItemType Directory -Path $target -Force)
        Get-ChildItem $src -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.(trace|conf|txt)$' } | ForEach-Object {
            Copy-Item $_.FullName $target
            $manifest += "collected {0} ({1} bytes, SHA256 {2})" -f $_.FullName, $_.Length, (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        }
    }
}

$manifest += "Finished:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') local"
$manifest | Set-Content -Path (Join-Path $OutputDirectory '00-manifest.txt') -Encoding UTF8
Write-Host "Results: $OutputDirectory" -ForegroundColor Green
$OutputDirectory
