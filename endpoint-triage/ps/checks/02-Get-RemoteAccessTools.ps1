<#
.SYNOPSIS
    Remote-access and RMM software: installed programs, services, processes and known file locations.
.DESCRIPTION
    Read-only. Scammers use AnyDesk, TeamViewer, ScreenConnect, UltraViewer, QuickAssist and others,
    often run portable from Downloads rather than installed, so files are checked as well as installs.
    Pass the tools the organisation uses legitimately with -Expected so they are labelled.
.PARAMETER Expected
    Names (regex fragments) of remote-access tools that are legitimately in use, e.g. 'Splashtop','Syncro'.
.EXAMPLE
    .\02-Get-RemoteAccessTools.ps1 -Expected 'Splashtop','Syncro','RustDesk'
#>
[CmdletBinding()]
param([string[]]$Expected = @())

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning

$toolRx = 'anydesk|rustdesk|teamviewer|screenconnect|connectwise|splashtop|atera|ninja|netsupport|logmein|goto(assist|resolve)?|remotepc|supremo|ammyy|ultraviewer|zoho ?assist|bomgar|beyondtrust|dwagent|dwservice|meshagent|tacticalrmm|simplehelp|kaseya|n-able|solarwinds|action1|syncro|level\.io|remcos|quick ?assist|parsec|chrome remote desktop|remoting_host|tightvnc|ultravnc|realvnc|tigervnc|radmin|aeroadmin|getscreen|iperius|hoptodesk|rport|pulseway|fleetdeck'
$expectedTools = $Expected
function Get-Label([string]$Text, [string[]]$Known = $expectedTools) {
    foreach ($e in $Known) { if ($e -and $Text -match $e) { return 'expected' } }
    'REVIEW'
}

Write-TriageSection 'Installed programs (machine and loaded user hives), newest first'
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
$programs = @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })
foreach ($h in (Get-TriageUserHive | Where-Object Loaded)) {
    $programs += @(Get-ItemProperty "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })
}
$programs | Sort-Object InstallDate -Descending |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation | Format-TriageTable

Write-TriageSection 'Remote-access programs installed'
$programs | Where-Object { $_.DisplayName -match $toolRx -or $_.Publisher -match $toolRx } |
    Select-Object @{ n = 'Status'; e = { Get-Label $_.DisplayName } }, DisplayName, DisplayVersion, InstallDate, InstallLocation | Format-TriageTable

Write-TriageSection 'Remote-access services'
Get-CimInstance Win32_Service | Where-Object { $_.Name -match $toolRx -or $_.DisplayName -match $toolRx -or $_.PathName -match $toolRx } |
    Select-Object @{ n = 'Status'; e = { Get-Label "$($_.Name) $($_.DisplayName)" } }, Name, DisplayName, State, StartMode, PathName | Format-TriageList

Write-TriageSection 'Remote-access processes running'
Get-CimInstance Win32_Process | Where-Object { $_.Name -match $toolRx -or $_.ExecutablePath -match $toolRx } |
    Select-Object @{ n = 'Status'; e = { Get-Label $_.Name } }, ProcessId, Name, ExecutablePath, CommandLine, CreationDate | Format-TriageList

Write-TriageSection 'Remote-access executables and config folders on disk (including portable copies)'
$folders = @("$env:ProgramData")
foreach ($p in Get-TriageLocalProfileFolder) {
    $folders += Join-Path $p.FullName 'Downloads'
    $folders += Join-Path $p.FullName 'Desktop'
    $folders += Join-Path $p.FullName 'AppData\Roaming'
    $folders += Join-Path $p.FullName 'AppData\Local'
    $folders += Join-Path $p.FullName 'AppData\Local\Temp'
}
& { foreach ($f in $folders) {
    if (-not (Test-Path $f)) { continue }
    Get-ChildItem $f -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $toolRx } | ForEach-Object {
        $sig = if (-not $_.PSIsContainer -and $_.Extension -in '.exe', '.msi') { Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue } else { $null }
        [pscustomobject]@{
            Status   = Get-Label $_.Name
            Path     = $_.FullName
            Created  = $_.CreationTime
            Modified = $_.LastWriteTime
            Size     = if ($_.PSIsContainer) { '<dir>' } else { $_.Length }
            Signer   = if ($sig -and $sig.SignerCertificate) { "$($sig.Status): $($sig.SignerCertificate.GetNameInfo('SimpleName', $false))" } else { '' }
            SHA256   = if (-not $_.PSIsContainer -and $_.Extension -in '.exe', '.msi') { (Get-FileHash $_.FullName -Algorithm SHA256).Hash } else { '' }
        }
    }
} } | Format-TriageList

Write-TriageSection 'Downloads of the last 30 days (all profiles), executables, installers, scripts and archives'
& { foreach ($p in Get-TriageLocalProfileFolder) {
    Get-ChildItem (Join-Path $p.FullName 'Downloads') -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) -and $_.Extension -match '^\.(exe|msi|msix|appx|bat|cmd|ps1|vbs|js|hta|lnk|zip|rar|7z|iso|img|dll|scr)$' } |
        Select-Object FullName, CreationTime, Length
} } | Sort-Object CreationTime | Format-TriageTable
