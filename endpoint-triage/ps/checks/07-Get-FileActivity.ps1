<#
.SYNOPSIS
    Files created in a time window, and executables, scripts and archives created or modified in it.
.DESCRIPTION
    Read-only. Walks the profile, ProgramData, Windows temp and system folders and filters out the
    caches that churn constantly (browser caches, Windows Update, Defender, Office add-in packages,
    icon caches). Expect some noise; look for executables, scripts, archives and anything in
    Downloads, Temp, ProgramData or Startup.
    Known benign: AnyDesk drops gcapi.dll (a Google Chrome offer DLL) in Downloads and Temp;
    C:\Windows\appcompat\AIDD\Buffer\*.txt files are written when AnyDesk privacy mode starts;
    File History copies files into AppData\Local\Microsoft\Windows\FileHistory on its schedule.
.PARAMETER From
    Start of the window (local time).
.PARAMETER To
    End of the window (local time).
.PARAMETER Root
    Folders to walk. Default: users, ProgramData, Windows temp, System32, SysWOW64, Program Files and the drive root.
.PARAMETER ExtraExclude
    Additional regex of paths to ignore.
.EXAMPLE
    .\07-Get-FileActivity.ps1 -From '2026-01-15 14:00' -To '2026-01-15 16:30'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][datetime]$From,
    [Parameter(Mandatory)][datetime]$To,
    [string[]]$Root,
    [string]$ExtraExclude
)

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning
"Window: $($From.ToString('yyyy-MM-dd HH:mm:ss')) to $($To.ToString('yyyy-MM-dd HH:mm:ss')) (local time)"

if (-not $Root) {
    $Root = @((Join-Path $env:SystemDrive 'Users'), $env:ProgramData, (Join-Path $env:SystemRoot 'Temp'), (Join-Path $env:SystemRoot 'Tasks'),
        (Join-Path $env:SystemRoot 'System32'), (Join-Path $env:SystemRoot 'SysWOW64'), $env:ProgramFiles, ${env:ProgramFiles(x86)})
}
$noise = '\\(Cache|Code Cache|GPUCache|DawnWebGPUCache|DawnGraphiteCache|GrShaderCache|ShaderCache|D3DSCache|DxCache|IndexedDB|Service Worker|CacheStorage|blob_storage|CryptnetUrlCache|IdentityCache|OneAuth|INetCache|WebCache|Prefetch|WinSxS|SoftwareDistribution|servicing|LogFiles|ETLLogs|Diagnosis|WindowsApps|Windows Defender|USOPrivate|USOShared|BreadcrumbStore|System Volume Information|\$Recycle\.Bin|WER|Search\\Data|SolutionPackages|rescache|iconcache|Explorer\\(thumbcache|iconcache)|Packages\\[^\\]+\\(AC|LocalCache|TempState|LocalState)|Sync Data|Session Storage|Sessions|Local Storage|Extension State|shared_proto_db|Site Characteristics Database|WebStorage|File System|Network|Segmentation Platform|optimization_guide|AutofillStrikeDatabase|Feature Engagement Tracker|GCM Store)\\|\.(etl|evtx|tmp-wal|ldb|log\.old)$|-journal$|\\LOG(\.old)?$|\\LOCK$|\\CURRENT$|\\MANIFEST-\d+$'
$extraRx = $ExtraExclude
$exeRx = '\.(exe|dll|sys|msi|msix|appx|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|lnk|zip|rar|7z|iso|img|cab|jar)$'

$all = New-Object System.Collections.ArrayList
& {
    $seen = @{}
    foreach ($r in $Root) {
        if (-not $r -or -not (Test-Path $r)) { continue }
        $recurse = $r -notmatch '\\(System32|SysWOW64)$'
        $items = if ($recurse) { Get-ChildItem $r -Recurse -File -Force -ErrorAction SilentlyContinue } else { Get-ChildItem $r -File -Force -ErrorAction SilentlyContinue }
        foreach ($f in $items) {
            if ($seen.ContainsKey($f.FullName)) { continue }
            $created = $f.CreationTime -ge $From -and $f.CreationTime -le $To
            $modified = $f.LastWriteTime -ge $From -and $f.LastWriteTime -le $To
            if (-not ($created -or $modified)) { continue }
            $seen[$f.FullName] = $true
            if ($f.FullName -match $noise) { continue }
            if ($extraRx -and $f.FullName -match $extraRx) { continue }
            [pscustomobject]@{ Created = $f.CreationTime; Modified = $f.LastWriteTime; CreatedInWindow = $created; Size = $f.Length; Path = $f.FullName }
        }
    }
} | ForEach-Object { [void]$all.Add($_) }
'Note: System32 and SysWOW64 are checked at the top level only (no recursion) to keep the run short.'

Write-TriageSection 'Executables, scripts, shortcuts and archives created or modified in the window'
$all | Where-Object { $_.Path -match $exeRx } | Sort-Object Created | ForEach-Object {
    $sig = if ($_.Path -match '\.(exe|dll|sys|msi|scr)$') { Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue } else { $null }
    [pscustomobject]@{
        Created  = $_.Created.ToString('yyyy-MM-dd HH:mm:ss')
        Modified = $_.Modified.ToString('yyyy-MM-dd HH:mm:ss')
        Size     = $_.Size
        Signer   = if ($sig -and $sig.SignerCertificate) { "$($sig.Status): $($sig.SignerCertificate.GetNameInfo('SimpleName', $false))" } elseif ($sig) { "$($sig.Status)" } else { '' }
        Path     = $_.Path
    }
} | Format-TriageTable

Write-TriageSection 'All other files CREATED in the window (noise filtered)'
$all | Where-Object { $_.CreatedInWindow -and $_.Path -notmatch $exeRx } | Sort-Object Created |
    Select-Object @{ n = 'Created'; e = { $_.Created.ToString('yyyy-MM-dd HH:mm:ss') } }, Size, Path | Format-TriageTable
