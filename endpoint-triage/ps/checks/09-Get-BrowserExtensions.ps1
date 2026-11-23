<#
.SYNOPSIS
    Browser extensions in every profile of Chrome, Edge, Brave, Vivaldi, Opera and Firefox, with real names and risky permissions.
.DESCRIPTION
    Read-only. Reads extension manifests only. It never opens browser history, cookies, saved
    passwords (Login Data) or Local State. Names written as __MSG_...__ are resolved from the
    extension's _locales folder. Extensions able to read every site ("<all_urls>", http://*/*)
    can read and change pages, including online banking.
.EXAMPLE
    .\09-Get-BrowserExtensions.ps1
#>
[CmdletBinding()]
param()

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning

function Resolve-ExtensionText([string]$Text, [string]$Dir, [string]$Locale) {
    if ($Text -notmatch '^__MSG_(.+)__$') { return $Text }
    $key = $Matches[1]
    foreach ($loc in @($Locale, 'en', 'en_US', 'en_GB') | Where-Object { $_ }) {
        $file = Join-Path $Dir "_locales\$loc\messages.json"
        if (-not (Test-Path $file)) { continue }
        $json = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $json.PSObject.Properties) { if ($p.Name -ieq $key) { return $p.Value.message } }
    }
    $Text
}

$browsers = @{
    'Chrome'  = 'AppData\Local\Google\Chrome\User Data'
    'Edge'    = 'AppData\Local\Microsoft\Edge\User Data'
    'Brave'   = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'
    'Vivaldi' = 'AppData\Local\Vivaldi\User Data'
    'Opera'   = 'AppData\Roaming\Opera Software\Opera Stable'
}

Write-TriageSection 'Chromium-based browser extensions (newest first)'
& {
    foreach ($p in Get-TriageLocalProfileFolder) {
        foreach ($b in $browsers.Keys) {
            $dataDir = Join-Path $p.FullName $browsers[$b]
            if (-not (Test-Path $dataDir)) { continue }
            foreach ($ext in (Get-ChildItem $dataDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Extensions' } | Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem $_ -Directory })) {
                $ver = Get-ChildItem $ext.FullName -Directory | Sort-Object LastWriteTime | Select-Object -Last 1
                if (-not $ver) { continue }
                $mf = Join-Path $ver.FullName 'manifest.json'
                if (-not (Test-Path $mf)) { continue }
                $m = Get-Content $mf -Raw -Encoding UTF8 | ConvertFrom-Json
                $hosts = @($m.host_permissions) + @($m.permissions | Where-Object { $_ -match '://|<all_urls>' }) + @($m.content_scripts | ForEach-Object { $_.matches })
                [pscustomobject]@{
                    User        = $p.Name
                    Browser     = $b
                    Profile     = Split-Path (Split-Path $ext.FullName -Parent) -Parent | Split-Path -Leaf
                    Id          = $ext.Name
                    Name        = Resolve-ExtensionText -Text $m.name -Dir $ver.FullName -Locale $m.default_locale
                    Version     = $m.version
                    Installed   = $ext.CreationTime
                    AllSites    = [bool]($hosts | Where-Object { $_ -match '<all_urls>|^\*://\*/|^https?://\*/' })
                    Permissions = (@($m.permissions) | Where-Object { $_ -notmatch '://' }) -join ','
                }
            }
        }
    }
} | Sort-Object Installed -Descending | Format-TriageTable -Property User, Browser, Profile, Installed, Name, Version, AllSites, Id
'Google defaults such as Google Docs Offline (ghbmnnjooekpmoecnnnilnnbdlolhkhi) and Chrome Web Store Payments (nmmhkkegccagdldgiimedpiccmgmieda) are normal.'

Write-TriageSection 'Firefox add-ons'
& {
    foreach ($p in Get-TriageLocalProfileFolder) {
        Get-ChildItem (Join-Path $p.FullName 'AppData\Roaming\Mozilla\Firefox\Profiles') -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $f = Join-Path $_.FullName 'extensions.json'
            if (-not (Test-Path $f)) { return }
            $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($a in $j.addons) {
                if ($a.location -eq 'app-builtin' -or $a.location -eq 'app-system-defaults') { continue }
                [pscustomobject]@{
                    User      = $p.Name
                    Profile   = $_.Name
                    Name      = $a.defaultLocale.name
                    Id        = $a.id
                    Active    = $a.active
                    Installed = if ($a.installDate) { ([datetime]'1970-01-01').AddMilliseconds($a.installDate).ToLocalTime() } else { $null }
                }
            }
        }
    }
} | Format-TriageTable
