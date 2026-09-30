# Runs the BEC test suite inside the m365-admin container. Called by scripts/test.sh.
# Needs no tenant and no sign-in. Pester and PSScriptAnalyzer come from the image when it
# has them, otherwise they are downloaded once into /test-modules (a host cache folder).
param([string[]]$Tag)
$Tag = $Tag -split ',' | Where-Object { $_ }

$cache = '/test-modules'
if (Test-Path $cache) { $env:PSModulePath = "$cache$([IO.Path]::PathSeparator)$env:PSModulePath" }

$needed = @{ Pester = '5.5.0'; PSScriptAnalyzer = '1.21.0' }
foreach ($name in $needed.Keys) {
    if (-not (Get-Module -ListAvailable $name | Where-Object Version -ge ([version]$needed[$name]))) {
        Write-Host "Downloading $name into the test module cache (first run only)..." -ForegroundColor Yellow
        Save-Module -Name $name -MinimumVersion $needed[$name] -Path $cache -Repository PSGallery -Force
    }
}
Import-Module Pester -MinimumVersion $needed.Pester
Import-Module PSScriptAnalyzer

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
if ($Tag) { $config.Filter.Tag = $Tag }
Invoke-Pester -Configuration $config
