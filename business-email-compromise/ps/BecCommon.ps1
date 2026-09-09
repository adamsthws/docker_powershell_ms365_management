# Shared helpers for BEC case sessions. Dot-sourced by BecExchange.ps1 and BecGraph.ps1.
# Everything a function writes lands in the case folder (mounted at /case), so evidence
# ends up on the host without docker cp.

$global:BecCaseDir = if ($env:BEC_CASE_DIR) { $env:BEC_CASE_DIR } else { (Get-Location).Path }

function Get-BecPath {
    param([Parameter(Mandatory)][string]$Name)
    $path = Join-Path $global:BecCaseDir $Name
    $parent = Split-Path $path -Parent
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $path
}

function Get-BecTimestamp { (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') }

# Every change made to the tenant is appended to actions.log; the technical report's
# containment section is written from it.
function Write-BecLog {
    param([Parameter(Mandatory)][string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss}Z  {1}' -f (Get-Date).ToUniversalTime(), $Message
    Add-Content -Path (Get-BecPath 'actions.log') -Value $line
    Write-Host $line -ForegroundColor Cyan
}

# Every step function calls this first: it says what is about to happen, whether the tenant
# will be changed, and asks the admin to proceed. The answer is recorded in actions.log.
# -Force skips the prompt; use it only for calls made from inside another gated step.
function Confirm-BecStep {
    param(
        [Parameter(Mandatory)][string]$Step,
        [Parameter(Mandatory)][string]$Description,
        [string[]]$Changes,
        [string[]]$Writes,
        [switch]$Force
    )
    if ($Force) { return $true }

    Write-Host ''
    Write-Host "=== $Step ===" -ForegroundColor Yellow
    Write-Host $Description
    if ($Changes) {
        Write-Host 'This CHANGES the tenant:' -ForegroundColor Red
        $Changes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    } else {
        Write-Host 'Read-only: nothing in the tenant is changed.' -ForegroundColor DarkGray
    }
    if ($Writes) {
        Write-Host 'Writes to the case folder:' -ForegroundColor DarkGray
        $Writes | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
    }

    $answer = Read-Host 'Proceed? [y/N]'
    $ok = $answer -match '^\s*(y|yes)\s*$'
    if ($ok) { Write-BecLog "Proceeding: $Step" } else { Write-BecLog "Declined: $Step"; Write-Host 'Skipped.' -ForegroundColor DarkGray }
    $ok
}

function Get-BecCase {
    $path = Join-Path $global:BecCaseDir 'case.json'
    if (-not (Test-Path $path)) { throw "No case.json in $global:BecCaseDir. Create the case with scripts/new-case.sh first." }
    Get-Content $path -Raw | ConvertFrom-Json -AsHashtable
}

function Save-BecCase {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Case)
    $Case | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $global:BecCaseDir 'case.json')
}

function Set-BecCaseValue {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Writes only the local case.json, and logs the change.')]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Value)
    $case = Get-BecCase
    $case[$Name] = $Value
    Save-BecCase $case
    Write-BecLog "case.$Name = $($Value -join ', ')"
}

function Add-BecCaseValue {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Value)
    $case = Get-BecCase
    $case[$Name] = @(@($case[$Name]) + $Value | Where-Object { $_ } | Select-Object -Unique)
    Save-BecCase $case
    Write-BecLog "case.$Name += $($Value -join ', ')"
}

function Resolve-BecUpn {
    param([string]$Upn)
    if ($Upn) { return $Upn }
    $case = Get-BecCase
    if ($case.upn) { return $case.upn }
    throw 'No mailbox given. Pass -Upn or set "upn" in case.json.'
}

# Audit ClientIP values carry ports ("192.0.2.10:56353", "[2001:db8::1]:443"); strip them so
# they compare against sign-in log and message trace IPs.
function ConvertTo-BecIp {
    param([string]$Ip)
    if (-not $Ip) { return '' }
    if ($Ip -match '^\[(.+)\]:\d+$') { return $Matches[1] }
    if ($Ip -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { return $Matches[1] }
    $Ip
}

function Test-BecKnownGoodIp {
    param([string]$Ip, [string[]]$Prefixes)
    if (-not $Ip) { return $false }
    foreach ($p in $Prefixes) { if ($p -and $Ip -like "$p*") { return $true } }
    $false
}

function Get-BecKnownGoodPrefixes { @((Get-BecCase).knownGoodIpPrefixes | Where-Object { $_ }) }
function Get-BecAttackerIps { @((Get-BecCase).attackerIps | Where-Object { $_ }) }

# Lists every command a script calls, the named parameters it passes and the function it is
# called from. The tests use it for static checks; Test-BecCommandSurface uses it to check
# cmdlets and parameters exist in the connected module before anything runs against a tenant.
function Get-BecCommandUsage {
    param([Parameter(Mandatory)][string[]]$Path)
    foreach ($file in $Path) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
        $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object {
            $name = $_.GetCommandName()
            if (-not $name) { return }
            $parent = $_.Parent
            while ($parent -and $parent -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $parent = $parent.Parent }
            [pscustomobject]@{
                File       = Split-Path $file -Leaf
                Function   = if ($parent) { $parent.Name } else { '' }
                Command    = $name
                Parameters = @($_.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object ParameterName)
                Splatted   = [bool]@($_.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Splatted }).Count
                Line       = $_.Extent.StartLineNumber
            }
        }
    }
}

# Read-only and local: checks that every cmdlet the helpers call, and every named parameter
# they pass, exists in the modules loaded in this session. Run it right after Connect-BecExchange
# or Connect-BecGraph; Exchange cmdlets only exist once connected. Splatted parameters are listed
# but not checked.
function Test-BecCommandSurface {
    $files = if (Get-Command Get-BecSentTrace -ErrorAction SilentlyContinue) { 'BecCommon.ps1', 'BecExchange.ps1' } else { 'BecCommon.ps1', 'BecGraph.ps1' }
    $paths = $files | ForEach-Object { Join-Path $PSScriptRoot $_ }
    $ours = Get-ChildItem $PSScriptRoot -Filter '*.ps1' | ForEach-Object {
        [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null).FindAll(
            { $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true).Name
    }

    $results = Get-BecCommandUsage $paths | Where-Object { $_.Command -notin $ours } | Group-Object Command | ForEach-Object {
        $name = $_.Name
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        $used = @($_.Group.Parameters | Sort-Object -Unique)
        if (-not $cmd) {
            return [pscustomobject]@{ Command = $name; Status = 'MISSING COMMAND'; Detail = 'not found in this session (connected to the right service?)' }
        }
        $known = @($cmd.Parameters.Keys) + @($cmd.Parameters.Values.Aliases)
        $unknown = @($used | Where-Object { $_ -notin $known })
        [pscustomobject]@{
            Command = $name
            Status  = if ($unknown) { 'UNKNOWN PARAMETER' } else { 'OK' }
            Detail  = if ($unknown) { "-$($unknown -join ', -')" } elseif ($_.Group.Splatted -contains $true) { 'splatted parameters not checked' } else { '' }
        }
    }
    $results | Sort-Object Status, Command | Format-Table -AutoSize | Out-Host
    $bad = @($results | Where-Object Status -ne 'OK')
    if ($bad) { Write-Warning "$($bad.Count) problem(s) found. Fix them before running the helpers against this tenant." }
    else { Write-Host "All $(@($results).Count) commands and their parameters exist in this session." -ForegroundColor Green }
}

function Show-BecCase {
    $case = Get-BecCase
    Write-Host "Case folder: $global:BecCaseDir" -ForegroundColor Green
    [pscustomobject]$case | Format-List
}
