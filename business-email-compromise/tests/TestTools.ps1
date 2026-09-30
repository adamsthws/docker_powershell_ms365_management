# Shared helpers for the BEC test suite.

$global:BecTestRoot = Split-Path $PSScriptRoot -Parent
$global:BecPsFiles = Get-ChildItem (Join-Path $BecTestRoot 'ps') -Filter '*.ps1' | Sort-Object Name

# Exchange Online cmdlets only exist after Connect-ExchangeOnline, so they cannot be resolved
# offline. Anything the helpers call that is neither ours, core PowerShell, Graph, nor in this
# list fails the static tests (usually a typo). Test-BecCommandSurface checks this list against
# a real connected session.
$global:BecExchangeCmdlets = @(
    'Connect-ExchangeOnline', 'Disconnect-ExchangeOnline', 'Get-ConnectionInformation',
    'Get-InboxRule', 'Remove-InboxRule',
    'Get-Mailbox', 'Set-Mailbox', 'Get-MailboxPermission', 'Get-RecipientPermission',
    'Get-MailboxFolderStatistics', 'Get-MobileDevice', 'Get-TransportRule',
    'Search-UnifiedAuditLog', 'Get-MessageTraceV2', 'Get-BlockedSenderAddress',
    'Get-RecoverableItems', 'Restore-RecoverableItems'
)

$global:BecMutatingVerbs = 'Set', 'New', 'Remove', 'Restore', 'Enable', 'Disable', 'Update', 'Revoke', 'Add'

function Get-BecFunctionInfo {
    param([Parameter(Mandatory)][string[]]$Path)
    foreach ($file in $Path) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$null)
        foreach ($fn in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            $calls = @($fn.Body.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true))
            $binding = @($fn.Body.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' })
            [pscustomobject]@{
                Name                  = $fn.Name
                File                  = Split-Path $file -Leaf
                Ast                   = $fn
                Calls                 = $calls
                Confirm               = $calls | Where-Object { $_.GetCommandName() -eq 'Confirm-BecStep' } | Select-Object -First 1
                Parameters            = @($fn.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
                SupportsShouldProcess = [bool]@($binding.NamedArguments | Where-Object ArgumentName -eq 'SupportsShouldProcess').Count
                UsesShouldProcess     = $fn.Extent.Text -match '\$PSCmdlet\.ShouldProcess\('
            }
        }
    }
}

# Bec (ours), Exchange, Graph, Core, or Unknown.
function Get-BecCommandKind {
    param([Parameter(Mandatory)][string]$Name, [string[]]$Ours)
    if ($Name -in $Ours) { return 'Bec' }
    if ($Name -in $global:BecExchangeCmdlets) { return 'Exchange' }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) { return 'Unknown' }
    if ($cmd.Source -like 'Microsoft.Graph*') { return 'Graph' }
    'Core'
}

function Test-BecMutatingCommand {
    param([string]$Name, [string]$Kind)
    $Kind -in 'Exchange', 'Graph' -and ($Name -split '-')[0] -in $global:BecMutatingVerbs
}

# A fresh case folder in Pester's TestDrive, set as the active case.
function New-TestCase {
    param([string[]]$KnownGood = @('203.0.113.', '2001:db8:1234:'), [string[]]$AttackerIps = @())
    $dir = Join-Path $TestDrive ('case-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path "$dir/evidence", "$dir/notification" -Force | Out-Null
    [ordered]@{
        client              = 'contoso'
        upn                 = 'jane@contoso.com'
        knownGoodIpPrefixes = $KnownGood
        attackerIps         = $AttackerIps
        phishingSubjects    = @()
    } | ConvertTo-Json | Set-Content "$dir/case.json"
    $global:BecCaseDir = $dir
    $dir
}

function Get-TestLog { Get-Content (Join-Path $global:BecCaseDir 'actions.log') -Raw -ErrorAction SilentlyContinue }

# Runs a command and returns only the warnings it wrote. -WarningVariable is silently ignored
# by non-advanced functions, so capture the warning stream instead.
function Get-TestWarnings([scriptblock]$Command) {
    & $Command 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object Message
}
