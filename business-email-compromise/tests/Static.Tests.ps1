# Static checks: no tenant, no mocks. These read the source and fail on anything that would
# break or bypass the runbook's guarantees before it reaches a live environment.

BeforeDiscovery {
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    $functions = Get-BecFunctionInfo $BecPsFiles.FullName
    $fileCases = $BecPsFiles | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
    $gatedCases = $functions | Where-Object Confirm | ForEach-Object { @{ Name = $_.Name; File = $_.File } }
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    . (Join-Path $BecTestRoot 'ps/BecCommon.ps1')
    $functions = Get-BecFunctionInfo $BecPsFiles.FullName
    $ours = @($functions.Name)
    $usage = Get-BecCommandUsage $BecPsFiles.FullName
    $kinds = @{}
    $usage.Command | Sort-Object -Unique | ForEach-Object { $kinds[$_] = Get-BecCommandKind $_ $ours }
    $gated = @($functions | Where-Object Confirm)
    $gatedNames = @($gated.Name)
    function Get-Fn([string]$Name) { $functions | Where-Object Name -eq $Name | Select-Object -First 1 }
    function Get-TenantCalls($Fn) { $Fn.Calls | Where-Object { $kinds[$_.GetCommandName()] -in 'Exchange', 'Graph' } }
}

Describe 'Syntax and lint' -Tag Static {
    It '<Name> parses without errors' -ForEach $fileCases {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        $errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" } | Should -BeNullOrEmpty
    }

    It '<Name> passes PSScriptAnalyzer' -ForEach $fileCases {
        $settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
        Invoke-ScriptAnalyzer -Path $Path -Settings $settings |
            ForEach-Object { "$($_.Severity) $($_.RuleName) line $($_.Line): $($_.Message)" } | Should -BeNullOrEmpty
    }
}

Describe 'Commands and parameters' -Tag Static {
    It 'every command resolves (Exchange cmdlets must be in the known list in TestTools.ps1)' {
        $usage | Where-Object { $kinds[$_.Command] -eq 'Unknown' } |
            ForEach-Object { "$($_.File):$($_.Line) $($_.Command)" } | Should -BeNullOrEmpty
    }

    It 'Graph cmdlets and their named parameters exist in the installed Microsoft.Graph modules' {
        $problems = $usage | Where-Object { $kinds[$_.Command] -eq 'Graph' } | ForEach-Object {
            $row = $_
            $cmd = Get-Command $row.Command
            $known = @($cmd.Parameters.Keys) + @($cmd.Parameters.Values.Aliases)
            $row.Parameters | Where-Object { $_ -notin $known } | ForEach-Object { "$($row.File):$($row.Line) $($row.Command) -$_" }
        }
        $problems | Should -BeNullOrEmpty
    }

    It 'BecExchange.ps1 never calls Graph and BecGraph.ps1 never calls Exchange (MSAL conflict)' {
        $usage | Where-Object {
            ($_.File -eq 'BecExchange.ps1' -and $kinds[$_.Command] -eq 'Graph') -or
            ($_.File -eq 'BecGraph.ps1' -and $kinds[$_.Command] -eq 'Exchange') -or
            ($_.File -eq 'BecCommon.ps1' -and $kinds[$_.Command] -in 'Exchange', 'Graph')
        } | ForEach-Object { "$($_.File):$($_.Line) $($_.Command)" } | Should -BeNullOrEmpty
    }

    It 'Stubs.ps1 covers every tenant cmdlet and named parameter the helpers use' {
        $stubs = Get-BecFunctionInfo (Join-Path $PSScriptRoot 'Stubs.ps1')
        $problems = $usage | Where-Object { $kinds[$_.Command] -in 'Exchange', 'Graph' } | ForEach-Object {
            $row = $_
            $stub = $stubs | Where-Object Name -eq $row.Command
            if (-not $stub) { return "$($row.Command): no stub" }
            $known = @($stub.Parameters) + [System.Management.Automation.Cmdlet]::CommonParameters + [System.Management.Automation.Cmdlet]::OptionalCommonParameters
            $row.Parameters | Where-Object { $_ -notin $known } | ForEach-Object { "$($row.Command): stub lacks -$_" }
        }
        $problems | Sort-Object -Unique | Should -BeNullOrEmpty
    }
}

Describe 'Every step is gated' -Tag Static {
    It 'functions that call tenant cmdlets are gated, or only called from gated steps' {
        $problems = $functions | Where-Object { -not $_.Confirm -and (Get-TenantCalls $_) } | ForEach-Object {
            $helper = $_.Name
            $callers = @($functions | Where-Object { $_.Name -ne $helper -and @($_.Calls | ForEach-Object { $_.GetCommandName() }) -contains $helper })
            if (-not $callers) { "$helper calls the tenant, is not gated and is not called by any step" }
            $callers | Where-Object { -not $_.Confirm } | ForEach-Object { "$helper is called from ungated $($_.Name)" }
        }
        $problems | Should -BeNullOrEmpty
    }

    It '<Name> has a -Force switch and passes it through to Confirm-BecStep' -ForEach $gatedCases {
        $fn = Get-Fn $Name
        $fn.Parameters | Should -Contain 'Force'
        $fn.Confirm.Extent.Text | Should -Match '-Force:\$Force'
    }

    It '<Name> returns when the admin declines: if (-not (Confirm-BecStep ...)) { return }' -ForEach $gatedCases {
        $fn = Get-Fn $Name
        $gates = $fn.Ast.Body.FindAll({ $args[0] -is [System.Management.Automation.Language.IfStatementAst] }, $true) | Where-Object {
            $clause = $_.Clauses[0]
            $clause.Item1.Extent.Text -match '^-not\s*\(\s*Confirm-BecStep\b' -and
            $clause.Item1.Extent.Text -notmatch '-and|-or' -and
            $clause.Item2.Extent.Text -match '^\{\s*return\s*\}$' -and
            $clause.Item1.Extent.StartOffset -le $fn.Confirm.Extent.StartOffset -and
            $clause.Item1.Extent.EndOffset -ge $fn.Confirm.Extent.EndOffset
        }
        $gates | Should -Not -BeNullOrEmpty -Because 'a declined prompt must stop the step before it does anything'
    }

    It '<Name> describes the step (-Step and -Description)' -ForEach $gatedCases {
        $text = (Get-Fn $Name).Confirm.Extent.Text
        $text | Should -Match '-Step\b'
        $text | Should -Match '-Description\b'
    }

    It 'every tenant change is behind a prompt that lists it, with -WhatIf support' {
        $problems = $functions | ForEach-Object {
            $fn = $_
            $mutating = @($fn.Calls | Where-Object { Test-BecMutatingCommand $_.GetCommandName() $kinds[$_.GetCommandName()] })
            if (-not $mutating) { return }
            if (-not $fn.Confirm) { return "$($fn.Name): changes the tenant without Confirm-BecStep" }
            $firstChange = ($mutating | ForEach-Object { $_.Extent.StartOffset } | Measure-Object -Minimum).Minimum
            if ($fn.Confirm.Extent.StartOffset -gt $firstChange) { "$($fn.Name): changes the tenant before asking" }
            if ($fn.Confirm.Extent.Text -notmatch '-Changes\b') { "$($fn.Name): prompt does not list the changes (-Changes)" }
            if (-not $fn.SupportsShouldProcess) { "$($fn.Name): missing [CmdletBinding(SupportsShouldProcess)]" }
            if (-not $fn.UsesShouldProcess) { "$($fn.Name): never calls `$PSCmdlet.ShouldProcess()" }
            if ($fn.Ast.Body.ParamBlock.Extent.Text -match "ConfirmImpact\s*=\s*'High'") { "$($fn.Name): ConfirmImpact High would ask twice" }
        }
        $problems | Should -BeNullOrEmpty
    }

    It 'steps call other steps with -Force so the admin is asked once' {
        $problems = $gated | ForEach-Object {
            $fn = $_
            $fn.Calls | Where-Object { $_.GetCommandName() -in $gatedNames -and $_.GetCommandName() -ne $fn.Name } | ForEach-Object {
                if ($_.CommandElements.ParameterName -notcontains 'Force') { "$($fn.Name) calls $($_.GetCommandName()) without -Force (line $($_.Extent.StartLineNumber))" }
            }
        }
        $problems | Should -BeNullOrEmpty
    }

    It '<Name> is listed in Show-BecHelp' -ForEach $gatedCases {
        $help = $functions | Where-Object { $_.Name -eq 'Show-BecHelp' -and $_.File -eq $File }
        $help.Ast.Extent.Text | Should -Match ([regex]::Escape($Name))
    }

    It 'Remove-BecInboxRule refuses to run without an evidence snapshot' {
        (Get-Fn 'Remove-BecInboxRule').Ast.Extent.Text | Should -Match "snapshot-\*"
    }
}

Describe 'Documentation' -Tag Static {
    BeforeAll {
        $docs = Get-ChildItem $BecTestRoot -Recurse -Include '*.md', '*.txt' | Where-Object FullName -notmatch '[\\/]tests[\\/]'
        $scripts = Get-ChildItem (Join-Path $BecTestRoot 'scripts') -Filter '*.sh' | ForEach-Object Name
    }

    It 'every Bec command and script named in the docs exists' {
        $problems = $docs | ForEach-Object {
            $doc = $_
            [regex]::Matches((Get-Content $doc.FullName -Raw), '\b[A-Z][a-z]+-Bec[A-Za-z]+\b') | ForEach-Object Value | Sort-Object -Unique |
                Where-Object { $_ -notin $ours } | ForEach-Object { "$($doc.Name): $_ does not exist" }
            [regex]::Matches((Get-Content $doc.FullName -Raw), '\b[\w-]+\.sh\b') | ForEach-Object Value | Sort-Object -Unique |
                Where-Object { $_ -notin $scripts } | ForEach-Object { "$($doc.Name): $_ does not exist" }
        }
        $problems | Should -BeNullOrEmpty
    }

    It 'docs never tell the admin to skip a prompt with -Force' {
        # AGENTS.md is exempt: it explains the rule for people extending the tooling.
        $docs | Where-Object Name -ne 'AGENTS.md' | Select-String -Pattern '-Bec\w+[^\r\n]*\s-Force\b' |
            ForEach-Object { "$($_.Filename):$($_.LineNumber) $($_.Line.Trim())" } | Should -BeNullOrEmpty
    }

    It 'every step is documented in a procedure' {
        $procedures = (Get-ChildItem (Join-Path $BecTestRoot 'procedures') -Filter '*.md' | Get-Content -Raw) -join "`n"
        $gatedNames | Where-Object { $procedures -notmatch [regex]::Escape($_) } | Should -BeNullOrEmpty
    }

    It 'docs, templates and scripts only use documentation IP ranges' {
        $files = @($docs) + @(Get-ChildItem (Join-Path $BecTestRoot 'ps'), (Join-Path $BecTestRoot 'scripts') -File)
        $ipv4 = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
        $ipv6 = '\b(?=[0-9a-fA-F:]*[a-fA-F])[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b'
        $problems = $files | ForEach-Object {
            $file = $_
            $text = Get-Content $file.FullName -Raw
            [regex]::Matches($text, $ipv4) | ForEach-Object Value | Where-Object { $_ -notmatch '^(192\.0\.2|198\.51\.100|203\.0\.113)\.' } | ForEach-Object { "$($file.Name): $_" }
            [regex]::Matches($text, $ipv6) | ForEach-Object Value | Where-Object { $_ -notmatch '^2001:db8' } | ForEach-Object { "$($file.Name): $_" }
        }
        $problems | Sort-Object -Unique | Should -BeNullOrEmpty
    }
}
