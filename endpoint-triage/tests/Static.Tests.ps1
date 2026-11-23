# Static checks: no endpoint, no mocks. They read the source and fail on anything that would break
# on Windows PowerShell 5.1, change the endpoint from a check, or leak real data into the repo.

BeforeDiscovery {
    $root = Split-Path $PSScriptRoot -Parent
    $psFiles = Get-ChildItem (Join-Path $root 'ps') -Recurse -Filter '*.ps1'
    $fileCases = $psFiles | ForEach-Object { @{ Name = $_.FullName.Substring($root.Length + 1); Path = $_.FullName } }
    $checkCases = Get-ChildItem (Join-Path $root 'ps/checks') -Filter '*.ps1' | ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
    $readOnlyCases = @(Get-ChildItem (Join-Path $root 'ps/checks') -Filter '*.ps1') + @(Get-Item (Join-Path $root 'ps/TriageCommon.ps1')) |
        ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
}

BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    function Get-Ast([string]$Path) {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
    }
    function Get-CommandName($Ast) {
        $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object {
            [pscustomobject]@{ Name = $_.GetCommandName(); Line = $_.Extent.StartLineNumber; Text = $_.Extent.Text }
        } | Where-Object Name
    }
}

Describe 'Syntax, lint and Windows PowerShell 5.1 compatibility' -Tag Static {
    It '<Name> parses without errors' -ForEach $fileCases {
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
        $errors | ForEach-Object { "line $($_.Extent.StartLineNumber): $($_.Message)" } | Should -BeNullOrEmpty
    }

    It '<Name> passes PSScriptAnalyzer (including PSUseCompatibleSyntax for 5.1)' -ForEach $fileCases {
        $settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
        Invoke-ScriptAnalyzer -Path $Path -Settings $settings |
            ForEach-Object { "$($_.Severity) $($_.RuleName) line $($_.Line): $($_.Message)" } | Should -BeNullOrEmpty
    }

    It '<Name> is ASCII-only (5.1 reads BOM-less files as ANSI)' -ForEach $fileCases {
        $bytes = [IO.File]::ReadAllBytes($Path)
        $bad = for ($i = 0; $i -lt $bytes.Length; $i++) { if ($bytes[$i] -gt 127) { $i; break } }
        $bad | Should -BeNullOrEmpty -Because 'non-ASCII characters (smart quotes, dashes) break under Windows PowerShell 5.1'
    }

    It '<Name> uses no PowerShell 7-only cmdlet parameters' -ForEach $fileCases {
        $text = Get-Content $Path -Raw
        $hits = @()
        if ($text -match 'ForEach-Object\s+-Parallel') { $hits += 'ForEach-Object -Parallel' }
        if ($text -match 'ConvertFrom-Json\s+[^|\r\n]*-AsHashtable') { $hits += 'ConvertFrom-Json -AsHashtable' }
        if ($text -match 'Get-Date\s+[^|\r\n]*-AsUTC') { $hits += 'Get-Date -AsUTC' }
        $joins = (Get-Ast $Path).FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Join-Path' }, $true)
        foreach ($j in $joins) {
            $positional = @($j.CommandElements | Select-Object -Skip 1 | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] })
            if ($positional.Count -gt 2) { $hits += "Join-Path with more than two path arguments, line $($j.Extent.StartLineNumber)" }
        }
        $hits | Should -BeNullOrEmpty
    }
}

Describe 'Checks only read' -Tag Static {
    It '<Name> calls no command that changes the endpoint' -ForEach $readOnlyCases {
        $changing = '^(Set|Remove|Stop|Start|Restart|Disable|Enable|Clear|Register|Unregister|Rename|Move|Install|Uninstall|Suspend|Resume|Reset|Grant|Revoke|Block|Unblock|Update|Publish|Push|Copy|Mount|Dismount|Invoke|Limit|Protect|Unprotect|Save|Export|Out-File|Set-Content|Add-Content|New-Item)-?'
        $allowed = 'New-Object', 'New-TimeSpan', 'Add-Type', 'Add-Member', 'Invoke-ScriptAnalyzer'
        $nativeAllowed = @{ 'quser' = '.*'; 'netsh' = '\bshow\b' }
        $problems = Get-CommandName (Get-Ast $Path) | Where-Object {
            $n = $_.Name
            if ($n -in $allowed) { return $false }
            if ($nativeAllowed.ContainsKey($n)) { return $_.Text -notmatch $nativeAllowed[$n] }
            if ($n -match '^(New|Add)-') { return $true }
            if ($n -match $changing) { return $true }
            if ($n -match '^(reg|sc|net|net1|icacls|takeown|schtasks|wmic|bcdedit|vssadmin|wevtutil|cmd|powershell|pwsh|del|rd|rmdir)(\.exe)?$') { return $true }
            $false
        } | ForEach-Object { "line $($_.Line): $($_.Text)" }
        $problems | Should -BeNullOrEmpty
    }

    It '<Name> never touches browser credential or cookie stores' -ForEach $readOnlyCases {
        # Code only: help text may say these files are never read.
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $code = ($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' '
        $code | Should -Not -Match 'Login Data|Cookies|Local State|Web Data|key4\.db|logins\.json|cookies\.sqlite'
    }
}

Describe 'Check script conventions' -Tag Static {
    It '<Name> has help with SYNOPSIS, DESCRIPTION and EXAMPLE' -ForEach $checkCases {
        $help = (Get-Ast $Path).GetHelpContent()
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Description | Should -Not -BeNullOrEmpty
        $help.Examples | Should -Not -BeNullOrEmpty
    }

    It '<Name> is named NN-Verb-Noun.ps1 and dot-sources TriageCommon.ps1' -ForEach $checkCases {
        $Name | Should -Match '^\d{2}-[A-Z][a-z]+-[A-Za-z]+\.ps1$'
        Get-Content $Path -Raw | Should -Match "if \(-not \(Get-Command Write-TriageSection -ErrorAction SilentlyContinue\)\) \{ \. \(Join-Path \(Split-Path \`$PSScriptRoot -Parent\) 'TriageCommon\.ps1'\) \}"
    }

    It '<Name> uses $PSScriptRoot only to load TriageCommon.ps1 when run by hand (the runner runs it as text)' -ForEach $checkCases {
        $uses = @(Get-Content $Path | Where-Object { $_ -match '\$PSScriptRoot' -and $_ -notmatch '^\s*#' })
        $uses.Count | Should -Be 1
        $uses[0] | Should -Match '^if \(-not \(Get-Command Write-TriageSection'
    }

    It '<Name> is run by Invoke-EndpointTriage.ps1 and documented in README.md' -ForEach $checkCases {
        $n = $Name.Substring(0, 2)
        Get-Content (Join-Path $root 'ps/Invoke-EndpointTriage.ps1') -Raw | Should -Match "N = '$n'"
        Get-Content (Join-Path $root 'README.md') -Raw | Should -Match ([regex]::Escape($Name))
    }
}

Describe 'No real data in the repo' -Tag Static {
    It 'only documentation, private or loopback IPv4 addresses appear in tracked text files' {
        $octet = '(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
        $rx = "(?<![\d.])$octet\.$octet\.$octet\.$octet(?![\d.])"
        # 2.5.29.x are X.509 extension OIDs, not addresses.
        $ok = '^(2\.5\.29\.|127\.|0\.0\.0\.0$|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)'
        $hits = Get-ChildItem $root -Recurse -File -Include '*.ps1', '*.md', '*.sh', '*.psd1' | ForEach-Object {
            $f = $_
            Select-String -Path $f.FullName -Pattern $rx -AllMatches | ForEach-Object {
                foreach ($m in $_.Matches) { if ($m.Value -notmatch $ok) { "$($f.Name):$($_.LineNumber) $($m.Value)" } }
            }
        }
        $hits | Should -BeNullOrEmpty
    }
}
