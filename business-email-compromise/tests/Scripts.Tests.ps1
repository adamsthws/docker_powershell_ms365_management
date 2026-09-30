# Runs the host shell scripts for real (they only touch the filesystem until docker starts).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestTools.ps1')
    $scripts = Join-Path $BecTestRoot 'scripts'
    function Invoke-Script([string]$Name, [string]$Answer, [string[]]$Arguments) {
        $output = $Answer | bash (Join-Path $scripts $Name) @Arguments 2>&1
        [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output -join "`n" }
    }
}

Describe 'Shell scripts' -Tag Scripts {
    It '<_> passes bash -n' -ForEach (Get-ChildItem (Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts') -Filter '*.sh').Name {
        bash -n (Join-Path $scripts $_) 2>&1 | Should -BeNullOrEmpty
        $LASTEXITCODE | Should -Be 0
    }
}

Describe 'new-case.sh' -Tag Scripts {
    BeforeEach { $env:BEC_CASES_DIR = Join-Path $TestDrive ([guid]::NewGuid().ToString('N')) }
    AfterEach { Remove-Item Env:BEC_CASES_DIR }

    It 'prints usage without arguments' {
        $r = Invoke-Script 'new-case.sh' '' @()
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match 'new-case.sh <client-slug>'
    }

    It 'creates nothing when declined' {
        $r = Invoke-Script 'new-case.sh' 'n' @('contoso', 'jane@contoso.com')
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match 'Skipped'
        $env:BEC_CASES_DIR | Should -Not -Exist
    }

    It 'creates a valid case when approved' {
        $r = Invoke-Script 'new-case.sh' 'y' @('contoso', 'jane@contoso.com', '203.0.113.', '2001:db8:1234:')
        $r.ExitCode | Should -Be 0
        $case = Get-ChildItem $env:BEC_CASES_DIR -Directory | Select-Object -First 1
        $case.Name | Should -Match '^\d{8}-contoso-jane$'
        $json = Get-Content (Join-Path $case 'case.json') -Raw | ConvertFrom-Json
        $json.upn | Should -Be 'jane@contoso.com'
        $json.knownGoodIpPrefixes | Should -Be @('203.0.113.', '2001:db8:1234:')
        foreach ($p in 'intake.md', 'actions.log', 'evidence', 'notification', 'report') { Join-Path $case $p | Should -Exist }
    }

    It 'writes valid JSON with no known-good prefixes' {
        Invoke-Script 'new-case.sh' 'y' @('contoso', 'jane@contoso.com') | Out-Null
        $case = Get-ChildItem $env:BEC_CASES_DIR -Directory | Select-Object -First 1
        (Get-Content (Join-Path $case 'case.json') -Raw | ConvertFrom-Json).knownGoodIpPrefixes | Should -BeNullOrEmpty
    }

    It 'refuses to overwrite an existing case' {
        Invoke-Script 'new-case.sh' 'y' @('contoso', 'jane@contoso.com') | Out-Null
        $r = Invoke-Script 'new-case.sh' 'y' @('contoso', 'jane@contoso.com')
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match 'already exists'
    }
}

Describe 'bec-shell.sh' -Tag Scripts {
    It 'rejects an unknown mode' {
        $r = Invoke-Script 'bec-shell.sh' '' @('teams', $TestDrive)
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match 'bec-shell.sh exo'
    }

    It 'refuses a folder without case.json' {
        $r = Invoke-Script 'bec-shell.sh' 'y' @('exo', $TestDrive)
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match 'No case.json'
    }

    It 'starts nothing when declined' {
        $dir = Join-Path $TestDrive 'case'
        New-Item -ItemType Directory $dir | Out-Null
        '{ "upn": "jane@contoso.com" }' | Set-Content (Join-Path $dir 'case.json')
        $r = Invoke-Script 'bec-shell.sh' 'n' @('exo', $dir)
        $r.ExitCode | Should -Not -Be 0
        $r.Output | Should -Match 'Mailbox:\s+jane@contoso.com'
        $r.Output | Should -Match 'Skipped'
    }
}
