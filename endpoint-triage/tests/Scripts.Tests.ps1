# Shell script tests: syntax, the argument checks that run before anything connects or changes, and
# what the scripts write.

BeforeAll {
    $script:dir = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts'
    $script:certSh = Join-Path $dir 'new-winrm-cert.sh'
}

Describe 'new-winrm-cert.sh' -Tag Scripts {
    BeforeAll {
        $script:certDir = Join-Path $TestDrive 'cert'
        $script:made = & bash $certSh -u 'triage-x' -d $certDir -n 30 2>&1 | Out-String
        $script:madeExit = $LASTEXITCODE
        $script:text = & openssl x509 -in (Join-Path $certDir 'winrm-client.pem') -noout -text 2>&1 | Out-String
    }

    It 'passes bash -n' {
        & bash -n $certSh 2>&1 | Should -BeNullOrEmpty
    }

    It 'writes the key, PEM and DER certificate' {
        $madeExit | Should -Be 0
        foreach ($f in 'winrm-client.key', 'winrm-client.pem', 'winrm-client.cer') { Join-Path $certDir $f | Should -Exist }
        $made | Should -Match 'thumbprint [0-9A-F]{40}'
    }

    It 'makes a client-authentication certificate that cannot sign others' {
        $text | Should -Match 'TLS Web Client Authentication'
        $text | Should -Not -Match 'TLS Web Server Authentication'
        $text | Should -Match 'CA:FALSE'
    }

    It 'carries the UPN user@localhost that Windows maps to the account' {
        $text | Should -Match 'othername:\s*(UPN|1\.3\.6\.1\.4\.1\.311\.20\.2\.3)[:;]+\s*(UTF8:)?triage-x@localhost'
    }

    It 'keeps the private key private' {
        (& stat -c '%a' (Join-Path $certDir 'winrm-client.key')) | Should -Be '600'
    }

    It 'refuses to overwrite without -f, and overwrites with it' {
        $out = & bash $certSh -u 'triage-x' -d $certDir 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'already exists'
        & bash $certSh -u 'triage-x' -d $certDir -f 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 0
    }

    It 'refuses to write inside a git repository' {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Set-ItResult -Skipped -Because 'git is not installed'; return }
        $repo = Join-Path $TestDrive 'somerepo'
        New-Item -ItemType Directory -Path $repo | Out-Null
        & git -C $repo init -q 2>&1 | Out-Null
        $out = & bash $certSh -d (Join-Path $repo 'certs/new') 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'inside a git repository'
        Join-Path $repo 'certs' | Should -Not -Exist
    }

    It 'refuses a user name Windows would not accept' {
        $out = & bash $certSh -u 'bad name' -d (Join-Path $TestDrive 'other') 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'user name'
    }
}
