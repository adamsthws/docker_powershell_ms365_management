# Shell script tests: syntax, the argument checks that run before anything connects or changes, and
# what the scripts write. (winrm_client.py is syntax-checked on the host by test.sh: the container
# has no Python.)

BeforeAll {
    $script:dir = Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts'
    $script:sh = Join-Path $dir 'triage.sh'
    $script:certSh = Join-Path $dir 'new-winrm-cert.sh'
    $script:setupSh = Join-Path $dir 'setup-command.sh'
    $script:key = Join-Path $TestDrive 'id_test'
    Set-Content $key 'not a real key'
}

Describe 'triage.sh' -Tag Scripts {
    It 'passes bash -n' {
        & bash -n $sh 2>&1 | Should -BeNullOrEmpty
        $LASTEXITCODE | Should -Be 0
    }

    It 'prints usage with -h' {
        $out = & bash $sh -h 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $out | Should -Match 'Invoke-EndpointTriage\.ps1'
        $out | Should -Match 'auto \(default\)'
    }

    It 'refuses an unknown transport' {
        $out = & bash $sh -t telnet 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'transport must be'
    }

    It 'refuses WinRM without a client certificate' {
        $out = & bash $sh -t winrm -c (Join-Path $TestDrive 'nope.pem') -k (Join-Path $TestDrive 'nope.key') 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'new-winrm-cert\.sh'
    }

    It 'refuses SSH with a missing key file' {
        $out = & bash $sh -t ssh -i (Join-Path $TestDrive 'nope') 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'private key not found'
    }

    It 'refuses runner arguments with characters cmd.exe would interpret' {
        $out = & bash $sh -t ssh -i $key -- -Time '50%' 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'may not contain'
    }

    It 'refuses a malformed thumbprint' {
        $out = & bash $sh -t ssh -i $key -F 'xyz' 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'thumbprint'
    }

    It 'accepts a DOMAIN\user name' {
        $out = & bash $sh -t ssh -u 'AzureAD\someone' -i $key -p 1 2>&1 | Out-String
        $out | Should -Not -Match 'unexpected characters'
    }

    It 'reports nothing answering when auto-detecting on a closed port' {
        $out = & bash $sh -p 1 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'nothing answering'
    }

    It 'refuses a bad GitHub user for the key lookup' {
        $out = & bash $sh -t ssh -K 'bad user;' 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'not a GitHub user name'
    }
}

Describe 'triage.sh SSH key choice' -Tag Scripts {
    BeforeAll {
        # Made-up key pairs: the public halves are fake strings, the private halves placeholders.
        $script:sshDir = Join-Path $TestDrive 'dotssh'
        New-Item -ItemType Directory -Path $sshDir | Out-Null
        $script:matchPub = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAImatchexample'
        foreach ($k in @(
                @('id_other', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIotherexample other@example'),
                @('work_match', "$matchPub analyst@example"),
                @('nopriv_match', "$matchPub stray@example"))) {
            Set-Content (Join-Path $sshDir "$($k[0]).pub") $k[1]
            if ($k[0] -ne 'nopriv_match') { Set-Content (Join-Path $sshDir $k[0]) 'not a real key' }
        }
        $script:keysFile = Join-Path $TestDrive 'user.keys'
        Set-Content $keysFile "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQexample`n$matchPub"
        $script:oldSshDir = $env:ENDPOINT_TRIAGE_SSH_DIR
        $script:oldKeys = $env:ENDPOINT_TRIAGE_KEYS_FILE
        $env:ENDPOINT_TRIAGE_SSH_DIR = $sshDir
    }
    AfterAll {
        $env:ENDPOINT_TRIAGE_SSH_DIR = $oldSshDir
        $env:ENDPOINT_TRIAGE_KEYS_FILE = $oldKeys
    }

    It 'uses only the key pair whose public key the endpoint trusts' {
        $env:ENDPOINT_TRIAGE_KEYS_FILE = $keysFile
        $out = & bash $sh -t ssh -p 1 2>&1 | Out-String
        $out | Should -Match ('Using SSH key ' + [regex]::Escape((Join-Path $sshDir 'work_match')) + ' ')
        $out | Should -Not -Match 'id_other|nopriv_match'
    }

    It 'fails clearly when no local key pair is in the list' {
        $none = Join-Path $TestDrive 'none.keys'
        Set-Content $none 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInobodyexample'
        $env:ENDPOINT_TRIAGE_KEYS_FILE = $none
        $out = & bash $sh -t ssh -p 1 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'none of the key pairs .* has its public key in .*\(1 key\(s\) there\); give the key with -i'
    }

    It 'fails clearly when the list is empty' {
        $empty = Join-Path $TestDrive 'empty.keys'
        Set-Content $empty ''
        $env:ENDPOINT_TRIAGE_KEYS_FILE = $empty
        $out = & bash $sh -t ssh -p 1 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'lists no keys'
    }

    It 'skips the lookup when -i names the key' {
        $env:ENDPOINT_TRIAGE_KEYS_FILE = Join-Path $TestDrive 'missing.keys'
        $out = & bash $sh -t ssh -p 1 -i (Join-Path $sshDir 'id_other') 2>&1 | Out-String
        $out | Should -Not -Match 'Using SSH key|cannot read'
        $out | Should -Match 'Connecting over SSH'
    }
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

Describe 'setup-command.sh' -Tag Scripts {
    BeforeAll {
        $script:sha = '0123456789abcdef0123456789abcdef01234567'
        $script:oldXdg = $env:XDG_CONFIG_HOME
        $env:XDG_CONFIG_HOME = Join-Path $TestDrive 'emptyconfig'   # no winrm-gist: never the real one
        $script:pub = Join-Path $TestDrive 'id_test.pub'
        Set-Content $pub 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample analyst@example'
        $script:common = @('-r', $sha, '-g', 'example-owner/example-repo')
        $script:line = (& bash $setupSh @common -n 2>$null | Out-String).Trim()
    }
    AfterAll { $env:XDG_CONFIG_HOME = $oldXdg }

    It 'passes bash -n' {
        & bash -n $setupSh 2>&1 | Should -BeNullOrEmpty
    }

    It 'prints one line that downloads the script pinned to the commit' {
        @($line -split "`n").Count | Should -Be 1
        $line | Should -Match ([regex]::Escape("https://raw.githubusercontent.com/example-owner/example-repo/$sha/endpoint-triage/ps/setup/Set-TriageAccess.ps1"))
    }

    It 'takes the SSH keys from the repository owner on GitHub by default, with no key material in the line' {
        $line | Should -Match ' -GitHubUser example-owner$'
        $line | Should -Not -Match 'AAAA|MII|PublicKey|ClientCertificate'
        (& bash $setupSh @common -n -k analyst-example 2>$null | Out-String).Trim() | Should -Match ' -GitHubUser analyst-example$'
    }

    It 'puts a local public key in the line with -i, quoted for PowerShell' {
        $l = (& bash $setupSh @common -i $pub 2>$null | Out-String).Trim()
        $l | Should -Match " -PublicKey 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample analyst@example'$"
        $l | Should -Not -Match ' -GitHubUser '
    }

    It 'refuses -k and -i together, and a bad GitHub user' {
        & bash $setupSh @common -k analyst-example -i $pub 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 2
        & bash $setupSh @common -k 'bad user;' 2>&1 | Out-Null
        $LASTEXITCODE | Should -Be 2
    }

    It 'offers WinRM only with a Gist, and checks the Gist ID' {
        $out = & bash $setupSh @common -t winrm 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'no Gist'
        $out = & bash $setupSh @common -t winrm -G 'not-a-gist' 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'not a Gist ID'
        (& bash $setupSh @common -n 2>&1 | Out-String) | Should -Match 'WinRM is not offered'
    }

    It 'starts exactly like the command documented at the top of Set-TriageAccess.ps1' {
        $doc = Get-Content (Join-Path (Split-Path $dir -Parent) 'ps/setup/Set-TriageAccess.ps1') | Where-Object { $_ -match 'DownloadString\(' } | Select-Object -First 1
        $docPrefix = ($doc.Trim() -split "raw\.githubusercontent\.com/")[0]
        $line | Should -BeLike "$([WildcardPattern]::Escape($docPrefix))*"
        $doc | Should -Match 'endpoint-triage/ps/setup/Set-TriageAccess\.ps1'
        $doc | Should -Match '-GitHubUser <GITHUB USER> -ClientCertificate'
    }

    It 'gives -Status and -Remove commands without keys or certificates' {
        $status = (& bash $setupSh @common -m status 2>$null | Out-String).Trim()
        $status | Should -Match '\)\) -Status$'
        $remove = (& bash $setupSh @common -m remove -u triage-x 2>$null | Out-String).Trim()
        $remove | Should -Match '\)\) -Remove -UserName triage-x$'
    }

    It 'limits the methods with -t' {
        (& bash $setupSh @common -n -t ssh 2>$null | Out-String).Trim() | Should -Match '\)\) -Ssh -GitHubUser example-owner$'
    }

    It 'refuses a private key given as the public key' {
        $priv = Join-Path $TestDrive 'id_test'
        $kind = 'OPENSSH ' + 'PRIVATE KEY'   # built at runtime: no key header appears in the repository
        Set-Content $priv "-----BEGIN $kind-----`nnot-real`n-----END $kind-----"
        $out = & bash $setupSh @common -t ssh -i $priv 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 2
        $out | Should -Match 'not an SSH public key'
    }

    It 'warns when the ref is a branch rather than a commit' {
        $out = & bash $setupSh -r main -g 'example-owner/example-repo' -n 2>&1 | Out-String
        $out | Should -Match 'not a commit'
    }
}
