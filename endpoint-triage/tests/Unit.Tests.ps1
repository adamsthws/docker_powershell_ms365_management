# Behaviour tests for the parsers, with synthetic data (documentation IPs, made-up IDs).
# They run under pwsh on Linux; the Windows-only parts (event logs, registry) are not exercised here.

BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent
    . (Join-Path $root 'ps/TriageCommon.ps1')

    function New-TraceLine([string]$Time, [string]$Proc, [string]$Component, [string]$Message) {
        '{0,8} {1}  {2,10}  {3,5}  {4,5} 12  {5} - {6}' -f 'info', "2026-01-15 $Time", $Proc, 1000, 2000, $Component, $Message
    }

    $script:anyDir = Join-Path $TestDrive 'anydesk'
    New-Item -ItemType Directory -Path $anyDir | Out-Null
    $lines = @(
        'header line that is not a trace entry'
        (New-TraceLine '14:00:00.000' 'hub' 'main' 'Command Line params: "C:\Users\user\Downloads\AnyDesk.exe"')
        (New-TraceLine '14:00:05.000' 'lsvc' 'anynet.relay_conn' 'External address: 198.51.100.20:49731.')
        (New-TraceLine '14:00:06.000' 'lsvc' 'gcpsa' 'Downloading gcapi.dll.')
        (New-TraceLine '14:00:07.000' 'lsvc' 'permission_profile_manager' 'Migrating V0 -> V1')
        (New-TraceLine '14:00:08.000' 'lsvc' 'app.screen_recording_service' 'Screen recording manager registered with os_session_id 1')
        (New-TraceLine '14:01:00.000' 'lsvc' 'anynet.any_socket' 'Accept request from 111222333 (via relay).')
        (New-TraceLine '14:01:00.050' 'lsvc' 'anynet.any_socket' 'Client-ID: 111222333 (FPR: abcdef123456).')
        (New-TraceLine '14:01:00.060' 'lsvc' 'anynet.any_socket' 'Logged in from 203.0.113.10:50001 on relay 1a2b3c4d.')
        (New-TraceLine '14:01:01.000' 'back' 'app.backend_session' 'Remote version: 9.8.3')
        (New-TraceLine '14:01:30.000' 'lsvc' 'app.session' '3: Authenticated by local user (elevated).')
        (New-TraceLine '14:01:31.000' 'lsvc' 'os_win.start_uac_handle' 'Opening UAC dialog.')
        (New-TraceLine '14:05:00.000' 'back' 'app.backend_session' 'The remote user requested to enable privacy mode.')
        (New-TraceLine '14:05:00.100' 'back' 'os_win.input_injector' 'New input state: blocked')
        (New-TraceLine '14:15:00.100' 'back' 'os_win.input_injector' 'New input state: unblocked')
        (New-TraceLine '14:20:00.000' 'back' 'app.backend_session' 'Sending file manager (11) permissions (enabled allowed supported)')
        (New-TraceLine '14:21:00.000' 'back' 'app.file_transfer' 'Preparing files for upload: invoice.pdf')
        (New-TraceLine '14:30:00.000' 'lsvc' 'anynet.any_socket' 'Logged in from 203.0.113.11:50002 on relay 5e6f7a8b.')
        (New-TraceLine '14:30:10.000' 'lsvc' 'app.session' '3: Authenticated by local user.')
        (New-TraceLine '14:31:00.000' 'back' 'os_win.input_injector' 'New input state: blocked')
        (New-TraceLine '14:33:30.000' 'back' 'app.backend_session' 'Session stopped.')
    )
    $lines | Set-Content (Join-Path $anyDir 'ad.trace') -Encoding ascii
    "Incoming    2026-01-15, 14:01    User                111222333    111222333`r`nIncoming    2026-01-15, 14:30    User                111222333    111222333" |
        Set-Content (Join-Path $anyDir 'connection_trace.txt') -Encoding Unicode
    "ad.anynet.id=444555666`nad.anynet.alias=`nad.anynet.last_relay=relay-example:443" | Set-Content (Join-Path $anyDir 'system.conf') -Encoding ascii
}

Describe 'AnyDesk trace parsing' -Tag Unit {
    BeforeAll {
        $script:entries = @(ConvertFrom-TriageAnyDeskTrace -Path (Join-Path $anyDir 'ad.trace'))
        $script:summary = Get-TriageAnyDeskSummary -Entry $entries
    }

    It 'skips lines that are not trace entries' {
        $entries.Count | Should -Be 20
    }

    It 'finds both incoming sessions with the remote ID, IP, port and relay' {
        $summary.Sessions.Count | Should -Be 2
        $summary.Sessions[0].RemoteId | Should -Be '111222333'
        $summary.Sessions[0].RemoteIp | Should -Be '203.0.113.10'
        $summary.Sessions[0].RemotePort | Should -Be '50001'
        $summary.Sessions[0].Relay | Should -Be '1a2b3c4d'
        $summary.Sessions[0].Fingerprint | Should -Be 'abcdef123456'
        $summary.Sessions[1].RemoteIp | Should -Be '203.0.113.11'
    }

    It 'marks only the session accepted with elevation as elevated' {
        $summary.Sessions[0].Elevated | Should -BeTrue
        $summary.Sessions[1].Elevated | Should -BeFalse
        $summary.Elevations.Message | Should -Contain 'Opening UAC dialog.'
    }

    It 'measures privacy-mode windows, closing one at session stop' {
        $summary.PrivacyWindows.Count | Should -Be 2
        $summary.PrivacyWindows[0].Duration.TotalMinutes | Should -Be 10
        $summary.PrivacyWindows[1].Duration.TotalSeconds | Should -Be 150
        $summary.PrivacyTotal.TotalSeconds | Should -Be 750
    }

    It 'reports file transfer events but not permission announcements' {
        $summary.FileEvents.Message | Should -Contain 'Preparing files for upload: invoice.pdf'
        ($summary.FileEvents.Message -join ' ') | Should -Not -Match 'permissions \('
        ($summary.FileEvents.Message -join ' ') | Should -Not -Match 'Command Line params|Migrating'
        @($summary.FileEvents).Count | Should -Be 1
    }

    It 'keeps routine capture and recording-service lines out of the notable events' {
        ($summary.Notable.Message -join ' ') | Should -Not -Match 'Screen recording manager'
        ($summary.Notable.Message -join ' ') | Should -Match 'privacy mode'
    }

    It 'reports the endpoint''s external address' {
        $summary.ExternalAddresses | Should -Be '198.51.100.20:49731'
    }
}

Describe 'AnyDesk config and connection trace' -Tag Unit {
    It 'reads this endpoint''s AnyDesk ID and reports no unattended password' {
        $c = Get-TriageAnyDeskConfig -Path (Join-Path $anyDir 'system.conf')
        $c.AnyDeskId | Should -Be '444555666'
        $c.UnattendedPassword | Should -BeFalse
    }

    It 'flags an unattended-access password' {
        $f = Join-Path $TestDrive 'pw.conf'
        "ad.anynet.id=444555666`nad.anynet.pwd_hash=0123abcd`nad.anynet.pwd_salt=ff00" | Set-Content $f -Encoding ascii
        $c = Get-TriageAnyDeskConfig -Path $f
        $c.UnattendedPassword | Should -BeTrue
        $c.PasswordKeys | Should -Contain 'ad.anynet.pwd_hash'
    }

    It 'reads a UTF-16 connection_trace.txt' {
        $rows = @(ConvertFrom-TriageAnyDeskConnectionTrace -Path (Join-Path $anyDir 'connection_trace.txt'))
        $rows.Count | Should -Be 2
        $rows[0].Direction | Should -Be 'Incoming'
        $rows[0].Time | Should -Be '2026-01-15, 14:01'
        $rows[0].RemoteIds | Should -Match '111222333'
    }
}

Describe '03-Get-AnyDeskActivity.ps1 on collected files' -Tag Unit {
    It 'produces the session, elevation and privacy sections from a folder of copied files' {
        $out = & (Join-Path $root 'ps/checks/03-Get-AnyDeskActivity.ps1') -Path $anyDir | Out-String
        $out | Should -Match 'Incoming sessions'
        $out | Should -Match '203\.0\.113\.10'
        $out | Should -Match 'total 00:12:30'
        $out | Should -Match 'UnattendedPassword\s+:\s+False'
    }
}

Describe 'Prefetch parsing' -Tag Unit {
    It 'reads the executable name and run times from an uncompressed version 30 file' {
        $b = New-Object byte[] 0x100
        [BitConverter]::GetBytes([int]30).CopyTo($b, 0)
        [Text.Encoding]::ASCII.GetBytes('SCCA').CopyTo($b, 4)
        [Text.Encoding]::Unicode.GetBytes('IPCONFIG.EXE').CopyTo($b, 0x10)
        $t1 = [datetime]'2026-01-15 14:10:00'
        $t2 = [datetime]'2026-01-15 14:12:30'
        [BitConverter]::GetBytes($t2.ToFileTime()).CopyTo($b, 0x80)
        [BitConverter]::GetBytes($t1.ToFileTime()).CopyTo($b, 0x88)
        $f = Join-Path $TestDrive 'IPCONFIG.EXE-12345678.pf'
        [IO.File]::WriteAllBytes($f, $b)

        $pf = ConvertFrom-TriagePrefetch -Path $f
        $pf.Executable | Should -Be 'IPCONFIG.EXE'
        $pf.Version | Should -Be 30
        $pf.RunTimes.Count | Should -Be 2
        $pf.RunTimes[0] | Should -Be $t1
        $pf.RunTimes[1] | Should -Be $t2
    }

    It 'rejects a file without the SCCA signature' {
        $f = Join-Path $TestDrive 'bad.pf'
        [IO.File]::WriteAllBytes($f, (New-Object byte[] 0x100))
        { ConvertFrom-TriagePrefetch -Path $f } | Should -Throw '*SCCA*'
    }
}

Describe 'Formatting helpers' -Tag Unit {
    It 'Format-TriageTable says (none) for no input' {
        @() | Format-TriageTable | Should -Be '  (none)'
    }
    It 'Write-TriageSection emits a blank line and a heading' {
        $s = @(Write-TriageSection 'Example')
        $s[1] | Should -Be '=== Example'
    }
}
