# Shared helpers for the endpoint triage checks.
# Runs on the endpoint under Windows PowerShell 5.1 (and PowerShell 7). Keep this file ASCII-only:
# Windows PowerShell 5.1 reads BOM-less files as ANSI and mangles anything else.
# Nothing in here changes the endpoint.

function Write-TriageSection {
    <# .SYNOPSIS Emits a section heading line for the text report. #>
    param([Parameter(Mandatory)][string]$Title)
    ''
    "=== $Title"
}

function Format-TriageTable {
    <# .SYNOPSIS Formats objects as a wide table string, or '(none)' when there are none. #>
    param([Parameter(ValueFromPipeline)]$InputObject, [string[]]$Property)
    begin { $items = New-Object System.Collections.ArrayList }
    process { if ($null -ne $InputObject) { [void]$items.Add($InputObject) } }
    end {
        if ($items.Count -eq 0) { return '  (none)' }
        if ($Property) { $items | Format-Table -Property $Property -AutoSize -Wrap | Out-String -Width 300 }
        else { $items | Format-Table -AutoSize -Wrap | Out-String -Width 300 }
    }
}

function Format-TriageList {
    <# .SYNOPSIS Formats objects as a list string, or '(none)' when there are none. #>
    param([Parameter(ValueFromPipeline)]$InputObject)
    begin { $items = New-Object System.Collections.ArrayList }
    process { if ($null -ne $InputObject) { [void]$items.Add($InputObject) } }
    end {
        if ($items.Count -eq 0) { return '  (none)' }
        $items | Format-List | Out-String -Width 300
    }
}

function Test-TriageElevated {
    <# .SYNOPSIS True when running elevated on Windows. Several checks need it to see other users and the Security log. #>
    if ($env:OS -ne 'Windows_NT') { return $false }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-TriageElevationWarning {
    <# .SYNOPSIS Emits a warning line when not elevated, so a thin result is not mistaken for a clean one. #>
    if (-not (Test-TriageElevated)) {
        'WARNING: not running elevated. Other users, the Security log and some registry keys will be missing from these results.'
    }
}

function Get-TriageUserHive {
    <#
    .SYNOPSIS Lists the user registry hives that are loaded (HKEY_USERS\<SID>), with the profile path.
    .DESCRIPTION Only hives of users with a running session (or a service account) are loaded. Profiles
    whose hive is not loaded are returned with Loaded = $false so the report can say they were not checked.
    #>
    $profiles = @{}
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue | ForEach-Object {
        $profiles[$_.PSChildName] = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
    }
    $loaded = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -notmatch '_Classes$' -and $_.PSChildName -ne '.DEFAULT' } |
            ForEach-Object { $_.PSChildName })
    foreach ($sid in ($loaded + @($profiles.Keys) | Sort-Object -Unique)) {
        [pscustomobject]@{
            Sid         = $sid
            ProfilePath = $profiles[$sid]
            Loaded      = $loaded -contains $sid
            Root        = "Registry::HKEY_USERS\$sid"
        }
    }
}

function Get-TriageLocalProfileFolder {
    <# .SYNOPSIS Profile folders under the users directory (skips Default, Public and All Users). #>
    $usersDir = Join-Path $env:SystemDrive 'Users'
    Get-ChildItem $usersDir -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin 'Default', 'Default User', 'All Users', 'Public' }
}

function ConvertFrom-TriageMamCompressed {
    <#
    .SYNOPSIS Decompresses a Windows 10/11 Prefetch file (MAM / Xpress Huffman). Returns the bytes unchanged if not compressed.
    .DESCRIPTION Uses ntdll RtlDecompressBufferEx, so compressed files can only be read on Windows.
    #>
    param([Parameter(Mandatory)][byte[]]$Bytes)
    if ($Bytes.Length -lt 8 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x41 -or $Bytes[2] -ne 0x4D) { return , $Bytes }
    if (-not ('TriagePrefetchNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TriagePrefetchNative {
    [DllImport("ntdll.dll")] static extern uint RtlGetCompressionWorkSpaceSize(ushort format, out uint bufferWorkspace, out uint fragmentWorkspace);
    [DllImport("ntdll.dll")] static extern uint RtlDecompressBufferEx(ushort format, byte[] output, int outputSize, byte[] input, int inputSize, out int finalSize, byte[] workspace);
    public static byte[] Decompress(byte[] data) {
        int size = BitConverter.ToInt32(data, 4);
        byte[] input = new byte[data.Length - 8];
        Array.Copy(data, 8, input, 0, input.Length);
        uint bufferWorkspace, fragmentWorkspace;
        RtlGetCompressionWorkSpaceSize(4, out bufferWorkspace, out fragmentWorkspace);
        byte[] workspace = new byte[bufferWorkspace];
        byte[] output = new byte[size];
        int finalSize;
        uint status = RtlDecompressBufferEx(4, output, size, input, input.Length, out finalSize, workspace);
        if (status != 0) { throw new InvalidOperationException("RtlDecompressBufferEx failed: 0x" + status.ToString("X8")); }
        return output;
    }
}
'@
    }
    , [TriagePrefetchNative]::Decompress($Bytes)
}

function ConvertFrom-TriagePrefetch {
    <#
    .SYNOPSIS Reads a Prefetch (.pf) file and returns the executable name and its last run times (up to 8).
    .DESCRIPTION Supports format versions 26 (Windows 8.1) and 30/31 (Windows 10/11). Run times come
    from the file itself, so they survive even when the file's own timestamps only show the latest run.
    Run counts are not returned: their offset differs between builds and is easy to misread.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $data = ConvertFrom-TriageMamCompressed -Bytes ([IO.File]::ReadAllBytes($Path))
    $version = [BitConverter]::ToInt32($data, 0)
    $signature = [Text.Encoding]::ASCII.GetString($data, 4, 4)
    if ($signature -ne 'SCCA') { throw "Not a Prefetch file (no SCCA signature): $Path" }
    $exe = [Text.Encoding]::Unicode.GetString($data, 0x10, 60).Split([char]0)[0]
    $times = @()
    if ($version -ge 26) {
        for ($i = 0; $i -lt 8; $i++) {
            $ft = [BitConverter]::ToInt64($data, 0x80 + 8 * $i)
            if ($ft -gt 0) { $times += [datetime]::FromFileTime($ft) }
        }
    }
    [pscustomobject]@{
        File       = Split-Path $Path -Leaf
        Executable = $exe
        Version    = $version
        RunTimes   = @($times | Sort-Object)
    }
}

function ConvertFrom-TriageAnyDeskTrace {
    <#
    .SYNOPSIS Parses AnyDesk ad.trace / ad_svc.trace lines into objects (Time, Level, Process, Component, Message).
    .DESCRIPTION Times are as AnyDesk wrote them: local time on the endpoint. Lines that do not match
    the trace format (continuations, banners) are skipped.
    #>
    param([Parameter(Mandatory)][string[]]$Path)
    $rx = '^\s*(?<level>\w+)\s+(?<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(?<proc>\S+)\s+(?<pid>\d+)\s+(?<tid>\d+)\s+(?:\d+\s+)?(?<comp>\S+)\s+-\s+(?<msg>.*)$'
    foreach ($p in $Path) {
        foreach ($line in [IO.File]::ReadAllLines($p)) {
            $m = [regex]::Match($line, $rx)
            if (-not $m.Success) { continue }
            [pscustomobject]@{
                Time      = [datetime]::ParseExact($m.Groups['ts'].Value, 'yyyy-MM-dd HH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture)
                Level     = $m.Groups['level'].Value
                Process   = $m.Groups['proc'].Value
                ProcessId = [int]$m.Groups['pid'].Value
                Component = $m.Groups['comp'].Value
                Message   = $m.Groups['msg'].Value.Trim()
                Source    = Split-Path $p -Leaf
            }
        }
    }
}

function Get-TriageAnyDeskSummary {
    <#
    .SYNOPSIS Turns parsed AnyDesk trace entries into sessions, elevation, privacy-mode windows and file activity.
    .OUTPUTS One object with Sessions, Elevations, PrivacyWindows, PrivacyTotal, FileEvents, ExternalAddresses, Notable.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Entry)
    $entries = @($Entry | Sort-Object Time)

    $sessions = New-Object System.Collections.ArrayList
    $pendingId = $null
    $pendingFpr = $null
    foreach ($e in $entries) {
        if ($e.Message -match '^Accept request from (?<id>\S+)') { $pendingId = $Matches['id']; $pendingFpr = $null }
        elseif ($e.Message -match '^Client-ID: (?<id>\S+?)\.? \(FPR: (?<fpr>[0-9a-f]+)\)') {
            # Logged before or after the "Logged in from" line depending on version: attach either way.
            $pendingId = $Matches['id']
            $pendingFpr = $Matches['fpr']
            $last = $sessions | Where-Object { $_.RemoteId -eq $pendingId -and -not $_.Fingerprint -and ($e.Time - $_.Time).TotalSeconds -lt 5 } | Select-Object -Last 1
            if ($last) { $last.Fingerprint = $pendingFpr }
        }
        elseif ($e.Message -match '^Logged in from (?<ip>.+?):(?<port>\d+) on relay (?<relay>\S+?)\.?$') {
            $already = $sessions | Where-Object { $_.Time -eq $e.Time -or ($_.RemoteIp -eq $Matches['ip'] -and $_.RemotePort -eq $Matches['port']) }
            if (-not $already) {
                [void]$sessions.Add([pscustomobject]@{
                        Time        = $e.Time
                        RemoteId    = $pendingId
                        RemoteIp    = $Matches['ip']
                        RemotePort  = $Matches['port']
                        Relay       = $Matches['relay']
                        Fingerprint = $pendingFpr
                        Accepted    = $null
                        Elevated    = $false
                    })
            }
        }
        elseif ($e.Message -match 'Authenticated by (?<how>.+?)\.?$') {
            $s = $sessions | Where-Object { $_.Time -le $e.Time } | Select-Object -Last 1
            if ($s) {
                $s.Accepted = $e.Time
                if ($e.Message -match '\(elevated\)') { $s.Elevated = $true }
            }
        }
    }

    $remoteInfo = $entries | Where-Object { $_.Message -match '^Remote (OS|version):' } |
        ForEach-Object { $_.Message } | Sort-Object -Unique

    $elevations = $entries | Where-Object { $_.Message -match 'Opening UAC dialog|Starting an elevated backend|Spawning backend \(elevated 1' } |
        Select-Object Time, Message

    $windows = New-Object System.Collections.ArrayList
    $start = $null
    foreach ($e in $entries) {
        if ($e.Message -match 'New input state: blocked') { if (-not $start) { $start = $e.Time } }
        elseif ($start -and ($e.Message -match 'New input state: unblocked|Session stopped')) {
            [void]$windows.Add([pscustomobject]@{ Start = $start; End = $e.Time; Duration = $e.Time - $start })
            $start = $null
        }
    }
    if ($start) { [void]$windows.Add([pscustomobject]@{ Start = $start; End = $null; Duration = $null }) }
    $total = New-TimeSpan
    foreach ($w in $windows) { if ($w.Duration) { $total = $total + $w.Duration } }

    $fileRx = '\bfile[_ ]?(transfer|manager)|\bupload|\bdownload(ing|ed)?\b|Preparing files|clipboard files|paste files|Sending file|Receiving file'
    $fileEvents = $entries | Where-Object {
        ($_.Message -match $fileRx -or $_.Component -match '(^|\.)file_(transfer|manager)|^ft\.') -and
        $_.Message -notmatch '^Command Line params|gcapi\.dll|permissions \(|Remote caps|Purging clipboard files|fiber'
    } | Select-Object Time, Component, Message

    $notableRx = 'privacy mode|Rejecting|tcp.?tunnel request|remote shell|\bVPN\b|session recording|restart (the )?(computer|system|remote)|switch(ing)? sides|unattended|password|Received a sysinfo|chat message|whiteboard|lock account(?! parameters)|logoff'
    $notable = $entries | Where-Object {
        $_.Message -match $notableRx -and $_.Message -notmatch 'permissions \(|Remote caps|Session features|Selecting Profile|hasPw'
    } | Select-Object Time, Component, Message

    [pscustomobject]@{
        Sessions          = @($sessions)
        RemoteInfo        = @($remoteInfo)
        Elevations        = @($elevations)
        PrivacyWindows    = @($windows)
        PrivacyTotal      = $total
        FileEvents        = @($fileEvents)
        ExternalAddresses = @($entries | Where-Object { $_.Message -match '^External address: (.+?)\.?$' } | ForEach-Object { $Matches[1] } | Sort-Object -Unique)
        Notable           = @($notable)
    }
}

function Get-TriageAnyDeskConfig {
    <#
    .SYNOPSIS Reads AnyDesk .conf files and reports this endpoint's ID, alias and whether unattended access is set.
    .DESCRIPTION An unattended-access password (ad.anynet.pwd_hash or a permission profile password) means
    anyone with the password can connect without the user accepting: treat it as persistence.
    #>
    param([Parameter(Mandatory)][string[]]$Path)
    $values = @{}
    foreach ($p in $Path) {
        foreach ($line in [IO.File]::ReadAllLines($p)) {
            if ($line -match '^(?<k>[^=]+)=(?<v>.*)$') { $values[$Matches['k'].Trim()] = $Matches['v'] }
        }
    }
    $pwKeys = @($values.Keys | Where-Object { $_ -match 'pwd_hash|pwd_salt|\.pwd$|password' -and $values[$_] })
    [pscustomobject]@{
        AnyDeskId          = $values['ad.anynet.id']
        Alias              = $values['ad.anynet.alias']
        UnattendedPassword = $pwKeys.Count -gt 0
        PasswordKeys       = $pwKeys
        LastRelay          = $values['ad.anynet.last_relay']
        RecentPeers        = @($values.Keys | Where-Object { $_ -eq 'ad.security.permission_profiles.address_to_profile' } |
                ForEach-Object { ($values[$_] -split ';') | ForEach-Object { ($_ -split ':')[0] } } | Where-Object { $_ } | Sort-Object -Unique)
    }
}

function ConvertFrom-TriageAnyDeskConnectionTrace {
    <# .SYNOPSIS Reads AnyDesk connection_trace.txt (UTF-16 or UTF-8) into Direction, Time, Type and remote IDs. #>
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $looksUtf16 = $bytes.Length -gt 1 -and ($bytes[1] -eq 0 -or ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE))
    $text = if ($looksUtf16) { [Text.Encoding]::Unicode.GetString($bytes) } else { [Text.Encoding]::UTF8.GetString($bytes) }
    foreach ($line in ($text -split "`r?`n")) {
        $f = @(($line.Trim([char]0xFEFF, ' ', "`t") -split '\s{2,}|\t') | Where-Object { $_ })
        if ($f.Count -lt 3) { continue }
        [pscustomobject]@{
            Direction = $f[0]
            Time      = $f[1]
            Type      = $f[2]
            RemoteIds = (@($f | Select-Object -Skip 3) -join ' ')
        }
    }
}
