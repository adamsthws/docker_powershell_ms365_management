<#
.SYNOPSIS
    Autostart persistence: Run keys, Winlogon, AppInit, LSA, IFEO, startup folders, services, WMI,
    SSH keys, Defender, hosts, proxy and root certificates.
.DESCRIPTION
    Read-only. Covers the machine and every LOADED user hive. Users without a running session have no
    loaded hive; they are listed at the top so the gap is visible.
    Known normal findings: the WMI subscription "SCM Event Log Filter/Consumer" is a Windows default;
    OneDrive RunOnce cleanup entries and OneDriveSetup in service-account hives are normal.
.PARAMETER Since
    Start of the period for "recent" events (service installs, Defender changes, new root certificates).
    Default 30 days ago.
.EXAMPLE
    .\04-Get-AutostartPersistence.ps1 -Since '2026-01-01'
#>
[CmdletBinding()]
param([datetime]$Since = (Get-Date).AddDays(-30))

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning

$hives = @(Get-TriageUserHive)
Write-TriageSection 'User hives (only Loaded = True are covered below)'
$hives | Format-TriageTable -Property Sid, ProfilePath, Loaded

Write-TriageSection 'Run / RunOnce / policy Run / Load / Run= (machine and loaded users)'
$runKeys = 'Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce',
'Software\Microsoft\Windows\CurrentVersion\RunOnceEx', 'Software\Microsoft\Windows\CurrentVersion\RunServices',
'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce', 'Software\Microsoft\Windows NT\CurrentVersion\Windows',
'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$roots = @('HKLM:') + @($hives | Where-Object Loaded | ForEach-Object { $_.Root })
& {
    foreach ($r in $roots) {
        foreach ($k in $runKeys) {
            $p = "$r\$k"
            if (-not (Test-Path $p)) { continue }
            $item = Get-ItemProperty $p
            foreach ($prop in $item.PSObject.Properties) {
                if ($prop.Name -like 'PS*') { continue }
                if ($k -match 'NT\\CurrentVersion\\Windows$' -and $prop.Name -notin 'Load', 'Run', 'AppInit_DLLs') { continue }
                if ($k -match 'Winlogon$' -and ($r -eq 'HKLM:' -or $prop.Name -notin 'Shell', 'Userinit')) { continue }
                [pscustomobject]@{ Key = ($p -replace 'Registry::HKEY_USERS\\', 'HKU\'); Name = $prop.Name; Value = "$($prop.Value)" }
            }
        }
    }
} | Format-TriageTable

Write-TriageSection 'Winlogon (expected: Shell = explorer.exe, Userinit = ...\userinit.exe,)'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' |
    Select-Object Shell, Userinit, Taskman, AppSetup, GinaDLL, VMApplet | Format-TriageList
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' -ErrorAction SilentlyContinue | ForEach-Object { "Notify: $($_.PSChildName)" }

Write-TriageSection 'AppInit_DLLs, AppCertDlls, LSA packages, Netsh helpers'
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue |
    Select-Object PSPath, AppInit_DLLs, LoadAppInit_DLLs | Format-TriageList
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | Format-TriageList
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object 'Authentication Packages', 'Notification Packages', 'Security Packages' | Format-TriageList
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -ErrorAction SilentlyContinue | Select-Object 'Security Packages' | Format-TriageList
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | Format-TriageList

Write-TriageSection 'Image File Execution Options debuggers and SilentProcessExit monitors (accessibility backdoors)'
& {
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
            $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($d) { [pscustomobject]@{ Image = $_.PSChildName; Debugger = $d } }
        }
    }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{ Image = $_.PSChildName; Debugger = 'SilentProcessExit: ' + (Get-ItemProperty $_.PSPath).MonitorProcess }
    }
} | Format-TriageTable

Write-TriageSection 'Startup folders'
$startup = @(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
foreach ($p in Get-TriageLocalProfileFolder) { $startup += Join-Path $p.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
Get-ChildItem $startup -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } |
    Select-Object FullName, CreationTime, LastWriteTime | Format-TriageTable

Write-TriageSection 'Services whose binary is outside System32/SysWOW64 (with signer)'
Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\windows\\(system32|syswow64)\\' } | ForEach-Object {
    $exe = if ($_.PathName -match '^"([^"]+)"') { $Matches[1] } else { ($_.PathName -split ' ')[0] }
    $sig = if (Test-Path $exe -ErrorAction SilentlyContinue) { Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue } else { $null }
    [pscustomobject]@{
        Name      = $_.Name
        State     = $_.State
        StartMode = $_.StartMode
        RunAs     = $_.StartName
        Signer    = if ($sig -and $sig.SignerCertificate) { "$($sig.Status): $($sig.SignerCertificate.GetNameInfo('SimpleName', $false))" } elseif ($sig) { "$($sig.Status)" } else { 'file not found' }
        Path      = $_.PathName
    }
} | Format-TriageTable

Write-TriageSection "Services installed since $($Since.ToString('yyyy-MM-dd')) (System 7045)"
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $Since } -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ Time = $_.TimeCreated; Service = $_.Properties[0].Value; Path = $_.Properties[1].Value; StartType = $_.Properties[3].Value; Account = $_.Properties[4].Value }
} | Format-TriageTable

Write-TriageSection 'WMI event subscriptions (default: SCM Event Log Filter / Consumer only)'
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query | Format-TriageTable
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
    Select-Object @{ n = 'Class'; e = { $_.CimClass.CimClassName } }, Name, CommandLineTemplate, ScriptText, ExecutablePath | Format-TriageList
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter, Consumer | Format-TriageList

Write-TriageSection 'OpenSSH authorized keys (a key is a way back in)'
$keyFiles = @(Join-Path $env:ProgramData 'ssh\administrators_authorized_keys')
foreach ($p in Get-TriageLocalProfileFolder) { $keyFiles += Join-Path $p.FullName '.ssh\authorized_keys' }
& {
    foreach ($f in $keyFiles) {
        if (-not (Test-Path $f)) { continue }
        $item = Get-Item $f -Force
        foreach ($line in (Get-Content $f | Where-Object { $_ -and $_ -notmatch '^\s*#' })) {
            $parts = $line -split '\s+'
            [pscustomobject]@{ File = $f; Modified = $item.LastWriteTime; Type = $parts[0]; Comment = ($parts | Select-Object -Skip 2) -join ' ' }
        }
    }
} | Format-TriageTable
Get-Service sshd -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-TriageTable

Write-TriageSection 'Microsoft Defender'
Get-MpComputerStatus -ErrorAction SilentlyContinue |
    Select-Object AMRunningMode, RealTimeProtectionEnabled, IsTamperProtected, AntivirusEnabled, BehaviorMonitorEnabled, AntivirusSignatureLastUpdated | Format-TriageList
$pref = Get-MpPreference -ErrorAction SilentlyContinue
if ($pref) {
    "ExclusionPath:      $($pref.ExclusionPath -join '; ')"
    "ExclusionProcess:   $($pref.ExclusionProcess -join '; ')"
    "ExclusionExtension: $($pref.ExclusionExtension -join '; ')"
    "ExclusionIpAddress: $($pref.ExclusionIpAddress -join '; ')"
    "DisableRealtimeMonitoring: $($pref.DisableRealtimeMonitoring)   PUAProtection: $($pref.PUAProtection)"
    'Note: exclusions show as blank or "N/A: Must be an administrator" when not elevated.'
}
Write-TriageSection 'Defender detections'
Get-MpThreatDetection -ErrorAction SilentlyContinue |
    Select-Object InitialDetectionTime, ThreatID, ActionSuccess, ProcessName, @{ n = 'Resources'; e = { $_.Resources -join '; ' } } | Format-TriageList
Write-TriageSection "Defender protection changes since $($Since.ToString('yyyy-MM-dd')) (5001 RTP off, 5010/5012 off, 5007 config, 1116/1117 detections)"
'5007 entries for Diagnostics, ServiceStartStates, CoreService hashes and EcsConfigs are routine service churn.'
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001, 5007, 5010, 5012, 1116, 1117; StartTime = $Since } -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -ne 5007 -or $_.Message -notmatch 'InitializingComponentProgress|ServiceStartStates|WdConfigHash|ProductAppDataPath|EcsConfigs|LastKnownGoodPlatformLocation|Features\\Controls' } |
    ForEach-Object {
        $m = ($_.Message -replace '\s+', ' ')
        $m = if ($_.Id -eq 5007) { ($m -split 'Old value:')[1] } else { $m }
        [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Detail = $m.Substring(0, [math]::Min(220, $m.Length)) }
    } | Format-TriageTable

Write-TriageSection 'Hosts file entries (non-comment)'
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsLines = @(Get-Content $hostsFile -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' })
if ($hostsLines) { $hostsLines } else { '  (none)' }
"hosts last modified: $((Get-Item $hostsFile -ErrorAction SilentlyContinue).LastWriteTime)"

Write-TriageSection 'Proxy settings (WinHTTP and each loaded user)'
netsh winhttp show proxy | Out-String
& {
    foreach ($h in ($hives | Where-Object Loaded)) {
        $i = Get-ItemProperty "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($i) { [pscustomobject]@{ Sid = $h.Sid; ProxyEnable = $i.ProxyEnable; ProxyServer = $i.ProxyServer; AutoConfigURL = $i.AutoConfigURL } }
    }
} | Format-TriageTable

Write-TriageSection "Root certificates valid from $($Since.ToString('yyyy-MM-dd')) or later (a planted root enables interception)"
Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
    Where-Object { $_.NotBefore -ge $Since } | Select-Object PSParentPath, Subject, NotBefore, Thumbprint | Format-TriageList
