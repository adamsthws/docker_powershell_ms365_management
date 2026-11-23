<#
.SYNOPSIS
    Turns temporary remote PowerShell access for triage on (WinRM or SSH), shows it (-Status) or removes it again (-Remove).
.DESCRIPTION
    ONE-LINE SETUP ON THE ENDPOINT
    -----------------------------
    Paste ONE line into an elevated Windows PowerShell on the endpoint (Start > type "powershell" >
    Run as administrator). It downloads this script from the public repository and runs it in memory:

        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; & ([scriptblock]::Create((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/adamsthws/docker_powershell_ms365_management/<REF>/endpoint-triage/ps/setup/Set-TriageAccess.ps1'))) -GitHubUser <GITHUB USER> -ClientCertificate '<GIST RAW URL>'

    Do not fill that in by hand: on your own machine run

        endpoint-triage/scripts/setup-command.sh            (or -m status / -m remove)

    It prints the line with <REF> pinned to a published commit (so the code that runs is exactly the
    code you reviewed). SSH takes your public keys from https://github.com/<GITHUB USER>.keys, and
    WinRM downloads your client certificate (from new-winrm-cert.sh) from your Gist, pinned to one
    revision, so the line carries no key material. The same line with -Status or -Remove instead
    shows or undoes the setup.

    If security software blocks download-and-run, copy this file over with the remote-support tool's
    file transfer instead and, in that folder, run it from its text with the same parameters:

        & ([scriptblock]::Create([IO.File]::ReadAllText("$PWD\Set-TriageAccess.ps1"))) -GitHubUser <GITHUB USER> -ClientCertificate .\winrm-client.cer

    WHAT IT DOES
    ------------
    CHANGES THE ENDPOINT (except -Status). It lists the changes and asks before making them; -WhatIf
    shows the plan and changes nothing.

    Methods, tried in this order until one works (limit them with -Ssh or -WinRM):
    1. SSH from the GitHub release of Win32-OpenSSH (seconds: a 6 MB download). Needs -GitHubUser
       or -PublicKey. The download's sshd.exe must carry a valid Microsoft signature. Changes no
       security setting, and the session is a full administrator.
    2. WinRM (seconds; built into Windows), for when GitHub is blocked or security software stops
       the new service. Needs -ClientCertificate. An HTTPS listener on 127.0.0.1 with a temporary
       self-signed server certificate, certificate authentication, and a mapping from your client
       certificate to the temporary admin. LocalAccountTokenFilterPolicy is set to 1 so the local
       admin gets a full (elevated) token over WinRM; -Remove puts it back.
    3. SSH from the Windows optional feature OpenSSH.Server (several minutes, via Windows Update).
    If sshd is already installed, SSH reuses it instead of installing anything.
    WinRM cannot use the SSH keys: Windows only accepts RSA or ECDSA X.509 client certificates,
    so it needs its own certificate.

    Both methods use a temporary local administrator (default 'temp-local-admin') with a random password
    nobody sees: Windows cannot do key or certificate logins for Entra ID accounts, and typing the
    user's own password over a session you suspect adds risk.

    Everything that existed before is recorded in C:\ProgramData\endpoint-triage\access-state.json.
    -Remove undoes exactly what was done (run it LAST, at the console or through the remote-support
    tool, not over the remote session it is removing).

    Exposure: SSH listens on 127.0.0.1 only. The WinRM listener only answers on 127.0.0.1, but the
    port is opened by the Windows HTTP service on all addresses; it is the Windows Firewall (no
    inbound rule is added for it) that keeps it off the network. -Status reports any inbound
    firewall rule that would expose it.
.PARAMETER WinRM
    Only try WinRM.
.PARAMETER Ssh
    Only try SSH (GitHub release, then Windows optional feature).
.PARAMETER GitHubUser
    Take your SSH public keys from https://github.com/<GitHubUser>.keys. The fingerprints are shown
    before anything changes.
.PARAMETER PublicKey
    Your SSH public key, one line ('ssh-ed25519 AAAA... comment'). Can be combined with -GitHubUser.
.PARAMETER ClientCertificate
    Your WinRM client certificate, made with scripts/new-winrm-cert.sh: an https:// URL to download
    it from (a Gist raw URL pinned to a revision, as setup-command.sh gives), a path to the .cer
    file, or the certificate itself as base64 or PEM text. It must be for client authentication
    with the UPN <UserName>@localhost.
.PARAMETER WinRMPort
    Port for the WinRM HTTPS listener. Default 5986.
.PARAMETER OpenSshZipUrl
    Where to download Win32-OpenSSH from. Default: the latest GitHub release for this CPU.
.PARAMETER UserName
    The temporary local administrator. Default 'temp-local-admin'.
.PARAMETER Status
    Show what is set up now. Changes nothing.
.PARAMETER Remove
    Undo everything the enable step did.
.PARAMETER KeepOpenSsh
    With -Remove: leave OpenSSH installed even if this script installed it.
.EXAMPLE
    .\Set-TriageAccess.ps1 -GitHubUser analyst-example -ClientCertificate .\triage-client.cer -WhatIf
.EXAMPLE
    .\Set-TriageAccess.ps1 -Ssh -PublicKey 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA analyst@example'
.EXAMPLE
    .\Set-TriageAccess.ps1 -Status
.EXAMPLE
    .\Set-TriageAccess.ps1 -Remove
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Enable')]
param(
    [Parameter(ParameterSetName = 'Enable')]
    [switch]$WinRM,

    [Parameter(ParameterSetName = 'Enable')]
    [switch]$Ssh,

    [Parameter(ParameterSetName = 'Enable')]
    [ValidatePattern('^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$')]
    [string]$GitHubUser,

    [Parameter(ParameterSetName = 'Enable')]
    [ValidatePattern('^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+( .*)?$')]
    [string]$PublicKey,

    [Parameter(ParameterSetName = 'Enable')]
    [string]$ClientCertificate,

    [Parameter(ParameterSetName = 'Enable')]
    [ValidateRange(1024, 65535)]
    [int]$WinRMPort = 5986,

    [Parameter(ParameterSetName = 'Enable')]
    [ValidatePattern('^https://')]
    [string]$OpenSshZipUrl,

    [Parameter(ParameterSetName = 'Enable')]
    [Parameter(ParameterSetName = 'Remove')]
    [ValidatePattern('^[A-Za-z0-9._-]{1,20}$')]
    [string]$UserName = 'temp-local-admin',

    [Parameter(Mandatory, ParameterSetName = 'Status')]
    [switch]$Status,

    [Parameter(Mandatory, ParameterSetName = 'Remove')]
    [switch]$Remove,

    [Parameter(ParameterSetName = 'Remove')]
    [switch]$KeepOpenSsh
)

$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this from an elevated (Administrator) PowerShell.' }

$sshDir = Join-Path $env:ProgramData 'ssh'
$sshConfig = Join-Path $sshDir 'sshd_config'
$keyFile = Join-Path $sshDir 'administrators_authorized_keys'
$triageDir = Join-Path $env:ProgramData 'endpoint-triage'
$stateFile = Join-Path $triageDir 'access-state.json'
$backupDir = Join-Path $triageDir 'access-backup'
$accountNote = 'Temporary triage account (Set-TriageAccess)'   # Windows allows 48 characters
$systemPolicies = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$listenerSelector = @{ Address = 'IP:127.0.0.1'; Transport = 'HTTPS' }
$zipUrlOverride = $OpenSshZipUrl
$sshKeyRx = '^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+( .*)?$'
$script:clientCert = $null
$script:sshKeys = @()
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------------ state

function Read-AccessState {
    $h = @{}
    if (Test-Path $stateFile) {
        foreach ($p in (Get-Content $stateFile -Raw | ConvertFrom-Json).PSObject.Properties) { $h[$p.Name] = $p.Value }
    }
    $h
}

function Write-AccessState([hashtable]$State) {
    [void](New-Item -ItemType Directory -Path $triageDir -Force)
    New-Object psobject -Property $State | ConvertTo-Json | Set-Content $stateFile -Encoding ascii
}

# ------------------------------------------------------------------ helpers

function Get-OpenSshCapability { Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1 }

function Get-SshKeygenPath {
    $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if (-not $svc) { return $null }
    $exe = $svc.PathName.Trim('"')
    $kg = Join-Path (Split-Path $exe -Parent) 'ssh-keygen.exe'
    if (Test-Path $kg) { $kg } else { $null }
}

function Get-RandomSecret {
    $secure = New-Object Security.SecureString
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    foreach ($c in ([Convert]::ToBase64String($bytes) + 'a1!').ToCharArray()) { $secure.AppendChar($c) }
    $secure.MakeReadOnly()
    $secure
}

function Get-InboundExposure([int]$Port) {
    # Enabled inbound allow rules that would let the network reach this port. The WinRM port is served
    # by the System process (http.sys), so rules limited to another program or service do not count.
    # Built-in System rules for any port (Wi-Fi Direct, Teredo) carry conditions these cmdlets do not
    # show and did not expose the port in testing, so an any-port rule counts only for any program.
    Get-NetFirewallPortFilter -Protocol TCP -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -contains "$Port" -or $_.LocalPort -contains 'Any' } |
        Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
        Where-Object {
            $named = ($_ | Get-NetFirewallPortFilter).LocalPort -contains "$Port"
            $app = ($_ | Get-NetFirewallApplicationFilter).Program
            $svc = ($_ | Get-NetFirewallServiceFilter).Service
            $svc -eq 'Any' -and ($app -eq 'Any' -or ($named -and $app -eq 'System'))
        } |
        ForEach-Object { $_.DisplayName } | Sort-Object -Unique
}

# ------------------------------------------------------------------ temporary admin

function Add-TriageAdmin([hashtable]$State) {
    $existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $State.ContainsKey('UserExisted')) {
        $State.UserName = $UserName
        $State.UserExisted = [bool]$existing
        Write-AccessState $State
    }
    if ($existing -and $State.UserExisted) { throw "Local user '$UserName' already existed before triage. Pick another name with -UserName." }
    $secret = Get-RandomSecret
    if ($existing) { Set-LocalUser -Name $UserName -Password $secret }
    else { New-LocalUser -Name $UserName -Password $secret -PasswordNeverExpires -Description $accountNote | Out-Null }
    if (-not (Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.Name -like "*\$UserName" })) {
        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $UserName
    }
    $secret
}

function Undo-TriageAdmin([hashtable]$State) {
    if ($State.UserExisted -or -not $State.UserName) { return $null }
    $account = Get-LocalUser -Name $State.UserName -ErrorAction SilentlyContinue
    $sid = if ($account) { $account.SID.Value } else { $State.PendingProfileSid }
    if (-not $sid) { return $null }
    if ($account) {
        $running = @(Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -like "*\$($State.UserName)" })
        if ($running) {
            return "'$($State.UserName)' still has programs running ($(($running.ProcessName | Sort-Object -Unique) -join ', ')): a remote session still open? Close it and run -Remove again."
        }
    }
    $userProfile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }
    if ($userProfile -and $userProfile.Loaded) {
        # Windows can keep the registry hive loaded for a long time after the last logoff. Remove the
        # account now (that ends the access) and the profile folder after a restart.
        if ($account) { Remove-LocalUser -Name $State.UserName }
        $State.PendingProfileSid = $sid
        Write-AccessState $State
        return "Removed account '$($State.UserName)', but Windows still has its profile $($userProfile.LocalPath) loaded. Restart the PC and run -Remove again to delete the profile."
    }
    if ($userProfile) { $userProfile | Remove-CimInstance }
    if ($account) { Remove-LocalUser -Name $State.UserName }
    $State.Remove('PendingProfileSid')
    $null
}

# ------------------------------------------------------------------ WinRM

function Get-ClientCertificate {
    if (-not $ClientCertificate) { throw 'WinRM needs -ClientCertificate (make one with scripts/new-winrm-cert.sh).' }
    $path = $null
    $text = $ClientCertificate.Trim()
    if ($text -match '^https://') {
        $path = $text
        Write-Host "Downloading the WinRM client certificate from $text ..."
        $text = (New-Object Net.WebClient).DownloadString($text).Trim()
    }
    $isFile = $false
    if ($path -notmatch '^https://') { try { $isFile = Test-Path -LiteralPath $text -PathType Leaf } catch { $isFile = $false } }
    if ($isFile) {
        $path = (Resolve-Path -LiteralPath $text).Path
        $bytes = [IO.File]::ReadAllBytes($path)
    }
    else {
        if (-not $path) { $path = 'The -ClientCertificate text' }
        $b64 = ($text -replace '-----(BEGIN|END) CERTIFICATE-----', '') -replace '\s', ''
        if ($b64 -notmatch '^[A-Za-z0-9+/]+={0,2}$') { throw "$path is neither an existing file nor a base64 or PEM certificate." }
        $bytes = [Convert]::FromBase64String($b64)
    }
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $bytes)
    $eku = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
    if (-not $eku -or $eku.Format($false) -notmatch '1\.3\.6\.1\.5\.5\.7\.3\.2|Client Authentication') { throw "$path is not a client-authentication certificate." }
    $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
    if (-not $san -or $san.Format($false) -notmatch [regex]::Escape("$UserName@localhost")) { throw "$path does not carry the UPN $UserName@localhost (make it with: new-winrm-cert.sh -u $UserName)." }
    if ($cert.NotAfter -lt (Get-Date)) { throw "$path expired on $($cert.NotAfter)." }
    $cert
}

function Enable-WinRMTriage([hashtable]$State, [Security.SecureString]$Secret) {
    $client = $script:clientCert

    $svc = Get-Service WinRM
    $State.WinRMServiceStartType = "$($svc.StartType)"
    $State.WinRMServiceRunning = $svc.Status -eq 'Running'
    Write-AccessState $State
    if ($svc.StartType -eq 'Disabled') { Set-Service WinRM -StartupType Manual }
    if ($svc.Status -ne 'Running') { Start-Service WinRM }

    $cfg = Get-PSSessionConfiguration -Name 'microsoft.powershell'
    if ("$($cfg.Permission)" -match 'NETWORK AccessDenied') { throw 'PowerShell remoting is switched off on this PC (Disable-PSRemoting or a policy); not changing that.' }

    $State.CertAuthBefore = "$((Get-Item WSMan:\localhost\Service\Auth\Certificate).Value)"
    Write-AccessState $State
    Set-Item WSMan:\localhost\Service\Auth\Certificate -Value $true

    $latfp = Get-ItemProperty $systemPolicies -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue
    $State.LatfpExisted = [bool]$latfp
    $State.LatfpValue = if ($latfp) { $latfp.LocalAccountTokenFilterPolicy } else { $null }
    Write-AccessState $State
    Set-ItemProperty $systemPolicies -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord

    $State.ClientCertThumbprint = $client.Thumbprint
    foreach ($storeName in 'Root', 'TrustedPeople') {
        $store = New-Object Security.Cryptography.X509Certificates.X509Store $storeName, 'LocalMachine'
        $store.Open('ReadWrite')
        $had = $store.Certificates.Find('FindByThumbprint', $client.Thumbprint, $false).Count -gt 0
        if (-not $had) { $store.Add($client) }
        $store.Close()
        $State["ClientCertAdded$storeName"] = -not $had
        Write-AccessState $State
    }

    $server = New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'endpoint-triage WinRM (temporary)' `
        -NotAfter (Get-Date).AddDays(7) -KeyExportPolicy NonExportable
    $State.ServerCertThumbprint = $server.Thumbprint
    Write-AccessState $State

    New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $listenerSelector `
        -ValueSet @{ Hostname = 'localhost'; CertificateThumbprint = $server.Thumbprint; Port = "$WinRMPort" } | Out-Null
    $State.ListenerCreated = $true
    $State.WinRMPort = $WinRMPort
    Write-AccessState $State

    $cred = New-Object Management.Automation.PSCredential $UserName, $Secret
    New-Item -Path WSMan:\localhost\ClientCertificate -Subject "$UserName@localhost" -URI '*' -Issuer $client.Thumbprint -Credential $cred -Force | Out-Null
    $State.MappingCreated = $true
    Write-AccessState $State

    Start-Sleep -Seconds 1
    if (-not (Get-NetTCPConnection -LocalPort $WinRMPort -State Listen -ErrorAction SilentlyContinue)) { throw "Nothing is listening on port $WinRMPort after creating the listener." }
}

function Disable-WinRMTriage([hashtable]$State) {
    if (-not $State.ContainsKey('WinRMServiceStartType')) { return }
    if ((Get-Service WinRM).Status -ne 'Running') { Start-Service WinRM }
    if ($State.MappingCreated) {
        Get-ChildItem WSMan:\localhost\ClientCertificate -ErrorAction SilentlyContinue |
            Where-Object { $_.Keys -contains "Issuer=$($State.ClientCertThumbprint)" } | Remove-Item -Recurse -Force
    }
    if ($State.ListenerCreated) { Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $listenerSelector -ErrorAction SilentlyContinue }
    if ($State.ServerCertThumbprint) { Remove-Item "Cert:\LocalMachine\My\$($State.ServerCertThumbprint)" -ErrorAction SilentlyContinue }
    foreach ($storeName in 'Root', 'TrustedPeople') {
        if ($State["ClientCertAdded$storeName"]) {
            $store = New-Object Security.Cryptography.X509Certificates.X509Store $storeName, 'LocalMachine'
            $store.Open('ReadWrite')
            $store.Certificates.Find('FindByThumbprint', $State.ClientCertThumbprint, $false) | ForEach-Object { $store.Remove($_) }
            $store.Close()
        }
    }
    if ($State.ContainsKey('LatfpExisted')) {
        if ($State.LatfpExisted) { Set-ItemProperty $systemPolicies -Name LocalAccountTokenFilterPolicy -Value $State.LatfpValue -Type DWord }
        else { Remove-ItemProperty $systemPolicies -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue }
    }
    if ($State.CertAuthBefore) { Set-Item WSMan:\localhost\Service\Auth\Certificate -Value ($State.CertAuthBefore -eq 'true') }
    if (-not $State.WinRMServiceRunning) { Stop-Service WinRM -ErrorAction SilentlyContinue }
    if ($State.WinRMServiceStartType) { Set-Service WinRM -StartupType $State.WinRMServiceStartType }
    foreach ($k in @($State.Keys | Where-Object { $_ -match '^(WinRM|CertAuth|Latfp|ClientCert|ServerCert|Listener|Mapping)' })) { $State.Remove($k) }
}

# ------------------------------------------------------------------ SSH

function Get-SshPublicKeys {
    $keys = @()
    if ($PublicKey) { $keys += $PublicKey.Trim() }
    if ($GitHubUser) {
        $url = "https://github.com/$GitHubUser.keys"
        Write-Host "Downloading SSH public keys from $url ..."
        $found = @(((New-Object Net.WebClient).DownloadString($url) -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -match $sshKeyRx })
        if (-not $found) { throw "$url lists no usable SSH public key." }
        $keys += $found | ForEach-Object { "$_ github:$GitHubUser" }
    }
    @($keys | Select-Object -Unique)
}

function Get-KeyFingerprint([string]$Line) {
    # SHA256 fingerprint as ssh-keygen -l prints it, without needing ssh-keygen.
    $blob = [Convert]::FromBase64String(($Line -split '\s+')[1])
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($blob)
    'SHA256:' + ([Convert]::ToBase64String($hash).TrimEnd('='))
}

$envKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'

function Get-MachinePathRaw {
    # Unexpanded, as stored (REG_EXPAND_SZ with %SystemRoot% and the like).
    (Get-Item $envKey).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
}

function Test-MachinePathHas([string]$Dir) {
    @((Get-MachinePathRaw) -split ';' | Where-Object { $_.TrimEnd('\') -eq $Dir.TrimEnd('\') }).Count -gt 0
}

function Install-OpenSshFromGitHub([hashtable]$State) {
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'ARM64' } else { 'Win64' }
    $url = if ($zipUrlOverride) { $zipUrlOverride } else { "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-$arch.zip" }
    $dest = Join-Path $env:ProgramFiles 'OpenSSH'
    if (Test-Path $dest) { throw "$dest already exists; not overwriting it." }
    $zip = Join-Path $triageDir 'OpenSSH.zip'
    $extract = Join-Path $triageDir 'openssh-extract'
    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing -TimeoutSec 180
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $extract -Force
    $src = Get-ChildItem $extract -Directory | Select-Object -First 1
    $sshd = Join-Path $src.FullName 'sshd.exe'
    $sig = Get-AuthenticodeSignature $sshd
    if ($sig.Status -ne 'Valid' -or "$($sig.SignerCertificate.Subject)" -notmatch 'O=Microsoft Corporation') {
        throw "sshd.exe in the download is not validly signed by Microsoft ($($sig.Status), $($sig.SignerCertificate.Subject))."
    }
    Move-Item $src.FullName $dest
    $State.SshSource = 'GitHub'
    $State.SshInstallDir = $dest
    Write-AccessState $State
    $State.SshPathHadDir = Test-MachinePathHas $dest
    Write-AccessState $State
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dest 'install-sshd.ps1') | Out-Null
    Remove-Item $zip, $extract -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) { throw 'install-sshd.ps1 did not create the sshd service.' }
}

function Enable-SshTriage([hashtable]$State, [string]$Source) {
    if (-not $script:sshKeys) { throw 'SSH needs -GitHubUser or -PublicKey.' }
    if (-not $State.ContainsKey('SshExistedBefore')) {
        $svc = Get-Service sshd -ErrorAction SilentlyContinue
        $State.SshExistedBefore = [bool]$svc
        $State.SshdStartType = if ($svc) { "$($svc.StartType)" } else { $null }
        $State.SshdRunning = [bool]($svc -and $svc.Status -eq 'Running')
        $State.SshDirExisted = Test-Path $sshDir
        [void](New-Item -ItemType Directory -Path $backupDir -Force)
        $State.SshdConfigBackedUp = Test-Path $sshConfig
        if ($State.SshdConfigBackedUp) { Copy-Item $sshConfig (Join-Path $backupDir 'sshd_config') -Force }
        $State.AuthorizedKeysBackedUp = Test-Path $keyFile
        if ($State.AuthorizedKeysBackedUp) { Copy-Item $keyFile (Join-Path $backupDir 'administrators_authorized_keys') -Force }
        Write-AccessState $State
    }

    if ($State.SshExistedBefore) { $State.SshSource = 'existing' }
    elseif ($Source -eq 'GitHub') { Install-OpenSshFromGitHub $State }
    else {
        Write-Host 'Installing OpenSSH Server from Windows Update (can take several minutes)...'
        $State.SshSource = 'WindowsUpdate'
        Write-AccessState $State
        Add-WindowsCapability -Online -Name (Get-OpenSshCapability).Name | Out-Null
    }
    Write-AccessState $State

    if (-not (Test-Path $sshConfig)) { Start-Service sshd; Stop-Service sshd }   # first start writes the default config and host keys
    $out = New-Object System.Collections.ArrayList
    $inserted = $false
    foreach ($l in (Get-Content $sshConfig | Where-Object { $_ -notmatch '^\s*#?\s*ListenAddress\s' })) {
        [void]$out.Add($l)
        if (-not $inserted -and $l -match '^\s*#?\s*Port\s') { [void]$out.Add('ListenAddress 127.0.0.1'); $inserted = $true }
    }
    if (-not $inserted) { [void]$out.Insert(0, 'ListenAddress 127.0.0.1') }
    $out | Set-Content $sshConfig -Encoding ascii

    $script:sshKeys | Set-Content $keyFile -Encoding ascii
    icacls $keyFile /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
    Set-Service sshd -StartupType Manual
    Restart-Service sshd
    Start-Sleep -Seconds 1
    $listen = @(Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.LocalAddress } | Sort-Object -Unique)
    if (-not $listen) { throw 'sshd is not listening on port 22.' }
    if ($listen | Where-Object { $_ -notin '127.0.0.1', '::1' }) { throw "sshd is listening on $($listen -join ', '), not only 127.0.0.1." }
}

function Disable-SshTriage([hashtable]$State) {
    Remove-Item (Join-Path $triageDir 'OpenSSH.zip'), (Join-Path $triageDir 'openssh-extract') -Recurse -Force -ErrorAction SilentlyContinue
    if (-not $State.ContainsKey('SshExistedBefore')) { return }
    if ($State.AuthorizedKeysBackedUp -and (Test-Path (Join-Path $backupDir 'administrators_authorized_keys'))) {
        Copy-Item (Join-Path $backupDir 'administrators_authorized_keys') $keyFile -Force
    }
    elseif (Test-Path $keyFile) { Remove-Item $keyFile -Force }

    if ($State.SshExistedBefore) {
        if ($State.SshdConfigBackedUp -and (Test-Path (Join-Path $backupDir 'sshd_config'))) { Copy-Item (Join-Path $backupDir 'sshd_config') $sshConfig -Force }
        if ($State.SshdStartType) { Set-Service sshd -StartupType $State.SshdStartType }
        if ($State.SshdRunning) { Restart-Service sshd } else { Stop-Service sshd -ErrorAction SilentlyContinue }
    }
    elseif ($KeepOpenSsh) {
        Stop-Service sshd -ErrorAction SilentlyContinue
        if (Get-Service sshd -ErrorAction SilentlyContinue) { Set-Service sshd -StartupType Manual }
    }
    else {
        Stop-Service sshd -ErrorAction SilentlyContinue
        if ($State.SshSource -eq 'GitHub' -and $State.SshInstallDir -and (Test-Path $State.SshInstallDir)) {
            $uninstall = Join-Path $State.SshInstallDir 'uninstall-sshd.ps1'
            # Only if install-sshd.ps1 got as far as creating the service.
            if ((Get-Service sshd -ErrorAction SilentlyContinue) -and (Test-Path $uninstall)) { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $uninstall | Out-Null }
            Remove-Item $State.SshInstallDir -Recurse -Force
            if ($State.ContainsKey('SshPathHadDir') -and -not $State.SshPathHadDir) {
                # install-sshd.ps1 adds the folder to the machine PATH; take out only that entry.
                if (Test-MachinePathHas $State.SshInstallDir) {
                    $kept = (Get-MachinePathRaw) -split ';' | Where-Object { $_.TrimEnd('\') -ne $State.SshInstallDir.TrimEnd('\') }
                    Set-ItemProperty $envKey -Name Path -Value ($kept -join ';') -Type ExpandString
                }
            }
        }
        elseif ($State.SshSource -eq 'WindowsUpdate') {
            Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            $cap = Get-OpenSshCapability
            if ($cap.State -eq 'Installed') {
                Write-Host 'Uninstalling OpenSSH Server (can take a few minutes)...'
                Remove-WindowsCapability -Online -Name $cap.Name | Out-Null
            }
        }
        if (-not $State.SshDirExisted -and (Test-Path $sshDir)) { Remove-Item $sshDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    foreach ($k in @($State.Keys | Where-Object { $_ -match '^(Ssh|Sshd|AuthorizedKeys)' })) { $State.Remove($k) }
}

# ------------------------------------------------------------------ status

function Show-AccessStatus([hashtable]$State) {
    $account = if ($State.UserName) { $State.UserName } else { $UserName }
    $user = Get-LocalUser -Name $account -ErrorAction SilentlyContinue
    $winrmSvc = Get-Service WinRM -ErrorAction SilentlyContinue
    $listener = $null
    if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
        $listener = Get-WSManInstance -ResourceURI 'winrm/config/Listener' -Enumerate -ErrorAction SilentlyContinue | Where-Object { $_.Address -eq 'IP:127.0.0.1' -and $_.Transport -eq 'HTTPS' }
    }
    $sshSvc = Get-Service sshd -ErrorAction SilentlyContinue
    $sshListen = @(Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.LocalAddress } | Sort-Object -Unique)
    $keys = if (Test-Path $keyFile) { @(Get-Content $keyFile | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }) } else { @() }
    $hostKey = Join-Path $sshDir 'ssh_host_ed25519_key.pub'
    $keygen = Get-SshKeygenPath
    $latfp = (Get-ItemProperty $systemPolicies -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
    $winrmPort = if ($listener) { [int]$listener.Port } else { $null }

    [pscustomobject]@{
        Method                  = if ($State.Method) { $State.Method } else { '(none recorded)' }
        TemporaryAdmin          = if ($user) { "$account (enabled: $($user.Enabled))" } else { "$account not present" }
        WinRMService            = if ($winrmSvc) { "$($winrmSvc.Status), start type $($winrmSvc.StartType)" } else { 'not present' }
        WinRMListener127        = if ($listener) { "HTTPS on 127.0.0.1:$($listener.Port)" } else { 'none' }
        WinRMServerThumbprint   = if ($listener) { $listener.CertificateThumbprint } else { '' }
        WinRMFirewallExposure   = if ($winrmPort) { $r = @(Get-InboundExposure $winrmPort); if ($r) { 'EXPOSED by: ' + ($r -join '; ') } else { 'no inbound allow rule' } } else { '' }
        LocalAccountTokenFilter = if ($null -ne $latfp) { $latfp } else { 'not set' }
        SshdService             = if ($sshSvc) { "$($sshSvc.Status), start type $($sshSvc.StartType)" } else { 'not present' }
        SshListeningOn          = if ($sshListen) { ($sshListen -join ', ') + ':22' } else { 'nothing on port 22' }
        SshAuthorizedKeys       = "$($keys.Count) key(s): " + (($keys | ForEach-Object { $c = ($_ -split '\s+', 3)[2]; "$(Get-KeyFingerprint $_)$(if ($c) { " ($c)" })" }) -join '; ')
        SshHostKeyFingerprint   = if ((Test-Path $hostKey) -and $keygen) { (& $keygen -lf $hostKey) -join ' ' } else { '' }
        StateFile               = if (Test-Path $stateFile) { $stateFile } else { 'none (nothing set up by this script)' }
    } | Format-List | Out-String
}

# ------------------------------------------------------------------ main

$state = Read-AccessState

if ($Status) {
    Show-AccessStatus $state
    return
}

if ($PSCmdlet.ParameterSetName -eq 'Enable') {
    if ($state.UserName -and $state.UserName -ne $UserName) { throw "Access is already set up for '$($state.UserName)'. Run -Remove first." }
    if ($state.Method) { Write-Host "Access is already enabled via $($state.Method). Use -Status, or -Remove first." -ForegroundColor Yellow; Show-AccessStatus $state; return }

    $methods = @()
    $trySsh = $Ssh -or -not $WinRM
    $tryWinRM = $WinRM -or -not $Ssh
    if ($trySsh) { $methods += 'SshGitHub' }
    if ($tryWinRM) { $methods += 'WinRM' }
    if ($trySsh) { $methods += 'SshWindowsUpdate' }

    # Fetch keys and certificate now, so a wrong one fails before anything changes.
    if ($trySsh -and ($GitHubUser -or $PublicKey)) {
        try { $script:sshKeys = Get-SshPublicKeys } catch { Write-Warning "SSH keys: $($_.Exception.Message)" }
    }
    if ($tryWinRM -and $ClientCertificate) {
        try { $script:clientCert = Get-ClientCertificate } catch { Write-Warning "WinRM certificate: $($_.Exception.Message)" }
    }
    $usable = @($methods | Where-Object { ($_ -eq 'WinRM' -and $script:clientCert) -or ($_ -ne 'WinRM' -and $script:sshKeys) })
    # The GitHub release installs with its own script files (install-sshd.ps1), which a Group Policy
    # that turns scripts off stops, whatever -ExecutionPolicy says. This script itself runs as text.
    $gpoPolicy = @('MachinePolicy', 'UserPolicy' | ForEach-Object { "$(Get-ExecutionPolicy -Scope $_)" } | Where-Object { $_ -eq 'Restricted' })
    if ($gpoPolicy -and 'SshGitHub' -in $usable -and -not (Get-Service sshd -ErrorAction SilentlyContinue)) {
        Write-Host 'Skipping SshGitHub: Group Policy turns PowerShell scripts off, and its installer is a script.' -ForegroundColor DarkYellow
        $usable = @($usable | Where-Object { $_ -ne 'SshGitHub' })
    }
    foreach ($m in $methods) {
        if ($m -notin $usable -and -not ($m -eq 'SshGitHub' -and $gpoPolicy)) { Write-Host "Skipping $m (needs $(if ($m -eq 'WinRM') { 'a usable -ClientCertificate' } else { 'usable keys from -GitHubUser or -PublicKey' }))." -ForegroundColor DarkYellow }
    }
    if (-not $usable) { throw 'Nothing to try: give -GitHubUser or -PublicKey for SSH and/or -ClientCertificate for WinRM.' }

    Write-Host 'This will change the endpoint:' -ForegroundColor Yellow
    if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) { Write-Host "  - create local administrator '$UserName' with a random password nobody sees" }
    Write-Host "  - then try, in order, until one works: $($usable -join ' > ')"
    if ($usable | Where-Object { $_ -ne 'WinRM' }) {
        Write-Host '    SSH:   install OpenSSH if missing (GitHub release, else Windows Update), listen on 127.0.0.1:22 only, and allow these keys:'
        foreach ($k in $script:sshKeys) { $c = ($k -split '\s+', 3)[2]; Write-Host "             $(Get-KeyFingerprint $k)  $c" }
    }
    if ('WinRM' -in $usable) {
        Write-Host "    WinRM: start WinRM, HTTPS listener on 127.0.0.1:$WinRMPort with a temporary self-signed certificate,"
        Write-Host "           certificate authentication on, trust your client certificate (Root, TrustedPeople), map it to '$UserName',"
        Write-Host '           LocalAccountTokenFilterPolicy = 1'
        Write-Host "           client certificate thumbprint $($script:clientCert.Thumbprint)"
    }
    Write-Host "  - record the previous state in $stateFile"
    Write-Host 'Undo it all afterwards with: .\Set-TriageAccess.ps1 -Remove'
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enable temporary triage access')) { return }

    $state.EnabledAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Write-AccessState $state
    try { $secret = Add-TriageAdmin $state }
    catch {
        if (-not $state.UserExisted) { Remove-Item $triageDir -Recurse -Force -ErrorAction SilentlyContinue }
        throw
    }

    $sshdPreinstalled = [bool](Get-Service sshd -ErrorAction SilentlyContinue)
    foreach ($m in $usable) {
        if ($m -eq 'SshWindowsUpdate' -and $sshdPreinstalled -and 'SshGitHub' -in $usable) { continue }   # same existing sshd: already tried
        $started = Get-Date
        Write-Host "Trying $m ..." -ForegroundColor Cyan
        try {
            switch ($m) {
                'WinRM' { Enable-WinRMTriage $state $secret }
                'SshGitHub' { Enable-SshTriage $state 'GitHub' }
                'SshWindowsUpdate' { Enable-SshTriage $state 'WindowsUpdate' }
            }
            $state.Method = if ($m -ne 'WinRM' -and $state.SshSource -eq 'existing') { 'SshExisting' } else { $m }
            Write-AccessState $state
            Write-Host ("{0} ready after {1:N0}s." -f $state.Method, ((Get-Date) - $started).TotalSeconds) -ForegroundColor Green
            break
        }
        catch {
            Write-Warning "$m failed: $($_.Exception.Message)"
            try {
                if ($m -eq 'WinRM') { Disable-WinRMTriage $state } else { Disable-SshTriage $state }
            }
            catch { Write-Warning "Rolling back $m was incomplete: $($_.Exception.Message). -Remove will try again." }
            Write-AccessState $state
        }
    }

    if (-not $state.Method) {
        $problem = Undo-TriageAdmin $state
        if ($problem) { Write-Warning $problem } else { Remove-Item $triageDir -Recurse -Force -ErrorAction SilentlyContinue }
        throw 'No method worked; everything was rolled back (see the warnings above).'
    }

    Show-AccessStatus $state
    if ($state.Method -eq 'WinRM') {
        Write-Host "Forward a local port (e.g. 5986) to 127.0.0.1:$WinRMPort on this machine, then from your machine:" -ForegroundColor Green
        Write-Host "  endpoint-triage/scripts/triage.sh -t winrm -p 5986 -F $($state.ServerCertThumbprint)" -ForegroundColor Green
    }
    else {
        Write-Host 'Forward a local port (e.g. 2222) to 127.0.0.1:22 on this machine, then from your machine:' -ForegroundColor Green
        Write-Host "  endpoint-triage/scripts/triage.sh -t ssh -p 2222 -u $UserName   (compare the host key fingerprint above)" -ForegroundColor Green
    }
    return
}

# ------------------------------------------------------------------ remove
if (-not $Remove) { return }
if (-not $state.Count) {
    Write-Warning "No state file ($stateFile): nothing was set up by this script, or it was already removed."
    $leftover = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue | Where-Object { $_.Description -eq $accountNote }
    if (-not $leftover) { return }
    $state = @{ UserName = $UserName; UserExisted = $false }
}

Write-Host 'This will change the endpoint:' -ForegroundColor Yellow
if ($state.UserName -and -not $state.UserExisted) { Write-Host "  - delete local user '$($state.UserName)' and its profile" }
if ($state.ContainsKey('WinRMServiceStartType')) {
    Write-Host "  - WinRM: remove the 127.0.0.1 HTTPS listener, the certificate mapping, the temporary server certificate and the trusted client"
    Write-Host "           certificate; put certificate authentication, LocalAccountTokenFilterPolicy and the WinRM service back as they were"
}
if ($state.ContainsKey('SshExistedBefore')) {
    if ($state.SshExistedBefore) { Write-Host '  - SSH: put sshd_config, administrators_authorized_keys and the sshd service back as they were' }
    elseif ($KeepOpenSsh) { Write-Host '  - SSH: remove the key, stop sshd, leave OpenSSH installed' }
    else { Write-Host "  - SSH: remove the key and uninstall OpenSSH (installed from $($state.SshSource))" }
}
Write-Host "  - delete $triageDir (triage scripts, results and this state)"
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Remove temporary triage access')) { return }

$problems = @()
try { Disable-WinRMTriage $state } catch { $problems += "WinRM: $($_.Exception.Message)" }
try { Disable-SshTriage $state } catch { $problems += "SSH: $($_.Exception.Message)" }
$state.Remove('Method')
Write-AccessState $state
$p = Undo-TriageAdmin $state
if ($p) { $problems += $p }

if ($problems) {
    $problems | ForEach-Object { Write-Warning $_ }
    Write-Warning "Kept $triageDir so -Remove can finish the job later."
}
elseif (Test-Path $triageDir) { Remove-Item $triageDir -Recurse -Force }

Write-Host ''
Write-Host 'After removal:' -ForegroundColor Green
Show-AccessStatus @{ UserName = $state.UserName }
