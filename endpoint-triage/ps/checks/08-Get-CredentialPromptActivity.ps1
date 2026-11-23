<#
.SYNOPSIS
    Windows Security credential and passkey prompts in a time window, with the website and the app that asked.
.DESCRIPTION
    Read-only. When a "Windows Security" prompt appears (CredentialUIBroker.exe), it is either:
    - a passkey / WebAuthn sign-in: the WebAuthN log records the website (RpID) and the calling app
      (ImageName), whether a phone was used by QR code (hybrid), and whether it succeeded; or
    - a browser asking the user to confirm before showing a saved password, or another app asking
      for Windows credentials.
    This lists WebAuthn transactions in the window, and every CredentialUIBroker and consent.exe (UAC)
    run time from Prefetch, so each prompt can be matched to its cause.
    In the GetAssertion response flags, 0x1D = user present + user verified + backed-up passkey.
.PARAMETER From
    Start of the window (local time).
.PARAMETER To
    End of the window (local time).
.EXAMPLE
    .\08-Get-CredentialPromptActivity.ps1 -From '2026-01-15 14:00' -To '2026-01-15 16:30'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][datetime]$From,
    [Parameter(Mandatory)][datetime]$To
)

if (-not (Get-Command Write-TriageSection -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path $PSScriptRoot -Parent) 'TriageCommon.ps1') }   # run by hand; the runner loads it
Write-TriageElevationWarning
"Window: $($From.ToString('yyyy-MM-dd HH:mm:ss')) to $($To.ToString('yyyy-MM-dd HH:mm:ss')) (local time)"

Write-TriageSection 'WebAuthn / passkey transactions in the window'
$events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WebAuthN/Operational'; StartTime = $From; EndTime = $To } -ErrorAction SilentlyContinue | Sort-Object TimeCreated)
$byTx = @{}
foreach ($e in $events) {
    $m = $e.Message
    if ($m -notmatch 'TransactionI[dD]: (\{[0-9a-fA-F-]+\})') { continue }
    $tx = $Matches[1]
    if (-not $byTx.ContainsKey($tx)) {
        $byTx[$tx] = [pscustomobject]@{ Started = $e.TimeCreated; Ended = $null; Transaction = $tx; RpId = ''; App = ''; Publisher = ''; Hybrid = ''; Result = ''; Flags = '' }
    }
    $t = $byTx[$tx]
    if ($m -match 'RpID: (\S+)') { $t.RpId = $Matches[1] }
    if ($m -match 'Hybrid Protocol setup completed.*SetupType: (\S+)') { $t.Hybrid = $Matches[1] }
    if ($m -match 'Ctap (WebAuthN|GetAssertion|MakeCredential) completed') { $t.Ended = $e.TimeCreated; $t.Result = 'completed' }
    if ($m -match 'Cbor decode GetAssertion response.*Flags: (0x[0-9A-Fa-f]+)') { $t.Flags = $Matches[1] }
    if ($m -match 'Error: (0x[0-9A-Fa-f]+)\. (?!The operation completed successfully)(.+?)\.') { $t.Result = "error $($Matches[1]) $($Matches[2])" }
}
# Image name and publisher arrive as separate 2106 events straight after the WebAuthN start; attach them to the nearest transaction.
foreach ($e in ($events | Where-Object { $_.Id -eq 2106 })) {
    $owner = $byTx.Values | Where-Object { $_.Started -le $e.TimeCreated } | Sort-Object Started | Select-Object -Last 1
    if (-not $owner) { continue }
    if ($e.Message -match 'Ctap Name: ImageName Value: (.+)$') { $owner.App = $Matches[1].Trim() }
    if ($e.Message -match 'Ctap Name: ImagePublisher Value: (.+)$') { $owner.Publisher = $Matches[1].Trim() }
}
$byTx.Values | Where-Object { $_.RpId -or $_.App } | Sort-Object Started | Format-TriageList

Write-TriageSection 'Every WebAuthn website (RpID) in the log, any date (shows what the user normally signs in to with passkeys)'
Get-WinEvent -LogName 'Microsoft-Windows-WebAuthN/Operational' -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'RpID: (\S+)' } |
    ForEach-Object { [pscustomobject]@{ Date = $_.TimeCreated.ToString('yyyy-MM-dd'); RpId = [regex]::Match($_.Message, 'RpID: (\S+)').Groups[1].Value } } |
    Sort-Object Date, RpId -Unique | Format-TriageTable

Write-TriageSection 'Prompt programs from Prefetch: CredentialUIBroker (Windows Security prompt) and consent.exe (UAC)'
'Prefetch keeps the last 8 runs; if the earliest run listed is after the window, older runs were pushed out.'
Get-ChildItem (Join-Path $env:SystemRoot 'Prefetch') -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(CREDENTIALUIBROKER|CONSENT)\.EXE-' } | ForEach-Object {
        try { $pf = ConvertFrom-TriagePrefetch -Path $_.FullName } catch { return }
        [pscustomobject]@{
            Executable = $pf.Executable
            InWindow   = (@($pf.RunTimes | Where-Object { $_ -ge $From -and $_ -le $To }) | ForEach-Object { $_.ToString('HH:mm:ss') }) -join ', '
            AllRuns    = ($pf.RunTimes | ForEach-Object { $_.ToString('yyyy-MM-dd HH:mm:ss') }) -join ', '
        }
    } | Format-TriageList

Write-TriageSection 'Vault / credential reads and explicit-credential logons in the window (Security 5379, 5381, 5382, 4648)'
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5379, 5381, 5382, 4648; StartTime = $From; EndTime = $To } -ErrorAction SilentlyContinue |
    ForEach-Object {
        $x = [xml]$_.ToXml(); $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        [pscustomobject]@{ Time = $_.TimeCreated; Id = $_.Id; Subject = $d.SubjectUserName; Target = "$($d.TargetName)$($d.TargetUserName)"; Process = $d.ProcessName; ClientPid = $d.ClientProcessId }
    } | Format-TriageTable
