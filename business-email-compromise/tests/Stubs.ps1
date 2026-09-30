# Offline stand-ins for the Exchange Online and Microsoft Graph cmdlets the helpers call.
# Unit tests dot-source this, then Mock these functions to return fake tenant data. Each stub
# declares the parameters the helpers pass; Static.Tests.ps1 fails if a helper starts using a
# cmdlet or parameter that is missing here, so keep them in step.

#region Exchange Online

function Connect-ExchangeOnline { [CmdletBinding()] param($UserPrincipalName, [switch]$ShowBanner, [switch]$Device) }
function Get-ConnectionInformation { [CmdletBinding()] param() }
function Get-InboxRule { [CmdletBinding()] param($Mailbox, $Identity, [switch]$IncludeHidden) }
function Remove-InboxRule { [CmdletBinding(SupportsShouldProcess)] param($Mailbox, $Identity) }
function Get-Mailbox { [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $ResultSize, $RecipientTypeDetails) }
function Set-Mailbox { [CmdletBinding(SupportsShouldProcess)] param([Parameter(Position = 0)]$Identity, $RetainDeletedItemsFor, $LitigationHoldEnabled) }
function Get-MailboxPermission { [CmdletBinding()] param([Parameter(Position = 0)]$Identity) }
function Get-RecipientPermission { [CmdletBinding()] param([Parameter(Position = 0)]$Identity) }
function Get-MailboxFolderStatistics { [CmdletBinding()] param([Parameter(Position = 0)]$Identity, [switch]$IncludeOldestAndNewestItems) }
function Get-MobileDevice { [CmdletBinding()] param($Mailbox) }
function Get-TransportRule { [CmdletBinding()] param() }
function Search-UnifiedAuditLog { [CmdletBinding()] param($StartDate, $EndDate, $ResultSize, $SessionCommand, $SessionId, $UserIds, $IPAddresses, $Operations) }
function Get-MessageTraceV2 { [CmdletBinding()] param($StartDate, $EndDate, $ResultSize, $SenderAddress, $RecipientAddress, $Subject, $SubjectFilterType) }
function Get-BlockedSenderAddress { [CmdletBinding()] param() }
function Get-RecoverableItems { [CmdletBinding()] param($Identity, $SourceFolder, $FilterStartTime, $FilterItemType, $ResultSize) }
function Restore-RecoverableItems { [CmdletBinding()] param($Identity, $SourceFolder, $FilterStartTime, $FilterItemType, $ResultSize, $SubjectContains) }

#endregion

#region Microsoft Graph

function Connect-MgGraph { [CmdletBinding()] param($Scopes, [switch]$NoWelcome, [switch]$UseDeviceCode) }
function Get-MgContext { [CmdletBinding()] param() }
function Update-MgUser { [CmdletBinding()] param($UserId, [switch]$AccountEnabled) }
function Revoke-MgUserSignInSession { [CmdletBinding()] param($UserId) }
function Get-MgUserAuthenticationMethod { [CmdletBinding()] param($UserId) }
function Get-MgUserRegisteredDevice { [CmdletBinding()] param($UserId, [switch]$All) }
function Get-MgUserOwnedDevice { [CmdletBinding()] param($UserId, [switch]$All) }
function Get-MgUserOauth2PermissionGrant { [CmdletBinding()] param($UserId, [switch]$All) }
function Get-MgServicePrincipal { [CmdletBinding()] param($ServicePrincipalId) }
function Get-MgUserAppRoleAssignment { [CmdletBinding()] param($UserId, [switch]$All) }
function Get-MgBetaAuditLogSignIn { [CmdletBinding()] param($Filter, [switch]$All) }

#endregion
