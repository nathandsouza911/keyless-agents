#Requires -Version 7.4
<#
.SYNOPSIS
  Remove everything setup.ps1 created: the app registration (its service principal and consent go with it)
  and the local key, certificate and state files.

.DESCRIPTION
  Deletes only the app registration recorded in setup.ps1's state file, after checking that its app ID and
  display name match. Nothing else in the tenant is read or changed. Deleted app registrations stay in the
  tenant's recycle bin for 30 days (Entra admin center > App registrations > Deleted applications).

.EXAMPLE
  ./deploy/test-tenant/uninstall.ps1 -TenantId 00000000-0000-0000-0000-000000000000
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TenantId,
    [ValidateSet('agent-read-only-investigation', 'dormant-accounts')][string]$AppProfile = 'agent-read-only-investigation',
    [string]$OutDir = (Join-Path (Get-Location) 'secrets/profiles')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$CredentialProfile = @{ 'agent-read-only-investigation' = 'agent-read-only-investigation'; 'dormant-accounts' = 'directory-read-auditlog-read' }[$AppProfile]
$statePath = Join-Path $OutDir "$CredentialProfile.state.json"
if (-not (Test-Path $statePath)) { throw "No state file at ${statePath}: nothing recorded to remove." }
$state = Get-Content $statePath -Raw | ConvertFrom-Json
if ($state.tenantId -ne $TenantId) { throw 'The state file is for a different tenant. Nothing was done.' }

Write-Host "Deletes app registration $($state.appId) ('Cloud Locksmith ($AppProfile)') in tenant $TenantId,"
Write-Host "and the local files $CredentialProfile.pem, .cer.pem and .state.json in $OutDir."
if ($WhatIfPreference) { Write-Host 'WhatIf: nothing was connected to or deleted.'; return }

Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All' -NoWelcome
try {
    $app = Get-MgApplication -ApplicationId $state.applicationObjectId -ErrorAction SilentlyContinue
    if ($app) {
        if ($app.AppId -ne $state.appId -or $app.DisplayName -ne "Cloud Locksmith ($AppProfile)") {
            throw 'The app registration no longer matches the state file. Nothing was deleted.'
        }
        Remove-MgApplication -ApplicationId $app.Id
        Write-Host 'App registration deleted (its service principal and admin consent with it).'
    } else {
        Write-Host 'The app registration was already gone.'
    }
} finally {
    Disconnect-MgGraph | Out-Null
}
foreach ($file in "$CredentialProfile.pem", "$CredentialProfile.cer.pem", "$CredentialProfile.state.json") {
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $OutDir $file)
}
Write-Host 'Local key, certificate and state removed. Remove the CLW_PROFILE_* lines from your .env.'
