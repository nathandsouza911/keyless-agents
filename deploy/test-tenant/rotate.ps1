#Requires -Version 7.4
<#
.SYNOPSIS
  Replace the certificate of the app registration setup.ps1 created, without deleting the app or its consent.

.DESCRIPTION
  Creates a new certificate (90 days) on this machine, then sets it as the app's only certificate
  credential. Microsoft Graph replaces the whole credential list in one update, so the old certificate
  stops working at once: the broker fails closed (sessions get a refusal) until you put the new
  thumbprint in .env and restart it. Do this at a quiet time. The old key file is kept, renamed, until
  you delete it.

.EXAMPLE
  ./deploy/test-tenant/rotate.ps1 -TenantId 00000000-0000-0000-0000-000000000000
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
$EnvPrefix = @{ 'agent-read-only-investigation' = 'CLW_PROFILE_AGENTRO'; 'dormant-accounts' = 'CLW_PROFILE_DIRREAD' }[$AppProfile]
$statePath = Join-Path $OutDir "$CredentialProfile.state.json"
$keyPath = Join-Path $OutDir "$CredentialProfile.pem"
if (-not (Test-Path $statePath)) { throw "No state file at ${statePath}: run setup.ps1 first." }
$state = Get-Content $statePath -Raw | ConvertFrom-Json
if ($state.tenantId -ne $TenantId) { throw 'The state file is for a different tenant. Nothing was done.' }

Write-Host "Replaces the certificate of app $($state.appId) ('Cloud Locksmith ($AppProfile)') in tenant $TenantId."
Write-Host 'The old certificate stops working immediately; update .env and restart the broker straight after.'
if ($WhatIfPreference) { Write-Host 'WhatIf: nothing was connected to or changed.'; return }

$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    "CN=cloud-locksmith-$AppProfile", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(90))

Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All' -NoWelcome
try {
    $app = Get-MgApplication -ApplicationId $state.applicationObjectId
    if ($app.AppId -ne $state.appId -or $app.DisplayName -ne "Cloud Locksmith ($AppProfile)") {
        throw 'The app registration no longer matches the state file. Nothing was changed.'
    }
    Update-MgApplication -ApplicationId $app.Id -KeyCredentials @(@{
        Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = $cert.RawData; DisplayName = "CN=cloud-locksmith-$AppProfile" })
} finally {
    Disconnect-MgGraph | Out-Null
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
if (Test-Path $keyPath) { Move-Item $keyPath "$keyPath.replaced-$stamp" }
Set-Content -Path $keyPath -Value $rsa.ExportPkcs8PrivateKeyPem() -NoNewline -Encoding ascii
Set-Content -Path (Join-Path $OutDir "$CredentialProfile.cer.pem") -Value $cert.ExportCertificatePem() -NoNewline -Encoding ascii
if ($IsWindows) { icacls $keyPath /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null } else { chmod 600 $keyPath }
Write-Host 'Rotated. Now set in .env and restart the broker:' -ForegroundColor Green
Write-Host "  $($EnvPrefix)_CERT_THUMBPRINT=$($cert.Thumbprint)"
Write-Host "New certificate expires $($cert.NotAfter.ToString('yyyy-MM-dd')). Delete $keyPath.replaced-$stamp when the broker works."
