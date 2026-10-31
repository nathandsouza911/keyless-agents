#Requires -Version 7.4
<#
.SYNOPSIS
  Create Cloud Locksmith's read-only app registration in a TEST Microsoft Entra tenant.

.DESCRIPTION
  USE A TEST TENANT, NEVER A PRODUCTION ONE. Cloud Locksmith v0.1 is beta software.

  What this does in the tenant you name:
    1. creates ONE app registration, "Cloud Locksmith (<profile>)", single-tenant, no redirect URI, no secret;
    2. adds a certificate credential to it (created here; the private key never leaves this machine);
    3. requests exactly these Microsoft Graph APPLICATION permissions, all read-only:
         agent-read-only-investigation:  User.Read.All, AuditLog.Read.All,
                                         RoleManagement.Read.Directory, Application.Read.All
         dormant-accounts:               User.Read.All, AuditLog.Read.All
       None of them can create, change, disable or delete anything;
    4. creates the app's service principal;
    5. opens the app's API permissions page in the Entra admin center. YOU select "Grant admin consent"
       there; this script never does. Granting Microsoft Graph application permissions needs the
       Privileged Role Administrator or Global Administrator role.

  It signs you in to Microsoft Graph PowerShell with one delegated scope, Application.ReadWrite.All, to
  create the app (Application Developer or a higher role is enough for that). Microsoft records that
  sign-in as a consent for "Microsoft Graph Command Line Tools"; if you tick "Consent on behalf of your
  organization" it becomes tenant-wide. Neither script removes it: see the README. Nothing else in the
  tenant is read or changed. Undo the app with uninstall.ps1.

.PARAMETER TenantId
  The test tenant's ID (a GUID). You will be asked to type it again to confirm you mean this tenant.

.PARAMETER AppProfile
  agent-read-only-investigation (default; all v0.1 tools) or dormant-accounts (dormant accounts only).

.PARAMETER OutDir
  Where the private key, the certificate and the state file go. Default: ./secrets/profiles. Keep it out of
  any repository.

.EXAMPLE
  ./deploy/test-tenant/setup.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TenantId,
    [ValidateSet('agent-read-only-investigation', 'dormant-accounts')][string]$AppProfile = 'agent-read-only-investigation',
    [string]$OutDir = (Join-Path (Get-Location) 'secrets/profiles')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$GraphAppId = '00000003-0000-0000-c000-000000000000'
$Permissions = @{
    'agent-read-only-investigation' = @('User.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All')
    'dormant-accounts'              = @('User.Read.All', 'AuditLog.Read.All')
}[$AppProfile]
$EnvPrefix = @{ 'agent-read-only-investigation' = 'CLW_PROFILE_AGENTRO'; 'dormant-accounts' = 'CLW_PROFILE_DIRREAD' }[$AppProfile]
$CredentialProfile = @{ 'agent-read-only-investigation' = 'agent-read-only-investigation'; 'dormant-accounts' = 'directory-read-auditlog-read' }[$AppProfile]
$DisplayName = "Cloud Locksmith ($AppProfile)"

Write-Host ''
Write-Host '  TEST TENANT ONLY. Cloud Locksmith v0.1 is beta software.' -ForegroundColor Yellow
Write-Host "  Tenant:      $TenantId"
Write-Host "  Creates:     one app registration, '$DisplayName', with a certificate (no secret)"
Write-Host "  Requests:    Microsoft Graph application permissions, all read-only:"
$Permissions | ForEach-Object { Write-Host "                 $_" }
Write-Host '  You grant admin consent yourself, in the browser page this opens.'
Write-Host "  Undo:        ./deploy/test-tenant/uninstall.ps1 -TenantId $TenantId -AppProfile $AppProfile"
Write-Host ''

if ($WhatIfPreference) {
    Write-Host 'WhatIf: nothing was connected to or created.'
    return
}
$typed = Read-Host 'Type the tenant ID again to confirm you mean this tenant (it must be a TEST tenant)'
if ($typed.Trim().ToLowerInvariant() -ne $TenantId.ToLowerInvariant()) { throw 'The tenant IDs differ. Nothing was done.' }

foreach ($module in 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications') {
    if (-not (Get-Module -ListAvailable -Name $module)) { throw "Install $module first: Install-Module $module -Scope CurrentUser" }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$keyPath = Join-Path $OutDir "$CredentialProfile.pem"
$certPath = Join-Path $OutDir "$CredentialProfile.cer.pem"
$statePath = Join-Path $OutDir "$CredentialProfile.state.json"
if (Test-Path $keyPath) { throw "$keyPath exists. Run uninstall.ps1 first, or choose another -OutDir." }

# 1. The certificate: RSA 2048, self-signed, 90 days. The private key is written here, nowhere else.
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    "CN=cloud-locksmith-$AppProfile", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$cert = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(90))
Set-Content -Path $keyPath -Value $rsa.ExportPkcs8PrivateKeyPem() -NoNewline -Encoding ascii
Set-Content -Path $certPath -Value $cert.ExportCertificatePem() -NoNewline -Encoding ascii
if ($IsWindows) {
    # Only the current user may read the private key.
    icacls $keyPath /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
} else {
    chmod 600 $keyPath
}

# 2. Sign in with the one scope needed to create an app registration.
Connect-MgGraph -TenantId $TenantId -Scopes 'Application.ReadWrite.All' -NoWelcome
try {
    $graph = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
    $roles = foreach ($name in $Permissions) {
        $role = $graph.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }
        if (-not $role) { throw "Microsoft Graph has no application permission named $name" }
        @{ Id = $role.Id; Type = 'Role' }
    }

    # 3. The app registration: single tenant, the certificate, exactly these permissions.
    $app = New-MgApplication -DisplayName $DisplayName -SignInAudience 'AzureADMyOrg' `
        -KeyCredentials @(@{ Type = 'AsymmetricX509Cert'; Usage = 'Verify'; Key = $cert.RawData; DisplayName = "CN=cloud-locksmith-$AppProfile" }) `
        -RequiredResourceAccess @(@{ ResourceAppId = $GraphAppId; ResourceAccess = $roles })
    # Recorded at once, so uninstall.ps1 can always remove the app, even if a later step fails.
    $state = @{ tenantId = $TenantId; profile = $AppProfile; appId = $app.AppId; applicationObjectId = $app.Id;
                servicePrincipalId = $null; created = (Get-Date).ToUniversalTime().ToString('o') }
    $state | ConvertTo-Json | Set-Content -Path $statePath -Encoding utf8
    # 4. Its service principal.
    $sp = New-MgServicePrincipal -AppId $app.AppId
    $state.servicePrincipalId = $sp.Id
    $state | ConvertTo-Json | Set-Content -Path $statePath -Encoding utf8
} catch {
    if (Test-Path $statePath) {
        Write-Host "Setup failed after the app was created. Remove it with: ./deploy/test-tenant/uninstall.ps1 -TenantId $TenantId -AppProfile $AppProfile" -ForegroundColor Red
    }
    throw
} finally {
    Disconnect-MgGraph | Out-Null
}

# 5. Admin consent: yours, in the Entra admin center (the app has no redirect URI, so the bare consent URL would
#    end on an error page after consenting).
$consent = "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$($app.AppId)"
Write-Host ''
Write-Host 'Created. Now grant admin consent:' -ForegroundColor Green
Write-Host "  1. Open: $consent"
Write-Host "  2. Check the list shows exactly the permissions above, then select 'Grant admin consent for <tenant>'."
Write-Host '     (A newly created app can take a minute to appear.)'
try { Start-Process $consent } catch { }
Write-Host ''
Write-Host "The broker reads the key at /run/secrets/profiles/$CredentialProfile.pem: keep it in the folder"
Write-Host "docker-compose.yml mounts there (CLW_PROFILE_CERT_DIR, default ./secrets/profiles; git-ignored)."
Write-Host 'Put these in the deployment''s .env, never in a repository:'
Write-Host "  $($EnvPrefix)_CLIENT_ID=$($app.AppId)"
Write-Host "  $($EnvPrefix)_CERT_THUMBPRINT=$($cert.Thumbprint)"
Write-Host "The certificate expires on $($cert.NotAfter.ToString('yyyy-MM-dd')). Before then: ./deploy/test-tenant/rotate.ps1"
