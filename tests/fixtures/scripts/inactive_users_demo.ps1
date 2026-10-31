# Inactive users report: a realistic Graph PowerShell SDK script written for
# Cloud Locksmith's tests in the style of public community scripts (not copied).
param([int]$Days = 90)

if (-not (Get-Module -ListAvailable Microsoft.Graph.Users)) {
    $answer = Read-Host "Microsoft.Graph is not installed. Install it now? [Y/N]"
    if ($answer -eq 'Y') { Install-Module Microsoft.Graph -Scope CurrentUser }
}

Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome

$users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, SignInActivity -Filter "accountEnabled eq true"
$licensed = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,assignedLicenses&$top=999'

$report = foreach ($user in $users) {
    $last = $user.SignInActivity.LastSuccessfulSignInDateTime
    [PSCustomObject]@{ User = $user.DisplayName; Upn = $user.UserPrincipalName; LastSignIn = $last }
}

# Disable accounts not used for $Days days (the line a security lead must not approve).
foreach ($stale in $report | Where-Object { $_.LastSignIn -lt (Get-Date).AddDays(-$Days) }) {
    Update-MgUser -UserId $stale.Upn -AccountEnabled:$false
}

$report | Export-Csv -Path "./inactive.csv" -NoTypeInformation
$report | Out-GridView
