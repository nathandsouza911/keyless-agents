# Cloud Locksmith script-run bootstrap (Part B, M5; SD-044).
#
# The PowerShell task image's entry point:
#   pwsh -NoProfile -NonInteractive -File /clw/bootstrap.ps1 <script_sha256> <bootstrap_sha256>
# with the approved script's UTF-8 bytes on stdin, and in the environment
# exactly CLW_RUN_TOKEN (the run's capability) and CLW_BROKER_URL.
#
# 1. Refuses to run unless this file's SHA-256 is <bootstrap_sha256> (the
#    digest the runner recorded in RUN_STARTED) and the script's bytes hash to
#    <script_sha256> (the approved digest).
# 2. Connects the Graph SDK with the capability token, then removes the token
#    from the environment. "Graph" is the facade: graph.microsoft.com resolves
#    to the facade proxy on the script network, trusted through this
#    deployment's CA only.
# 3. Loads the compatibility shims (disclosed, and covered by the bootstrap
#    digest):
#      Connect-MgGraph     ignores its arguments: the run is already connected
#      Disconnect-MgGraph  no-op, so an early disconnect does not drop the run
#      Out-GridView        writes its input as one line: CLW_OUTPUT <json>
#      Read-Host           fails at once: script runs are non-interactive
# 4. Runs the script as a file (so its own `exit` ends the script, not this
#    bootstrap), with every output stream on stdout as plain text, and ends
#    with one line: CLW_SCRIPT_EXIT <code>.
#
# A refusal is one line, CLW_BOOTSTRAP_FAILED <reason>, and exit code 70.
# None of this is enforcement: the facade decides what the script may read.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$PSStyle.OutputRendering = 'PlainText'
$MaxScriptBytes = 262144

function Stop-Bootstrap([string] $Reason) {
    [Console]::Out.WriteLine("CLW_BOOTSTRAP_FAILED $Reason")
    [Console]::Out.Flush()
    exit 70
}

function Get-Sha256([byte[]] $Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { -join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

if ($args.Count -ne 2 -or $args[0] -notmatch '^[0-9a-f]{64}$' -or $args[1] -notmatch '^[0-9a-f]{64}$') {
    Stop-Bootstrap 'usage'
}
if ((Get-Sha256 ([IO.File]::ReadAllBytes($PSCommandPath))) -ne $args[1]) { Stop-Bootstrap 'bootstrap_mismatch' }

$stdin = [Console]::OpenStandardInput()
$buffer = [IO.MemoryStream]::new()
$chunk = [byte[]]::new(65536)
while (($n = $stdin.Read($chunk, 0, $chunk.Length)) -gt 0) {
    $buffer.Write($chunk, 0, $n)
    if ($buffer.Length -gt $MaxScriptBytes) { Stop-Bootstrap 'script_too_large' }
}
$bytes = $buffer.ToArray()
if ((Get-Sha256 $bytes) -ne $args[0]) { Stop-Bootstrap 'script_digest_mismatch' }

$token = $env:CLW_RUN_TOKEN
Remove-Item Env:CLW_RUN_TOKEN -ErrorAction SilentlyContinue
if (-not $token) { Stop-Bootstrap 'no_capability' }
try {
    Import-Module Microsoft.Graph.Authentication
    Microsoft.Graph.Authentication\Connect-MgGraph -AccessToken (ConvertTo-SecureString $token -AsPlainText -Force) -NoWelcome
} catch {
    Stop-Bootstrap 'connect_failed'
}
Remove-Variable token

function global:Connect-MgGraph { }
function global:Disconnect-MgGraph { }
function global:Out-GridView { 'CLW_OUTPUT ' + (ConvertTo-Json -InputObject @($input) -Depth 4 -Compress) }
function global:Read-Host { throw 'Read-Host is not available: Cloud Locksmith script runs are non-interactive.' }

# A file in /tmp (a noexec tmpfs: pwsh reads it, nothing executes it as a binary).
$path = '/tmp/clw-script.ps1'
[IO.File]::WriteAllBytes($path, $bytes)
$ErrorActionPreference = 'Continue'
$global:LASTEXITCODE = 0
$code = 0
try {
    # Errors as their message alone: the default view adds colour codes and
    # points at this bootstrap's line rather than the script's.
    & $path *>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { "ERROR: $($_.Exception.Message)" } else { $_ }
    } | Out-Default
    if ($LASTEXITCODE) { $code = $LASTEXITCODE }
} catch {
    "ERROR: $($_.Exception.Message)" | Out-Default  # a terminating error ends the script
    $code = 1
}
[Console]::Out.Flush()
[Console]::Out.WriteLine("CLW_SCRIPT_EXIT $code")
[Console]::Out.Flush()
exit 0
