# Cloud Locksmith script analyser (Part B, M4; SD-043).
#
# Reads a script's text (from the file named by the first argument, else stdin)
# and writes ONE line of JSON to stdout:
#   CLW_ANALYSIS {"version":..., "parse_errors":[...], "commands":[...], "graph_calls":[...],
#                 "unresolved":[...], "risks":[...]}
# It parses the script with PowerShell's own parser and NEVER executes any of it.
# It runs in a container with no network (the runner's analyser sandbox); the
# cmdlet-to-endpoint mapping comes from the metadata bundled with
# Microsoft.Graph.Authentication (what Find-MgGraphCommand reads), indexed at
# image build time by build_command_index.ps1 into /clw/graph-commands.json.
#
# The analysis explains; it does not enforce. Anything it cannot resolve is
# reported as unresolved, and at run time it is denied unless the approved
# manifest allows it.

$ErrorActionPreference = 'Stop'
$AnalyserVersion = '1'
$MaxItems = 500

function Out-Analysis($Object) {
    'CLW_ANALYSIS ' + (ConvertTo-Json -InputObject $Object -Depth 6 -Compress)
}

# A missing or unreadable index fails the whole analysis (ErrorActionPreference
# Stop): never every cmdlet silently reported as unknown.
$CommandIndex = Get-Content -Raw -LiteralPath '/clw/graph-commands.json' | ConvertFrom-Json -AsHashtable

$text = if ($args.Count -gt 0) { Get-Content -Raw -LiteralPath $args[0] } else { [Console]::In.ReadToEnd() }
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)

$parseErrors = @($errors | Select-Object -First 20 | ForEach-Object {
    @{ line = $_.Extent.StartLineNumber; message = $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length)) } })

$commands = [System.Collections.Generic.List[object]]::new()
$graphCalls = [System.Collections.Generic.List[object]]::new()
$unresolved = [System.Collections.Generic.List[object]]::new()
$risks = [System.Collections.Generic.List[object]]::new()

function Add-Risk($Kind, $Line, $Detail) {
    if ($risks.Count -lt $MaxItems) { $risks.Add(@{ kind = $Kind; line = $Line; detail = "$Detail".Substring(0, [Math]::Min(160, "$Detail".Length)) }) }
}

# Constant string assignments, so Invoke-MgGraphRequest -Uri $Uri can be resolved when $Uri is a literal.
# Every assignment to each variable, in source order: its end and its value if
# that is a string (else $null). A use takes the nearest assignment before it,
# so `$Uri = "<literal>"; Invoke-MgGraphRequest -Uri $Uri` resolves even when
# $Uri is later set to a nextLink (that later use stays unresolved). A loop can
# make a use see a later assignment at run time: the analysis explains, the
# facade enforces.
$assignments = @{}
foreach ($a in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
    $left = $a.Left.Extent.Text
    $right = $a.Right
    if ($right -is [System.Management.Automation.Language.CommandExpressionAst]) { $right = $right.Expression }
    $value = if ($right -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                 $right -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { $right } else { $null }
    if (-not $assignments.ContainsKey($left)) { $assignments[$left] = [System.Collections.Generic.List[object]]::new() }
    $assignments[$left].Add(@{ end = $a.Extent.EndOffset; value = $value })
}

function Get-AssignedString([string] $Name, [int] $Before) {
    $prior = @($assignments[$Name] | Where-Object { $_ -and $_.end -le $Before })
    if ($prior.Count -eq 0) { return $null }
    $prior[-1].value
}

$preinstalled = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
$riskyCommands = @{
    'Invoke-Expression' = 'dynamic_code'; 'iex' = 'dynamic_code'; 'Add-Type' = 'compiled_code';
    'Start-Process' = 'native_process'; 'Start-Job' = 'background_job'; 'Read-Host' = 'interactive_prompt';
    'Select-MgProfile' = 'removed_in_sdk_v2'; 'Install-Module' = 'module_install'; 'Install-PSResource' = 'module_install';
    'Save-Module' = 'module_install'; 'Invoke-Item' = 'opens_files'; 'Out-File' = 'file_write'; 'Set-Content' = 'file_write';
    'Add-Content' = 'file_write'; 'Export-Csv' = 'file_write'; 'Export-Excel' = 'file_write'; 'New-Item' = 'file_write';
    'Get-Credential' = 'credential_access'; 'Get-StoredCredential' = 'credential_access';
    'ConvertFrom-SecureString' = 'credential_access';
}

foreach ($c in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    if ($commands.Count -ge $MaxItems) { break }
    $name = $c.GetCommandName()
    $line = $c.Extent.StartLineNumber
    if ($null -eq $name) {
        Add-Risk 'dynamic_command' $line $c.Extent.Text   # & $something, . $path
        continue
    }
    $commands.Add(@{ name = $name; line = $line })
    $bare = ($name -split '\\')[-1]
    if ($riskyCommands.ContainsKey($bare)) { Add-Risk $riskyCommands[$bare] $line $name }
    if ($name -match '\\') { Add-Risk 'module_qualified_call' $line $name }
    if ($bare -like 'Connect-*' -and $bare -ne 'Connect-MgGraph') { Add-Risk 'other_service' $line $bare }
    if ($bare -eq 'Import-Module') {
        $module = ($c.CommandElements | Select-Object -Skip 1 | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] } |
                   Select-Object -First 1).Extent.Text.Trim("'`"")
        if ($module -and $preinstalled -notcontains $module) { Add-Risk 'module_not_preinstalled' $line $module }
    }
    if ($bare -in @('Invoke-RestMethod', 'Invoke-WebRequest', 'irm', 'iwr', 'curl', 'wget')) {
        $uriElement = $null
        for ($i = 1; $i -lt $c.CommandElements.Count; $i++) {
            $el = $c.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -eq 'Uri') { $uriElement = $c.CommandElements[$i + 1] }
        }
        if ($null -eq $uriElement -and $c.CommandElements.Count -gt 1) { $uriElement = $c.CommandElements[1] }
        $literal = if ($uriElement -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $uriElement.Value } else { $null }
        if ($literal -and $literal -notmatch '^https://graph\.microsoft\.com/') { Add-Risk 'non_graph_web_call' $line $literal }
        elseif ($literal) { $graphCalls.Add(@{ source = $bare; method = 'GET'; uri = $literal; line = $line }) }
        else { $unresolved.Add(@{ line = $line; command = $bare; reason = 'web call with a computed URI' }) }
        continue
    }
    if ($bare -eq 'Invoke-MgGraphRequest') {
        $method = 'GET'; $uriElement = $null
        for ($i = 1; $i -lt $c.CommandElements.Count; $i++) {
            $el = $c.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                if ($el.ParameterName -eq 'Uri') { $uriElement = $c.CommandElements[$i + 1] }
                if ($el.ParameterName -eq 'Method') { $method = "$($c.CommandElements[$i + 1].Extent.Text)".Trim("'`"").ToUpper() }
            }
        }
        $uri = $null
        if ($uriElement -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $uriElement -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { $uri = $uriElement }
        elseif ($uriElement -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $uri = Get-AssignedString $uriElement.Extent.Text $c.Extent.StartOffset
        }
        if ($uri -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $uri.NestedExpressions.Count -gt 0) {
            Add-Risk 'string_built_url' $line $uri.Extent.Text
            $unresolved.Add(@{ line = $line; command = $bare; reason = 'URI built from variables' })
        } elseif ($null -ne $uri) {
            $graphCalls.Add(@{ source = $bare; method = $method; uri = $uri.Value; line = $line })
        } else {
            $unresolved.Add(@{ line = $line; command = $bare; reason = 'URI not a constant (for example a nextLink)' })
        }
        continue
    }
    if ($bare -like '*-Mg*' -and $bare -notin @('Connect-MgGraph', 'Disconnect-MgGraph', 'Get-MgContext')) {
        $found = @($CommandIndex[$bare.ToLowerInvariant()] | Where-Object { $_ } | ForEach-Object { [pscustomobject]$_ })
        if ($found.Count -eq 0) { $unresolved.Add(@{ line = $line; command = $bare; reason = 'not a known Graph SDK cmdlet' }); continue }
        # The cmdlet's parameters as written: literal values only (a variable is reported as $null).
        $parameters = @{}
        for ($i = 1; $i -lt $c.CommandElements.Count; $i++) {
            $el = $c.CommandElements[$i]
            if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
            $value = $null
            $next = if ($el.Argument) { $el.Argument } elseif ($i + 1 -lt $c.CommandElements.Count -and
                $c.CommandElements[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst]) { $c.CommandElements[$i + 1] } else { $null }
            if ($next -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $value = $next.Value }
            elseif ($next -is [System.Management.Automation.Language.ArrayLiteralAst]) {
                $value = @($next.Elements | Where-Object { $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] } | ForEach-Object Value)
            }
            elseif ($next -is [System.Management.Automation.Language.ConstantExpressionAst]) { $value = "$($next.Value)" }
            elseif ($null -eq $next) { $value = $true }   # a switch
            $parameters[$el.ParameterName] = $value
        }
        $isCollection = $parameters.ContainsKey('All') -or $parameters.ContainsKey('Filter') -or $parameters.ContainsKey('Top') -or
                        -not ($parameters.Keys | Where-Object { $_ -match 'Id$' })
        $chosen = $found | Where-Object { ($_.URI -notmatch '\{[^}]+\}$') -eq $isCollection } | Sort-Object APIVersion, URI -Unique
        if (-not $chosen) { $chosen = $found | Sort-Object APIVersion, URI -Unique }
        foreach ($entry in $chosen | Select-Object -First 2) {
            $graphCalls.Add(@{ source = $bare; method = $entry.Method; uri = $entry.URI; api_version = $entry.APIVersion
                               line = $line; parameters = $parameters })
        }
    }
}

# Encoded commands and environment or credential-store reads, from the token stream.
foreach ($t in $tokens) {
    $value = $t.Text
    if ($value -match '^-(e|ec|enc|encodedcommand)$') { Add-Risk 'encoded_command' $t.Extent.StartLineNumber $value }
    if ($t.Kind -eq 'Variable' -and $value -match '^\$env:') { Add-Risk 'environment_read' $t.Extent.StartLineNumber $value }
}

Out-Analysis @{
    version = $AnalyserVersion
    parse_errors = $parseErrors
    commands = @($commands)
    graph_calls = @($graphCalls)
    unresolved = @($unresolved)
    risks = @($risks)
}
