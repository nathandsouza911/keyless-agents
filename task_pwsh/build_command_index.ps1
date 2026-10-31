# Builds the analyser's offline cmdlet-to-endpoint index (Part B; SD-043, SD-044).
#
# Run once, at image build time. It reads the command metadata bundled with
# Microsoft.Graph.Authentication (the same data Find-MgGraphCommand loads),
# keeps only what the analyser uses, and writes
#   { "<lowercase command or alias>": [ { "Method": ..., "URI": ..., "APIVersion": ... }, ... ] }
# to the path in its first argument. Loading the whole metadata took about
# 500 MiB and 3 s per analysis (30 s under gVisor); the index is a fraction of that.

$ErrorActionPreference = 'Stop'
if ($args.Count -ne 1) { throw 'usage: build_command_index.ps1 <output path>' }

$module = Get-Module -ListAvailable Microsoft.Graph.Authentication | Sort-Object Version -Descending | Select-Object -First 1
$source = Join-Path $module.ModuleBase 'custom/common/MgCommandMetadata.json'
$metadata = Get-Content -Raw -LiteralPath $source | ConvertFrom-Json

$index = @{}
foreach ($entry in $metadata) {
    $item = [ordered]@{ Method = $entry.Method; URI = $entry.Uri; APIVersion = $entry.ApiVersion }
    foreach ($name in @($entry.Command) + @($entry.CommandAlias)) {
        if (-not $name) { continue }
        $key = $name.ToLowerInvariant()
        if (-not $index.ContainsKey($key)) { $index[$key] = [System.Collections.Generic.List[object]]::new() }
        $index[$key].Add($item)
    }
}
if ($index.Count -lt 1000) { throw "the command metadata looks wrong: $($index.Count) commands" }
ConvertTo-Json -InputObject $index -Depth 4 -Compress | Set-Content -LiteralPath $args[0] -Encoding utf8NoBOM
"indexed $($index.Count) command names from $source"
