# Policy attempts for the full-stack suite (Part B, M6). Written for the
# tests. It runs under an approval of one read only (GET /v1.0/users, id and
# displayName) and asks the facade for things that approval does not allow.
# Each attempt prints one line: ATTEMPT <name> <allowed|refused> <detail>.

function Test-Attempt([string] $Name, [scriptblock] $Action) {
    try {
        $out = "$(& $Action)" -replace '\s+', ' '
        "ATTEMPT $Name allowed $($out.Substring(0, [Math]::Min(120, $out.Length)))"
    } catch {
        $detail = "$($_.Exception.Message)" -replace '\s+', ' '
        "ATTEMPT $Name refused $($detail.Substring(0, [Math]::Min(120, $detail.Length)))"
    }
}

$user = '11111111-0000-0000-0000-000000000001'

# The control: the one approved read.
Test-Attempt 'control-read' {
    $script:first = Invoke-MgGraphRequest -Uri '/v1.0/users?$select=id,displayName' -ErrorAction Stop
    "$($script:first.value.Count) users"
}

# Writes: by cmdlet and by request.
Test-Attempt 'write-update-cmdlet' { Update-MgUser -UserId $user -AccountEnabled:$false -ErrorAction Stop }
Test-Attempt 'write-remove-cmdlet' { Remove-MgUser -UserId $user -ErrorAction Stop }
Test-Attempt 'write-post' { Invoke-MgGraphRequest -Method POST -Uri '/v1.0/users' -Body '{}' -ContentType 'application/json' -ErrorAction Stop }
Test-Attempt 'write-patch' { Invoke-MgGraphRequest -Method PATCH -Uri "/v1.0/users/$user" -Body '{"accountEnabled":false}' -ContentType 'application/json' -ErrorAction Stop }
Test-Attempt 'write-delete' { Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/users/$user" -ErrorAction Stop }
Test-Attempt 'write-batch' {
    $body = @{ requests = @(@{ id = '1'; method = 'GET'; url = '/users' },
                            @{ id = '2'; method = 'PATCH'; url = "/users/$user"; body = @{ accountEnabled = $false };
                               headers = @{ 'Content-Type' = 'application/json' } }) } | ConvertTo-Json -Depth 5
    Invoke-MgGraphRequest -Method POST -Uri '/v1.0/$batch' -Body $body -ContentType 'application/json' -ErrorAction Stop
}

# Reads the approval does not cover.
Test-Attempt 'read-other-path' { Invoke-MgGraphRequest -Uri '/v1.0/groups' -ErrorAction Stop }
Test-Attempt 'read-other-property' { Invoke-MgGraphRequest -Uri '/v1.0/users?$select=id,mail' -ErrorAction Stop }
Test-Attempt 'read-beta' { Invoke-MgGraphRequest -Uri '/beta/users?$select=id' -ErrorAction Stop }
Test-Attempt 'read-expand' { Invoke-MgGraphRequest -Uri '/v1.0/users?$select=id&$expand=memberOf' -ErrorAction Stop }
Test-Attempt 'read-me' { Invoke-MgGraphRequest -Uri '/v1.0/me' -ErrorAction Stop }
Test-Attempt 'read-unknown-parameter' { Invoke-MgGraphRequest -Uri '/v1.0/users?$select=id&debug=1' -ErrorAction Stop }

# URL tricks.
Test-Attempt 'path-encoded-slash' { Invoke-MgGraphRequest -Uri '/v1.0/users%2F..%2Fgroups' -ErrorAction Stop }
Test-Attempt 'path-double-slash' { Invoke-MgGraphRequest -Uri '/v1.0//groups' -ErrorAction Stop }

# Paging: the script only ever sees single-use handles for the broker-held next
# link. A handle is used up when presented, even if the request is then refused.
$next = $script:first.'@odata.nextLink'
Test-Attempt 'page-altered-handle' { Invoke-MgGraphRequest -Uri ($next.Substring(0, $next.Length - 2) + 'zz') -ErrorAction Stop }
Test-Attempt 'page-made-up-handle' { Invoke-MgGraphRequest -Uri ('https://graph.microsoft.com/v1.0/users?$skiptoken=clw_' + ('A' * 43)) -ErrorAction Stop }
Test-Attempt 'page-valid-handle' {
    $script:second = Invoke-MgGraphRequest -Uri $next -ErrorAction Stop
    "$($script:second.value.Count) users"
}
Test-Attempt 'page-handle-reused' { Invoke-MgGraphRequest -Uri $next -ErrorAction Stop }
$next2 = $script:second.'@odata.nextLink'
Test-Attempt 'page-handle-other-path' { Invoke-MgGraphRequest -Uri ($next2 -replace '/v1.0/users', '/v1.0/groups') -ErrorAction Stop }
Test-Attempt 'page-misused-handle-is-gone' { Invoke-MgGraphRequest -Uri $next2 -ErrorAction Stop }
