# Written for the tests (not copied): a URI held in a variable, then
# reassigned to each next link while paging.
$Headers = @{ConsistencyLevel = "Eventual"}
$Uri = "https://graph.microsoft.com/beta/users?`$count=true&`$filter=userType eq 'Member'&`$top=500&`$select=id,displayName"
$Page = Invoke-MgGraphRequest -Uri $Uri -Headers $Headers
while ($null -ne $Page.'@odata.nextLink') {
    $Uri = $Page.'@odata.nextLink'
    $Page = Invoke-MgGraphRequest -Uri $Uri -Headers $Headers
}
"$($Page.value.Count) on the last page"
