[CmdletBinding()]
param(
    [string] $RequestFile,
    [string] $HelperFile,
    [string] $Distribution,
    [string] $CondaExecutable,
    [string] $Environment
)

$response = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'adapter_complete_response.json') -Raw | ConvertFrom-Json
$request = Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$response.request_id = $request.request_id
$response | ConvertTo-Json -Depth 20 -Compress
