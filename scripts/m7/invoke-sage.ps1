[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $RequestFile,

    [string] $HelperFile = '',
    [string] $Distribution = 'Ubuntu-26.04',
    [string] $CondaExecutable = '',
    [string] $Environment = 'cubealqot-m7'
)

$ErrorActionPreference = 'Stop'
$crate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localConfig = Join-Path $PSScriptRoot 'local-config.ps1'
. $localConfig
if ([string]::IsNullOrWhiteSpace($CondaExecutable)) {
    $CondaExecutable = Get-M7CondaExecutable -CrateRoot $crate
}

if ([string]::IsNullOrWhiteSpace($HelperFile)) {
    $HelperFile = Join-Path $PSScriptRoot 'sage_smoke.py'
}

function Convert-WindowsPathToWsl {
    param([Parameter(Mandatory = $true)][string] $WindowsPath)

    $converted = & wsl.exe --distribution $Distribution --exec wslpath -a -u -- $WindowsPath
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($converted -join ''))) {
        throw "Could not convert Windows path to WSL path: $WindowsPath"
    }
    return ($converted -join "`n").Trim()
}

if (-not (Test-Path -LiteralPath $RequestFile -PathType Leaf)) {
    throw "Request file does not exist: $RequestFile"
}

if (-not (Test-Path -LiteralPath $HelperFile -PathType Leaf)) {
    throw "Sage helper is missing: $HelperFile"
}

$requestJson = Get-Content -LiteralPath $RequestFile -Raw
try {
    $null = $requestJson | ConvertFrom-Json
}
catch {
    throw "Request file is not valid JSON: $RequestFile"
}

$helperWslPath = Convert-WindowsPathToWsl -WindowsPath (Resolve-Path -LiteralPath $HelperFile).Path
$requestWslPath = Convert-WindowsPathToWsl -WindowsPath (Resolve-Path -LiteralPath $RequestFile).Path

$wslArguments = @(
    '--distribution', $Distribution,
    '--exec', $CondaExecutable,
    'run', '--no-capture-output', '--name', $Environment,
    'python', $helperWslPath, $requestWslPath
)

$responseLines = @(& wsl.exe @wslArguments)
if ($LASTEXITCODE -ne 0) {
    throw "Sage invocation failed with exit code $LASTEXITCODE (distribution=$Distribution, environment=$Environment, conda=$CondaExecutable)"
}

$responseText = ($responseLines -join "`n").Trim()
if ([string]::IsNullOrWhiteSpace($responseText)) {
    throw 'Sage invocation returned an empty response'
}

try {
    $response = $responseText | ConvertFrom-Json
}
catch {
    throw "Sage invocation returned invalid JSON: $responseText"
}

if ($null -eq $response.ok -or -not [bool]$response.ok) {
    throw "Sage invocation returned a non-success response: $responseText"
}

$response | ConvertTo-Json -Depth 20 -Compress
