[CmdletBinding()]
param(
    [switch] $RunDisposableSmoke,
    [switch] $AllowNativeCampaign
)

$ErrorActionPreference = 'Stop'
$crate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$previousHelperSha256 = '10e4e2761c96ec97ae388d28ee30b56322104ec1d26e895658b49b7c58198b25'
$expectedHelperSha256 = '88196fd1f3a90b1bbad9a6a5a6a0c46ce8d8b0fa1d99fdff31727c3923f56c9a'
$qualifiedHelper = Join-Path $crate 'out/m7-pari-qualification/pq01-work/helper/sage_integral_points.py'
$productionHelper = Join-Path $crate 'scripts/m7/sage_integral_points.py'
$cutoverRoot = Join-Path $crate 'out/m7-pari-qualification/pq04-cutover-20260921'
$priorPreparationArchive = Join-Path $cutoverRoot 'pre-cutover-sage_integral_points.py'
$archiveHelper = Join-Path $cutoverRoot 'pre-cutover-sage_integral_points-pq04-current.py'
$binary = Join-Path $crate 'target/release/cubealqot-family.exe'

function Hash([string] $path) {
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

if (-not (Test-Path -LiteralPath $qualifiedHelper -PathType Leaf)) {
    throw "Qualified PQ-01 helper is missing: $qualifiedHelper"
}
if ((Hash $qualifiedHelper) -cne $expectedHelperSha256) {
    throw 'Qualified helper digest differs from the PQ-02 manifest.'
}

$active = @(Get-CimInstance Win32_Process | Where-Object {
    $_.Name -in @('cubealqot.exe', 'cubealqot-family.exe', 'cargo.exe', 'rustup.exe') -and
    ($_.Name -in @('cubealqot.exe', 'cubealqot-family.exe') -or
        [string]$_.CommandLine -match 'cubealqot.*--start|cubealqot.*invoke-sage|sage_integral_points')
})
$nativeCampaign = @($active | Where-Object {
    $_.Name -eq 'cubealqot.exe' -and
    [string]$_.CommandLine -match 'cubealqot\.exe.*--start' -and
    [string]$_.CommandLine -notmatch 'invoke-sage|sage_integral_points'
})
$blocking = @($active | Where-Object {
    $_.ProcessId -notin @($nativeCampaign | ForEach-Object ProcessId)
})
if ($blocking.Count -gt 0 -or ($nativeCampaign.Count -gt 0 -and -not $AllowNativeCampaign)) {
    $details = $active | ForEach-Object { "$($_.Name) PID=$($_.ProcessId): $($_.CommandLine)" }
    throw "PQ-04 cutover refused without an explicit native-campaign handoff:`n$($details -join "`n")"
}
if ($nativeCampaign.Count -gt 0) {
    Write-Warning 'Native cubealqot campaign remains active. Its loaded snapshot/output are untouched; use a separate proof store until it exits.'
}

New-Item -ItemType Directory -Force -Path $cutoverRoot | Out-Null
if (Test-Path -LiteralPath $archiveHelper -PathType Leaf) {
    if ((Hash $archiveHelper) -cne $previousHelperSha256) {
        throw "Existing cutover archive does not match the recorded pre-cutover helper: $archiveHelper"
    }
    if ((Hash $productionHelper) -cne $previousHelperSha256 -and
        (Hash $productionHelper) -cne $expectedHelperSha256) {
        throw "Production helper is neither the recorded pre-cutover build nor the qualified build."
    }
} else {
    if ((Hash $productionHelper) -cne $previousHelperSha256) {
        throw 'Production helper is not the expected pre-cutover build.'
    }
    Copy-Item -LiteralPath $productionHelper -Destination $archiveHelper
}
if ((Hash $productionHelper) -cne $expectedHelperSha256) {
    Copy-Item -LiteralPath $qualifiedHelper -Destination $productionHelper -Force
}
if ((Hash $productionHelper) -cne $expectedHelperSha256) {
    throw 'Production helper digest did not match the qualified PQ-02 helper after replacement.'
}

Push-Location $crate
try {
    & cargo build --locked --release --bin cubealqot-family
    if ($LASTEXITCODE -ne 0) { throw 'Release cubealqot-family build failed.' }
    $doctorText = & $binary doctor --backend sage 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Qualified production doctor failed: $doctorText" }
    $doctor = $doctorText | ConvertFrom-Json
    if ($doctor.backend -cne 'CONFIGURED') {
        throw "Qualified production doctor did not report CONFIGURED: $doctorText"
    }
} finally {
    Pop-Location
}

$record = [ordered]@{
    status = 'CUTOVER_COMPLETE'
    utc = [DateTime]::UtcNow.ToString('o')
    helper_sha256 = Hash $productionHelper
    qualified_helper_sha256 = $expectedHelperSha256
    archived_previous_helper = $archiveHelper
    prior_preparation_archive = if (Test-Path -LiteralPath $priorPreparationArchive -PathType Leaf) { $priorPreparationArchive } else { $null }
    executable = $binary
    executable_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
    target_file = (Join-Path $crate 'out/m7-pari-qualification/pq04-targets-20260921.json')
}
$record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $cutoverRoot 'cutover.json') -Encoding utf8
$record | ConvertTo-Json -Depth 10

if ($RunDisposableSmoke) {
    $smokeOutput = Join-Path $cutoverRoot 'disposable-smoke-library'
    $smokeStore = Join-Path $cutoverRoot 'disposable-smoke-store'
    if (-not (Test-Path -LiteralPath $smokeStore -PathType Container)) {
        $sourceStore = Join-Path $crate 'out/m7-proof-store'
        if (-not (Test-Path -LiteralPath $sourceStore -PathType Container)) {
            throw "Cannot seed the disposable smoke store: $sourceStore is missing."
        }
        Copy-Item -LiteralPath $sourceStore -Destination $smokeStore -Recurse
    }
    & (Join-Path $crate 'scripts/m7/run-candidate-campaign.ps1') `
        -Hours 2 -TimeoutSeconds 180 `
        -CandidateFile (Join-Path $crate 'out/m7-pari-qualification/pq04-targets-20260921.json') `
        -OnlyN 11 `
        -OutputDirectory $smokeOutput `
        -ProofStore $smokeStore
    if ($LASTEXITCODE -ne 0) { throw 'Disposable PQ-04 smoke campaign failed.' }
}

Write-Host ''
Write-Host 'Persistent target command (run only after this cutover succeeds):'
Write-Host (Join-Path $crate 'scripts/m7/run-candidate-campaign.ps1')
Write-Host "  -Hours 24 -TimeoutSeconds 3600 -CandidateFile `"$(Join-Path $crate 'out/m7-pari-qualification/pq04-targets-20260921.json')`" -OutputDirectory `"$(Join-Path $crate 'out/m7-proof-library-pq04-20260921')`" -ProofStore `"$(Join-Path $crate 'out/m7-proof-store')`""
