[CmdletBinding()]
param(
# The requested [1, 20_000_000_000] interval is represented by q=2 onward:
# q=1 is not a prime candidate and the native engine deliberately rejects it.
    [UInt64] $Start = 2,
    [UInt64] $End = 20000000000,
    [ValidateRange(1,128)][int] $Threads = 4,
    [ValidateRange(1,100000000)][int] $ChunkSize = 1000000,
    [ValidateRange(1,604800)][int] $AdmissionTimeoutSeconds = 7200,
    [string] $ProofStore = '',
    [string] $Snapshot = '',
    [string] $ResumeDirectory = '',
    [switch] $SmokeTest
)
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) { $PSNativeCommandUseErrorActionPreference = $false }
$crate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$prepare = Join-Path $PSScriptRoot 'prepare-placement-benchmark.py'
if ($ResumeDirectory) {
    $runDirectory = (Resolve-Path -LiteralPath $ResumeDirectory).Path
    Write-Host 'Resume uses the frozen range, threads, store snapshot and binary; other arguments are ignored.'
    & python $prepare $runDirectory --verify
    if ($LASTEXITCODE -ne 0) { throw 'Resume identity validation failed' }
} else {
    if ($SmokeTest) { $Start = 10000000000; $End = 10000019999; $ChunkSize = 5000; $Threads = 2 }
    if (-not $SmokeTest) {
        if ([string]::IsNullOrWhiteSpace($ProofStore) -or [string]::IsNullOrWhiteSpace($Snapshot)) {
            throw 'Non-smoke placement benchmarks require -ProofStore and -Snapshot.'
        }
        if (-not (Test-Path -LiteralPath $ProofStore -PathType Container)) { throw "Proof store not found: $ProofStore" }
        if (-not (Test-Path -LiteralPath $Snapshot -PathType Leaf)) { throw "Theorem snapshot not found: $Snapshot" }
    }
    $runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N')
    $runDirectory = Join-Path $crate "out/m7-placement-bench/$runId"
    $prepareArgs = @($prepare, $runDirectory, '--start', "$Start", '--end', "$End", '--threads', "$Threads", '--chunk-size', "$ChunkSize", '--timeout', "$AdmissionTimeoutSeconds")
    if (-not $SmokeTest) { $prepareArgs += @('--store', (Resolve-Path -LiteralPath $ProofStore).Path, '--snapshot', (Resolve-Path -LiteralPath $Snapshot).Path) }
    if ($SmokeTest) { $prepareArgs += '--smoke' }
    & python @prepareArgs
    if ($LASTEXITCODE -ne 0) { throw 'Benchmark preparation failed' }
    & cargo build --locked --release --manifest-path (Join-Path $runDirectory 'build/Cargo.toml') --target-dir (Join-Path $runDirectory 'build/target') --bin family-placement-bench
    if ($LASTEXITCODE -ne 0) { throw 'Benchmark build failed' }
    & python $prepare $runDirectory --seal
    if ($LASTEXITCODE -ne 0) { throw 'Could not seal benchmark identity' }
}
Write-Host "RESULT DIRECTORY: $runDirectory"
Write-Host 'Native range timing begins after one offline committed-store load and bounded warmup.'
Write-Host 'On interruption, rerun with -ResumeDirectory pointing to this directory.'
$lock = [System.IO.File]::Open((Join-Path $runDirectory 'benchmark.lock'), [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try {
    & (Join-Path $runDirectory 'build/target/release/family-placement-bench.exe') $runDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Benchmark failed or interrupted; inspect retained evidence before resuming' }
} finally { $lock.Dispose() }
