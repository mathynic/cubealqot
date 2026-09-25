$ErrorActionPreference = 'Stop'

$crate = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$report = Join-Path $crate 'profile-baseline.json'

Push-Location $crate
try {
    cargo bench --bench baseline
    if ($LASTEXITCODE -ne 0) {
        throw 'Criterion baseline benchmark failed'
    }

    cargo run --quiet -- profile --start 2 --end 10000 --threads 1 --output $report
    if ($LASTEXITCODE -ne 0) {
        throw 'stage profiler failed'
    }

    Write-Host "Profiler report written to $report"
}
finally {
    Pop-Location
}
