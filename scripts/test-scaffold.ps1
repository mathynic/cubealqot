$ErrorActionPreference = 'Stop'

$crate = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Push-Location $crate
try {
    cargo test --all-targets
    if ($LASTEXITCODE -ne 0) {
        throw "cargo test failed"
    }

    & cargo test --test scaffold deliberate_failure_proves_scaffold_is_live -- --ignored
    if ($LASTEXITCODE -eq 0) {
        throw "the deliberate failure test unexpectedly passed"
    }

    Write-Host 'Scaffold checks passed: normal suite is green and the failure sentinel was detected.'
    exit 0
}
finally {
    Pop-Location
}
