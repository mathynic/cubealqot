$ErrorActionPreference = 'Stop'

$crate = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

Push-Location $crate
try {
    python scripts\oracle.py --self-test
    if ($LASTEXITCODE -ne 0) {
        throw "Python oracle self-test failed"
    }

    cargo run --locked --quiet -- validate --max 1005
    if ($LASTEXITCODE -ne 0) {
        throw "Rust/Python differential validation failed"
    }

    Write-Host 'Differential validation passed.'
    exit 0
}
finally {
    Pop-Location
}
