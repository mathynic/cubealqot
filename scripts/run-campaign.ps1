[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [UInt64]$Start,

    [Parameter(Mandatory = $true)]
    [UInt64]$End,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 1024)]
    [Int]$Threads,

    [UInt64]$CheckpointEvery = 1000000000,

    [string]$OutputPath = '',

    [string]$CheckpointPath = '',

    [switch]$UseFamilyMap
)

$ErrorActionPreference = 'Stop'

if ($Start -lt 2) {
    throw 'Start must be at least 2.'
}
if ($End -lt $Start) {
    throw 'End must not precede Start.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $repoRoot 'out'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

function Resolve-RepoPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

$familyStorePath = Join-Path $outDir 'm7-proof-store'
$familySnapshotPath = $null
if ($UseFamilyMap) {
    if (-not (Test-Path -LiteralPath $familyStorePath -PathType Container)) {
        throw "Family store not found: $familyStorePath"
    }

    $familySnapshotPath = Get-ChildItem -LiteralPath $outDir -Filter 'm7-proof-snapshot*.json' -File |
        Sort-Object LastWriteTimeUtc, Name |
        Select-Object -Last 1 -ExpandProperty FullName
    if ([string]::IsNullOrWhiteSpace($familySnapshotPath)) {
        throw "No theorem snapshot found in: $outDir"
    }
}

$invariant = [Globalization.CultureInfo]::InvariantCulture
$startText = $Start.ToString($invariant)
$endText = $End.ToString($invariant)
$outputName = if ($UseFamilyMap) {
    "survivors-$startText-$endText-t$Threads-family.jsonl"
} else {
    "survivors-$startText-$endText-t$Threads.jsonl"
}
$checkpointName = if ($UseFamilyMap) {
    "run-$startText-$endText-t$Threads-family.checkpoint.json"
} else {
    "run-$startText-$endText-t$Threads.checkpoint.json"
}
$outputPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    Join-Path $outDir $outputName
} else {
    Resolve-RepoPath $OutputPath
}
$checkpointPath = if ([string]::IsNullOrWhiteSpace($CheckpointPath)) {
    Join-Path $outDir $checkpointName
} else {
    Resolve-RepoPath $CheckpointPath
}

$familyEnabled = $UseFamilyMap

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($null -eq $cargo) {
    $cargoPath = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (-not (Test-Path -LiteralPath $cargoPath)) {
        throw 'cargo was not found on PATH or in the default Rust installation directory.'
    }
} else {
    $cargoPath = $cargo.Source
}

$arguments = @(
    'run', '--release', '--', 'run',
    '--start', $startText,
    '--end', $endText,
    '--threads', $Threads.ToString($invariant),
    '--output', $outputPath,
    '--checkpoint', $checkpointPath,
    '--checkpoint-every', $CheckpointEvery.ToString($invariant),
    '--dump-beyond', 'F8'
)

if ($familyEnabled) {
    $arguments += '--family-store', $familyStorePath
    $arguments += '--family-snapshot', $familySnapshotPath
}

if (Test-Path -LiteralPath $checkpointPath) {
    if ($familyEnabled) {
        $checkpointHead = @(Get-Content -LiteralPath $checkpointPath -TotalCount 20)
        if (-not ($checkpointHead -match '"schema_version"\s*:\s*3')) {
            throw "Existing checkpoint is a legacy no-map checkpoint; choose new OutputPath/CheckpointPath for a map-enabled run: $checkpointPath"
        }
    }
    $arguments += '--resume'
    Write-Host "Resuming campaign $startText..$endText with $Threads thread(s)."
} else {
    Write-Host "Starting campaign $startText..$endText with $Threads thread(s)."
}

Write-Host "Output:     $outputPath"
Write-Host "Checkpoint: $checkpointPath"
Write-Host "Checkpoint every: $CheckpointEvery candidates"
if ($familyEnabled) {
    Write-Host "Family store:    $familyStorePath"
    Write-Host "Family snapshot: $familySnapshotPath"
} else {
    Write-Host 'Family map:       disabled (legacy no-map path)'
}
& $cargoPath @arguments
exit $LASTEXITCODE
