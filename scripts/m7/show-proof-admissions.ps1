[CmdletBinding()]
param(
    [string] $ProofStore = '',
    [string] $Binary = '',
    [Alias('N')][string[]] $OnlyN = @(),
    [switch] $Full,
    [switch] $Json
)

$ErrorActionPreference = 'Stop'
$crate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))

function Resolve-CratePath([string] $Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $crate $Path))
}

if ([string]::IsNullOrWhiteSpace($ProofStore)) {
    $ProofStore = Join-Path $crate 'out/m7-proof-store'
} else {
    $ProofStore = Resolve-CratePath $ProofStore
}
if ([string]::IsNullOrWhiteSpace($Binary)) {
    $Binary = Join-Path $crate 'target/release/cubealqot-family.exe'
} else {
    $Binary = Resolve-CratePath $Binary
}

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "cubealqot-family executable not found: $Binary"
}
if (-not (Test-Path -LiteralPath $ProofStore -PathType Container)) {
    throw "Proof store not found: $ProofStore"
}

$checkText = (& $Binary store check --store $ProofStore 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Proof store check failed: $checkText"
}

$listText = (& $Binary store list --store $ProofStore 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Proof store listing failed: $listText"
}
try {
    $listing = $listText | ConvertFrom-Json
} catch {
    throw "Proof store listing was not valid JSON: $($_.Exception.Message)"
}

$entries = @($listing.entries)
if ($OnlyN.Count -gt 0) {
    $entries = @($entries | Where-Object { [string]$_.n -in $OnlyN })
}
$entries = @($entries | Sort-Object { [int64]$_.n })

if ($Json) {
    [ordered]@{
        store_id = [string]$listing.store_id
        store = $ProofStore
        count = $entries.Count
        entries = $entries
    } | ConvertTo-Json -Depth 20
    return
}

Write-Host "Store: $ProofStore"
Write-Host "Store ID: $($listing.store_id)"
Write-Host "Admissions: $($entries.Count)"

if ($Full) {
    $entries |
        Select-Object n,status,proof_kind,completeness,provenance,solution_count,admission_id,certificate_digest |
        Format-List
} else {
    $entries |
        Select-Object n,status,proof_kind,provenance,solution_count |
        Format-Table -AutoSize
}
