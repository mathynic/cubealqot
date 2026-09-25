[CmdletBinding()]
param(
    [ValidateRange(1, 168)][int] $Hours = 24,
    [ValidateRange(1, 604800)][int[]] $TimeoutSeconds = @(),
    [string] $OutputDirectory = '',
    [Alias('N')][string[]] $OnlyN = @(),
    [string] $CandidateFile = '',
    [string] $ProofStore = '',
    [string] $MwPointsDirectory = '',
    [switch] $PlanOnly
)

$ErrorActionPreference = 'Stop'
# Native exit 2 is an expected inconclusive result, not a PowerShell exception.
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$crate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
function Resolve-CratePath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $crate $Path))
}
$candidateFile = if ([string]::IsNullOrWhiteSpace($CandidateFile)) {
    Join-Path $crate 'out/m7-candidate-analysis/recommended-jobs.json'
} else {
    Resolve-CratePath $CandidateFile
}
if (-not (Test-Path -LiteralPath $candidateFile -PathType Leaf)) {
    throw "Candidate file not found: $candidateFile"
}
$jobs = @((Get-Content -LiteralPath $candidateFile -Raw | ConvertFrom-Json).jobs | Sort-Object priority)
if ($OnlyN.Count -gt 0) {
    foreach ($selected in $OnlyN) {
        if ($selected -notin @($jobs | ForEach-Object { [string]$_.N })) {
            throw "N=$selected is not in the recommended candidate list."
        }
    }
    $jobs = @($jobs | Where-Object { [string]$_.N -in $OnlyN })
}
$binary = Join-Path $crate 'target/release/cubealqot-family.exe'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $crate 'out/m7-proof-library'
}
$OutputDirectory = Resolve-CratePath $OutputDirectory
if ([string]::IsNullOrWhiteSpace($ProofStore)) {
    $ProofStore = Join-Path $crate 'out/m7-proof-store'
}
$ProofStore = Resolve-CratePath $ProofStore
$mwPointsRoot = $null
if (-not [string]::IsNullOrWhiteSpace($MwPointsDirectory)) {
    $mwPointsRoot = Resolve-CratePath $MwPointsDirectory
    if (-not (Test-Path -LiteralPath $mwPointsRoot -PathType Container)) {
        throw "Mordell-Weil points directory not found: $mwPointsRoot"
    }
}
$limits = @(60, 300, 800)
if ($TimeoutSeconds.Count -gt 0) {
    $limits = $TimeoutSeconds
    for ($index = 1; $index -lt $limits.Count; $index++) {
        if ($limits[$index] -le $limits[$index - 1]) {
            throw 'TimeoutSeconds must be strictly increasing (no duplicate passes).'
        }
    }
} elseif ($Hours -eq 24) { $limits = @(120, 600, 1600) }
elseif ($Hours -ne 12) { throw 'Specify TimeoutSeconds for a custom Hours budget.' }

Write-Host "Candidates: $(($jobs | ForEach-Object { $_.N }) -join ', ')"
Write-Host "Per-Sage-call limits: $($limits -join ', ') seconds; up to two calls per prove."
Write-Host "Library: $OutputDirectory"
Write-Host "Committed proof store: $ProofStore"
if ($PlanOnly) { return }
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Build first: cargo build --locked --release --bin cubealqot-family'
}
if (-not (Test-Path -LiteralPath $ProofStore -PathType Container)) {
    throw "Committed proof store not found: $ProofStore"
}
$storeCheckText = (& $binary store check --store $ProofStore 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw "Committed proof store check failed: $storeCheckText" }
$storeCheck = $storeCheckText | ConvertFrom-Json
$storeListText = (& $binary store list --store $ProofStore 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw "Committed proof store listing failed: $storeListText" }
$storeList = $storeListText | ConvertFrom-Json
$storeId = [string]$storeList.store_id
if ([string]::IsNullOrWhiteSpace($storeId)) { throw 'Committed proof store did not report a store identity.' }

function Get-CommittedAdmission($artifactPath, $storePath) {
    $text = (& $binary verify $artifactPath --store $storePath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { return $null }
    try { $value = $text | ConvertFrom-Json } catch { return $null }
    if ($value.status -notin @('CERTIFIED_EMPTY', 'CERTIFIED_SOLUTIONS') -or
        [string]$value.verification -cne 'loaded-admission' -or
        [string]::IsNullOrWhiteSpace([string]$value.admission_id)) { return $null }
    return $value
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
$inputs = Join-Path $OutputDirectory 'inputs'
$certificates = Join-Path $OutputDirectory 'certificates'
$receipts = Join-Path $OutputDirectory 'receipts'
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N')
$runDir = Join-Path $OutputDirectory "runs/$runId"
foreach ($directory in @($inputs, $certificates, $receipts, $runDir)) {
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
}
# One active writer per library. The file may remain after interruption; its
# exclusive open handle, not its existence, is the lock.
$lock = [System.IO.File]::Open((Join-Path $OutputDirectory 'campaign.lock'),
    [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite,
    [System.IO.FileShare]::None)
try {
    [System.IO.File]::Copy($candidateFile, (Join-Path $runDir 'candidates.json'))
    $manifest = [ordered]@{
        started_utc = [DateTime]::UtcNow.ToString('o'); hours = $Hours
        per_call_limits_seconds = $limits
        selected_n = @($jobs | ForEach-Object { [string]$_.N })
        executable_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash
        candidates_sha256 = (Get-FileHash -LiteralPath $candidateFile -Algorithm SHA256).Hash
        proof_store = $ProofStore; store_id = $storeId
        mw_points_directory = $mwPointsRoot
    }
    [System.IO.File]::WriteAllText((Join-Path $runDir 'manifest.json'),
        ($manifest | ConvertTo-Json -Depth 10), $utf8)
    $finished = @{}
    foreach ($job in $jobs) {
        $n = [string]$job.N
        if ($n -notmatch '^[1-9][0-9]*$') { throw "Invalid candidate N: $n" }
        $factors = @($job.factors | ForEach-Object {
            [ordered]@{ prime = [string]$_[0]; exponent = [int]$_[1]
                certificate = [ordered]@{ kind = 'u64'; n = [string]$_[0] } }
        })
        $factorText = ConvertTo-Json -InputObject $factors -Depth 10 -Compress
        $factorPath = Join-Path $inputs "N$n.json"
        if (Test-Path -LiteralPath $factorPath) {
            if ([System.IO.File]::ReadAllText($factorPath) -cne $factorText) {
                throw "Existing factors differ for N=$n; use a separate library."
            }
        } else { [System.IO.File]::WriteAllText($factorPath, $factorText, $utf8) }
        $receiptPath = Join-Path $receipts "N$n.json"
        if (Test-Path -LiteralPath $receiptPath) {
            $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
            $artifact = Join-Path $certificates ([string]$receipt.artifact_name)
            if (($receipt.status -in @('CERTIFIED_EMPTY', 'CERTIFIED_SOLUTIONS')) -and
                ([string]$receipt.n -ceq $n) -and
                (Test-Path -LiteralPath $artifact -PathType Leaf) -and
                ((Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash -ceq $receipt.sha256)) {
                $committed = Get-CommittedAdmission $artifact $ProofStore
                if ($null -eq $committed) {
                    throw "Receipt/artifact for N=$n is not a committed admission in $ProofStore; inspect $receiptPath"
                }
                $receiptAdmissionId = [string]$receipt.admission_id
                if (-not [string]::IsNullOrWhiteSpace($receiptAdmissionId) -and
                    $receiptAdmissionId -cne [string]$committed.admission_id) {
                    throw "Receipt admission identity differs from committed admission for N=$n"
                }
                $finished[$n] = $true
                Write-Host "N=${n}: skipping committed admission $($committed.admission_id); no backend replay."
            } else { throw "Invalid resume receipt for N=$n; inspect $receiptPath" }
        }
    }

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($limit in $limits) {
        foreach ($job in $jobs) {
            $n = [string]$job.N
            if ($finished.ContainsKey($n)) { continue }
            $remaining = $Hours * 3600 - $clock.Elapsed.TotalSeconds
            # Reserve for two backend calls and ordinary process overhead.
            $timeout = [int][Math]::Min($limit, [Math]::Floor(($remaining - 60) / 2))
            if ($timeout -lt 1) {
                Write-Host 'Campaign time budget reached; no new jobs will start.'
                return
            }
            $tag = "N$n-limit$limit-$runId"
            $outputPath = Join-Path $certificates "$tag.json"
            $stdoutPath = Join-Path $runDir "$tag.stdout.json"
            $stderrPath = Join-Path $runDir "$tag.stderr.log"
            Write-Host "$(Get-Date -Format o) N=$n, limit=$timeout seconds per Sage call"
            $ErrorActionPreference = 'Continue'
            $proveArgs = @(
                'prove', '--n', $n, '--factors', (Join-Path $inputs "N$n.json"),
                '--backend', 'sage', '--timeout-seconds', $timeout,
                '--store', $ProofStore, '--output', $outputPath
            )
            if ($null -ne $mwPointsRoot) {
                $candidatePoints = Join-Path $mwPointsRoot "N$n.json"
                if (Test-Path -LiteralPath $candidatePoints -PathType Leaf) {
                    $proveArgs += @('--mw-points', $candidatePoints)
                }
            }
            try {
                & $binary @proveArgs 1> $stdoutPath 2> $stderrPath
                $code = $LASTEXITCODE
            } finally { $ErrorActionPreference = 'Stop' }
            $response = Get-Content -LiteralPath $stdoutPath -Raw | ConvertFrom-Json
            $record = [ordered]@{
                time_utc = [DateTime]::UtcNow.ToString('o'); n = $n
                timeout_seconds = $timeout; exit_code = $code
                result = $response; stdout = $stdoutPath; stderr = $stderrPath
            }
            [System.IO.File]::AppendAllText((Join-Path $runDir 'results.jsonl'),
                (($record | ConvertTo-Json -Depth 20 -Compress) + "`n"), $utf8)
            Write-Host "N=${n}: exit=$code status=$($response.status)"
            if ($code -eq 0 -and $response.status -in @('CERTIFIED_EMPTY', 'CERTIFIED_SOLUTIONS')) {
                if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
                    throw "CLI reported success without artifact for N=$n"
                }
                $receipt = [ordered]@{
                    n = $n; status = $response.status
                    artifact_name = [System.IO.Path]::GetFileName($outputPath)
                    sha256 = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
                    run_id = $runId; admission_id = [string]$response.admission_id
                    store_id = $storeId; store_root = $ProofStore
                }
                $committed = Get-CommittedAdmission $outputPath $ProofStore
                if ($null -eq $committed -or [string]$committed.admission_id -cne [string]$response.admission_id) {
                    throw "CLI success for N=$n was not committed and reloadable from $ProofStore"
                }
                [System.IO.File]::WriteAllText((Join-Path $receipts "N$n.json"),
                    ($receipt | ConvertTo-Json -Compress), $utf8)
                $finished[$n] = $true
            } elseif ($code -eq 2 -and $response.status -eq 'INCONCLUSIVE') {
                # Retain evidence and retry only in a later, larger-budget pass.
            } else {
                throw "Unexpected failure for N=$n; inspect $stdoutPath and $stderrPath"
            }
        }
    }
    Write-Host "Campaign finished: $($finished.Count)/$($jobs.Count) recorded certified results."
    Write-Host 'Remaining families are inconclusive. Retain certificates and m7-adapter-evidence.'
} finally {
    $lock.Dispose()
}
