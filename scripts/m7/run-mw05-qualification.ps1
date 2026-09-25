[CmdletBinding()]
param(
    [ValidateRange(1, 168)][int] $Hours = 72,
    [ValidateRange(1, 604800)][int] $DiscoveryBudgetSeconds = 3600,
    [ValidateRange(1, 604800)][int] $DiscoveryAttemptTimeoutSeconds = 120,
    [ValidateRange(1, 604800)][int] $ProofTimeoutSeconds = 3600,
    [string] $CandidateFile = '',
    [string] $RankedCofactorsFile = '',
    [string] $Binary = '',
    [string] $OutputDirectory = '',
    [string] $ProofStore = '',
    [string[]] $OnlyN = @(),
    [switch] $DiscoveryOnly,
    [switch] $PlanOnly
)

$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$crate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $PSScriptRoot 'local-config.ps1')
$condaExecutable = Get-M7CondaExecutable -CrateRoot $crate
function Resolve-CratePath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $crate $Path))
}
function Write-AtomicJson([string]$Path, $Value) {
    $parent = Split-Path -Parent $Path
    [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $backup = "$temporary.bak"
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    try {
        [System.IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 30), $utf8)
        if ([System.IO.File]::Exists($Path)) {
            [System.IO.File]::Replace($temporary, $Path, $backup, $true)
        } else {
            [System.IO.File]::Move($temporary, $Path)
        }
    } finally {
        if ([System.IO.File]::Exists($temporary)) {
            [System.IO.File]::Delete($temporary)
        }
        if ([System.IO.File]::Exists($backup)) {
            [System.IO.File]::Delete($backup)
        }
    }
}
function Convert-WindowsPathToWsl([string]$Path) {
    $value = & wsl.exe --distribution Ubuntu-26.04 --exec wslpath -a -u -- $Path
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($value -join ''))) {
        throw "Could not convert path to WSL: $Path"
    }
    return ($value -join "`n").Trim()
}
function Read-JsonFile([string]$Path) {
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
function Get-Hash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Read-DiscoverySummary([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return Read-JsonFile $Path } catch { return $null }
}
function Read-JsonLines([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    $records = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $records += ($line | ConvertFrom-Json) } catch { }
    }
    return $records
}
function Test-MeaningfulValue($Value) {
    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace($Value) }
    $items = @($Value)
    if ($items.Count -eq 0) { return $false }
    if ($items -is [array] -and ($items | Where-Object {
        $_ -is [string] -and [string]::IsNullOrWhiteSpace($_)
    }).Count -eq $items.Count) { return $false }
    return $true
}
function Get-ComparableJson($Value) {
    if (-not (Test-MeaningfulValue $Value)) { return $null }
    return ($Value | ConvertTo-Json -Depth 20 -Compress)
}
function Test-CompleteCandidateJob($Job) {
    if ($null -eq $Job) { return $false }
    if (-not (Test-MeaningfulValue $Job.A) -or
        -not (Test-MeaningfulValue $Job.D) -or
        -not (Test-MeaningfulValue $Job.factors)) { return $false }
    $coefficients = @($Job.curve_coefficients)
    if ($coefficients.Count -ne 5) { return $false }
    return ($coefficients | Where-Object { -not (Test-MeaningfulValue $_) }).Count -eq 0
}
function Assert-CompatibleCandidateFields($Primary, $Fallback, [string]$N) {
    foreach ($field in @('factors','A','D','curve_coefficients')) {
        $primaryValue = Get-ComparableJson $Primary.$field
        $fallbackValue = Get-ComparableJson $Fallback.$field
        if ($null -ne $primaryValue -and $null -ne $fallbackValue -and
            $primaryValue -cne $fallbackValue) {
            throw "Candidate and ranked fallback disagree for N=$N field=$field"
        }
    }
}

$candidatePath = if ([string]::IsNullOrWhiteSpace($CandidateFile)) {
    Join-Path $crate 'out/m7-candidate-analysis/candidate-jobs.json'
} else { Resolve-CratePath $CandidateFile }
if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
    throw "Candidate file not found: $candidatePath"
}

$outputRoot = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $crate 'out/mw-05-qualification'
} else { Resolve-CratePath $OutputDirectory }
$storeRoot = if ([string]::IsNullOrWhiteSpace($ProofStore)) {
    Join-Path $outputRoot 'proof-store'
} else { Resolve-CratePath $ProofStore }
$binary = if ([string]::IsNullOrWhiteSpace($Binary)) {
    Join-Path $crate 'target-mw05-release/release/cubealqot-family.exe'
} else { Resolve-CratePath $Binary }
$driver = Join-Path $crate 'scripts/m7/discover_mw_points.py'
$discoveryScheduleVersion = 'mw03-discovery-v2'
$candidate = Read-JsonFile $candidatePath
$rankedPath = if ([string]::IsNullOrWhiteSpace($RankedCofactorsFile)) {
    Join-Path $crate 'out/m7-candidate-analysis/ranked-cofactors.json'
} else { Resolve-CratePath $RankedCofactorsFile }

$missingPointNs = @('27','29','65','73','93','104','123','133','147','171','213','301','387','939','1159')
$missingRankTwoNs = @('51','80','98','135','169')
$rankGapControlNs = @('39','115','117')
$defaultNs = @($missingPointNs + $missingRankTwoNs + $rankGapControlNs)
$requestedNs = if ($OnlyN.Count -gt 0) { @($OnlyN | ForEach-Object { [string]$_ }) } else { $defaultNs }
$candidateJobs = @($candidate.jobs)
$fallbackNeeded = @($requestedNs | Where-Object {
    $n = [string]$_
    $primary = @($candidateJobs | Where-Object { [string]$_.N -eq $n })[0]
    $null -eq $primary -or -not (Test-CompleteCandidateJob $primary)
})
$rankedHash = $null
if ($fallbackNeeded.Count -gt 0) {
    if (-not (Test-Path -LiteralPath $rankedPath -PathType Leaf)) {
        throw "Ranked cofactor fallback is missing: $rankedPath"
    }
    $ranked = Read-JsonFile $rankedPath
    $rankedHash = Get-Hash $rankedPath
}
$rankedJobs = if ($null -ne $ranked) { @($ranked.cofactors) } else { @() }
$jobs = @($requestedNs | ForEach-Object {
    $n = [string]$_
    $primary = @($candidateJobs | Where-Object { [string]$_.N -eq $n })[0]
    $fallback = @($rankedJobs | Where-Object { [string]$_.N -eq $n })[0]
    if ($null -ne $primary -and $null -ne $fallback) {
        Assert-CompatibleCandidateFields $primary $fallback $n
    }
    if (Test-CompleteCandidateJob $primary) {
        $primary
    } elseif (Test-CompleteCandidateJob $fallback) {
        $fallback
    } else {
        throw "No complete candidate job is available for N=$n"
    }
})

Write-Host "MW-05 qualification candidates: $(($jobs | ForEach-Object { $_.N }) -join ', ')"
Write-Host "Discovery budget: $DiscoveryBudgetSeconds seconds per N; attempt timeout: $DiscoveryAttemptTimeoutSeconds seconds"
Write-Host "Proof timeout: $ProofTimeoutSeconds seconds per Sage call; overall budget: $Hours hours"
Write-Host "Qualification output: $outputRoot"
Write-Host "Disposable proof store: $storeRoot"
if ($DiscoveryOnly) { Write-Host 'Mode: discovery only (no theorem proof is attempted)' }

if ($PlanOnly) { return }
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Build first: cargo build --locked --release --bin cubealqot-family'
}
if (-not (Test-Path -LiteralPath $driver -PathType Leaf)) {
    throw "Discovery driver is missing: $driver"
}
$legacyHelper = Join-Path $crate 'scripts/m7/sage_integral_points.py'
$mw04Helper = Join-Path $crate 'scripts/m7/sage_integral_points_mw04.py'
$mw02Helper = Join-Path $crate 'scripts/m7/mw02_rank_basis.py'
if (-not (Test-Path -LiteralPath $legacyHelper -PathType Leaf) -or
    -not (Test-Path -LiteralPath $mw04Helper -PathType Leaf)) {
    throw 'One or more approved Sage helper files are missing.'
}

$directories = @(
    $outputRoot,
    (Join-Path $outputRoot 'requests'),
    (Join-Path $outputRoot 'points'),
    (Join-Path $outputRoot 'journals'),
    (Join-Path $outputRoot 'logs'),
    (Join-Path $outputRoot 'proofs'),
    (Join-Path $outputRoot 'results'),
    (Join-Path $outputRoot 'state')
)
foreach ($directory in $directories) { [System.IO.Directory]::CreateDirectory($directory) | Out-Null }
[System.IO.Directory]::CreateDirectory($storeRoot) | Out-Null

$lockPath = Join-Path $outputRoot 'campaign.lock'
$lock = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate,
    [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
try {
    $manifestPath = Join-Path $outputRoot 'manifest.json'
    $manifestValue = [ordered]@{
        schema_version = 2
        campaign = 'MW-05'
        started_utc = [DateTime]::UtcNow.ToString('o')
        candidate_file = $candidatePath
        candidate_file_sha256 = Get-Hash $candidatePath
        ranked_cofactors_file = $rankedPath
        ranked_cofactors_file_sha256 = $rankedHash
        selected_n = $requestedNs
        missing_rank_one_n = $missingPointNs
        missing_rank_two_n = $missingRankTwoNs
        rank_gap_controls = $rankGapControlNs
        discovery_budget_seconds = $DiscoveryBudgetSeconds
        discovery_attempt_timeout_seconds = $DiscoveryAttemptTimeoutSeconds
        proof_timeout_seconds = $ProofTimeoutSeconds
        overall_hours = $Hours
        discovery_only = [bool]$DiscoveryOnly
        executable_sha256 = Get-Hash $binary
        helper_identities = [ordered]@{
            no_hint_sha256 = Get-Hash $legacyHelper
            mw04_hint_sha256 = Get-Hash $mw04Helper
            mw04_base_sha256 = Get-Hash $legacyHelper
            mw04_mw02_sha256 = Get-Hash $mw02Helper
            distribution = 'Ubuntu-26.04'
            environment = 'cubealqot-m7'
            sage_version = '10.8'
        }
        proof_store = $storeRoot
        theorem_policy = 'Qualification output only; no canonical M7 production-store publication.'
    }
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $old = Read-JsonFile $manifestPath
        # discovery_only is an execution-mode selector, not a mathematical
        # premise or environment identity.  Allow a discovery-only resume of
        # a prior full run (and the reverse) while keeping all inputs,
        # budgets, executable, helper identities and store fixed.
        foreach ($name in @('candidate_file_sha256','ranked_cofactors_file_sha256','selected_n','discovery_budget_seconds','discovery_attempt_timeout_seconds','proof_timeout_seconds','executable_sha256','proof_store','helper_identities')) {
            $oldValue = ($old.$name | ConvertTo-Json -Compress)
            $newValue = ($manifestValue[$name] | ConvertTo-Json -Compress)
            if ($name -eq 'selected_n') {
                $oldSelected = @($old.selected_n | ForEach-Object { [string]$_ })
                $newSelected = @($manifestValue.selected_n | ForEach-Object { [string]$_ })
                $outsideOriginalScope = @($newSelected | Where-Object { $_ -notin $oldSelected })
                if ($outsideOriginalScope.Count -eq 0) { continue }
            }
            if ($oldValue -cne $newValue) { throw "Existing MW-05 manifest is incompatible at $name; use a new output directory." }
        }
    } else {
        Write-AtomicJson $manifestPath $manifestValue
    }

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $summary = @()
    foreach ($job in $jobs) {
        $n = [string]$job.N
        $requestPath = Join-Path $outputRoot "requests/N$n.json"
        $pointPath = Join-Path $outputRoot "points/N$n.json"
        $journalPath = Join-Path $outputRoot "journals/N$n.jsonl"
        $discoveryStdout = Join-Path $outputRoot "logs/N$n.discovery.stdout.json"
        $discoveryStderr = Join-Path $outputRoot "logs/N$n.discovery.stderr.log"
        $proofArtifact = Join-Path $outputRoot "proofs/N$n.json"
        $proofStdout = Join-Path $outputRoot "logs/N$n.prove.stdout.json"
        $proofStderr = Join-Path $outputRoot "logs/N$n.prove.stderr.log"
        $resultPath = Join-Path $outputRoot "results/N$n.json"
        $statePath = Join-Path $outputRoot "state/N$n.json"
        $factorPath = Join-Path $outputRoot "requests/N$n.factors.json"

        $factors = @($job.factors | ForEach-Object {
            [ordered]@{
                prime = [string]$_[0]
                exponent = [int]$_[1]
                certificate = [ordered]@{ kind = 'u64'; n = [string]$_[0] }
            }
        })
        $factorJson = ConvertTo-Json -InputObject $factors -Depth 10 -Compress
        if (Test-Path -LiteralPath $factorPath -PathType Leaf) {
            if ([System.IO.File]::ReadAllText($factorPath) -cne $factorJson) {
                throw "Existing factor input differs for N=$n; use a new output directory."
            }
        } else { [System.IO.File]::WriteAllText($factorPath, $factorJson) }

        $requestValue = [ordered]@{
            schema_version = 2
            request_id = "mw05-N$n"
            problem = [ordered]@{
                n = $n
                factors = $factors
                a = [string]$job.A
                d = [string]$job.D
                curve_coefficients = @($job.curve_coefficients | ForEach-Object { [string]$_ })
            }
        }
        $requestJson = $requestValue | ConvertTo-Json -Depth 20
        if (Test-Path -LiteralPath $requestPath -PathType Leaf) {
            if ([System.IO.File]::ReadAllText($requestPath) -cne $requestJson) {
                $repairable = $false
                try {
                    $existingRequest = Read-JsonFile $requestPath
                    $existingProblem = $existingRequest.problem
                    $existingCoefficients = @($existingProblem.curve_coefficients)
                    $repairable = [string]$existingProblem.n -eq $n -and
                        (-not (Test-MeaningfulValue $existingProblem.a) -or
                         -not (Test-MeaningfulValue $existingProblem.d) -or
                         $existingCoefficients.Count -ne 5)
                } catch { $repairable = $false }
                $hasEvidence = (Test-Path -LiteralPath $journalPath -PathType Leaf) -or
                    (Test-Path -LiteralPath $pointPath -PathType Leaf) -or
                    (Test-Path -LiteralPath $resultPath -PathType Leaf) -or
                    (Test-Path -LiteralPath $proofArtifact -PathType Leaf)
                if ($repairable -and -not $hasEvidence) {
                    # The prior runner could emit an invalid request for a
                    # sparse candidate entry.  It could not have produced
                    # discovery or theorem evidence, so replacing only this
                    # malformed transport record is safe and auditable.
                    [System.IO.File]::WriteAllText($requestPath, $requestJson)
                    Write-Host "N=${n}: repaired prior incomplete request before discovery"
                } else {
                    throw "Existing discovery request differs for N=$n; use a new output directory."
                }
            }
        } else { [System.IO.File]::WriteAllText($requestPath, $requestJson) }

        if ($clock.Elapsed.TotalSeconds -ge $Hours * 3600) {
            Write-Host "Overall budget reached before N=$n; resume with the same command."
            break
        }

        $discovery = Read-DiscoverySummary $discoveryStdout
        $discoveryNeedsRun = $null -eq $discovery -or
            $discovery.schedule_version -ne $discoveryScheduleVersion -or
            $discovery.status -in @('ERROR','TIMEOUT','INTERRUPTED') -or
            $discovery.schedule_complete -ne $true -or
            (($discovery.status -in @('POINT_CANDIDATES','NO_NEW_POINTS')) -and
                -not (Test-Path -LiteralPath $pointPath -PathType Leaf))
        if ($discoveryNeedsRun) {
            $remaining = [math]::Floor($Hours * 3600 - $clock.Elapsed.TotalSeconds)
            if ($remaining -le 0) {
                Write-Host "Overall budget reached before discovery for N=$n; resume with the same command."
                break
            }
            $caseDiscoveryBudget = [int][math]::Min($DiscoveryBudgetSeconds, $remaining)
            $requestWsl = Convert-WindowsPathToWsl (Resolve-Path -LiteralPath $requestPath).Path
            $driverWsl = Convert-WindowsPathToWsl (Resolve-Path -LiteralPath $driver).Path
            $pointWsl = Convert-WindowsPathToWsl ([System.IO.Path]::GetFullPath($pointPath))
            $journalWsl = Convert-WindowsPathToWsl ([System.IO.Path]::GetFullPath($journalPath))
            $discoveryArgs = @(
                '--distribution','Ubuntu-26.04','--exec',$condaExecutable,
                'run','--no-capture-output','--name','cubealqot-m7','python',$driverWsl,
                '--request',$requestWsl,'--output',$pointWsl,'--journal',$journalWsl,
                '--budget-seconds',[string]$caseDiscoveryBudget,
                '--attempt-timeout-seconds',[string]$DiscoveryAttemptTimeoutSeconds
            )
            Write-Host "$(Get-Date -Format o) N=${n}: bounded discovery starting"
            & wsl.exe @discoveryArgs 1> $discoveryStdout 2> $discoveryStderr
            $discoveryExit = $LASTEXITCODE
            $discovery = Read-DiscoverySummary $discoveryStdout
            if ($null -eq $discovery) {
                $discovery = [ordered]@{
                    status = if ($discoveryExit -eq 0) { 'ERROR' } else { 'INCONCLUSIVE' }
                    reason = "discovery produced no parseable summary; exit=$discoveryExit"
                }
            }
            $discovery | Add-Member -NotePropertyName exit_code -NotePropertyValue $discoveryExit -Force
        }

        $pointCount = 0
        if (Test-Path -LiteralPath $pointPath -PathType Leaf) {
            try { $pointCount = @((Read-JsonFile $pointPath).points).Count } catch { $pointCount = 0 }
        }
        $proof = [ordered]@{ status = if ($DiscoveryOnly) { 'NOT_RUN' } else { 'PENDING' } }
        if (-not $DiscoveryOnly) {
            $proof = if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
                $prior = Read-JsonFile $resultPath
                if ($prior.proof.status -in @('CERTIFIED_EMPTY','CERTIFIED_SOLUTIONS') -and
                    (Test-Path -LiteralPath $proofArtifact -PathType Leaf)) { $prior.proof } else { $null }
            } else { $null }
            if ($null -eq $proof) {
                $remaining = [math]::Floor($Hours * 3600 - $clock.Elapsed.TotalSeconds)
                if ($remaining -lt 2) {
                    $proof = [ordered]@{
                        status = 'NOT_STARTED_BUDGET'
                        reason = 'overall campaign budget exhausted before proof phase'
                    }
                }
            }
            if ($null -eq $proof) {
                # The CLI may make two backend calls during a single proof
                # attempt.  Give each call no more than half of the remaining
                # campaign budget so the campaign-level deadline remains real.
                $proofCallTimeout = [int][math]::Min($ProofTimeoutSeconds, [math]::Floor($remaining / 2))
                $proofArgs = @(
                    'prove','--n',$n,'--factors',$factorPath,'--backend','sage',
                    '--timeout-seconds',[string]$proofCallTimeout,
                    '--store',$storeRoot,'--output',$proofArtifact
                )
                # The presence of the point file selects the MW-04 wrapper,
                # even when discovery retained zero points.  Qualification
                # must exercise MW-02 rather than silently falling back to
                # the legacy cardinality policy.
                if (Test-Path -LiteralPath $pointPath -PathType Leaf) { $proofArgs += @('--mw-points',$pointPath) }
                Write-Host "$(Get-Date -Format o) N=${n}: Sage proof starting (points=$pointCount)"
                & $binary @proofArgs 1> $proofStdout 2> $proofStderr
                $proofExit = $LASTEXITCODE
                try { $proof = Read-JsonFile $proofStdout } catch {
                    $proof = [ordered]@{ status = 'OPERATIONAL_ERROR'; reason = "unparseable proof output; exit=$proofExit" }
                }
                $proof | Add-Member -NotePropertyName exit_code -NotePropertyValue $proofExit -Force
                if ($proofExit -eq 0 -and $proof.status -in @('CERTIFIED_EMPTY','CERTIFIED_SOLUTIONS')) {
                    if (-not (Test-Path -LiteralPath $proofArtifact -PathType Leaf)) {
                        throw "N=$n reported a theorem without an artifact."
                    }
                    $verifyText = & $binary verify $proofArtifact --store $storeRoot 2>&1 | Out-String
                    if ($LASTEXITCODE -ne 0) { throw "N=$n proof did not reload from its qualification store: $verifyText" }
                }
            }
        }

        $record = [ordered]@{
            schema_version = 2
            n = $n
            classification = if ($n -in $rankGapControlNs) { 'RANK_GAP_CONTROL' } elseif ($n -in $missingRankTwoNs) { 'POINTS_MISSING_RANK_TWO' } else { 'POINTS_MISSING_RANK_ONE' }
            input = [ordered]@{ request = $requestPath; factors = $factorPath; request_sha256 = Get-Hash $requestPath; factors_sha256 = Get-Hash $factorPath }
            limits = [ordered]@{
                discovery_budget_seconds = $DiscoveryBudgetSeconds
                discovery_attempt_timeout_seconds = $DiscoveryAttemptTimeoutSeconds
                proof_timeout_seconds = $ProofTimeoutSeconds
                actual_discovery_budget_seconds = if ($discovery -and $discovery.PSObject.Properties['budget_seconds']) { $discovery.budget_seconds } else { $null }
                actual_proof_call_timeout_seconds = if ($proof.PSObject.Properties['status'] -and $proof.status -notin @('PENDING','NOT_RUN','NOT_STARTED_BUDGET')) { $proofCallTimeout } else { $null }
            }
            backend_identity = [ordered]@{
                helper_sha256 = if (Test-Path -LiteralPath $pointPath -PathType Leaf) { Get-Hash $mw04Helper } else { Get-Hash $legacyHelper }
                base_helper_sha256 = if (Test-Path -LiteralPath $pointPath -PathType Leaf) { Get-Hash $legacyHelper } else { $null }
                mw02_helper_sha256 = if (Test-Path -LiteralPath $pointPath -PathType Leaf) { Get-Hash $mw02Helper } else { $null }
                distribution = 'Ubuntu-26.04'
                environment = 'cubealqot-m7'
                sage_version = '10.8'
            }
            discovery = $discovery
            discovery_point_file = if (Test-Path -LiteralPath $pointPath -PathType Leaf) { $pointPath } else { $null }
            discovery_journal = $journalPath
            proof = $proof
            proof_artifact = if (Test-Path -LiteralPath $proofArtifact -PathType Leaf) { $proofArtifact } else { $null }
            logs = [ordered]@{ discovery_stdout = $discoveryStdout; discovery_stderr = $discoveryStderr; proof_stdout = $proofStdout; proof_stderr = $proofStderr }
            note = 'Qualification evidence only; no rank, saturation, enumeration or family theorem is inferred from bounded failure.'
            recorded_utc = [DateTime]::UtcNow.ToString('o')
        }
        Write-AtomicJson $resultPath $record
        Write-AtomicJson $statePath ([ordered]@{ n = $n; phase = if ($proof.status -in @('CERTIFIED_EMPTY','CERTIFIED_SOLUTIONS')) { 'PROVED' } else { 'RESEARCH_RETAINED' }; result = $resultPath })
        $summary += $record
        Write-Host "N=${n}: discovery=$($discovery.status), proof=$($proof.status)"
    }
    $summaryPath = Join-Path $outputRoot 'qualification-summary.json'
    Write-AtomicJson $summaryPath ([ordered]@{
        schema_version = 2
        status = 'RECORDED'
        campaign = 'MW-05'
        output = $outputRoot
        cases = @($summary | ForEach-Object { $_.n })
        certified = @($summary | Where-Object { $_.proof.status -in @('CERTIFIED_EMPTY','CERTIFIED_SOLUTIONS') } | ForEach-Object { $_.n })
        inconclusive_or_unresolved = @($summary | Where-Object { $_.proof.status -notin @('CERTIFIED_EMPTY','CERTIFIED_SOLUTIONS') } | ForEach-Object { $_.n })
        note = 'This summary is not a theorem map and is not imported into the canonical proof store.'
    })
    Write-Host "MW-05 qualification evidence retained at $outputRoot"
} finally {
    $lock.Dispose()
}
