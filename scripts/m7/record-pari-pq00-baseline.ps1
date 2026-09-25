[CmdletBinding()]
param(
    [string]$OutputDirectory = '',
    [string]$StorePath = '',
    [string]$BinaryPath = ''
)

$ErrorActionPreference = 'Stop'

$crate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
. (Join-Path $PSScriptRoot 'local-config.ps1')
function Resolve-CratePath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $crate $Path))
}
function Write-Utf8([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}
function Write-Json([string]$Path, $Value) {
    Write-Utf8 $Path (($Value | ConvertTo-Json -Depth 100) + "`n")
}
function Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}
function Run-Captured([string]$FilePath, [string[]]$Arguments) {
    $output = (& $FilePath @Arguments 2>&1 | Out-String).TrimEnd()
    [pscustomobject]@{
        exit_code = $LASTEXITCODE
        output = $output
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $OutputDirectory = Join-Path $crate "out/m7-pari-qualification/pq00-baseline-$stamp"
} else {
    $OutputDirectory = Resolve-CratePath $OutputDirectory
}
if ([string]::IsNullOrWhiteSpace($StorePath)) {
    $StorePath = Join-Path $crate 'out/m7-proof-store'
} else {
    $StorePath = Resolve-CratePath $StorePath
}
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $crate 'target/release/cubealqot-family.exe'
} else {
    $BinaryPath = Resolve-CratePath $BinaryPath
}

if (-not (Test-Path -LiteralPath $StorePath -PathType Container)) {
    throw "Proof store not found: $StorePath"
}
if (-not (Test-Path -LiteralPath $BinaryPath -PathType Leaf)) {
    throw "Family CLI binary not found: $BinaryPath"
}
[System.IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null

$sourceFiles = @(
    Get-ChildItem -LiteralPath (Join-Path $crate 'src') -Recurse -File
    Get-ChildItem -LiteralPath (Join-Path $crate 'scripts/m7') -Recurse -File
    Get-ChildItem -LiteralPath (Join-Path $crate 'tests') -Recurse -File
    Get-Item (Join-Path $crate 'Cargo.toml')
    Get-Item (Join-Path $crate 'Cargo.lock')
) | Sort-Object FullName -Unique
$sourceDigests = @($sourceFiles | ForEach-Object {
    [ordered]@{
        path = [System.IO.Path]::GetRelativePath($crate, $_.FullName).Replace('\', '/')
        sha256 = Sha256 $_.FullName
        bytes = $_.Length
    }
})
Write-Json (Join-Path $OutputDirectory 'source-digests.json') $sourceDigests

$git = Get-Command git -ErrorAction SilentlyContinue
$gitRevision = $null
$gitStatus = 'no_git_checkout'
if ($null -ne $git) {
    $gitResult = Run-Captured $git.Source @('-C', $crate, 'rev-parse', 'HEAD')
    if ($gitResult.exit_code -eq 0 -and $gitResult.output -match '^[0-9a-fA-F]{40}$') {
        $gitRevision = $gitResult.output
        $gitStatus = 'git_revision_recorded'
    }
}

$rustc = Get-Command rustc -ErrorAction SilentlyContinue
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$python = Get-Command python -ErrorAction SilentlyContinue
$windowsTools = [ordered]@{}
foreach ($tool in @(@{name='rustc'; command=$rustc}, @{name='cargo'; command=$cargo}, @{name='python'; command=$python})) {
    if ($null -eq $tool.command) {
        $windowsTools[$tool.name] = $null
    } else {
        $version = Run-Captured $tool.command.Source @('--version')
        $windowsTools[$tool.name] = [ordered]@{
            path = $tool.command.Source
            version = $version.output
            exit_code = $version.exit_code
        }
    }
}

$wslList = Run-Captured 'wsl.exe' @('--list', '--verbose')
$uname = Run-Captured 'wsl.exe' @('-d', 'Ubuntu-26.04', '--exec', 'uname', '-a')
$conda = Get-M7CondaExecutable -CrateRoot $crate
$envName = 'cubealqot-m7'
$backendCode = "import sys,json,hashlib,importlib.util,pathlib; import sage.all; from sage.env import SAGE_VERSION; from sage.all import pari; names=['sage.schemes.elliptic_curves.ell_rational_field','sage.structure.proof.all','sage.libs.eclib.all']; mods={n:{'path':str((p:=pathlib.Path(importlib.util.find_spec(n).origin))),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for n in names}; print(json.dumps({'python':sys.version,'python_executable':sys.executable,'sage_version':str(SAGE_VERSION),'pari_version':str(pari('version()')),'modules':mods},sort_keys=True))"
$backendIdentity = Run-Captured 'wsl.exe' @('-d', 'Ubuntu-26.04', '--exec', $conda, 'run', '--no-capture-output', '-n', $envName, 'python', '-c', $backendCode)
$condaExplicit = Run-Captured 'wsl.exe' @('-d', 'Ubuntu-26.04', '--exec', $conda, 'list', '-n', $envName, '--explicit')
Write-Utf8 (Join-Path $OutputDirectory 'wsl-list.txt') (($wslList.output) + "`n")
Write-Utf8 (Join-Path $OutputDirectory 'uname.txt') (($uname.output) + "`n")
Write-Utf8 (Join-Path $OutputDirectory 'conda-explicit.txt') (($condaExplicit.output) + "`n")
Write-Utf8 (Join-Path $OutputDirectory 'backend-identity.txt') (($backendIdentity.output) + "`n")

$storeList = Run-Captured $BinaryPath @('store', 'list', '--store', $StorePath)
$storeCheck = Run-Captured $BinaryPath @('store', 'check', '--store', $StorePath)
Write-Utf8 (Join-Path $OutputDirectory 'store-list.raw.txt') (($storeList.output) + "`n")
Write-Utf8 (Join-Path $OutputDirectory 'store-check.raw.txt') (($storeCheck.output) + "`n")
$storeListJson = $storeList.output | ConvertFrom-Json
$storeCheckJson = $storeCheck.output | ConvertFrom-Json
$storeManifest = Get-Content (Join-Path $StorePath 'store.json') -Raw | ConvertFrom-Json
$admissionRecords = @(Get-ChildItem (Join-Path $StorePath 'admissions') -Filter '*.json' |
    Where-Object { $_.Name -notlike '*.commit.json' } |
    ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json })

$storeFiles = @(Get-ChildItem -LiteralPath $StorePath -Recurse -File | Sort-Object FullName | ForEach-Object {
    [ordered]@{
        path = [System.IO.Path]::GetRelativePath($StorePath, $_.FullName).Replace('\', '/')
        sha256 = Sha256 $_.FullName
        bytes = $_.Length
    }
})
Write-Json (Join-Path $OutputDirectory 'store-file-digests.json') $storeFiles
$admittedNs = @($admissionRecords | ForEach-Object { [string]$_.theorem.n })
$historicalNs = @('2', '3', '4', '5', '9', '21', '35')
$researchOnlyNs = @('37', '39', '53', '65', '85', '97', '103', '129', '133')
$newerCompletedNs = @($admittedNs | Where-Object { $_ -notin $historicalNs } | Sort-Object { [int]$_ })
$nativeProcesses = @(
    Get-Process -Name 'cubealqot', 'cubealqot-family' -ErrorAction SilentlyContinue |
        Select-Object Id, ProcessName, Path, StartTime
)

$manifest = [ordered]@{
    schema_version = 1
    task = 'PQ-00'
    captured_utc = [DateTime]::UtcNow.ToString('o')
    crate_root = $crate
    source_revision = [ordered]@{
        status = $gitStatus
        git_revision = $gitRevision
        source_digest_file = 'source-digests.json'
    }
    qualification_contract = [ordered]@{
        status = 'frozen-for-PQ-01-through-PQ-04'
        backend = 'SageMath-10.8-PARI-eclib'
        proof_all = $true
        rank_rule = 'certified algebraic upper bound R and exact independent subgroup rank d must satisfy d=R'
        basis_rule = 'exact rational points on the original curve; no guessed rank, floating determinant, or cached algorithm result'
        saturation = [ordered]@{
            api = 'eclib mwrank_MordellWeil.saturate'
            max_prime = -1
            min_prime = 2
            unresolved_primes = 'strictly parsed and empty; unknown format fails closed'
            returned_saturated_basis = 'authoritative and rechecked on the original model'
        }
        enumeration = 'integral_points on the original model with the checked full basis and both_signs=True'
        torsion = 'rank-zero free basis is empty; torsion remains part of integral-point enumeration'
        failure_policy = 'precision, missing points, rank gap, saturation failure, timeout, malformed output, and exceptions are INCONCLUSIVE'
        model_policy = 'minimal-model transformations are exact basis transport only; they do not replace original-model integral enumeration'
    }
    audit_findings = @(
        [ordered]@{ id = 'P2-cache-differential'; status = 'open-prerequisite'; summary = 'algorithm differential can be defeated by Sage curve caches' }
        [ordered]@{ id = 'P2-explicit-precision'; status = 'open-prerequisite'; summary = 'global precision does not change the omitted PARI ellrank precision argument' }
        [ordered]@{ id = 'P2-missing-basis-effort'; status = 'open-prerequisite'; summary = 'effort-zero can return an incomplete basis; timeout does not expand the attempt' }
    )
    windows_tools = $windowsTools
    backend_environment = [ordered]@{
        distribution = 'Ubuntu-26.04'
        conda_executable = $conda
        environment = $envName
        wsl_list_exit_code = $wslList.exit_code
        uname_exit_code = $uname.exit_code
        backend_identity_exit_code = $backendIdentity.exit_code
        conda_explicit_exit_code = $condaExplicit.exit_code
        conda_explicit_file = 'conda-explicit.txt'
        backend_identity_file = 'backend-identity.txt'
    }
    native_binary = [ordered]@{
        path = $BinaryPath
        sha256 = Sha256 $BinaryPath
        bytes = (Get-Item $BinaryPath).Length
    }
    proof_store = [ordered]@{
        path = $StorePath
        store_list_exit_code = $storeList.exit_code
        store_check_exit_code = $storeCheck.exit_code
        store_id = $storeListJson.store_id
        admission_count = $storeListJson.entries.Count
        store_check_admission_count = $storeCheckJson.admission_count
        backend_invoked = $storeCheckJson.backend_invoked
        store_manifest_sha256 = Sha256 (Join-Path $StorePath 'store.json')
        file_digest_file = 'store-file-digests.json'
        list_file = 'store-list.raw.txt'
        check_file = 'store-check.raw.txt'
    }
    historical_inventory = [ordered]@{
        requested_historical_n = $historicalNs
        admitted_historical_n = @($historicalNs | Where-Object { $_ -in $admittedNs })
        missing_historical_n = @($historicalNs | Where-Object { $_ -notin $admittedNs })
        research_only_not_admitted_n = @($researchOnlyNs | Where-Object { $_ -notin $admittedNs })
        all_admitted_n = @($admittedNs | Sort-Object { [int]$_ })
        policy = 'absence is recorded explicitly; no missing entry is trusted silently'
        newer_completed_n = $newerCompletedNs
    }
    policy_and_schema = [ordered]@{
        store_schema_version = $storeManifest.schema_version
        admission_schema_version = 1
        certificate_schema_version = 1
        rhs_version = 1
        accepted_trust = $storeManifest.policy.accepted_trust
        policy_ids = @($admissionRecords | ForEach-Object { $_.policy.policy_id } | Sort-Object -Unique)
        provenance_values = @($admissionRecords | ForEach-Object { $_.provenance } | Sort-Object -Unique)
    }
    exact_four_curve_identities = @(
        [ordered]@{ n = '11'; a = '1464'; d = '133'; coefficients = @('0','1464','0','194712','25896696') }
        [ordered]@{ n = '13'; a = '2380'; d = '183'; coefficients = @('0','2380','0','435540','79703820') }
        [ordered]@{ n = '15'; a = '6240'; d = '2865'; coefficients = @('0','6240','0','17877600','51219324000') }
        [ordered]@{ n = '19'; a = '7240'; d = '381'; coefficients = @('0','7240','0','2758440','1050965640') }
    )
    research_evidence = [ordered]@{
        directory = 'out/m7-rank-study'
        n11_followup = 'out/m7-rank-study/N11-followup.md'
        main_readme = 'out/m7-rank-study/README.md'
        status = 'backend-trusted-research-only'
        final_helper_qualification = 'deferred-to-PQ-01/PQ-02'
    }
    active_campaign_guard = [ordered]@{
        observed = ($nativeProcesses.Count -gt 0)
        native_processes = $nativeProcesses
        policy = 'do-not-modify-helper-binary-environment-inputs-snapshots-or-proof-store'
        pq04_cutover = if ($nativeProcesses.Count -gt 0) { 'deferred-until-campaign-and-backend-replay-processes-finish' } else { 'campaign-process-not-observed-at-capture; cutover remains separately gated on backend/replay completion' }
    }
}
Write-Json (Join-Path $OutputDirectory 'manifest.json') $manifest
Write-Host "PQ-00 baseline recorded: $OutputDirectory"
Write-Host "Admissions observed: $($storeListJson.entries.Count); offline backend invoked: $($storeCheckJson.backend_invoked)"
