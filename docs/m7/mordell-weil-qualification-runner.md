# Mordell–Weil recovery qualification runner

The qualification runner applies bounded point discovery and the proof path to
selected fixed-cofactor curves. It keeps research outcomes separate from
theorem admissions and does not publish into the canonical proof store by
default.

## Inputs

The default candidate file is
out/m7-candidate-analysis/candidate-jobs.json. The default selected set has
23 cofactors covering rank-one missing-point cases, rank-two missing-generator
cases, and rank-gap controls.

Each selected job must provide N, its factorization, A, D, and the five curve
coefficients. Incomplete jobs are enriched from ranked-cofactors.json. The
retained candidate-jobs.json contains only N and factors, and
ranked-cofactors.json is not included in this repository snapshot. Also, the
tracked candidate-jobs.json has no entries for N=39, 65, or 133, which are in
the runner's default 23-cofactor selection. A fresh clone therefore needs a
complete CandidateFile or a RankedCofactorsFile covering the selected cases
before the runner can proceed. PlanOnly also checks that the selected jobs are
complete.

The runner also requires the family CLI, the Mordell–Weil discovery driver,
the approved Sage helpers, and the separately configured Sage/PARI/eclib
environment.

## Local Conda configuration

Set `CUBEALQOT_CONDA_EXECUTABLE` in the ignored repository-root `.env.local`
file to the Conda executable path inside WSL. For example:

    CUBEALQOT_CONDA_EXECUTABLE=/path/to/conda

The Rust adapter and M7 PowerShell/Python runners read this setting. An
environment variable with the same name takes precedence. If neither is set,
they use `conda` from the WSL PATH.

## What it does

For each selected cofactor, the runner writes a frozen request, resumes the
discovery journal and point file, and passes the validated point file to the
family prover when one exists, including an empty file. It records discovery
status, proof status, budgets, backend identity, logs, hashes, and evidence
paths under the qualification output.

Discovery and proof work are bounded by per-cofactor and overall campaign
budgets. Timeouts, rank gaps, discovery failures, and incomplete proofs remain
inconclusive; none becomes CERTIFIED_EMPTY. Discovery is skipped only when
its schedule is complete. A completed proof is reused only when its artifact
and store admission reload successfully.

Successful results use the qualification store, which defaults to
out/mw-05-qualification/proof-store. This store is separate from the canonical
out/m7-proof-store unless ProofStore is explicitly set. The runner does not
export a theorem map.

## Running and resuming

Build an isolated family CLI:

    cargo build --locked --release --bin cubealqot-family --target-dir target-mw05-release

Supply complete candidate data and inspect the selection without writes or
backend calls:

    & .\scripts\m7\run-mw05-qualification.ps1 -CandidateFile .\path\complete-candidates.json -PlanOnly -OnlyN 93

Use DiscoveryOnly to run or resume point discovery without attempting theorem
proofs. Use OnlyN to select a subset of the original manifest; adding a
cofactor requires a new output directory. The manifest freezes inputs,
budgets, executable, helper identities, and proof store. Reusing it resumes
the same research case and preserves its journals and point files.

The default budgets are 3,600 seconds of discovery per cofactor, 120 seconds
per discovery attempt, 3,600 seconds per Sage proof call, and 72 hours overall.
Discovery and proof phases are clipped to remaining budgets. These are
resource limits, not completeness bounds.
