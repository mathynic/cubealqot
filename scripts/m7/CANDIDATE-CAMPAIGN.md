# Fixed-cofactor candidate campaign

This campaign runs fixed-cofactor family proofs and admits complete results to
the selected proof store.

## Canonical candidate input

The retained candidate input is
out/m7-candidate-analysis/candidate-jobs.json. It contains 171 research jobs;
each job supplies N and the prime factorization of N. Candidate jobs are
search inputs, not theorem admissions, and do not imply that a family is empty.

The runner's legacy default is
out/m7-candidate-analysis/recommended-jobs.json, which is not included in this
repository snapshot. To use the retained canonical input, pass CandidateFile
explicitly. The 171-job input is not equivalent to the older 18-family
recommendation set.

## Run a selected job

From the cubealqot directory in PowerShell, build the family CLI:

    cargo build --locked --release --bin cubealqot-family

Inspect a selected job without writing files or starting a backend:

    & .\scripts\m7\run-candidate-campaign.ps1 -CandidateFile .\out\m7-candidate-analysis\candidate-jobs.json -PlanOnly -OnlyN 93

Run that job with the standard 24-hour campaign budget:

    & .\scripts\m7\run-candidate-campaign.ps1 -CandidateFile .\out\m7-candidate-analysis\candidate-jobs.json -Hours 24 -OnlyN 93

Use OnlyN to select a focused batch. Omitting it selects all jobs in the input;
the campaign is sequential and stops starting work when its budget is used.

The standard 12-hour schedule uses per-call limits of 60, 300, and 800 seconds.
The standard 24-hour schedule uses 120, 600, and 1,600 seconds. Other hour
budgets require explicit, strictly increasing TimeoutSeconds values. These
limits schedule work; they do not establish completeness.

## Proof store and resume behavior

By default, run evidence is written under out/m7-proof-library and theorem
admissions are written to the canonical store at out/m7-proof-store. Override
these locations with OutputDirectory and ProofStore.

The runner records each run's candidate snapshot, executable and input hashes,
backend logs, results, proof artifacts, and receipts. A later run skips a
successful family only when its receipt and artifact hash agree and the proof
store reloads the same admission. That check loads the admission offline; it
does not replay Sage.

Only CERTIFIED_EMPTY and CERTIFIED_SOLUTIONS with exit code zero count as
success. INCONCLUSIVE is retained for a later run with larger declared limits.
Timeouts, bounded searches, and process failures never become theorems. The
campaign does not export a theorem map or modify the native search.

## Optional Mordell–Weil point hints

Pass MwPointsDirectory to provide optional N<n>.json point files:

    & .\scripts\m7\run-candidate-campaign.ps1 -CandidateFile .\out\m7-candidate-analysis\candidate-jobs.json -Hours 24 -OnlyN 93 -MwPointsDirectory .\out\mw-03-discovery\points

Present files are checked and their points are embedded in the proof request.
They remain untrusted hints and do not replace rank, independence, saturation,
torsion, or complete original-model integral-point checks. Missing files use
ordinary discovery.

Use CandidateFile to supply another jobs file. The selected input is copied
into the run manifest. Backend proofs require the separately configured
Sage/PARI/eclib environment.
