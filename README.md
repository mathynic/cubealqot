# cubealqot

Rust search and validation tools for the question: can the aliquot sum of a
nontrivial perfect cube be a perfect square?

For integers `m > 1`, the search tests whether `sigma(m^3) - m^3 = y^2`, where
`sigma` includes all positive divisors. Necessary-condition filters precede an
exact square test. Admitted fixed-cofactor theorems can exclude eligible
families `m = N*q`, with `q` prime and not dividing `N`.

Finite searches and saved nonsquare survivors are not a universal impossibility
proof. Independent research reports retain their stated assumptions; publishing
one here does not admit it to the proof store.

## Build and check

Use a current Rust toolchain supporting edition 2024. Python 3 is needed for the
independent oracle and survivor consolidation. On Windows, Rust's MSVC toolchain
uses the Visual Studio C++ build tools.

```text
cargo build --locked --release
cargo test --locked --lib
cargo run --locked -- validate --max 1005
cargo run --locked --bin cubealqot-family -- store check --store out/m7-proof-store
cargo run --locked -- --help
cargo run --locked --bin cubealqot-family -- --help
```

The GitHub workflow runs a portable subset of integration tests in addition to
the library tests. The full local suite includes historical migration/replay
tests needing retained campaign files under `out/m7-proof-library`, qualified
helper snapshots, PowerShell, and/or Sage. Those local research outputs are not
bundled; this repository does not claim that every historical integration test
is self-contained on a fresh clone. Test sources remain available.

New backend proof computations use the separately configured Sage/PARI/eclib
environment. See the [campaign instructions](scripts/m7/CANDIDATE-CAMPAIGN.md)
for the supported campaign workflow. Existing admissions can be checked and
loaded offline without starting Sage.

## Retained data

- `out/m7-proof-store/`: canonical committed theorem admissions, content-addressed
  evidence, store policy, imports, and snapshots. Lock files and staging are
  excluded. Byte-preserving Git attributes protect evidence digests. Admissions
  retain their original trust classification and provenance; they are not all
  self-contained mathematical certificates.
- `artifacts/survivors.jsonl`: consolidated, numerically sorted survivor snapshot,
  deduplicated by `m`, with full exact JSON integers.
- `artifacts/survivors.manifest.json`: source hashes, counts, captured byte lengths,
  duplicate count, and output digest. See [artifact notes](artifacts/README.md).
- `out/m7-candidate-analysis/candidate-jobs.json`: reusable cofactor campaign
  inputs. Candidate status and matching counts are historical observations,
  not proof admissions.

Build directories, raw campaign outputs, checkpoints, profiling JSON, nested
scratch output, Python caches, and local environment files are ignored. Existing
local files are left in place.

## Mathematical references

- [Fixed-cofactor family prover](fixed_cofactor_prover_final.md)
