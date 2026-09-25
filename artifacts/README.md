# Survivor snapshot

`survivors.jsonl` consolidates the complete records in the top-level
`out/survivors*.jsonl` files at export time. Identical records with the same `m`
are deduplicated and sorted by `m`; conflicting records abort consolidation.
Source files remain untouched. The manifest records exactly which source bytes
were captured and any unfinished final line omitted from a live file.

The initial export has 2,079 unique records (three identical duplicates removed).
Each record has stage F8 and rejection `exact_nonsquare`: these are survivors of
earlier filters, not solutions of the original equation. Source filename bounds
do not certify completed search intervals. Runs may have different family-proof
snapshots, so the combined output is not an unbiased coverage benchmark.

Integers can exceed JavaScript's exact-number range. Use an arbitrary-precision
JSON reader (for example, Python's standard `json` module) without float conversion.

To refresh from retained local outputs:

```text
python scripts/consolidate_survivors.py
```

Refresh the JSONL and manifest together. A fresh clone intentionally lacks the
raw source runs; it can use the consolidated snapshot but cannot reconstruct its
original source files. This artifact is not a resumable search checkpoint.
