"""Snapshot top-level out/survivors*.jsonl into one exact, deduplicated artifact.

No input is modified. Complete records are deduplicated by m and sorted
numerically. Conflicting duplicates or invalid factorizations abort the export.
An unfinished final line in a live source is omitted and recorded in the manifest.
"""

import datetime
import hashlib
import json
import math
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    records = {}
    sources = []
    duplicate_count = 0
    for source in sorted((root / "out").glob("survivors*.jsonl")):
        raw = source.read_bytes()
        complete = raw[: raw.rfind(b"\n") + 1]
        count = 0
        for line_number, line in enumerate(complete.splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            m = record["m"]
            if not isinstance(m, int) or m <= 1:
                raise ValueError(f"Invalid m: {source.name}:{line_number}")
            if math.prod(p**e for p, e in record["factors"]) != m:
                raise ValueError(f"Invalid factorization: {source.name}:{line_number}")
            if m in records:
                if records[m] != record:
                    raise ValueError(f"Conflicting records for m={m}")
                duplicate_count += 1
            else:
                records[m] = record
            count += 1
        sources.append({
            "path": source.relative_to(root).as_posix(),
            "bytes_read": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "records": count,
            "omitted_incomplete_tail_bytes": len(raw) - len(complete),
        })
    if not records:
        raise ValueError("No complete survivor records found")
    payload = "".join(
        json.dumps(records[m], separators=(",", ":"), ensure_ascii=False) + "\n"
        for m in sorted(records)
    ).encode("utf-8")
    manifest = {
        "schema_version": 1,
        "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_glob": "out/survivors*.jsonl",
        "deduplication": "identical records by m; conflicting duplicates rejected",
        "record_count": len(records),
        "duplicate_records_removed": duplicate_count,
        "minimum_m": min(records),
        "maximum_m": max(records),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "sources": sources,
    }
    destination = root / "artifacts"
    destination.mkdir(exist_ok=True)
    (destination / "survivors.jsonl").write_bytes(payload)
    (destination / "survivors.manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Exported {len(records)} records; removed {duplicate_count} identical duplicates")
    print(f"SHA-256: {manifest['sha256']}")


if __name__ == "__main__":
    main()
