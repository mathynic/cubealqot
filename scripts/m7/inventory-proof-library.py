#!/usr/bin/env python3
"""PP-00 inventory for the retained M7 proof library.

This command is deliberately read-only with respect to the source library and
never invokes Sage, WSL, Rust, or any backend.  It writes a deterministic JSON
inventory outside the source tree by default.  Hashes identify retained bytes;
they are not an admission authority or a proof of backend completeness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
HASH_ALGORITHM = "SHA-256"
CANONICAL_ENCODING = "json-sorted-keys-utf8-v1"
DEFAULT_LIBRARY = Path("out/m7-proof-library")
DEFAULT_OUTPUT = Path("out/m7-proof-inventory/pp00-inventory.json")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def relative_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, str(error)


def file_manifest(root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=lambda p: relative_path(root, p)):
        rows.append(
            {
                "path": relative_path(root, path),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return rows


def normalize_request(request: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(request))
    value.pop("request_id", None)
    return value


def normalize_response(response: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(response))
    value.pop("request_id", None)
    return value


def external_status(status: Any) -> str | None:
    return {
        "CertifiedEmpty": "CERTIFIED_EMPTY",
        "CertifiedSolutions": "CERTIFIED_SOLUTIONS",
        "Inconclusive": "INCONCLUSIVE",
    }.get(status, status)


def point_set(response: dict[str, Any]) -> list[tuple[str, str]]:
    return sorted((str(point["x"]), str(point["y"])) for point in response.get("points", []))


def transcript_jobs(root: Path) -> list[dict[str, Any]]:
    evidence_root = root / "certificates" / "m7-adapter-evidence"
    jobs = []
    if not evidence_root.is_dir():
        return jobs
    for directory in sorted(item for item in evidence_root.iterdir() if item.is_dir()):
        request_path = directory / "request.json"
        response_path = directory / "response.json"
        log_path = directory / "backend.log"
        request, request_error = load_json(request_path)
        response, response_error = load_json(response_path)
        jobs.append(
            {
                "job_id": directory.name,
                "path": relative_path(root, directory),
                "request": request,
                "response": response,
                "request_error": request_error,
                "response_error": response_error,
                "request_sha256": sha256_file(request_path) if request_path.is_file() else None,
                "response_sha256": sha256_file(response_path) if response_path.is_file() else None,
                "stderr_sha256": sha256_file(log_path) if log_path.is_file() else None,
                "files_present": {
                    "request": request_path.is_file(),
                    "response": response_path.is_file(),
                    "backend_log": log_path.is_file(),
                },
            }
        )
    return jobs


def campaign_rows(root: Path) -> list[dict[str, Any]]:
    rows = []
    runs_root = root / "runs"
    if not runs_root.is_dir():
        return rows
    for run in sorted(item for item in runs_root.iterdir() if item.is_dir()):
        results_path = run / "results.jsonl"
        if not results_path.is_file():
            continue
        try:
            lines = results_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            rows.append({"run_id": run.name, "parse_error": str(error)})
            continue
        for line_number, line in enumerate(lines, start=1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                rows.append(
                    {
                        "run_id": run.name,
                        "line": line_number,
                        "parse_error": str(error),
                    }
                )
                continue
            result = row.get("result") or {}
            rows.append(
                {
                    "run_id": run.name,
                    "line": line_number,
                    "n": str(row.get("n")) if row.get("n") is not None else None,
                    "status": result.get("status"),
                    "completeness": result.get("completeness"),
                    "job_id": result.get("job_id"),
                    "output": result.get("output"),
                    "exit_code": row.get("exit_code"),
                }
            )
    return rows


def matching_campaign_row(
    rows: list[dict[str, Any]],
    receipt: dict[str, Any],
    artifact_name: str,
    artifact_job_id: str | None,
) -> dict[str, Any] | None:
    for row in rows:
        if (
            row.get("run_id") == receipt.get("run_id")
            and row.get("n") == str(receipt.get("n"))
            and row.get("status") == receipt.get("status")
            and row.get("job_id") == artifact_job_id
            and str(row.get("output", "")).endswith(artifact_name)
        ):
            return row
    return None


def inspect_receipt(
    root: Path,
    receipt_path: Path,
    jobs: list[dict[str, Any]],
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    receipt, receipt_error = load_json(receipt_path)
    result: dict[str, Any] = {
        "receipt": relative_path(root, receipt_path),
        "category": "malformed",
        "issues": [],
    }
    if receipt_error or not isinstance(receipt, dict):
        result["issues"].append(f"receipt JSON invalid: {receipt_error or 'object required'}")
        return result

    artifact_name = receipt.get("artifact_name")
    artifact_path = root / "certificates" / str(artifact_name)
    result.update(
        {
            "n": str(receipt.get("n")),
            "status": receipt.get("status"),
            "run_id": receipt.get("run_id"),
            "artifact": relative_path(root, artifact_path),
            "receipt_sha256": receipt.get("sha256"),
            "artifact_sha256": sha256_file(artifact_path) if artifact_path.is_file() else None,
        }
    )
    if not artifact_path.is_file():
        result["issues"].append("receipt artifact is missing")
        return result
    if str(receipt.get("sha256", "")).lower() != result["artifact_sha256"]:
        result["issues"].append("receipt-to-artifact SHA-256 mismatch")

    envelope, envelope_error = load_json(artifact_path)
    if envelope_error or not isinstance(envelope, dict) or not isinstance(envelope.get("certificate"), dict):
        result["issues"].append(f"certificate envelope invalid: {envelope_error or 'certificate object required'}")
        return result
    certificate = envelope["certificate"]
    result.update(
        {
            "certificate_schema_version": certificate.get("schema_version"),
            "rhs_version": certificate.get("rhs_version"),
            "proof_kind": certificate.get("proof_kind"),
            "certificate_status": certificate.get("status"),
            "canonical_certificate_sha256": canonical_digest(certificate),
            "solutions": len(certificate.get("solutions", [])),
        }
    )
    if str(certificate.get("problem", {}).get("n")) != str(receipt.get("n")):
        result["issues"].append("receipt N differs from certificate N")
    if external_status(certificate.get("status")) != receipt.get("status"):
        result["issues"].append("receipt status differs from certificate status")

    backend = ((certificate.get("proof") or {}).get("data") or {}).get("backend")
    initial_job_id = None
    replay_matches = []
    if not isinstance(backend, dict):
        result["issues"].append("backend proof payload is missing")
    else:
        evidence = backend.get("evidence") or {}
        initial_job_id = evidence.get("job_id")
        result["initial_job_id"] = initial_job_id
        initial = next((job for job in jobs if job["job_id"] == initial_job_id), None)
        if initial is None:
            result["issues"].append("initial adapter transcript is missing")
        else:
            result["initial_transcript"] = initial["path"]
            for field, actual in (
                ("request_sha256", initial["request_sha256"]),
                ("response_sha256", initial["response_sha256"]),
                ("stderr_sha256", initial["stderr_sha256"]),
            ):
                if str(evidence.get(field, "")).lower() != str(actual).lower():
                    result["issues"].append(f"initial transcript {field} mismatch")
            if initial["request"] is None or initial["response"] is None:
                result["issues"].append("initial adapter transcript is incomplete")
            elif normalize_request(initial["request"]) != normalize_request(backend.get("request", {})):
                result["issues"].append("certificate request differs from initial transcript")
            elif normalize_response(initial["response"]) != normalize_response((backend.get("response") or {})):
                result["issues"].append("certificate response differs from initial transcript")

            for job in jobs:
                if job["job_id"] == initial_job_id or job["request"] is None or job["response"] is None:
                    continue
                if normalize_request(job["request"]) != normalize_request(backend.get("request", {})):
                    continue
                if normalize_response(job["response"]) != normalize_response((backend.get("response") or {})):
                    continue
                if not job["response"].get("ok") or not job["response"].get("complete"):
                    continue
                replay_matches.append(job["path"])
        result["replay_transcripts"] = replay_matches

    campaign = matching_campaign_row(
        rows,
        receipt,
        str(artifact_name),
        str(envelope.get("job_id")),
    )
    result["campaign_result"] = campaign
    content_ok = not result["issues"] or all(
        "transcript" not in issue and "backend proof" not in issue for issue in result["issues"]
    )
    initial_ok = initial_job_id is not None and any(job["job_id"] == initial_job_id for job in jobs)
    replay_ok = bool(replay_matches)
    campaign_ok = campaign is not None and campaign.get("exit_code") == 0
    if result["issues"]:
        result["category"] = "malformed" if any(
            "mismatch" in issue or "invalid" in issue or "differs" in issue for issue in result["issues"]
        ) else "successful_but_incomplete_provenance"
    elif content_ok and initial_ok and replay_ok and campaign_ok:
        result["category"] = "successful_with_recorded_replay_evidence"
    else:
        result["category"] = "successful_but_incomplete_provenance"
    result["checks"] = {
        "content_and_receipt_identity": content_ok,
        "initial_transcript": initial_ok,
        "matching_replay_transcript": replay_ok,
        "successful_campaign_result": campaign_ok,
    }
    return result


def build_inventory(library: Path) -> dict[str, Any]:
    library = library.resolve()
    if not library.is_dir():
        raise ValueError(f"proof library is not a directory: {library}")
    files = file_manifest(library)
    jobs = transcript_jobs(library)
    rows = campaign_rows(library)
    families = [
        inspect_receipt(library, path, jobs, rows)
        for path in sorted((library / "receipts").glob("*.json"))
    ]
    status_counts: dict[str, int] = {}
    for row in families:
        status_counts[row["category"]] = status_counts.get(row["category"], 0) + 1
    run_summaries = []
    for run_id in sorted({row.get("run_id") for row in rows if row.get("run_id")}):
        run_rows = [row for row in rows if row.get("run_id") == run_id]
        run_summaries.append(
            {
                "run_id": run_id,
                "result_count": len(run_rows),
                "certified_count": sum(row.get("status") == "CERTIFIED_EMPTY" for row in run_rows),
                "inconclusive_count": sum(row.get("status") == "INCONCLUSIVE" for row in run_rows),
                "parse_error_count": sum("parse_error" in row for row in run_rows),
            }
        )
    file_digest = canonical_digest(files)
    receipt_ns = sorted(
        row["n"] for row in families if row.get("n") is not None
    )
    benchmark_admissions = [
        item["path"]
        for item in files
        if "benchmark" in item["path"].lower()
        and (item["path"].endswith(".json") or item["path"].endswith(".jsonl"))
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "inventory_kind": "m7-proof-library-pp00",
        "source_root": "out/m7-proof-library",
        "hash_algorithm": HASH_ALGORITHM,
        "canonical_encoding": CANONICAL_ENCODING,
        "file_count": len(files),
        "total_bytes": sum(item["size"] for item in files),
        "file_manifest_sha256": file_digest,
        "files": files,
        "campaign_runs": run_summaries,
        "adapter_transcript_count": len(jobs),
        "families": families,
        "classification_counts": status_counts,
        "completion_accounting": {
            "known_completion_count": 7,
            "receipt_family_count": len(receipt_ns),
            "receipt_family_n": receipt_ns,
            "unaccounted_known_completions": max(0, 7 - len(receipt_ns)),
        },
        "benchmark_admissions": benchmark_admissions,
        "limitations": [
            "SHA-256 identifies retained bytes but does not authenticate the owner-controlled source or prove backend completeness.",
            "The legacy CLI environment_sha256 is a label digest, not an installed-environment identity.",
            "A successful historical classification accepts retained local campaign provenance; it is not a fresh Sage replay.",
            "Unlinked, partial, failed, malformed, or conflicting evidence is not admitted and must not become an empty theorem.",
            "No benchmark admission artifact was found; benchmark admission is not inferred from a certificate or result JSONL row.",
        ],
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def markdown_report(inventory: dict[str, Any]) -> str:
    lines = [
        "# PP-00 M7 proof-library inventory",
        "",
        "This report is an inventory of retained evidence. It does not admit a theorem,",
        "run Sage, or treat hashes as proof of backend completeness.",
        "",
        f"- Source: `{inventory['source_root']}`",
        f"- Files: {inventory['file_count']}",
        f"- Bytes: {inventory['total_bytes']}",
        f"- File-manifest SHA-256: `{inventory['file_manifest_sha256']}`",
        f"- Adapter transcript directories: {inventory['adapter_transcript_count']}",
        "",
        "## Family classification",
        "",
        "| N | Classification | Proof kind | Artifact SHA-256 | Initial transcript | Matching replay |",
        "|---:|---|---|---|---|---|",
    ]
    for family in sorted(inventory["families"], key=lambda item: int(item.get("n", "0"))):
        lines.append(
            "| {n} | {category} | {proof} | `{digest}` | `{initial}` | {replay} |".format(
                n=family.get("n", "?"),
                category=family.get("category", "?"),
                proof=family.get("proof_kind", "?"),
                digest=family.get("artifact_sha256", "?"),
                initial=family.get("initial_job_id", "missing"),
                replay="yes" if family.get("checks", {}).get("matching_replay_transcript") else "no",
            )
        )
    lines.extend(
        [
            "",
            "## Campaign runs",
            "",
            "| Run | Results | Certified | Inconclusive | Parse errors |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for run in inventory["campaign_runs"]:
        lines.append(
            f"| `{run['run_id']}` | {run['result_count']} | {run['certified_count']} | "
            f"{run['inconclusive_count']} | {run['parse_error_count']} |"
        )
    lines.extend(
        [
            "",
            "## PP-00 interpretation",
            "",
            "All seven retained receipt families are linked to their certificate, initial adapter transcript,",
            "matching replay transcript, and successful campaign result in this inventory. They remain",
            "backend-trusted historical completions; this is not a fresh Sage replay and is not yet a",
            "committed proof-store admission.",
            "",
            "The inventory also records all retained files, including inconclusive/partial campaign evidence.",
            "Those entries are not promoted to empty theorems. The legacy `environment_sha256` is retained",
            "as artifact metadata only; it is not treated as an installed-environment identity.",
            "No benchmark admission artifact was found in the source library; no benchmark completion was inferred.",
            "The seven known completion targets are accounted for by the seven receipt families listed above.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, default=DEFAULT_LIBRARY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args(argv)
    library = args.library.resolve()
    output = args.output.resolve()
    try:
        output.relative_to(library)
    except ValueError:
        pass
    else:
        parser.error("inventory output must be outside the source proof library")
    try:
        inventory = build_inventory(library)
        write_json(output, inventory)
        report = args.report.resolve() if args.report else output.with_suffix(".md")
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(markdown_report(inventory), encoding="utf-8")
    except (OSError, ValueError) as error:
        print(f"inventory failed: {error}", file=sys.stderr)
        return 2
    print(
        f"PP-00 inventory written: {output} "
        f"({inventory['file_count']} files, {len(inventory['families'])} receipt families, "
        f"manifest {inventory['file_manifest_sha256']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
