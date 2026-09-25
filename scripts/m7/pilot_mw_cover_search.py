"""Resumable covering and PARI pilot for unresolved N=73 and N=80.

Run this with the pinned Sage Python. Each matrix row is one bounded search
invocation. The journal is research evidence only; it never creates a theorem
admission or claims a finite-height search is complete. The optional PARI arm
uses new seeds 13, 17, 19 and efforts 24, 32 at 256-bit precision.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

import discover_mw_points as discovery
import mw02_rank_basis as mw02
from sage.all import EllipticCurve, QQ, ZZ, pari


BOUNDS = (10**7, 10**8, 10**9)
CASE_MATRIX = {"73": {"rank": 1, "covers": 1}, "80": {"rank": 2, "covers": 2}}
SCRIPT_VERSION = "mw-search-pilot-v3"
PARI_ARM = tuple(
    {"n": n, "rank": case["rank"], "method": "pari_seeded", "effort": effort,
     "seed": seed, "precision": 256, "budget_seconds": 600,
     "attempt_id": f"N{n}-pari-e{effort}-s{seed}-p256"}
    for n, case in CASE_MATRIX.items()
    for effort in (24, 32)
    for seed in (13, 17, 19)
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def append_jsonl(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()


def latest_records(path):
    latest = {}
    if not Path(path).exists():
        return latest
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            value = json.loads(line)
            latest[value["attempt_id"]] = value
    return latest


def make_matrix(include_pari=False, include_cached=False):
    covering = [
        {"n": n, "rank": case["rank"], "cover_index": cover, "height_bound": bound,
         "method": "cover", "budget_seconds": 600,
         "attempt_id": f"N{n}-cover-{cover}-height-{bound}"}
        for n, case in CASE_MATRIX.items()
        for cover in range(case["covers"])
        for bound in BOUNDS
    ]
    cached = [
        {"n": n, "rank": case["rank"], "cover_index": cover, "height_bound": bound,
         "method": "cover_cached", "budget_seconds": 600,
         "attempt_id": f"cached-N{n}-cover-{cover}-height-{bound}"}
        for n, case in CASE_MATRIX.items()
        for cover in range(case["covers"])
        for bound in BOUNDS
    ] if include_cached else []
    return covering + cached + (list(PARI_ARM) if include_pari else [])


def point_pool(problem, curve, retained, discovered):
    records = discovery._merge_points(curve, retained, discovered)
    return [discovery._require_point_record(curve, value) for value in records], records


def classify_pool(curve, pool, required_rank):
    if len(pool) < required_rank:
        return {"status": "new_coordinates_independence_unresolved",
                "candidate_count": len(pool)}
    try:
        selected, witness = mw02.select_independent_subset(
            curve, pool, required_rank, prime_bound=1000
        )
    except mw02.RankContradiction as error:
        return {"status": "rank_contradiction", "reason": str(error)}
    except (mw02.IndependenceUnresolved, ValueError) as error:
        return {"status": "new_coordinates_independence_unresolved",
                "candidate_count": len(pool), "reason": str(error)}
    return {
        "status": "required_independent_subgroup_established",
        "selected_points": [discovery.canonical_point(point) for point in selected],
        "independence_witness": witness,
    }


def load_case(input_root, pilot_root, n):
    source = Path(input_root)
    request = source / "requests" / f"N{n}.json"
    points = source / "points" / f"N{n}.json"
    if not request.is_file() or not points.is_file():
        raise discovery.DiscoveryError(f"missing retained request or point file for N={n}")
    problem, curve = discovery.load_problem(request)
    destination = Path(pilot_root) / "points" / f"N{n}.json"
    source_points = destination if destination.is_file() else points
    retained_records = discovery.load_point_file(source_points, problem, curve)
    if not destination.is_file():
        discovery.publish_point_file(destination, problem, retained_records)
    return problem, curve, request, destination, retained_records


def load_cached_covers(input_root, n, curve, expected_count):
    """Load prior exact cover expressions and verify identities on this model."""

    journal = Path(input_root) / "journals" / f"N{n}.jsonl"
    if not journal.is_file():
        raise discovery.DiscoveryError(f"missing retained discovery journal for N={n}")
    candidates = {}
    for line in journal.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        attempt_id = record.get("attempt_id", "")
        if not attempt_id.startswith("cover-") or not record.get("details", {}).get("cover"):
            continue
        try:
            cover_index = int(attempt_id.split("-")[1])
        except Exception:
            continue
        candidates[cover_index] = record
    minimal = curve.minimal_model()
    verified = {}
    for cover_index in range(expected_count):
        source = candidates.get(cover_index)
        if source is None:
            raise discovery.DiscoveryError(
                f"no completed retained cover data for N={n}, cover={cover_index}"
            )
        cover = source["details"]["cover"]
        quartic = pari(cover["quartic"])
        mapping = pari(cover["mapping"])
        identity = discovery._validate_cover_map(curve, minimal, quartic, mapping)
        if identity["identity_remainder"] != "0":
            raise discovery.DiscoveryError(
                f"retained cover map identity failed for N={n}, cover={cover_index}"
            )
        verified[cover_index] = {
            "quartic": cover["quartic"], "mapping": cover["mapping"],
            "precision_bits": source.get("details", {}).get("precision_bits"),
            "source_attempt_id": source["attempt_id"],
            "source_schedule_version": source.get("schedule_version"),
            "identity_remainder": identity["identity_remainder"],
        }
    return verified


def cached_cover_search(request, config):
    problem, curve = discovery.load_problem(request)
    minimal, _forward, inverse = discovery._minimal_model_data(curve)
    quartic = pari(config["quartic"])
    mapping = pari(config["mapping"])
    map_record = discovery._validate_cover_map(curve, minimal, quartic, mapping)
    results, skipped = [], []
    variable = pari("x")
    for raw_point in pari.hyperellratpoints(quartic, int(config["height_bound"])):
        try:
            t, v = raw_point[0], raw_point[1]
            if QQ(v) ** 2 != QQ(pari.subst(quartic, variable, t)):
                skipped.append({"point": str(raw_point), "reason": "off_cover"})
                continue
            mapped = pari.substvec(mapping, ["x", "y"], raw_point)
            if len(mapped) != 2:
                skipped.append({"point": str(raw_point), "reason": "malformed_map_output"})
                continue
            minimal_point = minimal([QQ(mapped[0]), QQ(mapped[1])])
            original = discovery._exact_original_point(curve, inverse, minimal_point)
            if original is None:
                skipped.append({"point": str(raw_point), "reason": "map_not_on_original_curve"})
                continue
            results.append(discovery.canonical_point(curve([QQ(original[0]), QQ(original[1])])) )
        except Exception as error:
            skipped.append({"point": str(raw_point), "reason": f"undefined_map:{type(error).__name__}"})
    return {
        "status": "POINT_CANDIDATES" if results else "NO_NEW_POINTS",
        "points": results,
        "details": {
            "cover": map_record, "skipped": skipped,
            "precision_bits": config.get("precision_bits"),
            "cover_cache_source_attempt_id": config.get("source_attempt_id"),
        },
    }


def run_cached_child(request, config, timeout_seconds):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as stream:
        config_path = Path(stream.name)
        json.dump(config, stream)
    try:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--child-config",
             str(config_path), "--request", str(request)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=(os.name == "posix"),
        )
        try:
            stdout, stderr = process.communicate(timeout=float(timeout_seconds))
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    process.kill()
            stdout, stderr = process.communicate()
            return {"status": "TIMEOUT", "points": [],
                    "details": {"timeout_seconds": timeout_seconds,
                                "stderr": stderr[-4000:]}}
        if process.returncode != 0:
            return {"status": "ERROR", "points": [], "details": {
                "exit_code": process.returncode, "stderr": stderr[-4000:]}}
        try:
            result = json.loads(stdout)
        except Exception as error:
            return {"status": "ERROR", "points": [], "details": {
                "reason": f"malformed child response: {error}", "stderr": stderr[-4000:]}}
        result.setdefault("details", {})["stderr"] = stderr[-4000:]
        return result
    finally:
        config_path.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="resumable bounded MW covering pilot")
    parser.add_argument("--input-root",
                        help="prior qualification directory containing requests/ and points/")
    parser.add_argument("--output-root",
                        help="separate pilot evidence directory")
    parser.add_argument("--attempt-timeout-seconds", type=int, default=600)
    parser.add_argument("--overall-budget-seconds", type=int, default=7200)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--include-pari-arm", action="store_true",
                        help="also compare fresh higher-effort seeded PARI attempts")
    parser.add_argument("--include-cached-covers", action="store_true",
                        help="search retained, identity-checked cover maps without rebuilding them")
    parser.add_argument("--only-pari-arm", action="store_true",
                        help="run only the separate PARI arm after covering attempts")
    parser.add_argument("--only-cached-covers", action="store_true",
                        help="run only the cached-cover arm")
    parser.add_argument("--validate-inputs-only", action="store_true",
                        help="load retained points and verify cached cover identities, then exit")
    parser.add_argument("--child-config")
    parser.add_argument("--request")
    args = parser.parse_args(argv)
    if args.child_config:
        result = cached_cover_search(args.request, read_json(args.child_config))
        json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    if not args.input_root or not args.output_root:
        raise discovery.DiscoveryError("--input-root and --output-root are required")
    if args.attempt_timeout_seconds != 600:
        raise discovery.DiscoveryError("the pilot matrix fixes each covering attempt at 600 seconds")
    if args.overall_budget_seconds <= 0:
        raise discovery.DiscoveryError("overall budget must be positive")

    output_root = Path(args.output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    journal = output_root / "pilot.jsonl"
    matrix_path = output_root / "experiment-matrix.json"
    matrix = make_matrix(args.include_pari_arm, args.include_cached_covers)
    active_matrix = matrix
    if args.only_pari_arm:
        if not args.include_pari_arm:
            raise discovery.DiscoveryError("--only-pari-arm requires --include-pari-arm")
        active_matrix = list(PARI_ARM)
    if args.only_cached_covers:
        if not args.include_cached_covers:
            raise discovery.DiscoveryError("--only-cached-covers requires --include-cached-covers")
        active_matrix = [item for item in matrix if item["method"] == "cover_cached"]
    inputs = {}
    for n in CASE_MATRIX:
        source = Path(args.input_root)
        request = source / "requests" / f"N{n}.json"
        point_file = source / "points" / f"N{n}.json"
        request_value = read_json(request)
        inputs[n] = {
            "request_path": str(request.resolve()), "request_sha256": sha256_file(request),
            "point_file_path": str(point_file.resolve()), "point_file_sha256": sha256_file(point_file),
            "n": request_value["problem"]["n"],
            "curve_coefficients": request_value["problem"]["curve_coefficients"],
            "retained_point_count": len(read_json(point_file)["points"]),
        }
    matrix_path.write_text(json.dumps({
        "script_version": SCRIPT_VERSION,
        "created_utc": utc_now(),
        "input_root": str(Path(args.input_root).resolve()),
        "attempt_timeout_seconds": args.attempt_timeout_seconds,
        "overall_budget_seconds": args.overall_budget_seconds,
        "pari_arm_included": args.include_pari_arm,
        "pari_arm": list(PARI_ARM) if args.include_pari_arm else [],
        "cached_cover_arm_included": args.include_cached_covers,
        "input_identities_and_sha256": inputs,
        "bounds_are_experimental": True,
        "matrix": matrix,
        "selected_attempt_ids": [item["attempt_id"] for item in active_matrix],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if journal.exists() and not args.resume:
        raise discovery.DiscoveryError("pilot journal exists; pass --resume to continue")

    case_data = {}
    for n in CASE_MATRIX:
        case_data[n] = load_case(args.input_root, output_root, n)
        problem, curve, _request, _output_points, retained = case_data[n]
        cached_covers = load_cached_covers(
            args.input_root, n, curve, CASE_MATRIX[n]["covers"]
        ) if args.include_cached_covers else {}
        pool, _records = point_pool(problem, curve, retained, [])
        case_data[n] = (*case_data[n], pool, cached_covers)
    if args.validate_inputs_only:
        if not args.include_cached_covers:
            raise discovery.DiscoveryError("input validation requires --include-cached-covers")
        manifest = {
            n: {
                "curve_coefficients": list(case_data[n][0]["curve_coefficients"]),
                "retained_point_count": len(case_data[n][4]),
                "covers": case_data[n][6],
            }
            for n in CASE_MATRIX
        }
        (output_root / "cached-cover-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        json.dump({"status": "INPUTS_VALIDATED", "cases": manifest}, sys.stdout,
                  sort_keys=True)
        sys.stdout.write("\n")
        return 0

    state = latest_records(journal)
    for attempt_id, prior in list(state.items()):
        if prior.get("status") == "STARTED":
            interrupted = {
                **prior,
                "status": "INTERRUPTED",
                "finished_utc": utc_now(),
                "reason": "resume found an attempt without a terminal journal record",
            }
            append_jsonl(journal, interrupted)
            state[attempt_id] = interrupted
    started = time.monotonic()
    summary = {}
    for n in CASE_MATRIX:
        established = next((record for record in reversed(list(state.values()))
                            if record.get("n") == n
                            and record.get("rank_check", {}).get("status")
                            == "required_independent_subgroup_established"), None)
        if established is not None:
            summary[n] = established["rank_check"]
    for item in active_matrix:
        n = item["n"]
        if summary.get(n, {}).get("status") == "required_independent_subgroup_established":
            append_jsonl(journal, {
                "script_version": SCRIPT_VERSION, "attempt_id": item["attempt_id"],
                "n": n, "status": "SKIPPED_RANK_ESTABLISHED", "utc": utc_now(),
            })
            continue
        prior = state.get(item["attempt_id"], {})
        if prior.get("status") in {
            "NO_POINT_WITHIN_BOUND", "NO_POINT_FROM_ATTEMPT", "NO_NEW_COORDINATES_WITHIN_BOUND",
            "new_coordinates_independence_unresolved",
            "required_independent_subgroup_established", "SKIPPED_RANK_ESTABLISHED",
        }:
            continue
        if time.monotonic() - started >= args.overall_budget_seconds:
            break
        problem, curve, request, output_points, retained, pool, cached_covers = case_data[n]
        config = dict(item)
        if item["method"] == "cover_cached":
            config.update(cached_covers[item["cover_index"]])
        restart = prior.get("status") in {"TIMEOUT", "INTERRUPTED", "STARTED", "ERROR"}
        append_jsonl(journal, {
            "script_version": SCRIPT_VERSION, "attempt_id": item["attempt_id"],
            "n": n, "rank_target": item["rank"], "method": item["method"],
            "cover_index": item.get("cover_index"), "height_bound": item.get("height_bound"),
            "effort": item.get("effort"), "seed": item.get("seed"),
            "precision": item.get("precision"), "budget_seconds": 600,
            "cover_map_source_attempt_id": config.get("source_attempt_id"),
            "cover_map_source_precision_bits": config.get("precision_bits"),
            "cover_map_identity_remainder": config.get("identity_remainder"),
            "started_utc": utc_now(), "status": "STARTED",
            "restart_after_prior_attempt": bool(restart),
            "prior_status": prior.get("status"),
        })
        attempt_started = time.monotonic()
        try:
            if item["method"] == "cover_cached":
                result = run_cached_child(request, config, 600)
            else:
                result = discovery._run_child(
                    request,
                    config,
                    [discovery.canonical_point(point) for point in pool],
                    min(600, args.attempt_timeout_seconds),
                )
        except KeyboardInterrupt:
            result = {"status": "INTERRUPTED", "points": [],
                      "details": {"reason": "pilot process interrupted"}}
        elapsed = time.monotonic() - attempt_started
        status = result.get("status", "ERROR")
        additions = []
        details = result.get("details", {})
        identity_ok = (item["method"] not in {"cover", "cover_cached"} or
                       details.get("cover", {}).get("identity_remainder") == "0")
        if status in {"POINT_CANDIDATES", "NO_NEW_POINTS"} and not identity_ok:
            status = "ERROR"
            details["validation_error"] = "cover/map exact identity validation missing"
        previous_keys = {(value["x"], value["y"]) for value in retained}
        if status == "POINT_CANDIDATES":
            additions = [
                discovery.canonical_point(discovery._require_point_record(curve, record))
                for record in result.get("points", [])
            ]
            pool, merged_records = point_pool(problem, curve, retained, additions)
            discovery.publish_point_file(output_points, problem, merged_records)
        else:
            merged_records = retained
        rank_result = classify_pool(curve, pool, item["rank"])
        new_coordinate_count = sum(
            (value["x"], value["y"]) not in previous_keys for value in additions
        )
        if status == "NO_NEW_POINTS":
            reported_status = ("NO_POINT_WITHIN_BOUND" if item["method"] in {"cover", "cover_cached"}
                               else "NO_POINT_FROM_ATTEMPT")
        elif status == "POINT_CANDIDATES":
            if rank_result["status"] == "required_independent_subgroup_established":
                reported_status = rank_result["status"]
            elif new_coordinate_count:
                reported_status = "new_coordinates_independence_unresolved"
            else:
                reported_status = "NO_NEW_COORDINATES_WITHIN_BOUND"
        else:
            reported_status = status
        record = {
            "script_version": SCRIPT_VERSION, "attempt_id": item["attempt_id"],
            "n": n, "rank_target": item["rank"], "method": item["method"],
            "cover_index": item.get("cover_index"), "height_bound": item.get("height_bound"),
            "effort": item.get("effort"), "seed": item.get("seed"),
            "precision": item.get("precision"), "budget_seconds": 600,
            "elapsed_seconds": round(elapsed, 3), "finished_utc": utc_now(),
            "status": reported_status, "worker_status": status,
            "restart_after_prior_attempt": bool(restart),
            "precision_bits": details.get("precision_bits"),
            "cover_precision_policy_bits": [128, 256, 512]
            if item["method"] in {"cover", "cover_cached"} else None,
            "precision_attempts": details.get("precision_attempts", []),
            "cover": details.get("cover"), "returned_point_count": len(additions),
            "new_coordinate_count": new_coordinate_count,
            "retained_point_count": len(merged_records), "points": additions,
            "rank_check": rank_result, "worker_details": details,
        }
        append_jsonl(journal, record)
        state[item["attempt_id"]] = record
        case_data[n] = (problem, curve, request, output_points, merged_records, pool, cached_covers)
        if rank_result["status"] == "required_independent_subgroup_established":
            summary[n] = rank_result
        elif n not in summary:
            summary[n] = {"status": reported_status,
                          "retained_point_count": len(merged_records)}
        json.dump({"n": n, "attempt_id": item["attempt_id"], "method": item["method"],
                   "status": reported_status,
                   "elapsed_seconds": round(elapsed, 3), "returned_point_count": len(additions),
                   "new_coordinate_count": new_coordinate_count,
                   "rank_status": rank_result["status"]}, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        sys.stdout.flush()

    for n in CASE_MATRIX:
        if n in summary and summary[n].get("status") == "required_independent_subgroup_established":
            continue
        completed = [record for record in state.values() if record.get("n") == n
                     and record.get("status") != "STARTED"]
        if completed:
            last = max(completed, key=lambda record: record.get("finished_utc", ""))
            summary[n] = {"status": last.get("status"),
                          "retained_point_count": last.get("retained_point_count", 0)}

    output = {
        "script_version": SCRIPT_VERSION,
        "status": "RECORDED",
        "completed_utc": utc_now(),
        "attempts": latest_records(journal),
        "cases": summary,
        "note": "bounded search only; no completeness or family theorem is asserted",
    }
    (output_root / "pilot-summary.json").write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except discovery.DiscoveryError as error:
        print(json.dumps({"status": "ERROR", "error": str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
