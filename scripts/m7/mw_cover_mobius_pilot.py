"""Resumable Möbius-chart experiment for M7 covering quartics.

The method searches the same verified 2-cover through alternate rational
coordinates t=(a*z+b)/(c*z+d).  This changes the height geometry seen by
PARI's hyperellratpoints without changing the curve or its rational points.
Every returned point is checked on the transformed quartic, mapped through
the exact covering map, then checked on the original model.

Known generators for N=11 and N=19 are held by the parent validation harness
only.  They are never passed to a search worker.
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
from sage.all import EllipticCurve, QQ, pari


VERSION = "mw-cover-mobius-v1"
BOUNDS = (10**4, 10**5, 10**6)
# Nonidentity GL2(Q) charts plus the original coordinate chart.
CHARTS = (
    ("identity", 1, 0, 0, 1),
    ("reciprocal", 0, 1, 1, 0),
    ("shift_plus_one", 1, 1, 0, 1),
    ("shift_minus_one", 1, -1, 0, 1),
    ("fractional_plus", 1, 0, 1, 1),
    ("fractional_minus", 1, 0, 1, -1),
)
CASES = {
    "11": {"rank": 1, "coefficients": ["0", "1464", "0", "194712", "25896696"]},
    "19": {"rank": 2, "coefficients": ["0", "7240", "0", "2758440", "1050965640"]},
}
VALIDATION_BASES = {
    "11": [{"x": "-8330/9", "y": "473032/27"}],
    "19": [{"x": "-3666", "y": "197412"}, {"x": "-46", "y": "30648"}],
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_json(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def append_jsonl(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()


def latest_records(path):
    latest = {}
    if Path(path).exists():
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                latest[record["attempt_id"]] = record
    return latest


def transformed_cover(curve, minimal, quartic, mapping, chart):
    name, a, b, c, d = chart
    if a * d - b * c == 0:
        raise discovery.DiscoveryError(f"singular Mobius chart: {name}")
    x, y = pari("x"), pari("y")
    numerator = a * x + b
    denominator = c * x + d
    t = numerator / denominator
    transformed_quartic = pari(denominator**4 * pari.subst(quartic, x, t))
    transformed_mapping = []
    for expression in mapping:
        at_t = pari.subst(expression, x, t)
        at_tw = pari.subst(at_t, y, y / denominator**2)
        transformed_mapping.append(at_tw)
    identity = discovery._validate_cover_map(
        curve, minimal, transformed_quartic, transformed_mapping
    )
    return transformed_quartic, transformed_mapping, identity


def search_cover(request_path, config):
    _problem, curve = discovery.load_problem(request_path)
    minimal, _forward, inverse = discovery._minimal_model_data(curve)
    quartic = pari(config["quartic"])
    mapping = pari(config["mapping"])
    base_identity = discovery._validate_cover_map(curve, minimal, quartic, mapping)
    chart = tuple(config["chart"])
    transformed_quartic, transformed_mapping, identity = transformed_cover(
        curve, minimal, quartic, mapping, chart
    )
    results, skipped = [], []
    x = pari("x")
    for raw_point in pari.hyperellratpoints(
        transformed_quartic, int(config["height_bound"])
    ):
        try:
            z, w = raw_point[0], raw_point[1]
            if QQ(w) ** 2 != QQ(pari.subst(transformed_quartic, x, z)):
                skipped.append({"point": str(raw_point), "reason": "off_transformed_cover"})
                continue
            mapped = pari.substvec(transformed_mapping, ["x", "y"], raw_point)
            if len(mapped) != 2:
                skipped.append({"point": str(raw_point), "reason": "malformed_map_output"})
                continue
            minimal_point = minimal([QQ(mapped[0]), QQ(mapped[1])])
            original = discovery._exact_original_point(curve, inverse, minimal_point)
            if original is None:
                skipped.append({"point": str(raw_point), "reason": "map_not_on_original_curve"})
                continue
            exact = curve([QQ(original[0]), QQ(original[1])])
            results.append(discovery.canonical_point(exact))
        except Exception as error:
            skipped.append({"point": str(raw_point), "reason": f"mapping_error:{type(error).__name__}"})
    unique = {(point["x"], point["y"]): point for point in results}
    return {
        "status": "POINT_CANDIDATES" if unique else "NO_NEW_POINTS",
        "points": sorted(unique.values(), key=lambda point: (QQ(point["x"]), QQ(point["y"]))),
        "details": {
            "cover_identity_remainder": base_identity["identity_remainder"],
            "transformed_cover_identity_remainder": identity["identity_remainder"],
            "transformed_quartic": str(transformed_quartic),
            "chart": list(chart),
            "skipped": skipped,
        },
    }


def run_child(request, config, timeout_seconds):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as stream:
        config_path = Path(stream.name)
        json.dump(config, stream)
    try:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--child-config", str(config_path),
             "--request", str(request)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=(os.name == "posix"),
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
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
            return {"status": "TIMEOUT", "points": [], "details": {"stderr": stderr[-4000:]}}
        if process.returncode:
            return {"status": "ERROR", "points": [], "details": {
                "exit_code": process.returncode, "stderr": stderr[-4000:]}}
        try:
            result = json.loads(stdout)
        except Exception as error:
            return {"status": "ERROR", "points": [], "details": {
                "reason": str(error), "stdout": stdout[-4000:], "stderr": stderr[-4000:]}}
        result.setdefault("details", {})["stderr"] = stderr[-4000:]
        return result
    finally:
        config_path.unlink(missing_ok=True)


def inventory(curve):
    data = discovery._cover_backend_data(curve, need_conductor=False)
    if data.get("precision_bits") is None:
        return {"status": "ERROR", "details": {
            "classification": data.get("classification"),
            "precision_attempts": data.get("precision_attempts")}}
    covers = []
    for index, cover in enumerate(data["covers"]):
        quartic, mapping = cover[0], cover[1]
        identity = discovery._validate_cover_map(curve, data["minimal"], quartic, mapping)
        covers.append({"cover_index": index, "quartic": str(quartic), "mapping": str(mapping),
                       "identity_remainder": identity["identity_remainder"]})
    return {"status": "INVENTORY_COMPLETE", "covers": covers,
            "precision_bits": data["precision_bits"],
            "precision_attempts": data["precision_attempts"]}


def run_inventory_child(request, timeout_seconds):
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--inventory-request", str(request)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=(os.name == "posix"),
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.communicate()
        return {"status": "TIMEOUT", "details": {"timeout_seconds": timeout_seconds}}
    if process.returncode:
        return {"status": "ERROR", "details": {"exit_code": process.returncode,
                                                 "stderr": stderr[-4000:]}}
    try:
        return json.loads(stdout)
    except Exception as error:
        return {"status": "ERROR", "details": {"reason": str(error), "stderr": stderr[-4000:]}}


def make_inputs(input_root, output_root):
    root = Path(output_root)
    requests = root / "requests"
    points_root = root / "points"
    requests.mkdir(parents=True, exist_ok=True)
    points_root.mkdir(parents=True, exist_ok=True)
    cases = {}
    for n, fixture in CASES.items():
        request = requests / f"N{n}.json"
        point_file = points_root / f"N{n}.json"
        request_value = {"schema_version": 1, "request_id": f"mobius-N{n}",
                         "problem": {"n": n, "curve_coefficients": fixture["coefficients"]}}
        if request.exists():
            current = discovery.load_problem(request)[0]
            if current["n"] != n or current["curve_coefficients"] != fixture["coefficients"]:
                raise discovery.DiscoveryError(f"saved request identity changed for N={n}")
        else:
            request.write_text(json.dumps(request_value, indent=2) + "\n", encoding="utf-8")
        empty = {"schema_version": 1, "kind": discovery.POINT_FILE_KIND, "n": n,
                 "curve_coefficients": fixture["coefficients"], "points": []}
        if not point_file.exists():
            point_file.write_text(json.dumps(empty, indent=2) + "\n", encoding="utf-8")
        curve = EllipticCurve([int(value) for value in fixture["coefficients"]])
        problem, curve = discovery.load_problem(request)
        retained = discovery.load_point_file(point_file, problem, curve)
        cases[n] = {"request": request, "point_file": point_file,
                    "retained": retained, "validation_basis": VALIDATION_BASES[n],
                    "curve": curve, "rank": fixture["rank"], "covers": []}

    # N=73/N=80 use the exact maps and retained points from the completed
    # pilot. The manifest is read-only and map identities are replayed below.
    previous = Path(input_root)
    audit_root = previous.parent / "mw-05-qualification-audit-20260922"
    cached_manifest_path = previous / "cached-cover-manifest.json"
    if not cached_manifest_path.is_file():
        raise discovery.DiscoveryError("input-root must contain cached-cover-manifest.json")
    cached_manifest = read_json(cached_manifest_path)
    for n, rank in (("73", 1), ("80", 2)):
        request_source = audit_root / "requests" / f"N{n}.json"
        points_source = previous / "points" / f"N{n}.json"
        if not request_source.is_file() or not points_source.is_file():
            raise discovery.DiscoveryError(f"missing retained exact inputs for N={n}")
        request = requests / f"N{n}.json"
        point_file = points_root / f"N{n}.json"
        if not request.exists():
            request.write_bytes(request_source.read_bytes())
        else:
            existing_problem, _existing_curve = discovery.load_problem(request)
            source_problem, _source_curve = discovery.load_problem(request_source)
            if existing_problem["curve_coefficients"] != source_problem["curve_coefficients"]:
                raise discovery.DiscoveryError(f"saved request identity changed for N={n}")
        if not point_file.exists():
            point_file.write_bytes(points_source.read_bytes())
        problem, curve = discovery.load_problem(request)
        retained = discovery.load_point_file(point_file, problem, curve)
        minimal, _forward, _inverse = discovery._minimal_model_data(curve)
        cached = cached_manifest[n]["covers"]
        covers = []
        for key in sorted(cached, key=int):
            entry = cached[key]
            quartic, mapping = pari(entry["quartic"]), pari(entry["mapping"])
            identity = discovery._validate_cover_map(curve, minimal, quartic, mapping)
            if identity["identity_remainder"] != "0" or entry["identity_remainder"] != "0":
                raise discovery.DiscoveryError(f"retained cover identity failed for N={n}")
            covers.append({"cover_index": int(key), "quartic": str(quartic),
                           "mapping": str(mapping), "identity_remainder": "0",
                           "precision_bits": entry["precision_bits"],
                           "source_attempt_id": entry["source_attempt_id"]})
        cases[n] = {"request": request, "point_file": point_file, "retained": retained,
                    "validation_basis": [], "curve": curve, "rank": rank, "covers": covers}
    return cases


def main(argv=None):
    parser = argparse.ArgumentParser(description="resumable Mobius-chart covering pilot")
    parser.add_argument("--input-root")
    parser.add_argument("--output-root")
    parser.add_argument("--attempt-timeout-seconds", type=int, default=120)
    parser.add_argument("--overall-budget-seconds", type=int, default=1800)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--child-config")
    parser.add_argument("--request")
    parser.add_argument("--inventory-request")
    args = parser.parse_args(argv)
    if args.child_config:
        result = search_cover(args.request, read_json(args.child_config))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    if args.inventory_request:
        _problem, curve = discovery.load_problem(args.inventory_request)
        print(json.dumps(inventory(curve), sort_keys=True, separators=(",", ":")))
        return 0
    if not args.input_root or not args.output_root:
        raise discovery.DiscoveryError("--input-root and --output-root are required")
    output = Path(args.output_root)
    output.mkdir(parents=True, exist_ok=True)
    journal = output / "mobius-pilot.jsonl"
    matrix_path = output / "experiment-matrix.json"
    cases = make_inputs(args.input_root, output)
    source_matrix = read_json(Path(args.input_root) / "experiment-matrix.json")
    source_hashes = source_matrix.get("input_identities_and_sha256", {})
    input_identities = {}
    for n, case in cases.items():
        if n in CASES:
            input_identities[n] = {
                "source": "withheld-generator-control; empty search seed",
                "request_sha256": sha256_file(case["request"]),
                "n": n,
                "curve_coefficients": [str(value) for value in case["curve"].a_invariants()],
                "initial_search_seed_points": [],
                "validation_basis_sha256": sha256_json(case["validation_basis"]),
            }
        else:
            source = source_hashes.get(n)
            if source is None:
                raise discovery.DiscoveryError(f"source input hashes missing for N={n}")
            input_identities[n] = {
                "source": "retained unresolved-case qualification inputs",
                "request_sha256": source["request_sha256"],
                "point_file_sha256": source["point_file_sha256"],
                "n": n,
                "curve_coefficients": [str(value) for value in case["curve"].a_invariants()],
                "initial_search_seed_count": int(source["retained_point_count"]),
            }
    inventory_records = {}
    prior_matrix = read_json(matrix_path) if matrix_path.exists() and args.resume else None
    if prior_matrix is not None:
        inventory_records = prior_matrix.get("cover_inventory", {})
        for n in CASES:
            result = inventory_records.get(n, {})
            if result.get("status") != "INVENTORY_COMPLETE":
                raise discovery.DiscoveryError(f"saved cover inventory missing for N={n}")
            minimal, _forward, _inverse = discovery._minimal_model_data(cases[n]["curve"])
            for cover in result["covers"]:
                identity = discovery._validate_cover_map(
                    cases[n]["curve"], minimal, pari(cover["quartic"]), pari(cover["mapping"])
                )
                if identity["identity_remainder"] != "0":
                    raise discovery.DiscoveryError(f"saved cover identity failed for N={n}")
            cases[n]["covers"] = result["covers"]
    else:
        for n in CASES:
            result = run_inventory_child(cases[n]["request"], args.attempt_timeout_seconds)
            inventory_records[n] = result
            if result.get("status") != "INVENTORY_COMPLETE":
                raise discovery.DiscoveryError(f"cover inventory for N={n} ended {result.get('status')}")
            cases[n]["covers"] = result["covers"]
    matrix = []
    for n, case in cases.items():
        for cover in case["covers"]:
            for chart in CHARTS:
                for bound in BOUNDS:
                    chart_name = chart[0]
                    matrix.append({
                        "n": n, "rank_target": case["rank"],
                        "cover_index": cover["cover_index"],
                        "cover_source_attempt_id": cover.get("source_attempt_id"),
                        "chart": chart_name, "chart_parameters": list(chart[1:]),
                        "height_bound": bound,
                        "budget_seconds": args.attempt_timeout_seconds,
                        "attempt_id": f"N{n}-cover{cover['cover_index']}-{chart_name}-H{bound}",
                    })
    matrix_value = {
        "script_version": VERSION, "created_utc": utc_now(),
        "attempt_timeout_seconds": args.attempt_timeout_seconds,
        "overall_budget_seconds": args.overall_budget_seconds,
        "experimental_bounds": list(BOUNDS), "charts": [list(c) for c in CHARTS],
        "withheld_validation_bases": VALIDATION_BASES,
        "input_identities": input_identities,
        "cover_inventory": inventory_records, "matrix": matrix,
    }
    if matrix_path.exists():
        if not args.resume:
            raise discovery.DiscoveryError("matrix already exists; pass --resume")
        previous = read_json(matrix_path)
        for key in ("script_version", "experimental_bounds", "charts", "withheld_validation_bases",
                    "cover_inventory", "matrix", "input_identities"):
            if key not in previous and key == "input_identities":
                continue
            if previous.get(key) != matrix_value.get(key):
                raise discovery.DiscoveryError(f"resume matrix mismatch at {key}; use a new output root")
        if "input_identities" not in previous:
            matrix_value["created_utc"] = previous.get("created_utc", matrix_value["created_utc"])
            matrix_path.write_text(json.dumps(matrix_value, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
    else:
        matrix_path.write_text(json.dumps(matrix_value, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    if journal.exists() and not args.resume:
        raise discovery.DiscoveryError("journal already exists; pass --resume")

    state = latest_records(journal)
    for attempt_id, record in list(state.items()):
        if record.get("status") == "STARTED":
            interrupted = {**record, "status": "INTERRUPTED", "finished_utc": utc_now(),
                           "reason": "resume found no terminal record"}
            append_jsonl(journal, interrupted)
            state[attempt_id] = interrupted
    started = time.monotonic()
    for item in matrix:
        n = item["n"]
        prior = state.get(item["attempt_id"], {})
        if prior.get("status") in {"NO_POINT_WITHIN_BOUND", "POINT_CANDIDATES",
                                    "REQUIRED_INDEPENDENT_SUBGROUP_ESTABLISHED",
                                    "SKIPPED_RANK_ESTABLISHED"}:
            continue
        established = any(r.get("n") == n and r.get("rank_check", {}).get("status")
                          == "required_independent_subgroup_established"
                          for r in state.values())
        if established:
            append_jsonl(journal, {"attempt_id": item["attempt_id"], "n": n,
                                   "status": "SKIPPED_RANK_ESTABLISHED", "utc": utc_now()})
            continue
        if time.monotonic() - started >= args.overall_budget_seconds:
            break
        cover = cases[n]["covers"][item["cover_index"]]
        chart = next(c for c in CHARTS if c[0] == item["chart"])
        config = {**item, "chart": [chart[0], *chart[1:]],
                  "quartic": cover["quartic"], "mapping": cover["mapping"],
                  "precision_bits": cover.get("precision_bits") or inventory_records.get(n, {}).get("precision_bits")}
        append_jsonl(journal, {**item, "script_version": VERSION, "status": "STARTED",
                               "started_utc": utc_now(), "restart_after_prior_attempt": prior.get("status")
                               in {"TIMEOUT", "INTERRUPTED", "ERROR", "STARTED"},
                               "cover_identity_remainder": cover["identity_remainder"]})
        attempt_started = time.monotonic()
        result = run_child(cases[n]["request"], config, args.attempt_timeout_seconds)
        elapsed = time.monotonic() - attempt_started
        if result.get("status") not in {"POINT_CANDIDATES", "NO_NEW_POINTS"} or (
            result.get("details", {}).get("cover_identity_remainder") != "0" or
            result.get("details", {}).get("transformed_cover_identity_remainder") != "0"
        ):
            status = result.get("status", "ERROR")
            points = []
        else:
            points = [discovery.canonical_point(discovery._require_point_record(cases[n]["curve"], p))
                      for p in result.get("points", [])]
            status = "POINT_CANDIDATES" if points else "NO_POINT_WITHIN_BOUND"
        retained = cases[n]["retained"]
        merged = discovery._merge_points(cases[n]["curve"], retained, points)
        pool = [discovery._require_point_record(cases[n]["curve"], point)
                for point in merged]
        try:
            selected, witness = mw02.select_independent_subset(
                cases[n]["curve"], pool, cases[n]["rank"], prime_bound=1000
            )
            rank_check = {"status": "required_independent_subgroup_established",
                          "selected_points": [discovery.canonical_point(p) for p in selected],
                          "independence_witness": witness}
        except (mw02.IndependenceUnresolved, mw02.RankContradiction, ValueError) as error:
            rank_check = {"status": "new_coordinates_independence_unresolved",
                          "reason": str(error), "pool_count": len(pool)}
        record = {**item, "script_version": VERSION, "status": status,
                  "worker_status": result.get("status"), "elapsed_seconds": round(elapsed, 3),
                  "finished_utc": utc_now(), "points": points,
                  "new_coordinate_count": len(points), "retained_point_count": len(merged),
                  "rank_check": rank_check, "worker_details": result.get("details", {})}
        append_jsonl(journal, record)
        state[item["attempt_id"]] = record
        if points:
            point_file = cases[n]["point_file"]
            discovery.publish_point_file(point_file, {"n": n, "curve_coefficients":
                [str(v) for v in cases[n]["curve"].a_invariants()]}, merged)
            cases[n]["retained"] = merged
        print(json.dumps({"attempt_id": item["attempt_id"], "status": status,
                          "elapsed_seconds": round(elapsed, 3),
                          "point_count": len(points), "rank_status": rank_check["status"]},
                         sort_keys=True), flush=True)
    latest = latest_records(journal)
    summary = {n: {"status": "required_independent_subgroup_established"
                   if any(r.get("n") == n and r.get("rank_check", {}).get("status")
                          == "required_independent_subgroup_established" for r in latest.values())
                   else "inconclusive",
                   "latest_attempts": [r for r in latest.values() if r.get("n") == n]}
               for n in cases}
    (output / "pilot-summary.json").write_text(json.dumps({
        "script_version": VERSION, "completed_utc": utc_now(), "cases": summary,
        "note": "bounded discovery only; no theorem admission or completeness claim"},
        indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except discovery.DiscoveryError as error:
        print(json.dumps({"status": "ERROR", "error": str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
