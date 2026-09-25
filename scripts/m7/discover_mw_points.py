"""MW-03 bounded Mordell--Weil point discovery driver.

This is a research driver only.  It retains exact original-model point
candidates and resumable attempt evidence.  It never creates an admission,
rank certificate, complete point set, ``CERTIFIED_EMPTY`` result, or
``CERTIFIED_SOLUTIONS`` result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from sage.all import EllipticCurve, Integer, QQ, ZZ, pari


POINT_FILE_KIND = "m7_mw_point_candidates"
POINT_FILE_SCHEMA_VERSION = 1
JOURNAL_SCHEMA_VERSION = 1
# v2 adds positive-rank cover inventory to rank-two discovery and records the
# explicit precision ladder used by cover inventory/reconstruction.  Journals
# from v1 remain readable so an interrupted campaign can be resumed; newly
# appended records and summaries use v2.
SCHEDULE_VERSION = "mw03-discovery-v2"
LEGACY_SCHEDULE_VERSIONS = {"mw03-discovery-v1"}
COVER_PRECISIONS = (128, 256, 512)
TERMINAL_STATUSES = {
    "POINT_CANDIDATES",
    "NO_NEW_POINTS",
    "RANK_PROVEN",
    "SKIPPED_CONDUCTOR_POLICY",
    "SKIPPED_RANK_POLICY",
    "SKIPPED_UNSUPPORTED_API",
}
RETRYABLE_STATUSES = {"TIMEOUT", "ERROR", "INTERRUPTED"}
INVENTORY_TERMINAL_STATUSES = {"INVENTORY_COMPLETE"}


class DiscoveryError(RuntimeError):
    """Malformed identity, journal or research input."""


def _canonical_integer(value):
    if not isinstance(value, str):
        raise DiscoveryError("integer must be a canonical decimal string")
    integer = ZZ(value)
    if str(integer) != value:
        raise DiscoveryError("integer is not canonical")
    return integer


def _canonical_rational(value):
    if not isinstance(value, str):
        raise DiscoveryError("rational must be a string")
    parts = value.split("/")
    if len(parts) > 2 or any(part == "" for part in parts):
        raise DiscoveryError("rational must be p or p/q")
    numerator = _canonical_integer(parts[0])
    denominator = ZZ(1) if len(parts) == 1 else _canonical_integer(parts[1])
    if denominator <= 0 or (len(parts) == 2 and denominator == 1):
        raise DiscoveryError("rational denominator is not canonical")
    if numerator.gcd(denominator) != 1:
        raise DiscoveryError("rational is not reduced")
    rational = QQ(numerator) / QQ(denominator)
    rendered = str(rational.numerator())
    if rational.denominator() != 1:
        rendered += f"/{rational.denominator()}"
    if rendered != value:
        raise DiscoveryError("rational is not canonical")
    return rational


def _rational_text(value):
    value = QQ(value)
    if value.denominator() == 1:
        return str(value.numerator())
    return f"{value.numerator()}/{value.denominator()}"


def load_problem(request_path):
    request_path = Path(request_path)
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except Exception as error:
        raise DiscoveryError(f"could not load request: {error}") from error
    if not isinstance(request, dict) or not isinstance(request.get("problem"), dict):
        raise DiscoveryError("request.problem must be an object")
    problem = request["problem"]
    n = _canonical_integer(problem.get("n"))
    coefficients = problem.get("curve_coefficients")
    if not isinstance(coefficients, list) or len(coefficients) != 5:
        raise DiscoveryError("problem.curve_coefficients must contain five integers")
    coefficients = [_canonical_integer(value) for value in coefficients]
    curve = EllipticCurve(coefficients)
    if [ZZ(value) for value in curve.a_invariants()] != coefficients:
        raise DiscoveryError("Sage changed the exact curve coefficients")
    identity = {
        "n": str(n),
        "curve_coefficients": [str(value) for value in coefficients],
    }
    return {**problem, **identity}, curve


def canonical_point(point):
    if point.is_zero():
        raise DiscoveryError("point at infinity is not an affine candidate")
    return {"x": _rational_text(point[0]), "y": _rational_text(point[1])}


def validate_point_record(curve, record):
    if not isinstance(record, dict) or set(record) != {"x", "y"}:
        return None
    try:
        point = curve([_canonical_rational(record["x"]), _canonical_rational(record["y"])])
    except Exception:
        return None
    if point.is_zero():
        return None
    return point


def _require_point_record(curve, record):
    point = validate_point_record(curve, record)
    if point is None:
        raise DiscoveryError("candidate point is malformed or off the exact curve")
    if canonical_point(point) != record:
        raise DiscoveryError("candidate point is not canonical")
    return point


def _identity_from_problem(problem):
    return {
        "n": problem["n"],
        "curve_coefficients": list(problem["curve_coefficients"]),
    }


def _point_sort_key(record):
    return (QQ(record["x"]), QQ(record["y"]))


def load_point_file(path, problem, curve):
    path = Path(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise DiscoveryError(f"could not load point file: {error}") from error
    if not isinstance(value, dict):
        raise DiscoveryError("point file must be an object")
    if value.get("kind") != POINT_FILE_KIND or value.get("schema_version") != POINT_FILE_SCHEMA_VERSION:
        raise DiscoveryError("unsupported point-file schema")
    if _identity_from_problem(value) != _identity_from_problem(problem):
        raise DiscoveryError("point-file problem identity mismatch")
    raw_points = value.get("points")
    if not isinstance(raw_points, list):
        raise DiscoveryError("point file points must be a list")
    result = {}
    for raw in raw_points:
        point = _require_point_record(curve, raw)
        result[tuple(canonical_point(point).values())] = canonical_point(point)
    return list(result.values())


def publish_point_file(path, problem, points):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    deduplicated = {
        (record["x"], record["y"]): record for record in points
    }
    ordered = sorted(deduplicated.values(), key=_point_sort_key)
    value = {
        "kind": POINT_FILE_KIND,
        "schema_version": POINT_FILE_SCHEMA_VERSION,
        "n": problem["n"],
        "curve_coefficients": list(problem["curve_coefficients"]),
        "points": ordered,
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def append_journal_record(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def load_journal_state(path, identity):
    path = Path(path)
    state = {}
    if not path.exists():
        return state
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception as error:
            raise DiscoveryError(f"malformed journal line {line_number}") from error
        if (
            record.get("journal_schema_version") != JOURNAL_SCHEMA_VERSION
            or record.get("schedule_version") not in {
                SCHEDULE_VERSION, *LEGACY_SCHEDULE_VERSIONS
            }
            or record.get("identity") != identity
            or not isinstance(record.get("attempt_id"), str)
        ):
            raise DiscoveryError(f"journal identity/schema mismatch at line {line_number}")
        state[record["attempt_id"]] = record
    return state


def pending_attempts(schedule, state):
    return [
        item for item in schedule
        if state.get(item["attempt_id"], {}).get("status") not in TERMINAL_STATUSES
    ]


def make_schedule(rank, cover_count, conductor, *, conductor_cap=10**12, cover_bounds=(10**4, 10**5, 10**6)):
    """Return a deterministic, finite research schedule."""

    schedule = []
    for effort in (8, 16):
        for seed in (2, 3, 5, 7, 11):
            schedule.append({
                "attempt_id": f"pari-seeded-e{effort}-s{seed}-p128",
                "method": "pari_seeded",
                "effort": effort,
                "seed": seed,
                "precision": 128,
            })
    if rank == 1:
        if conductor is not None and int(conductor) <= int(conductor_cap):
            schedule.append({
                "attempt_id": "heegner-conductor-capped",
                "method": "heegner",
                "conductor_cap": int(conductor_cap),
                "analytic_rank_one_hypothesis": True,
            })
        else:
            schedule.append({
                "attempt_id": "heegner-conductor-policy-skip",
                "method": "heegner",
                "skip_status": "SKIPPED_CONDUCTOR_POLICY",
                "conductor_cap": int(conductor_cap),
            })
    for cover_index in range(int(cover_count)):
        for bound in tuple(int(value) for value in cover_bounds):
            schedule.append({
                "attempt_id": f"cover-{cover_index}-height-{bound}",
                "method": "cover",
                "cover_index": cover_index,
                "height_bound": bound,
            })
    return schedule


def _minimal_model_data(curve):
    minimal = curve.minimal_model()
    forward = curve.isomorphism_to(minimal)
    inverse = minimal.isomorphism_to(curve)
    return minimal, forward, inverse


def _fresh_exact_curve(curve):
    """Rebuild the exact curve for a precision retry.

    PARI precision is process state, while Sage curve objects can retain
    backend state.  A retry therefore changes both the explicit precision and
    the curve object.  No result from a failed precision is reused as a
    covering or map authority.
    """

    return EllipticCurve([ZZ(value) for value in curve.a_invariants()])


def _is_small_norm_precision_failure(error):
    return "small_norm" in str(error).lower()


def _run_precision_ladder(operation):
    """Run a precision-dependent operation without hiding other failures."""

    attempts = []
    for precision in COVER_PRECISIONS:
        try:
            result = operation(int(precision))
        except Exception as error:
            if not _is_small_norm_precision_failure(error):
                raise
            attempts.append({
                "precision_bits": int(precision),
                "status": "PRECISION_FAILURE",
                "error": str(error),
            })
            continue
        attempts.append({
            "precision_bits": int(precision),
            "status": "SUCCESS",
        })
        return result, attempts
    return None, attempts


def _ell2cover_with_precision(minimal, precision):
    """Call the installed PARI API with an explicit precision argument."""

    return minimal.pari_curve().ell2cover(precision=int(precision))


def _cover_backend_data(curve, *, need_conductor):
    """Obtain cover inventory through an explicit, bounded precision ladder.

    ``small_norm`` is a recoverable arithmetic precision failure.  Other
    exceptions remain ordinary backend errors.  Exhausting the ladder returns
    no inventory, never a zero-cover result.
    """

    def attempt(precision):
        pari.set_real_precision_bits(int(precision))
        retry_curve = _fresh_exact_curve(curve)
        conductor = int(retry_curve.conductor()) if need_conductor else None
        minimal, _forward, inverse = _minimal_model_data(retry_curve)
        # cypari2's installed ell2cover interface has its own precision
        # parameter.  Changing PARI's global precision alone leaves the call
        # at its 64-bit default, so pass the selected precision explicitly.
        covers = _ell2cover_with_precision(minimal, precision)
        return {
            "curve": retry_curve,
            "minimal": minimal,
            "inverse": inverse,
            "covers": covers,
            "conductor": conductor,
            "precision_bits": int(precision),
        }
    result, attempts = _run_precision_ladder(attempt)
    if result is not None:
        result["precision_attempts"] = attempts
        return result
    return {
        "precision_bits": None,
        "precision_attempts": attempts,
        "classification": "PRECISION_LADDER_EXHAUSTED",
    }


def _exact_original_point(target_curve, inverse, point):
    if point.is_zero():
        return None
    original = inverse(point)
    if original.is_zero() or not target_curve(original[0], original[1]) == original:
        return None
    return original


def _ellrank_points(curve, config, seed_points):
    minimal, forward, inverse = _minimal_model_data(curve)
    pari.set_real_precision_bits(int(config["precision"]))
    pari.setrand(int(config["seed"]))
    supplied = []
    for record in seed_points:
        point = _require_point_record(curve, record)
        reduced = forward(point)
        supplied.append([reduced[0], reduced[1]])
    if supplied:
        raw = minimal.pari_curve().ellrank(
            int(config["effort"]), points=supplied, precision=int(config["precision"])
        )
    else:
        raw = minimal.pari_curve().ellrank(
            int(config["effort"]), precision=int(config["precision"])
        )
    lower, upper = int(ZZ(raw[0])), int(ZZ(raw[1]))
    candidates = []
    for raw_point in list(raw[3]):
        if len(raw_point) != 2:
            raise DiscoveryError("PARI returned a malformed candidate point")
        candidate = _exact_original_point(
            curve, inverse, minimal([QQ(raw_point[0]), QQ(raw_point[1])])
        )
        if candidate is None:
            continue
        # Verify membership against the actual original model before retaining.
        candidate = curve([QQ(candidate[0]), QQ(candidate[1])])
        candidates.append(canonical_point(candidate))
    return {
        "status": "POINT_CANDIDATES" if candidates else "NO_NEW_POINTS",
        "points": candidates,
        "details": {
            "lower_bound": lower,
            "upper_bound": upper,
            "raw_result": str(raw),
            "model": [str(value) for value in minimal.a_invariants()],
        },
    }


def _validate_cover_map(curve, minimal, quartic, mapping):
    x = pari("x")
    y = pari("y")
    a1, a2, a3, a4, a6 = minimal.a_invariants()
    X, Y = mapping[0], mapping[1]
    residual = Y**2 + a1 * X * Y + a3 * Y - (
        X**3 + a2 * X**2 + a4 * X + a6
    )
    numerator = pari.numerator(residual)
    relation = y**2 - quartic
    try:
        remainder = numerator % relation
    except Exception as error:
        raise DiscoveryError("cover map identity could not be reduced") from error
    if remainder != 0:
        raise DiscoveryError("cover map does not satisfy the exact curve identity")
    return {"quartic": str(quartic), "mapping": str(mapping), "identity_remainder": "0"}


def _cover_points(curve, config):
    backend = _cover_backend_data(curve, need_conductor=False)
    if backend.get("precision_bits") is None:
        return {
            "status": "ERROR",
            "points": [],
            "details": {
                "classification": backend["classification"],
                "precision_ladder": list(COVER_PRECISIONS),
                "precision_attempts": backend["precision_attempts"],
            },
        }
    minimal = backend["minimal"]
    inverse = backend["inverse"]
    covers = backend["covers"]
    index = int(config["cover_index"])
    if index < 0 or index >= len(covers):
        return {
            "status": "NO_NEW_POINTS",
            "points": [],
            "details": {
                "cover_count": len(covers),
                "precision_bits": backend["precision_bits"],
                "precision_attempts": backend["precision_attempts"],
            },
        }
    quartic, mapping = covers[index][0], covers[index][1]
    map_record = _validate_cover_map(curve, minimal, quartic, mapping)
    results = []
    skipped = []
    variable = pari("x")
    for raw_point in pari.hyperellratpoints(quartic, int(config["height_bound"])):
        try:
            t, v = raw_point[0], raw_point[1]
            quartic_value = QQ(pari.subst(quartic, variable, t))
            if QQ(v) ** 2 != quartic_value:
                skipped.append({"point": str(raw_point), "reason": "off_cover"})
                continue
            mapped = pari.substvec(mapping, ["x", "y"], raw_point)
            if len(mapped) != 2:
                skipped.append({"point": str(raw_point), "reason": "malformed_map_output"})
                continue
            minimal_point = minimal([QQ(mapped[0]), QQ(mapped[1])])
            original = _exact_original_point(curve, inverse, minimal_point)
            if original is None:
                skipped.append({"point": str(raw_point), "reason": "map_not_on_original_curve"})
                continue
            results.append(canonical_point(curve([QQ(original[0]), QQ(original[1])])) )
        except Exception as error:
            skipped.append({"point": str(raw_point), "reason": f"undefined_map:{type(error).__name__}"})
    return {
        "status": "POINT_CANDIDATES" if results else "NO_NEW_POINTS",
        "points": results,
        "details": {
            "cover": map_record,
            "skipped": skipped,
            "precision_bits": backend["precision_bits"],
            "precision_attempts": backend["precision_attempts"],
        },
    }


def perform_attempt(request_path, config, seed_points):
    _problem, curve = load_problem(request_path)
    method = config["method"]
    if method == "inventory":
        # Conductor and 2-cover inventory can invoke expensive Sage/eclib
        # work.  This method is deliberately run in the watchdog child; the
        # parent never performs either operation synchronously.
        backend = _cover_backend_data(
            curve, need_conductor=bool(config.get("need_conductor", False))
        )
        if backend.get("precision_bits") is None:
            return {
                "status": "ERROR",
                "points": [],
                "details": {
                    "classification": backend["classification"],
                    "precision_ladder": list(COVER_PRECISIONS),
                    "precision_attempts": backend["precision_attempts"],
                },
            }
        covers = backend["covers"]
        return {
            "status": "INVENTORY_COMPLETE",
            "points": [],
            "details": {
                "conductor": backend["conductor"],
                "cover_count": min(len(covers), int(config["max_cover_count"])),
                "cover_count_observed": len(covers),
                "precision_bits": backend["precision_bits"],
                "precision_attempts": backend["precision_attempts"],
            },
        }
    if method == "pari_seeded":
        return _ellrank_points(curve, config, seed_points)
    if method == "cover":
        return _cover_points(curve, config)
    if method == "heegner":
        minimal, _forward, inverse = _minimal_model_data(curve)
        value = minimal.pari_curve().ellheegner()
        point = minimal([QQ(value[0]), QQ(value[1])])
        original = _exact_original_point(curve, inverse, point)
        if original is None:
            return {"status": "ERROR", "points": [], "details": {"reason": "heegner point off model"}}
        return {
            "status": "POINT_CANDIDATES",
            "points": [canonical_point(curve([QQ(original[0]), QQ(original[1])]))],
            "details": {
                "analytic_rank_one_hypothesis": True,
                "warning": "ellheegner output is a candidate producer only",
            },
        }
    raise DiscoveryError(f"unsupported attempt method: {method}")


def _run_child(request_path, config, seed_points, timeout_seconds):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as stream:
        config_path = Path(stream.name)
        json.dump({"config": config, "seed_points": seed_points}, stream)
    try:
        command = [
            sys.executable, str(Path(__file__).resolve()),
            "--attempt-config", str(config_path), "--request", str(request_path),
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=(os.name == "posix"),
        )

        def terminate_process_group():
            if process.poll() is not None:
                return
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    return
                except ProcessLookupError:
                    return
            process.kill()

        try:
            stdout, stderr = process.communicate(timeout=float(timeout_seconds))
        except subprocess.TimeoutExpired:
            terminate_process_group()
            stdout, stderr = process.communicate()
            return {
                "status": "TIMEOUT",
                "points": [],
                "details": {
                    "stderr": stderr[-4000:],
                    "timeout_seconds": timeout_seconds,
                },
            }
        except KeyboardInterrupt:
            terminate_process_group()
            stdout, stderr = process.communicate()
            return {
                "status": "INTERRUPTED",
                "points": [],
                "details": {"stderr": stderr[-4000:], "reason": "parent interrupted"},
            }
        if process.returncode != 0:
            return {"status": "ERROR", "points": [], "details": {
                "exit_code": process.returncode, "stderr": stderr[-4000:],
            }}
        try:
            result = json.loads(stdout)
        except Exception as error:
            return {"status": "ERROR", "points": [], "details": {
                "reason": f"malformed child response: {error}", "stdout": stdout[-4000:],
                "stderr": stderr[-4000:],
            }}
        result.setdefault("details", {})["stderr"] = stderr[-4000:]
        return result
    finally:
        config_path.unlink(missing_ok=True)


def _merge_points(curve, current, additions):
    merged = {(record["x"], record["y"]): record for record in current}
    for record in additions:
        point = _require_point_record(curve, record)
        canonical = canonical_point(point)
        merged[(canonical["x"], canonical["y"])] = canonical
    return sorted(merged.values(), key=_point_sort_key)


def _child_main(config_path, request_path):
    value = json.loads(Path(config_path).read_text(encoding="utf-8"))
    result = perform_attempt(request_path, value["config"], value.get("seed_points", []))
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


def _remaining_timeout(started, budget_seconds, requested_seconds):
    remaining = float(budget_seconds) - (time.monotonic() - started)
    if remaining <= 0:
        return None
    return min(float(requested_seconds), remaining)


def _budget_timeout_result(reason):
    return {"status": "TIMEOUT", "points": [], "details": {"reason": reason}}


def pending_discovery_ids(
    state, schedule, rank_probe_id, rank_upper_bound, inventory_id
):
    """Return unfinished finite-work identifiers, never a completeness claim."""

    pending_ids = []
    if state.get(rank_probe_id, {}).get("status") not in TERMINAL_STATUSES:
        pending_ids.append(rank_probe_id)
    if (
        rank_upper_bound is not None
        and rank_upper_bound > 0
        and state.get(inventory_id, {}).get("status")
        not in INVENTORY_TERMINAL_STATUSES
    ):
        pending_ids.append(inventory_id)
    pending_ids.extend(item["attempt_id"] for item in pending_attempts(schedule, state))
    return sorted(set(pending_ids))


def summarize_discovery_status(outcomes, pending_ids, budget_exhausted):
    """Choose a resumable status; candidates never hide pending work."""

    if pending_ids:
        if any(record.get("status") == "TIMEOUT" for record in outcomes) or budget_exhausted:
            return "TIMEOUT"
        if any(record.get("status") in {"ERROR", "INTERRUPTED", "INCONCLUSIVE"} for record in outcomes):
            return "ERROR"
        return "INCONCLUSIVE"
    if any(record.get("status") == "POINT_CANDIDATES" for record in outcomes):
        return "POINT_CANDIDATES"
    if any(record.get("status") in {"TIMEOUT", "ERROR", "INTERRUPTED"} for record in outcomes):
        return "TIMEOUT" if any(record.get("status") == "TIMEOUT" for record in outcomes) else "ERROR"
    return "NO_NEW_POINTS"


def _parser():
    parser = argparse.ArgumentParser(description="bounded exact MW point discovery; never a theorem producer")
    parser.add_argument("--request", required=True)
    parser.add_argument("--output", default="mw-points.json")
    parser.add_argument("--journal", default="mw-discovery.jsonl")
    parser.add_argument("--input-point-file", action="append", default=[])
    parser.add_argument("--budget-seconds", type=int, default=3600)
    parser.add_argument("--attempt-timeout-seconds", type=int, default=120)
    parser.add_argument("--conductor-cap", type=int, default=10**12)
    parser.add_argument("--cover-bounds", default="10000,100000,1000000")
    parser.add_argument("--max-cover-count", type=int, default=8)
    parser.add_argument("--attempt-config")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    if args.attempt_config:
        _child_main(args.attempt_config, args.request)
        return 0
    if args.budget_seconds <= 0 or args.attempt_timeout_seconds <= 0:
        raise DiscoveryError("budgets must be positive")
    problem, curve = load_problem(args.request)
    identity = _identity_from_problem(problem)
    point_pool = []
    output = Path(args.output)
    journal = Path(args.journal)
    if output.exists():
        point_pool = load_point_file(output, problem, curve)
    for point_file in args.input_point_file:
        point_pool = _merge_points(curve, point_pool, load_point_file(point_file, problem, curve))
    publish_point_file(output, problem, point_pool)

    state = load_journal_state(journal, identity)
    # A prior unclosed child is never treated as successful.  It is made
    # retryable explicitly before the new process starts.
    for attempt_id, record in list(state.items()):
        if record.get("status") == "STARTED":
            append_journal_record(journal, {
                **record, "status": "INTERRUPTED", "reason": "resume_after_unclosed_attempt"
            })
            state[attempt_id] = {**record, "status": "INTERRUPTED"}

    started = time.monotonic()
    outcomes = []
    # The rank probe is deliberately not used as a theorem.  It only selects
    # the optional research branch and is itself bounded/replayable evidence.
    rank = None
    rank_lower_bound = None
    rank_upper_bound = None
    rank_probe = {
        "attempt_id": "rank-probe-e0-s1-p128",
        "method": "pari_seeded",
        "effort": 0,
        "seed": 1,
        "precision": 128,
    }
    rank_record = state.get(rank_probe["attempt_id"], {})
    prior_rank_details = rank_record.get("details", {})
    if (
        prior_rank_details.get("lower_bound") is not None
        and prior_rank_details.get("upper_bound") is not None
        and int(prior_rank_details["lower_bound"])
        <= int(prior_rank_details["upper_bound"])
    ):
        # An open interval is usable to schedule additional research, but not
        # to certify rank or completeness.  Preserve it while the probe is
        # retried so a short resumed budget cannot suppress covers.
        rank_lower_bound = int(prior_rank_details["lower_bound"])
        rank_upper_bound = int(prior_rank_details["upper_bound"])
    if (
        rank_record.get("status") in TERMINAL_STATUSES
        and rank_record.get("details", {}).get("lower_bound")
        == rank_record.get("details", {}).get("upper_bound")
    ):
        details = state[rank_probe["attempt_id"]].get("details", {})
        rank = int(details["upper_bound"])
        rank_lower_bound = rank
        rank_upper_bound = rank
    else:
        append_journal_record(journal, {
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "schedule_version": SCHEDULE_VERSION,
            "identity": identity,
            "attempt_id": rank_probe["attempt_id"],
            "status": "STARTED",
            "config": rank_probe,
        })
        timeout = _remaining_timeout(
            started, args.budget_seconds, args.attempt_timeout_seconds
        )
        result = (
            _budget_timeout_result("case budget exhausted before rank probe")
            if timeout is None
            else _run_child(args.request, rank_probe, point_pool, timeout)
        )
        record = {
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "schedule_version": SCHEDULE_VERSION,
            "identity": identity,
            "attempt_id": rank_probe["attempt_id"],
            **result,
        }
        verified_rank_points = [
            canonical_point(_require_point_record(curve, record))
            for record in result.get("points", [])
        ]
        point_pool = _merge_points(curve, point_pool, verified_rank_points)
        publish_point_file(output, problem, point_pool)
        # A closed rank interval is terminal evidence for this bounded rank
        # probe.  A gap is not: retaining a point while labelling the probe
        # POINT_CANDIDATES would make resume skip the unfinished rank work.
        if not (
            result.get("details", {}).get("lower_bound") is not None
            and result.get("details", {}).get("lower_bound")
            == result.get("details", {}).get("upper_bound")
        ) and result.get("status") in TERMINAL_STATUSES:
            record["details"] = {
                **record.get("details", {}),
                "original_status": record.get("status"),
                "reason": "rank interval remains open; retryable discovery evidence",
            }
            record["status"] = "INCONCLUSIVE"
        elif (
            result.get("details", {}).get("lower_bound") is not None
            and result.get("details", {}).get("lower_bound")
            == result.get("details", {}).get("upper_bound")
        ):
            record["status"] = "RANK_PROVEN"
        append_journal_record(journal, record)
        state[rank_probe["attempt_id"]] = record
        outcomes.append(record)
        if (
            result.get("details", {}).get("lower_bound") is not None
            and result.get("details", {}).get("upper_bound") is not None
        ):
            rank_lower_bound = int(result["details"]["lower_bound"])
            rank_upper_bound = int(result["details"]["upper_bound"])
        if record.get("status") == "RANK_PROVEN":
            rank = int(result["details"]["upper_bound"])

    conductor = None
    cover_count = 0
    inventory_id = "inventory-rank-one"
    inventory_pending = False
    if rank_upper_bound is not None and rank_upper_bound > 0:
        inventory_record = state.get(inventory_id, {})
        if inventory_record.get("status") in INVENTORY_TERMINAL_STATUSES:
            details = inventory_record.get("details", {})
            conductor = details.get("conductor")
            cover_count = int(details["cover_count"])
        else:
            inventory_pending = True
            inventory_config = {
                "attempt_id": inventory_id,
                "method": "inventory",
                "rank": rank,
                "rank_lower_bound": rank_lower_bound,
                "rank_upper_bound": rank_upper_bound,
                # Heegner is rank-one-only; rank-two cover inventory must not
                # be blocked by an unrelated conductor operation.
                "need_conductor": rank == 1,
                "max_cover_count": args.max_cover_count,
            }
            append_journal_record(journal, {
                "journal_schema_version": JOURNAL_SCHEMA_VERSION,
                "schedule_version": SCHEDULE_VERSION,
                "identity": identity,
                "attempt_id": inventory_id,
                "status": "STARTED",
                "config": inventory_config,
            })
            timeout = _remaining_timeout(
                started, args.budget_seconds, args.attempt_timeout_seconds
            )
            result = (
                _budget_timeout_result("case budget exhausted before curve inventory")
                if timeout is None
                else _run_child(args.request, inventory_config, point_pool, timeout)
            )
            inventory_record = {
                "journal_schema_version": JOURNAL_SCHEMA_VERSION,
                "schedule_version": SCHEDULE_VERSION,
                "identity": identity,
                "attempt_id": inventory_id,
                **result,
            }
            append_journal_record(journal, inventory_record)
            state[inventory_id] = inventory_record
            outcomes.append(inventory_record)
            if inventory_record.get("status") in INVENTORY_TERMINAL_STATUSES:
                inventory_pending = False
                details = inventory_record.get("details", {})
                conductor = details.get("conductor")
                cover_count = int(details["cover_count"])

    try:
        cover_bounds = tuple(int(value) for value in args.cover_bounds.split(","))
    except Exception as error:
        raise DiscoveryError("cover bounds must be comma-separated integers") from error
    # Do not manufacture a conductor-policy skip or a zero-cover schedule
    # while positive-rank inventory is unresolved.  The independent seeded
    # PARI attempts may proceed, but the inventory itself remains retryable.
    schedule_rank = None if inventory_pending else rank
    schedule = make_schedule(
        schedule_rank, cover_count, conductor,
        conductor_cap=args.conductor_cap, cover_bounds=cover_bounds,
    )
    for item in pending_attempts(schedule, state):
        if item.get("skip_status"):
            record = {
                "journal_schema_version": JOURNAL_SCHEMA_VERSION,
                "schedule_version": SCHEDULE_VERSION,
                "identity": identity,
                **item,
                "status": item["skip_status"],
                "points": [],
            }
            append_journal_record(journal, record)
            state[item["attempt_id"]] = record
            outcomes.append(record)
            continue
        timeout = _remaining_timeout(
            started, args.budget_seconds, args.attempt_timeout_seconds
        )
        if timeout is None:
            break
        config = dict(item)
        seed_points = list(point_pool)
        append_journal_record(journal, {
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "schedule_version": SCHEDULE_VERSION,
            "identity": identity,
            "attempt_id": item["attempt_id"],
            "status": "STARTED",
            "config": config,
            "seed_points": seed_points,
        })
        try:
            result = _run_child(args.request, config, seed_points, timeout)
        except KeyboardInterrupt:
            result = {"status": "INTERRUPTED", "points": [], "details": {"reason": "parent interrupted"}}
        verified_additions = []
        for record in result.get("points", []):
            verified_additions.append(canonical_point(_require_point_record(curve, record)))
        point_pool = _merge_points(curve, point_pool, verified_additions)
        publish_point_file(output, problem, point_pool)
        record = {
            "journal_schema_version": JOURNAL_SCHEMA_VERSION,
            "schedule_version": SCHEDULE_VERSION,
            "identity": identity,
            "attempt_id": item["attempt_id"],
            "status": result.get("status", "ERROR"),
            "points": verified_additions,
            "details": result.get("details", {}),
        }
        append_journal_record(journal, record)
        state[item["attempt_id"]] = record
        outcomes.append(record)

    pending_ids = pending_discovery_ids(
        state,
        schedule,
        rank_probe["attempt_id"],
        rank_upper_bound,
        inventory_id,
    )
    final_status = summarize_discovery_status(
        outcomes,
        pending_ids,
        time.monotonic() - started >= args.budget_seconds,
    )
    json.dump({
        "status": final_status,
        "n": problem["n"],
        "point_file": str(output),
        "journal": str(journal),
        "retained_point_count": len(point_pool),
        "attempt_count": len(outcomes),
        "pending_attempt_count": len(pending_ids),
        "pending_attempt_ids": pending_ids,
        "budget_seconds": args.budget_seconds,
        "attempt_timeout_seconds": args.attempt_timeout_seconds,
        # This is only completion of the finite discovery schedule, never
        # completeness of the Mordell--Weil group or integral-point set.
        "schedule_complete": not pending_ids,
        "schedule_version": SCHEDULE_VERSION,
        "note": "bounded research output; no rank, saturation, completeness or family theorem is asserted",
    }, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DiscoveryError as error:
        print(json.dumps({"status": "ERROR", "error": str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
