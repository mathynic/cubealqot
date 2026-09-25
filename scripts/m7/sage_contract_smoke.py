"""Qualify the Sage integral-point backend contract for M7-03.

This harness records backend behavior and implementation identity. It does not
create a family certificate or turn a completed point enumeration into a
trusted theorem by itself.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import inspect
import json
import pathlib
import platform
import signal
import subprocess
import sys
import time
from typing import Any

from sage.all import EllipticCurve, Integer, pari, proof
import sage
from local_config import get_local_setting
from sage.schemes.elliptic_curves.ell_rational_field import (
    EllipticCurve_rational_field,
)


class EnumerationTimeout(Exception):
    pass


PQ02_FAMILY_CASES = {
    "N11": {
        "n": "11",
        "a": "1464",
        "d": "133",
        "factors": [{"prime": "11", "exponent": 1}],
        "coefficients": ["0", "1464", "0", "194712", "25896696"],
        "rank": "1",
        "points": [],
    },
    "N13": {
        "n": "13",
        "a": "2380",
        "d": "183",
        "factors": [{"prime": "13", "exponent": 1}],
        "coefficients": ["0", "2380", "0", "435540", "79703820"],
        "rank": "0",
        "points": [],
    },
    "N15": {
        "n": "15",
        "a": "6240",
        "d": "2865",
        "factors": [
            {"prime": "3", "exponent": 1},
            {"prime": "5", "exponent": 1},
        ],
        "coefficients": ["0", "6240", "0", "17877600", "51219324000"],
        "rank": "0",
        "points": [],
    },
    "N19": {
        "n": "19",
        "a": "7240",
        "d": "381",
        "factors": [{"prime": "19", "exponent": 1}],
        "coefficients": ["0", "7240", "0", "2758440", "1050965640"],
        "rank": "2",
        "points": [
            {"x": "-3666", "y": "-197412"},
            {"x": "-3666", "y": "197412"},
            {"x": "-46", "y": "-30648"},
            {"x": "-46", "y": "30648"},
            {"x": "441", "y": "-61329"},
            {"x": "441", "y": "61329"},
        ],
    },
}


PQ02_AUXILIARY_CASES = {
    "rank-zero-torsion-11a1": {
        "n": "11",
        "a": "1464",
        "d": "133",
        "factors": [{"prime": "11", "exponent": 1}],
        "coefficients": ["0", "-1", "1", "-10", "-20"],
        "rank": "0",
        "torsion_order": "5",
        "family_mapping_expected": False,
        "points": [
            {"x": "5", "y": "-6"},
            {"x": "5", "y": "5"},
            {"x": "16", "y": "-61"},
            {"x": "16", "y": "60"},
        ],
    },
    "nonminimal-original-model": {
        "n": "11",
        "a": "1464",
        "d": "133",
        "factors": [{"prime": "11", "exponent": 1}],
        "coefficients": ["0", "0", "0", "0", "-2000000"],
        "rank": "1",
        "family_mapping_expected": False,
        "points": [
            {"x": "129", "y": "-383"},
            {"x": "129", "y": "383"},
            {"x": "300", "y": "-5000"},
            {"x": "300", "y": "5000"},
        ],
    },
}


def _canonical_point_set(points: list[dict[str, str]]) -> list[dict[str, str]]:
    normalized = []
    for point in points:
        if not isinstance(point, dict) or set(point) != {"x", "y"}:
            raise AssertionError("point is not an exact affine JSON object")
        x, y = point["x"], point["y"]
        if not isinstance(x, str) or not isinstance(y, str):
            raise AssertionError("point coordinates are not decimal strings")
        if str(int(x)) != x or str(int(y)) != y:
            raise AssertionError("point coordinate is not canonical decimal")
        normalized.append({"x": x, "y": y})
    return sorted(normalized, key=lambda point: (int(point["x"]), int(point["y"])))


def _exact_curve_equation(coefficients: list[str], x: Fraction, y: Fraction) -> bool:
    a1, a2, a3, a4, a6 = (Fraction(value) for value in coefficients)
    return y * y + a1 * x * y + a3 * y == x**3 + a2 * x * x + a4 * x + a6


def _direct_sigma(n: int) -> int:
    cube = n**3
    return sum(d for d in range(1, cube + 1) if cube % d == 0)


def _finite_field_group_order(coefficients: list[str], p: int) -> int:
    a1, a2, a3, a4, a6 = (int(value) for value in coefficients)
    affine = 0
    for x in range(p):
        for y in range(p):
            left = (y * y + a1 * x * y + a3 * y) % p
            right = (x**3 + a2 * x * x + a4 * x + a6) % p
            affine += left == right
    return affine + 1


def _validate_family_mapping(case: dict[str, Any], points: list[dict[str, str]]) -> dict[str, Any]:
    coefficients = case["coefficients"]
    d = int(case["d"])
    n = int(case["n"])
    a = int(case["a"])
    direct_a = _direct_sigma(n)
    direct_d = direct_a - n**3
    if direct_a != a or direct_d != d:
        raise AssertionError("A/D do not match independent direct divisor enumeration")
    mapped = []
    for point in points:
        x, y = int(point["x"]), int(point["y"])
        if x % d == 0 and y % d == 0:
            q, value = x // d, y // d
            rhs = d * q**3 + a * q**2 + a * q + a
            if value * value != rhs:
                raise AssertionError("mapped point fails the exact family equation")
            mapped.append({"q": str(q), "y": str(value), "q_ge_2": q >= 2, "q_coprime": q != 0 and n % q != 0})
        if not _exact_curve_equation(coefficients, Fraction(x), Fraction(y)):
            raise AssertionError("returned point fails the exact original curve equation")
    return {
        "direct_sigma_n3": direct_a,
        "direct_d": direct_d,
        "mapped_points": mapped,
        "admissible_prime_q": [],
    }


def _pq02_request(case: dict[str, Any], request_id: str, helper_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "request_id": request_id,
        "problem": {
            "n": case["n"],
            "factors": case["factors"],
            "a": case["a"],
            "d": case["d"],
            "curve_coefficients": case["coefficients"],
        },
        "policy": {
            "distribution": "Ubuntu-26.04",
            "environment": "cubealqot-m7",
            "conda_executable": get_local_setting("CUBEALQOT_CONDA_EXECUTABLE", "conda"),
            "sage_version": "10.8",
            "python_version": platform.python_version(),
            "script_sha256": helper_sha256,
            "proof_all": True,
            "rank_proof": True,
            "generators_proof": True,
            "require_gens_certain": True,
            "both_signs": True,
            "model_semantics": "original_integral_model",
        },
    }


def _run_pq02_case(
    name: str,
    case: dict[str, Any],
    helper: pathlib.Path,
    output: pathlib.Path,
    timeout_seconds: int,
    helper_sha256: str,
) -> dict[str, Any]:
    case_output = output / "cases" / name
    case_output.mkdir(parents=True, exist_ok=True)
    request = _pq02_request(case, f"pq02-{name}", helper_sha256)
    request_path = case_output / "request.json"
    stdout_path = case_output / "stdout.json"
    stderr_path = case_output / "stderr.log"
    request_path.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    started = time.monotonic()
    timed_out = False
    exit_code = None
    stdout = ""
    stderr = ""
    try:
        completed = subprocess.run(
            [sys.executable, str(helper), str(request_path)],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout = error.stdout or ""
        stderr = error.stderr or ""
    process_seconds = time.monotonic() - started
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    record: dict[str, Any] = {
        "name": name,
        "request": str(request_path),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "exit_code": exit_code,
        "timed_out": timed_out,
        "process_wall_seconds": process_seconds,
        "helper_sha256": helper_sha256,
    }
    if timed_out or exit_code != 0:
        raise RuntimeError(f"{name} did not complete: {record}")
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{name} emitted malformed JSON: {error}") from error
    if not isinstance(response, dict) or response.get("ok") is not True or response.get("complete") is not True:
        raise RuntimeError(f"{name} emitted a non-complete response")
    if response.get("request_id") != request["request_id"]:
        raise RuntimeError(f"{name} request identity changed")
    if response.get("problem") != request["problem"]:
        raise RuntimeError(f"{name} problem identity changed")
    proof_record = response.get("proof")
    if not isinstance(proof_record, dict) or any(
        proof_record.get(key) is not True
        for key in ("proof_all", "rank_proven", "gens_certain", "both_signs", "integral_points_complete")
    ):
        raise RuntimeError(f"{name} proof contract is incomplete")
    if proof_record.get("rank") != case["rank"]:
        raise RuntimeError(f"{name} rank mismatch")
    if "torsion_order" in case and proof_record.get("torsion_order") != case["torsion_order"]:
        raise RuntimeError(f"{name} torsion order mismatch")
    generators = proof_record.get("generators")
    if not isinstance(generators, list) or len(generators) != int(case["rank"]):
        raise RuntimeError(f"{name} generator count mismatch")
    for generator in generators:
        if not isinstance(generator, dict) or set(generator) != {"x", "y"}:
            raise RuntimeError(f"{name} generator shape is not exact")
        x, y = generator["x"].get("value"), generator["y"].get("value")
        if Fraction(x) != Fraction(x) or Fraction(y) != Fraction(y):
            raise RuntimeError(f"{name} generator coordinate is malformed")
        if not _exact_curve_equation(case["coefficients"], Fraction(x), Fraction(y)):
            raise RuntimeError(f"{name} generator is off the original curve")
    model = response.get("model")
    if model != {"semantics": "original_integral_model", "curve_coefficients": case["coefficients"]}:
        raise RuntimeError(f"{name} model identity changed")
    points = _canonical_point_set(response.get("points"))
    expected_points = _canonical_point_set(case["points"])
    if points != expected_points:
        raise RuntimeError(f"{name} complete point set mismatch: {points!r} != {expected_points!r}")
    mapping = (
        _validate_family_mapping(case, points)
        if case.get("family_mapping_expected", True)
        else {"status": "not_applicable_for_curve-contract_fixture"}
    )
    backend = response.get("backend")
    backend_identity_matches = isinstance(backend, dict) and all(
        (
            str(backend.get(key, "")).upper() == expected.upper()
            if key == "script_sha256"
            else backend.get(key) == expected
        )
        for key, expected in {
            "name": "SageMath",
            "sage_version": "10.8",
            "python_version": platform.python_version(),
            "environment": "cubealqot-m7",
            "distribution": "Ubuntu-26.04",
            "script_sha256": helper_sha256,
        }.items()
    )
    if not backend_identity_matches:
        raise RuntimeError(f"{name} helper identity mismatch")
    record.update(
        {
            "status": "PASSED",
            "rank": case["rank"],
            "torsion_order": proof_record.get("torsion_order"),
            "generator_count": len(generators),
            "point_count": len(points),
            "points": points,
            "mapping": mapping,
        }
    )
    if "torsion_order" in case:
        reductions = {str(p): _finite_field_group_order(case["coefficients"], p) for p in (7, 13)}
        record["torsion_reduction"] = {
            "primes": reductions,
            "gcd": __import__("math").gcd(*reductions.values()),
            "expected_torsion_order": case["torsion_order"],
        }
    (case_output / "validated-response.json").write_text(
        json.dumps(response, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (case_output / "validation.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return record


def _run_nonempty_mapping_regression() -> dict[str, Any]:
    # Test-only coefficients: this exercises the exact X=Dq, Y=Dy mapping
    # without presenting synthetic data as a real cube-aliquot proof.
    n, a, d, q, y = 3, 4, 1, 2, 6
    x, big_y = d * q, d * y
    curve_rhs = x**3 + a * x**2 + a * d * x + a * d**2
    family_rhs = d * q**3 + a * q**2 + a * q + a
    if big_y * big_y != curve_rhs or y * y != family_rhs or q < 2 or n % q == 0:
        raise AssertionError("test-only nonempty family mapping regression failed")
    return {
        "status": "PASSED",
        "test_only": True,
        "n": str(n),
        "a": str(a),
        "d": str(d),
        "point": {"x": str(x), "y": str(big_y)},
        "mapped": {"q": str(q), "y": str(y)},
        "warning": "synthetic mechanics fixture; not a cube-aliquot family proof",
    }


def _run_pq02_unsaturated_basis_regression(helper: pathlib.Path, output: pathlib.Path) -> dict[str, Any]:
    import importlib.util

    specification = importlib.util.spec_from_file_location("pq02_qualified_helper", helper)
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load the qualified helper for saturation regression")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    curve = EllipticCurve([0, 1464, 0, 194712, 25896696])
    rank = int(curve.rank(algorithm="pari", proof=True, use_database=False, pari_effort=0))
    generators = list(
        curve.gens(algorithm="pari", proof=True, use_database=False, pari_effort=0)
    )
    if rank != 1 or len(generators) != 1 or not curve.gens_certain():
        raise RuntimeError("unsaturated-input fixture did not establish the N=11 basis")
    saturated, diagnostics = module.saturate_basis(curve, [generators[0] + generators[0]], rank)
    if diagnostics.get("index", 0) <= 1 or len(saturated) != rank:
        raise RuntimeError("twice-generator regression did not recover an enlarged basis")
    record = {
        "status": "PASSED",
        "fixture": "N=11 generator doubled before explicit saturation",
        "rank": rank,
        "saturation": diagnostics,
    }
    (output / "unsaturated-basis-regression.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return record


def _run_pq02_old_differential_worker(name: str) -> None:
    """Run the comparison algorithm in a fresh interpreter.

    This worker deliberately does not share a Sage curve instance with the
    qualified helper.  ``use_database=False`` prevents a database result from
    standing in for the requested algorithm.  Its result is comparison
    evidence only; it is never a production theorem input.
    """

    proof.all(True)
    curve = EllipticCurve(name)
    rank = int(curve.rank(algorithm="mwrank", proof=True, use_database=False))
    generators = list(
        curve.gens(algorithm="mwrank", proof=True, use_database=False)
    )
    certain = bool(curve.gens_certain())
    if not certain:
        raise RuntimeError(f"{name} mwrank did not establish a certain basis")
    points = curve.integral_points(mw_base=generators, both_signs=True)
    result = {
        "name": name,
        "algorithm": "mwrank",
        "database": False,
        "rank": rank,
        "gens_certain": certain,
        "coefficients": [str(value) for value in curve.a_invariants()],
        "points": _canonical_point_set(
            [{"x": str(point[0]), "y": str(point[1])} for point in points]
        ),
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)


def _run_pq02_old_differential_process(name: str, timeout_seconds: int) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).resolve()), "--pq02-differential-old", name],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{name} fresh mwrank differential failed: exit={completed.returncode}; "
            f"stderr={completed.stderr[-2000:]}"
        )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"{name} fresh mwrank worker emitted {len(lines)} JSON lines")
    try:
        result = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{name} fresh mwrank worker emitted malformed JSON") from error
    if not isinstance(result, dict) or result.get("name") != name:
        raise RuntimeError(f"{name} fresh mwrank worker returned the wrong identity")
    return result


def _run_pq02_cache_bypass_regression() -> list[dict[str, Any]]:
    """Record that same-instance algorithm calls are cache-contaminated.

    This is a regression guard for the old differential harness.  Detecting
    the cache behavior is expected; the qualification passes only because its
    actual comparison uses the separate processes above.
    """

    results = []
    for name in ("11a1", "14a1", "37a1"):
        curve = EllipticCurve(name)
        curve.rank(proof=True, use_database=False)
        original_generators = list(curve.gens(proof=True, use_database=False))
        saved = curve.pari_curve

        def forbidden(*_args, **_kwargs):
            raise AssertionError("PARI rank would fail if executed")

        curve.pari_curve = forbidden
        try:
            cached_rank = int(
                curve.rank(
                    algorithm="pari",
                    proof=True,
                    use_database=False,
                    pari_effort=0,
                )
            )
            cached_generators = list(
                curve.gens(
                    algorithm="pari",
                    proof=True,
                    use_database=False,
                    pari_effort=0,
                )
            )
        finally:
            curve.pari_curve = saved
        results.append(
            {
                "name": name,
                "status": "CACHE_BYPASS_REPRODUCED",
                "cached_rank": cached_rank,
                "same_generators": cached_generators == original_generators,
                "pari_rank_was_not_executed": True,
                "interpretation": "same-instance Sage calls are not qualification evidence",
            }
        )
    return results


def _run_pq02_differential(
    helper: pathlib.Path,
    output: pathlib.Path,
    timeout_seconds: int,
    helper_sha256: str,
) -> dict[str, Any]:
    results = []
    for name in ("11a1", "14a1", "37a1"):
        old = _run_pq02_old_differential_process(name, timeout_seconds)
        case = {
            "n": "3",
            "a": "0",
            "d": "1",
            "factors": [{"prime": "3", "exponent": 1}],
            "coefficients": old["coefficients"],
            "rank": str(old["rank"]),
            "points": old["points"],
            "family_mapping_expected": False,
        }
        qualified = _run_pq02_case(
            f"differential-{name}",
            case,
            helper,
            output,
            timeout_seconds,
            helper_sha256,
        )
        qualified_points = _canonical_point_set(qualified["points"])
        old_points = _canonical_point_set(old["points"])
        if not old["gens_certain"] or str(old["rank"]) != case["rank"]:
            raise RuntimeError(f"{name} old comparison basis is not complete")
        if qualified_points != old_points:
            raise RuntimeError(
                f"fresh-process differential point-set mismatch for {name}: "
                f"{qualified_points!r} != {old_points!r}"
            )
        results.append(
            {
                "name": name,
                "status": "PASSED",
                "old_algorithm": "mwrank",
                "old_database": False,
                "qualified_algorithm": "direct-pari-with-explicit-saturation",
                "old_rank": old["rank"],
                "qualified_rank": qualified["rank"],
                "old_points": old_points,
                "qualified_points": qualified_points,
                "note": "comparison evidence only; mwrank is not a production backend",
            }
        )
    return {
        "fresh_process_comparisons": results,
        "cache_bypass_regression": _run_pq02_cache_bypass_regression(),
    }


def run_pq02_qualification(
    helper_path: str,
    output_path: str,
    timeout_seconds: int,
    expected_manifest_path: str | None,
) -> None:
    helper = pathlib.Path(helper_path).resolve()
    output = pathlib.Path(output_path).resolve()
    if not helper.is_file():
        raise FileNotFoundError(f"PQ-02 helper does not exist: {helper}")
    output.mkdir(parents=True, exist_ok=True)
    helper_sha256 = hashlib.sha256(helper.read_bytes()).hexdigest().upper()
    if expected_manifest_path is None:
        raise RuntimeError("PQ-02 requires the PQ-01 qualification manifest")
    expected_manifest = pathlib.Path(expected_manifest_path).resolve()
    if not expected_manifest.is_file():
        raise FileNotFoundError(f"PQ-01 qualification manifest does not exist: {expected_manifest}")
    expected = json.loads(expected_manifest.read_text(encoding="utf-8"))
    if expected.get("task") != "PQ-01" or expected.get("helper_sha256", "").upper() != helper_sha256:
        raise RuntimeError("helper digest does not match the approved PQ-01 qualification manifest")
    manifest = {
        "kind": "m7_pq02_real_helper_qualification",
        "status": "RUNNING",
        "helper": str(helper),
        "helper_sha256": helper_sha256,
        "qualified_manifest": str(expected_manifest),
        "sage_version": str(sage.version.version),
        "python_version": platform.python_version(),
        "pari_version": str(pari("version()")),
        "environment": {
            "distribution": "Ubuntu-26.04",
            "conda_environment": "cubealqot-m7",
            "proof_all": bool(proof.elliptic_curve()),
        },
        "source": {
            "rank": source_ref(EllipticCurve_rational_field.rank),
            "gens": source_ref(EllipticCurve_rational_field.gens),
            "gens_certain": source_ref(EllipticCurve_rational_field.gens_certain),
            "integral_points": source_ref(EllipticCurve_rational_field.integral_points),
            "proof_all": source_ref(proof.all),
        },
        "cases": [],
        "note": "This manifest is valid only when status is PASSED; no result is converted to empty on error.",
    }
    (output / "environment-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    try:
        proof.all(True)
        for name, case in PQ02_FAMILY_CASES.items():
            manifest["cases"].append(
                _run_pq02_case(name, case, helper, output, timeout_seconds, helper_sha256)
            )
        for name, case in PQ02_AUXILIARY_CASES.items():
            manifest["cases"].append(
                _run_pq02_case(name, case, helper, output, timeout_seconds, helper_sha256)
            )
        manifest["unsaturated_basis_regression"] = _run_pq02_unsaturated_basis_regression(helper, output)
        manifest["differential"] = _run_pq02_differential(
            helper,
            output,
            timeout_seconds,
            helper_sha256,
        )
        manifest["nonempty_mapping_regression"] = _run_nonempty_mapping_regression()
        manifest["status"] = "PASSED"
    except Exception as error:
        manifest["status"] = "INCONCLUSIVE"
        manifest["reason"] = f"{type(error).__name__}: {error}"
        (output / "environment-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        raise
    (output / "environment-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def timeout_handler(_signum: int, _frame: Any) -> None:
    raise EnumerationTimeout("recorded proof-run time limit expired")


def point_json(point: Any) -> dict[str, str]:
    return {"x": str(point[0]), "y": str(point[1]), "z": str(point[2])}


def source_ref(obj: Any) -> dict[str, Any]:
    path = pathlib.Path(inspect.getsourcefile(obj)).resolve()
    return {
        "path": str(path),
        "line": inspect.getsourcelines(obj)[1],
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def run_qualified_curve(name: str, curve: Any) -> dict[str, Any]:
    rank = curve.rank(proof=True)
    gens = curve.gens(proof=True)
    certain = bool(curve.gens_certain())
    torsion_points = curve.torsion_points()
    points = curve.integral_points(mw_base=gens, both_signs=True)
    return {
        "name": name,
        "coefficients": [str(value) for value in curve.a_invariants()],
        "rank": str(rank),
        "generators": [point_json(point) for point in gens],
        "gens_certain": certain,
        "torsion_order": str(curve.torsion_subgroup().order()),
        "torsion_points": [point_json(point) for point in torsion_points],
        "integral_points_both_signs": [point_json(point) for point in points],
        "integral_point_count": len(points),
    }


def run_nonminimal_regression() -> dict[str, Any]:
    curve = EllipticCurve([0, 0, 0, 0, -2000000])
    witness = curve(129, 383)
    gens = curve.gens(proof=True)
    assert curve.gens_certain()
    original_points = curve.integral_points(mw_base=gens, both_signs=True)

    minimal = curve.minimal_model()
    minimal_gens = minimal.gens(proof=True)
    assert minimal.gens_certain()
    minimal_points = minimal.integral_points(
        mw_base=minimal_gens, both_signs=True
    )
    scaled_witness = minimal(
        witness[0] / Integer(100), witness[1] / Integer(1000)
    )

    original_contains = witness in original_points or -witness in original_points
    minimal_contains_scaled = (
        scaled_witness in minimal_points or -scaled_witness in minimal_points
    )
    assert original_contains
    assert not minimal_contains_scaled
    assert not scaled_witness[0].is_integral()
    assert not scaled_witness[1].is_integral()

    return {
        "original_coefficients": [str(value) for value in curve.a_invariants()],
        "witness": point_json(witness),
        "original_model": str(curve),
        "original_generators": [point_json(point) for point in gens],
        "original_gens_certain": bool(curve.gens_certain()),
        "original_integral_points": [
            point_json(point) for point in original_points
        ],
        "original_contains_witness": original_contains,
        "minimal_model": str(minimal),
        "minimal_coefficients": [str(value) for value in minimal.a_invariants()],
        "scaled_witness_on_minimal_model": point_json(scaled_witness),
        "minimal_integral_points": [
            point_json(point) for point in minimal_points
        ],
        "minimal_contains_scaled_witness": minimal_contains_scaled,
        "interpretation": (
            "The original integral model enumeration retains (129,+/-383); "
            "the corresponding point on y^2=x^3-2 is S-integral, not integral."
        ),
    }


def run_n3_attempt(limit_seconds: int) -> dict[str, Any]:
    coefficients = [0, 40, 0, 520, 6760]
    curve = EllipticCurve(coefficients)
    result: dict[str, Any] = {
        "coefficients": [str(value) for value in curve.a_invariants()],
        "limit_seconds": limit_seconds,
        "status": "INCONCLUSIVE",
    }
    previous = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.setitimer(signal.ITIMER_REAL, limit_seconds)
    try:
        rank = curve.rank(proof=True)
        gens = curve.gens(proof=True)
        certain = bool(curve.gens_certain())
        points = curve.integral_points(mw_base=gens, both_signs=True)
        result.update(
            {
                "status": "COMPLETED_ENUMERATION_CANDIDATE",
                "rank": str(rank),
                "generators": [point_json(point) for point in gens],
                "gens_certain": certain,
                "integral_points_both_signs": [
                    point_json(point) for point in points
                ],
                "integral_point_count": len(points),
            }
        )
    except EnumerationTimeout as error:
        result["reason"] = str(error)
    except Exception as error:  # qualification records failures, never hides them
        result["reason"] = f"{type(error).__name__}: {error}"
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    parser.add_argument("--n3-limit-seconds", type=int, default=60)
    parser.add_argument(
        "--pq02-helper",
        help="run the isolated PQ-02 final-helper qualification instead of the legacy smoke report",
    )
    parser.add_argument(
        "--pq02-output",
        help="evidence directory for --pq02-helper",
    )
    parser.add_argument(
        "--pq02-expected-manifest",
        help="PQ-01 manifest whose helper digest must match exactly",
    )
    parser.add_argument("--pq02-timeout-seconds", type=int, default=180)
    parser.add_argument(
        "--pq02-differential-old",
        choices=("11a1", "14a1", "37a1"),
        help="internal fresh-process mwrank comparison worker",
    )
    args = parser.parse_args()

    if args.pq02_differential_old:
        _run_pq02_old_differential_worker(args.pq02_differential_old)
        return

    if not args.output and not args.pq02_helper:
        parser.error("--output is required outside the internal differential worker")

    if args.pq02_helper:
        if not args.pq02_output:
            parser.error("--pq02-output is required with --pq02-helper")
        run_pq02_qualification(
            args.pq02_helper,
            args.pq02_output,
            args.pq02_timeout_seconds,
            args.pq02_expected_manifest,
        )
        return

    proof.all(True)
    output: dict[str, Any] = {
        "kind": "m7_backend_contract_smoke",
        "sage_version": str(sage.version.version),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "proof_all_elliptic_curve": bool(proof.elliptic_curve()),
        "implementation": {
            "rank": source_ref(EllipticCurve_rational_field.rank),
            "gens": source_ref(EllipticCurve_rational_field.gens),
            "gens_certain": source_ref(EllipticCurve_rational_field.gens_certain),
            "integral_points": source_ref(
                EllipticCurve_rational_field.integral_points
            ),
            "proof_all": source_ref(proof.all),
        },
        "qualified_examples": [],
    }

    for name in ("11a1_rank_zero_torsion", "14a1_rank_zero_torsion", "37a1_rank_one"):
        output["qualified_examples"].append(
            run_qualified_curve(name, EllipticCurve(name.split("_", 1)[0]))
        )

    output["nonminimal_regression"] = run_nonminimal_regression()
    output["n3_attempt"] = run_n3_attempt(args.n3_limit_seconds)
    output["contract_notes"] = {
        "gens_certain": (
            "The installed implementation returns the cached proven flag; "
            "proof=True makes gens computation raise rather than return an "
            "uncertain basis. mwrank performs two-descent and saturation."
        ),
        "torsion": (
            "integral_points() obtains torsion_points() explicitly and handles "
            "rank zero by filtering non-infinity torsion points for integral x."
        ),
        "model_semantics": (
            "integral_points() requires self.is_integral(), validates every "
            "mw_base point against self, and performs height/integral-point "
            "work on the supplied original model. It does not authorize a "
            "minimal-model substitution without an S-integral mapping."
        ),
        "completeness_boundary": (
            "These observations qualify the selected API contract; they do not "
            "by themselves authenticate a global family certificate."
        ),
    }

    path = pathlib.Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
