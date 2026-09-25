"""MW-02 isolated Sage worker.

This worker is intentionally separate from ``sage_integral_points.py`` while
the normal campaign is live.  It keeps the established request/response
surface, but separates PARI rank evidence, an exact candidate pool, finite
field independence, and full saturation.  It is not wired into the campaign
until a later cutover task.
"""

from __future__ import annotations

import json
import platform
import sys
from pathlib import Path

import sage_integral_points as base
from mw02_rank_basis import (
    IndependenceUnresolved,
    RankContradiction,
    SaturationUnresolved,
    full_saturate_basis,
    select_independent_subset,
)
from sage.all import EllipticCurve, Integer, QQ, ZZ, pari, proof
from sage.version import version as sage_version
from cypari2 import PariError


def pari_rank_pool(coefficients):
    """Return fresh PARI rank evidence plus the complete accumulated pool.

    The point pool is deliberately allowed to exceed the PARI upper bound:
    points from separate calls are candidates until the finite-field witness
    selects a subset.  No external point file or Sage ``gens`` call supplies
    rank evidence here.
    """

    coefficients = [ZZ(value) for value in coefficients]
    known_coordinates = []
    known_keys = set()
    minimum_precision = base.PARI_PRECISIONS[0]
    attempts = 0

    for precision, effort in base.PARI_ATTEMPT_SCHEDULE:
        if precision < minimum_precision:
            continue
        attempts += 1
        curve = EllipticCurve(coefficients)
        pari.set_real_precision_bits(precision)
        pari.setrand(base.PARI_SEARCH_SEED)
        supplied = base._pari_point_arguments(known_coordinates)
        base.diagnostic(
            "pari-rank-attempt",
            phase="start",
            attempt=attempts,
            precision_bits=precision,
            effort=effort,
            seed=base.PARI_SEARCH_SEED,
            supplied_points=len(supplied),
        )
        try:
            if supplied:
                raw = curve.pari_curve().ellrank(
                    effort, points=supplied, precision=precision
                )
            else:
                raw = curve.pari_curve().ellrank(effort, precision=precision)
        except PariError as error:
            message = str(error)
            if "small_norm" in message.lower():
                base.diagnostic(
                    "pari-rank-attempt",
                    phase="failure",
                    classification="PRECISION_FAILURE",
                    attempt=attempts,
                    precision_bits=precision,
                    effort=effort,
                    error=message,
                )
                higher = [value for value in base.PARI_PRECISIONS if value > precision]
                if higher:
                    minimum_precision = max(minimum_precision, higher[0])
                continue
            raise RuntimeError("unexpected PARI rank failure") from error

        lower, upper, returned_points = base.parse_pari_ellrank_result(curve, raw)
        for point in returned_points:
            key = base._coordinate_key(point)
            if key not in known_keys:
                known_keys.add(key)
                known_coordinates.append(key)
        pool = [curve([x, y]) for x, y in known_coordinates]
        base.diagnostic(
            "pari-rank-evidence",
            lower_bound=lower,
            upper_bound=upper,
            returned_points=len(returned_points),
            candidate_pool=len(pool),
            attempt=attempts,
            precision_bits=precision,
            effort=effort,
            proof=True,
            basis_complete=False,
        )

        if upper == 0:
            if lower != 0:
                raise RuntimeError("PARI returned inconsistent rank-zero evidence")
            return curve, 0, pool, {
                "lower_bound": lower,
                "upper_bound": upper,
                "attempt": attempts,
                "precision_bits": precision,
                "effort": effort,
                "candidate_pool": len(pool),
            }
        if lower == upper and len(pool) >= upper:
            return curve, upper, pool, {
                "lower_bound": lower,
                "upper_bound": upper,
                "attempt": attempts,
                "precision_bits": precision,
                "effort": effort,
                "candidate_pool": len(pool),
            }
        base.diagnostic(
            "pari-rank-attempt",
            phase="incomplete",
            classification=("RANK_BOUND_GAP" if lower < upper else "POINTS_MISSING"),
            lower_bound=lower,
            upper_bound=upper,
            candidate_pool=len(pool),
            attempt=attempts,
        )

    raise RuntimeError("INCONCLUSIVE: bounded PARI rank-evidence policy exhausted")


def _integral_points(curve, checked_basis):
    result = []
    seen = set()
    for point in curve.integral_points(mw_base=checked_basis, both_signs=True):
        if point.is_zero():
            raise RuntimeError("integral_points returned the point at infinity")
        x, y = QQ(point[0]), QQ(point[1])
        if x.denominator() != 1 or y.denominator() != 1:
            raise RuntimeError("integral_points returned a non-integral affine point")
        if not base._curve_equation_holds(curve, x, y):
            raise RuntimeError("integral_points returned an off-curve point")
        key = (int(x), int(y))
        if key not in seen:
            seen.add(key)
            result.append({"x": str(key[0]), "y": str(key[1])})
    result.sort(key=lambda value: (Integer(value["x"]), Integer(value["y"])))
    return result


def main() -> None:
    request = base.load_request()
    policy, problem, coefficients, curve = base._checked_problem(request)
    proof.all(True)
    base.diagnostic("proof-mode", proof_all=True)

    curve, rank, pool, rank_evidence = pari_rank_pool(coefficients)
    if rank == 0:
        checked_basis = []
        saturation = {
            "status": "not_applicable",
            "max_prime": -1,
            "min_prime": 2,
            "candidate_pool": len(pool),
        }
    else:
        try:
            selected, independence = select_independent_subset(curve, pool, rank)
            base.diagnostic(
                "independence-complete",
                rank=rank,
                pool_size=len(pool),
                selected_points=len(selected),
                witness_ell=independence["ell"],
                proof=True,
            )
            checked_basis, saturation = full_saturate_basis(curve, selected, rank)
            base.diagnostic(
                "saturation-complete",
                index=saturation["index"],
                max_prime=saturation["max_prime"],
                min_prime=saturation["min_prime"],
                returned_points=len(checked_basis),
                output_independence=True,
            )
            if saturation.get("backend_log"):
                base.diagnostic(
                    "saturation-backend-transcript",
                    transcript=saturation["backend_log"],
                )
        except (IndependenceUnresolved, RankContradiction, SaturationUnresolved) as error:
            base.diagnostic(
                "basis-inconclusive",
                classification=type(error).__name__,
                error=str(error),
                candidate_pool=len(pool),
            )
            raise RuntimeError(f"INCONCLUSIVE: {error}") from error

    serialized_points = _integral_points(curve, checked_basis)
    torsion_order = curve.torsion_subgroup().order()
    response = {
        "schema_version": base.SCHEMA_VERSION,
        "request_id": request["request_id"],
        "ok": True,
        "complete": True,
        "problem": problem,
        "proof": {
            "proof_all": True,
            "rank_proven": True,
            "rank": base.canonical_integer(rank),
            "generators": [
                {
                    "x": {"value": base.rational_text(point[0])},
                    "y": {"value": base.rational_text(point[1])},
                }
                for point in checked_basis
            ],
            # This field is emitted only after independent selection and full
            # saturation have succeeded (or rank zero was established).
            "gens_certain": True,
            "both_signs": True,
            "integral_points_complete": True,
            "torsion_order": base.canonical_integer(torsion_order),
            "rank_evidence": rank_evidence,
            "candidate_pool_size": len(pool),
            "saturation": {
                key: value for key, value in saturation.items() if key != "backend_log"
            },
        },
        "model": {
            "semantics": base.ORIGINAL_INTEGRAL_MODEL,
            "curve_coefficients": [base.canonical_integer(value) for value in coefficients],
        },
        "points": serialized_points,
        "backend": {
            "name": "SageMath-MW-02-isolated",
            "sage_version": str(sage_version),
            "python_version": platform.python_version(),
            "environment": policy["environment"],
            "distribution": policy["distribution"],
            "script_sha256": base.script_digest(),
            "mw02_script_sha256": __import__("hashlib").sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
        },
    }
    json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
