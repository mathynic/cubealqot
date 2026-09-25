"""MW-04 Sage entrypoint with immutable discovery-point transport.

The active campaign helper is intentionally not modified while that campaign
is running.  This entrypoint delegates the qualified proof implementation to
the existing helper, but injects the request's exact original-model points
into every PARI ``ellrank(points=...)`` attempt.  The points remain hints:
the delegated rank, eclib saturation, torsion and original-model integral
point checks still have to succeed before a complete response is emitted.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

from sage.all import EllipticCurve, QQ


ROOT = Path(__file__).resolve().parent
BASE_PATH = ROOT / "sage_integral_points.py"
MW02_PATH = ROOT / "mw02_rank_basis.py"
EXPECTED_BASE_SHA256 = "88196fd1f3a90b1bbad9a6a5a6a0c46ce8d8b0fa1d99fdff31727c3923f56c9a"
EXPECTED_MW02_SHA256 = "19ca0c840d8d2fb7c96a23242063335e67f8e490f911cda5d1435e7eeb0b8241"
# This is only the finite-field witness budget.  It is not a completeness
# bound: failure to find a witness leaves the backend result inconclusive.
# The all-prime eclib saturation contract remains max_prime=-1/min_prime=2.
MW02_WITNESS_PRIME_BOUND = 100


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


if _sha256(BASE_PATH) != EXPECTED_BASE_SHA256:
    raise RuntimeError("qualified Sage base implementation digest mismatch")
if _sha256(MW02_PATH) != EXPECTED_MW02_SHA256:
    raise RuntimeError("qualified MW-02 implementation digest mismatch")


SPEC = importlib.util.spec_from_file_location("cubealqot_m7_sage_base", BASE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the qualified Sage implementation")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
MW02_SPEC = importlib.util.spec_from_file_location("cubealqot_m7_mw02", MW02_PATH)
if MW02_SPEC is None or MW02_SPEC.loader is None:
    raise RuntimeError("cannot load the qualified MW-02 implementation")
MW02 = importlib.util.module_from_spec(MW02_SPEC)
MW02_SPEC.loader.exec_module(MW02)


def script_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _canonical_rational(value: str):
    parts = value.split("/")
    if len(parts) > 2 or any(not part for part in parts):
        raise ValueError("discovery coordinate is not p or p/q")
    numerator = BASE.ZZ(parts[0])
    denominator = BASE.ZZ(parts[1]) if len(parts) == 2 else BASE.ZZ(1)
    if denominator <= 0 or (len(parts) == 2 and denominator == 1):
        raise ValueError("discovery denominator is not canonical")
    value = BASE.QQ(numerator) / BASE.QQ(denominator)
    if value.denominator() != denominator or value.numerator() != numerator:
        raise ValueError("discovery rational is not reduced")
    return value


def _checked_seed(request: dict, coefficients: list[str]):
    raw = request.get("discovery_points")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("discovery_points must be a list")
    curve = EllipticCurve([BASE.ZZ(value) for value in coefficients])
    result = []
    seen = set()
    for index, value in enumerate(raw):
        if not isinstance(value, dict) or set(value) != {"x", "y"}:
            raise ValueError(f"discovery point {index} is malformed")
        x = _canonical_rational(value["x"])
        y = _canonical_rational(value["y"])
        if not BASE._curve_equation_holds(curve, x, y):
            raise ValueError(f"discovery point {index} is off curve")
        key = (x, y)
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


_request = None
_seed = []
_original_load_request = BASE.load_request
_original_point_arguments = BASE._pari_point_arguments


def load_request() -> dict:
    global _request, _seed
    _request = _original_load_request()
    problem = _request.get("problem")
    coefficients = problem.get("curve_coefficients") if isinstance(problem, dict) else None
    if not isinstance(coefficients, list) or len(coefficients) != 5:
        raise ValueError("problem curve coefficients are unavailable")
    _seed = _checked_seed(_request, coefficients)
    return _request


def _pari_point_arguments(coordinates):
    merged = []
    seen = set()
    for point in [*_seed, *coordinates]:
        key = (QQ(point[0]), QQ(point[1]))
        if key not in seen:
            seen.add(key)
            merged.append(key)
    return _original_point_arguments(merged)


def _parse_pari_ellrank_result_with_pool(curve, result):
    """Parse PARI's rank interval without treating its pool as a basis.

    The older helper's parser intentionally requires ``len(points) <= upper``
    because it is fed directly into its cardinality-based basis policy.  The
    MW-02 contract is different: PARI points form an untrusted pool, and MW-02
    must select a witnessed independent subset from that pool.  We therefore
    retain all exact affine points here and defer every rank/basis decision to
    ``select_independent_subset``.
    """

    if not isinstance(result, (tuple, list)) and not hasattr(result, "__len__"):
        raise ValueError("PARI ellrank result is not a sequence")
    if len(result) != 4:
        raise ValueError("PARI ellrank result must have four fields")
    try:
        lower = int(BASE.ZZ(result[0]))
        upper = int(BASE.ZZ(result[1]))
        int(BASE.ZZ(result[2]))
    except (TypeError, ValueError, ArithmeticError) as error:
        raise ValueError("malformed PARI ellrank rank fields") from error
    if lower < 0 or upper < lower:
        raise ValueError("PARI ellrank returned an invalid rank interval")
    raw_points = result[3]
    if isinstance(raw_points, (str, bytes)):
        raise ValueError("PARI ellrank point list is not a sequence")
    try:
        raw_points = list(raw_points)
    except TypeError as error:
        raise ValueError("PARI ellrank point list is not iterable") from error
    points = []
    seen = set()
    for raw_point in raw_points:
        if isinstance(raw_point, (str, bytes)) or len(raw_point) != 2:
            raise ValueError("PARI ellrank point is not a coordinate pair")
        try:
            x, y = BASE.QQ(raw_point[0]), BASE.QQ(raw_point[1])
        except (TypeError, ValueError, ArithmeticError) as error:
            raise ValueError("malformed PARI ellrank point") from error
        point = curve([x, y])
        if point.is_zero():
            raise ValueError("PARI ellrank returned the point at infinity")
        key = (x, y)
        if key not in seen:
            seen.add(key)
            points.append(point)
    return lower, upper, points


def _qualified_pari_rank_basis(coefficients):
    """Retain the complete candidate pool and select it through MW-02.

    PARI supplies only a fresh rank interval and candidate points.  A pool
    larger than the rank is not rejected by cardinality: MW-02 proves the
    selected subset's independence, rejects only a witnessed rank
    contradiction, and leaves unresolved bounded evidence inconclusive.
    """

    known_coordinates = list(_seed)
    minimum_precision = BASE.PARI_PRECISIONS[0]
    attempts = 0
    for precision, effort in BASE.PARI_ATTEMPT_SCHEDULE:
        if precision < minimum_precision:
            continue
        attempts += 1
        curve = EllipticCurve(coefficients)
        BASE.pari.set_real_precision_bits(precision)
        BASE.pari.setrand(BASE.PARI_SEARCH_SEED)
        supplied = _pari_point_arguments(known_coordinates)
        BASE.diagnostic(
            "pari-rank-attempt",
            phase="start",
            attempt=attempts,
            precision_bits=precision,
            effort=effort,
            seed=BASE.PARI_SEARCH_SEED,
            supplied_points=len(supplied),
            candidate_pool_size=len(known_coordinates),
        )
        try:
            if supplied:
                raw = curve.pari_curve().ellrank(
                    effort, points=supplied, precision=precision
                )
            else:
                raw = curve.pari_curve().ellrank(effort, precision=precision)
        except BASE.PariError as error:
            message = str(error)
            if "small_norm" in message.lower():
                higher = [value for value in BASE.PARI_PRECISIONS if value > precision]
                if higher:
                    minimum_precision = max(minimum_precision, higher[0])
                BASE.diagnostic(
                    "pari-rank-attempt",
                    phase="failure",
                    classification="PRECISION_FAILURE",
                    attempt=attempts,
                    precision_bits=precision,
                    effort=effort,
                    error=message,
                )
                continue
            raise RuntimeError("unexpected PARI rank failure") from error

        lower, upper, returned_points = _parse_pari_ellrank_result_with_pool(curve, raw)
        for point in returned_points:
            key = (BASE.QQ(point[0]), BASE.QQ(point[1]))
            if key not in known_coordinates:
                known_coordinates.append(key)
        pool = [curve([x, y]) for x, y in known_coordinates]
        BASE.diagnostic(
            "pari-rank-attempt",
            phase="result",
            attempt=attempts,
            precision_bits=precision,
            effort=effort,
            lower_bound=lower,
            upper_bound=upper,
            returned_points=len(returned_points),
            candidate_pool_size=len(pool),
        )
        if upper == 0:
            if lower != 0 or pool:
                raise RuntimeError("PARI returned inconsistent rank-zero evidence")
            return curve, 0, []
        if lower < upper:
            continue
        try:
            selected, witness = MW02.select_independent_subset(
                curve, pool, upper, prime_bound=MW02_WITNESS_PRIME_BOUND
            )
        except MW02.RankContradiction:
            raise
        except (MW02.IndependenceUnresolved, ValueError) as error:
            BASE.diagnostic(
                "mw02-independence",
                status="INDEPENDENCE_UNRESOLVED",
                rank=upper,
                candidate_pool_size=len(pool),
                reason=str(error),
            )
            continue
        BASE.diagnostic(
            "mw02-independence",
            status="complete",
            rank=upper,
            candidate_pool_size=len(pool),
            selected_points=len(selected),
            witness=witness,
        )
        return curve, upper, selected
    raise RuntimeError("INCONCLUSIVE: bounded PARI/MW-02 rank policy exhausted")


def _qualified_saturate_basis(curve, candidate_points, rank):
    try:
        saturated, evidence = MW02.full_saturate_basis(
            curve,
            candidate_points,
            rank,
            prime_bound=MW02_WITNESS_PRIME_BOUND,
        )
    except (MW02.SaturationUnresolved, ValueError, ArithmeticError) as error:
        raise RuntimeError(f"INCONCLUSIVE: MW-02 full saturation unresolved: {error}") from error
    BASE.diagnostic("mw02-saturation", **evidence)
    return saturated, evidence


_original_diagnostic = BASE.diagnostic


def diagnostic(event: str, **values) -> None:
    # BASE.main emits a legacy pre-saturation label.  Preserve the transcript
    # while making clear that this is only a selected subgroup, not a certain
    # Mordell--Weil basis until MW-02 saturation completes.
    if event == "candidate-basis-checked":
        event = "candidate-subgroup-selected"
        values = {
            **values,
            "gens_certain": False,
            "status": "pending_full_saturation",
        }
    _original_diagnostic(event, **values)


BASE.load_request = load_request
BASE._pari_point_arguments = _pari_point_arguments
BASE.script_digest = script_digest
BASE.pari_rank_basis = _qualified_pari_rank_basis
BASE.saturate_basis = _qualified_saturate_basis
BASE.diagnostic = diagnostic


if __name__ == "__main__":
    BASE.main()
