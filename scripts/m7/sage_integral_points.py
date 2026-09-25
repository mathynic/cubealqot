"""Isolated PQ-01 Sage worker.

This is a disposable qualification copy of the M7 worker.  It preserves the
existing request/response format while making PARI rank and explicit eclib
saturation prerequisites for a complete response.  The production helper is
not changed by PQ-01.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
from pathlib import Path

from cypari2 import PariError
from sage.all import EllipticCurve, Integer, QQ, ZZ, pari, proof
from sage.version import version as sage_version


SCHEMA_VERSION = 1
ORIGINAL_INTEGRAL_MODEL = "original_integral_model"
SATURATION_MAX_PRIME = -1
SATURATION_MIN_PRIME = 2
UNSATURATED_PRIMES_RE = re.compile(r"^\[\s*(?P<body>.*?)\s*\]$")

# This is deliberately a finite qualification policy, not a claim that these
# attempts are complete for every curve.  Each attempt uses the low-level
# PARI ellrank interface with an explicit precision and a fresh Sage curve.
# A response is complete only after one attempt supplies enough exact points
# for the independent eclib saturation checks below.
PARI_PRECISIONS = (64, 128, 256)
PARI_EFFORTS = (0, 1, 4, 8)
PARI_ATTEMPT_SCHEDULE = tuple(
    (precision, effort)
    for effort in PARI_EFFORTS
    for precision in PARI_PRECISIONS
)
PARI_SEARCH_SEED = 1


def canonical_integer(value) -> str:
    integer = ZZ(value)
    return str(integer)


def rational_text(value) -> str:
    rational = QQ(value)
    if rational.denominator() == 1:
        return str(rational.numerator())
    return f"{rational.numerator()}/{rational.denominator()}"


def script_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def diagnostic(event: str, **values) -> None:
    record = {"event": event, **values}
    print(json.dumps(record, sort_keys=True, separators=(",", ":")), file=sys.stderr, flush=True)


def parse_unsaturated_primes(value) -> tuple[int, ...]:
    """Parse the pinned eclib ``saturate`` unresolved-prime representation.

    The qualified API currently exposes the result as a string such as
    ``"[ ]"`` or ``"[2, 3]"``.  No other representation is accepted: an
    unknown result is an uncertainty, not evidence that no primes remain.
    """

    if not isinstance(value, str):
        raise ValueError("eclib unresolved-prime result is not a string")
    match = UNSATURATED_PRIMES_RE.fullmatch(value)
    if match is None:
        raise ValueError("malformed eclib unresolved-prime result")
    body = match.group("body").strip()
    if not body:
        return ()
    result = []
    for token in body.split(","):
        token = token.strip()
        if not re.fullmatch(r"[0-9]+", token):
            raise ValueError("malformed unresolved-prime token")
        prime = int(token)
        if prime < 2:
            raise ValueError("unresolved-prime token is not a prime candidate")
        result.append(prime)
    if result != sorted(set(result)):
        raise ValueError("unresolved-prime list is not sorted and distinct")
    return tuple(result)


def validate_saturation_result(result) -> tuple[int, tuple[int, ...]]:
    """Require successful full saturation and a known empty unresolved set."""

    if not isinstance(result, (tuple, list)) or len(result) != 3:
        raise ValueError("unexpected eclib saturation result shape")
    ok, index, unresolved = result
    if not isinstance(ok, bool) or not ok:
        raise RuntimeError("eclib full saturation did not succeed")
    try:
        index = int(ZZ(index))
    except Exception as error:
        raise ValueError("malformed eclib saturation index") from error
    if index < 1:
        raise ValueError("eclib saturation index must be positive")
    unresolved = parse_unsaturated_primes(unresolved)
    if unresolved:
        raise RuntimeError(f"eclib reported unresolved saturation primes: {unresolved}")
    return index, unresolved


def _curve_equation_holds(curve, x, y) -> bool:
    x = QQ(x)
    y = QQ(y)
    a1, a2, a3, a4, a6 = curve.a_invariants()
    return y * y + a1 * x * y + a3 * y == x**3 + a2 * x * x + a4 * x + a6


def validate_basis_coordinates(curve, coordinates, rank: int) -> None:
    """Check exact affine membership, uniqueness and the proved rank count."""

    if not isinstance(rank, int) or rank < 0:
        raise ValueError("invalid established rank")
    coordinates = list(coordinates)
    if len(coordinates) != rank:
        raise ValueError("basis cardinality does not equal established rank")
    seen = set()
    for coordinate in coordinates:
        if not isinstance(coordinate, (tuple, list)) or len(coordinate) != 2:
            raise ValueError("basis coordinate has an unexpected shape")
        x, y = QQ(coordinate[0]), QQ(coordinate[1])
        key = (x, y)
        if key in seen:
            raise ValueError("basis contains duplicate points")
        seen.add(key)
        if not _curve_equation_holds(curve, x, y):
            raise ValueError("basis contains an off-curve point")


def validate_basis_points(curve, points, rank: int) -> None:
    coordinates = []
    for point in points:
        if point.is_zero():
            raise ValueError("basis contains the point at infinity")
        coordinates.append((QQ(point[0]), QQ(point[1])))
    validate_basis_coordinates(curve, coordinates, rank)


def parse_pari_ellrank_result(curve, result):
    """Parse PARI's exact ``ellrank`` result without inferring missing points.

    PARI returns ``[lower, upper, s, points]``.  The first two values are a
    rank interval; the points are independent candidates, not automatically
    a saturated Mordell--Weil basis.  In particular, ``lower == upper`` with
    an empty point list is not accepted as a basis claim for positive rank.
    """

    if not isinstance(result, (tuple, list)) and not hasattr(result, "__len__"):
        raise ValueError("PARI ellrank result is not a sequence")
    try:
        if len(result) != 4:
            raise ValueError("PARI ellrank result must have four fields")
        lower = int(ZZ(result[0]))
        upper = int(ZZ(result[1]))
        # Validate the auxiliary field's exact integer shape even though the
        # qualification contract does not use it as a theorem premise.
        int(ZZ(result[2]))
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
    if len(raw_points) > upper:
        raise ValueError("PARI returned more independent points than its upper bound")

    points = []
    coordinates = []
    for raw_point in raw_points:
        if isinstance(raw_point, (str, bytes)):
            raise ValueError("PARI ellrank point is not a coordinate pair")
        try:
            if len(raw_point) != 2:
                raise ValueError("PARI ellrank point is not a coordinate pair")
            x, y = QQ(raw_point[0]), QQ(raw_point[1])
        except (TypeError, ValueError, ArithmeticError) as error:
            raise ValueError("malformed PARI ellrank point") from error
        point = curve([x, y])
        if point.is_zero():
            raise ValueError("PARI ellrank returned the point at infinity")
        points.append(point)
        coordinates.append((x, y))
    validate_basis_coordinates(curve, coordinates, len(points))
    return lower, upper, points


def _coordinate_key(point):
    return QQ(point[0]), QQ(point[1])


def _pari_point_arguments(coordinates):
    return [[x, y] for x, y in coordinates]


def pari_rank_basis(coefficients):
    """Obtain a basis candidate through the bounded direct-PARI policy.

    Every attempt reconstructs the Sage curve and calls the low-level PARI
    object directly.  This prevents a prior Sage rank/generator call or a
    database result from satisfying the PARI qualification accidentally.
    Precision failures and point/rank gaps are diagnostics and trigger only
    the declared bounded retry policy.  Exhausting that policy raises an
    inconclusive error; it never returns rank zero or an empty basis.
    """

    coefficients = [ZZ(value) for value in coefficients]
    known_coordinates = []
    known_keys = set()
    minimum_precision = PARI_PRECISIONS[0]
    attempts = 0

    for precision, effort in PARI_ATTEMPT_SCHEDULE:
        if precision < minimum_precision:
            continue
        attempts += 1
        curve = EllipticCurve(coefficients)
        pari.set_real_precision_bits(precision)
        pari.setrand(PARI_SEARCH_SEED)
        supplied = _pari_point_arguments(known_coordinates)
        diagnostic(
            "pari-rank-attempt",
            phase="start",
            attempt=attempts,
            precision_bits=precision,
            effort=effort,
            seed=PARI_SEARCH_SEED,
            supplied_points=len(supplied),
        )
        try:
            if supplied:
                raw = curve.pari_curve().ellrank(
                    effort,
                    points=supplied,
                    precision=precision,
                )
            else:
                raw = curve.pari_curve().ellrank(
                    effort,
                    precision=precision,
                )
        except PariError as error:
            message = str(error)
            if "small_norm" in message.lower():
                diagnostic(
                    "pari-rank-attempt",
                    phase="failure",
                    classification="PRECISION_FAILURE",
                    attempt=attempts,
                    precision_bits=precision,
                    effort=effort,
                    error=message,
                )
                higher = [value for value in PARI_PRECISIONS if value > precision]
                if higher:
                    minimum_precision = max(minimum_precision, higher[0])
                continue
            diagnostic(
                "pari-rank-attempt",
                phase="failure",
                classification="UNEXPECTED_BACKEND_ERROR",
                attempt=attempts,
                precision_bits=precision,
                effort=effort,
                error=message,
            )
            raise RuntimeError("unexpected PARI rank failure") from error
        except Exception as error:
            diagnostic(
                "pari-rank-attempt",
                phase="failure",
                classification="UNEXPECTED_BACKEND_ERROR",
                attempt=attempts,
                precision_bits=precision,
                effort=effort,
                error=f"{type(error).__name__}: {error}",
            )
            raise

        try:
            lower, upper, returned_points = parse_pari_ellrank_result(curve, raw)
        except Exception as error:
            diagnostic(
                "pari-rank-attempt",
                phase="failure",
                classification="UNEXPECTED_BACKEND_ERROR",
                attempt=attempts,
                precision_bits=precision,
                effort=effort,
                error=f"malformed result: {type(error).__name__}: {error}",
            )
            raise

        for point in returned_points:
            key = _coordinate_key(point)
            if key not in known_keys:
                known_keys.add(key)
                known_coordinates.append(key)
        points = [curve([x, y]) for x, y in known_coordinates]
        diagnostic(
            "pari-rank-attempt",
            phase="result",
            attempt=attempts,
            precision_bits=precision,
            effort=effort,
            lower_bound=lower,
            upper_bound=upper,
            returned_points=len(returned_points),
            verified_points=len(points),
        )

        if upper == 0:
            if lower != 0 or points:
                raise RuntimeError("PARI returned inconsistent rank-zero evidence")
            diagnostic(
                "pari-rank-certified",
                rank=0,
                upper_bound=0,
                attempt=attempts,
                precision_bits=precision,
                effort=effort,
            )
            return curve, 0, []

        if lower < upper:
            classification = "RANK_BOUND_GAP"
        elif len(points) < upper:
            classification = "POINTS_MISSING"
        elif len(points) > upper:
            raise RuntimeError("verified PARI points exceed the rank upper bound")
        else:
            validate_basis_points(curve, points, upper)
            diagnostic(
                "pari-rank-basis-candidate",
                lower_bound=lower,
                upper_bound=upper,
                independent_points=len(points),
                attempt=attempts,
                precision_bits=precision,
                effort=effort,
            )
            return curve, upper, points

        diagnostic(
            "pari-rank-attempt",
            phase="incomplete",
            classification=classification,
            attempt=attempts,
            precision_bits=precision,
            effort=effort,
            lower_bound=lower,
            upper_bound=upper,
            verified_points=len(points),
        )

    diagnostic(
        "pari-rank-inconclusive",
        attempts=attempts,
        policy=[
            {"precision_bits": precision, "effort": effort}
            for precision, effort in PARI_ATTEMPT_SCHEDULE
        ],
    )
    raise RuntimeError("INCONCLUSIVE: bounded PARI rank/basis policy exhausted")


def _minimal_triple(point):
    x, y = QQ(point[0]), QQ(point[1])
    denominator = x.denominator().lcm(y.denominator())
    if denominator <= 0:
        raise ValueError("mapped basis point has an invalid denominator")
    return (ZZ(x * denominator), ZZ(y * denominator), ZZ(denominator))


def _point_coordinates(points):
    return [
        {"x": rational_text(point[0]), "y": rational_text(point[1])}
        for point in points
    ]


def _point_from_minimal_triple(minimal, triple):
    if not isinstance(triple, (tuple, list)) or len(triple) != 3:
        raise ValueError("malformed saturated basis point")
    x, y, denominator = (ZZ(value) for value in triple)
    if denominator <= 0:
        raise ValueError("saturated basis denominator must be positive")
    point = minimal([QQ(x) / denominator, QQ(y) / denominator])
    if point.is_zero() or not _curve_equation_holds(minimal, point[0], point[1]):
        raise ValueError("saturated basis point is not an exact minimal-model point")
    return point


def saturate_basis(curve, candidate_points, rank: int):
    """Explicitly saturate a candidate basis and map it back to the original E.

    ``max_prime=-1`` requests the complete eclib saturation search and
    ``min_prime=2`` covers every possible prime.  A success flag alone is not
    enough: the unresolved-prime representation is parsed and must be exactly
    empty.  The returned basis, rather than the input basis, is authoritative
    when eclib enlarges the lattice.
    """

    rank = int(rank)
    if rank <= 0:
        raise ValueError("saturation is only applicable to positive rank")
    validate_basis_points(curve, candidate_points, rank)

    from sage.libs.eclib.all import mwrank_MordellWeil

    minimal = curve.minimal_model()
    to_minimal = curve.isomorphism_to(minimal)
    from_minimal = minimal.isomorphism_to(curve)
    mw = mwrank_MordellWeil(minimal.mwrank_curve(), False)
    triples = [_minimal_triple(to_minimal(point)) for point in candidate_points]
    diagnostic(
        "saturation-start",
        rank=rank,
        max_prime=SATURATION_MAX_PRIME,
        min_prime=SATURATION_MIN_PRIME,
        candidate_points=len(triples),
    )
    mw.process(triples)
    processed_rank = int(mw.rank())
    if processed_rank != rank:
        raise RuntimeError(
            f"candidate basis has eclib rank {processed_rank}, established rank is {rank}"
        )
    raw_result = mw.saturate(
        max_prime=SATURATION_MAX_PRIME,
        min_prime=SATURATION_MIN_PRIME,
    )
    index, unresolved = validate_saturation_result(raw_result)
    saturated_rank = int(mw.rank())
    if saturated_rank != rank:
        raise RuntimeError(
            f"saturated eclib basis has rank {saturated_rank}, established rank is {rank}"
        )
    raw_points = mw.points()
    if not isinstance(raw_points, (tuple, list)):
        raise ValueError("malformed eclib saturated basis point list")
    if len(raw_points) != rank:
        raise ValueError("saturated basis cardinality does not equal established rank")

    saturated_minimal = [_point_from_minimal_triple(minimal, value) for value in raw_points]
    saturated_original = [from_minimal(point) for point in saturated_minimal]
    validate_basis_points(curve, saturated_original, rank)
    diagnostic(
        "saturation-complete",
        index=index,
        unresolved_primes=list(unresolved),
        returned_points=len(saturated_original),
        minimal_model=[canonical_integer(value) for value in minimal.a_invariants()],
        map="exact_original_to_minimal_to_original_isomorphisms",
        saturated_basis=_point_coordinates(saturated_original),
    )
    return saturated_original, {
        "ok": True,
        "index": index,
        "unresolved_primes": list(unresolved),
        "minimal_model": [canonical_integer(value) for value in minimal.a_invariants()],
    }


def load_request() -> dict:
    if len(sys.argv) != 2:
        raise ValueError("expected exactly one request file path")
    with open(sys.argv[1], encoding="utf-8") as request_file:
        request = json.load(request_file)
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")
    return request


def _checked_problem(request):
    if request.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported request schema")
    policy = request.get("policy")
    problem = request.get("problem")
    if not isinstance(policy, dict) or not isinstance(problem, dict):
        raise ValueError("request policy and problem must be objects")
    if policy.get("model_semantics") != ORIGINAL_INTEGRAL_MODEL:
        raise ValueError("unsupported model semantics")
    for key in ("proof_all", "rank_proof", "generators_proof", "require_gens_certain", "both_signs"):
        if policy.get(key) is not True:
            raise ValueError(f"required proof policy is not enabled: {key}")
    if not isinstance(request.get("request_id"), str) or not request["request_id"]:
        raise ValueError("request_id must be nonempty")
    for key in ("n", "a", "d"):
        value = problem.get(key)
        if not isinstance(value, str) or canonical_integer(value) != value:
            raise ValueError(f"problem.{key} is not a canonical decimal integer")
    factors = problem.get("factors")
    if not isinstance(factors, list):
        raise ValueError("problem.factors must be a list")
    for factor in factors:
        if not isinstance(factor, dict):
            raise ValueError("factor identity must be an object")
        prime = factor.get("prime")
        exponent = factor.get("exponent")
        if not isinstance(prime, str) or canonical_integer(prime) != prime:
            raise ValueError("factor prime is not a canonical decimal integer")
        if not isinstance(exponent, int) or isinstance(exponent, bool) or exponent < 1:
            raise ValueError("factor exponent is not a positive integer")
    raw_coefficients = problem.get("curve_coefficients")
    if not isinstance(raw_coefficients, list) or len(raw_coefficients) != 5:
        raise ValueError("curve coefficients must contain five exact integers")
    if any(
        not isinstance(value, str) or canonical_integer(value) != value
        for value in raw_coefficients
    ):
        raise ValueError("curve coefficients are not canonical decimal integers")
    coefficients = [ZZ(value) for value in raw_coefficients]
    curve = EllipticCurve(coefficients)
    if [canonical_integer(value) for value in curve.a_invariants()] != [canonical_integer(value) for value in coefficients]:
        raise ValueError("Sage curve coefficients changed during construction")
    return policy, problem, coefficients, curve


def main() -> None:
    request = load_request()
    policy, problem, coefficients, curve = _checked_problem(request)
    proof.all(True)
    diagnostic("proof-mode", proof_all=True)

    curve, rank, generators = pari_rank_basis(coefficients)
    diagnostic(
        "rank-complete",
        algorithm="pari-direct-ellrank",
        proof=True,
        upper_bound=rank,
        rank=rank,
        basis_contract="upper-bound-equals-exact-subgroup-rank-after-full-saturation",
    )
    diagnostic(
        "candidate-basis-checked",
        rank=rank,
        generators=len(generators),
        gens_certain=True,
        independence="rank-upper-bound-and-full-saturation-required",
        basis=_point_coordinates(generators),
    )

    if rank == 0:
        checked_basis = []
        saturation = {
            "status": "not_applicable",
            "max_prime": SATURATION_MAX_PRIME,
            "min_prime": SATURATION_MIN_PRIME,
        }
        diagnostic("saturation-not-applicable", rank=0)
    else:
        checked_basis, saturation = saturate_basis(curve, generators, rank)
        saturation["status"] = "complete"

    torsion_order = curve.torsion_subgroup().order()
    diagnostic("integral-points-start", original_model=True, both_signs=True, rank=rank)
    points = curve.integral_points(mw_base=checked_basis, both_signs=True)
    serialized_points = []
    seen_points = set()
    for point in points:
        if point.is_zero():
            raise RuntimeError("integral_points returned the point at infinity")
        x = QQ(point[0])
        y = QQ(point[1])
        if x.denominator() != 1 or y.denominator() != 1:
            raise RuntimeError("integral_points returned a non-integral affine point")
        if not _curve_equation_holds(curve, x, y):
            raise RuntimeError("integral_points returned an off-curve point")
        serialized = (str(x.numerator()), str(y.numerator()))
        if serialized not in seen_points:
            serialized_points.append({"x": serialized[0], "y": serialized[1]})
            seen_points.add(serialized)
    serialized_points.sort(key=lambda point: (Integer(point["x"]), Integer(point["y"])))
    diagnostic("integral-points-complete", count=len(serialized_points), original_model=True)

    response = {
        "schema_version": SCHEMA_VERSION,
        "request_id": request["request_id"],
        "ok": True,
        "complete": True,
        "problem": problem,
        "proof": {
            "proof_all": True,
            "rank_proven": True,
            "rank": canonical_integer(rank),
            "generators": [
                {
                    "x": {"value": rational_text(generator[0])},
                    "y": {"value": rational_text(generator[1])},
                }
                for generator in checked_basis
            ],
            "gens_certain": True,
            "both_signs": True,
            "integral_points_complete": True,
            "torsion_order": canonical_integer(torsion_order),
        },
        "model": {
            "semantics": ORIGINAL_INTEGRAL_MODEL,
            "curve_coefficients": [canonical_integer(value) for value in coefficients],
        },
        "points": serialized_points,
        "backend": {
            "name": "SageMath",
            "sage_version": str(sage_version),
            "python_version": platform.python_version(),
            "environment": policy["environment"],
            "distribution": policy["distribution"],
            "script_sha256": script_digest(),
        },
    }
    json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
