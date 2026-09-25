"""MW-02 exact rank-evidence and candidate-pool qualification.

This module is an isolated qualification implementation.  It is intentionally
not imported by the running campaign helper.  It separates three facts which
must not be conflated:

* PARI supplies the fresh rank interval and its upper bound (the caller owns
  that evidence);
* a finite-field witness proves independence of one or two supplied points;
* eclib full saturation, checked separately, supplies the trusted saturated
  basis used by the integral-point routine.

No failed bounded witness search is converted to dependence or rank zero.
"""

from __future__ import annotations

import io
import os
import tempfile
from itertools import combinations

from sage.all import EllipticCurve, GF, QQ, ZZ, prime_range


INITIAL_ELL_VALUES = (2, 3, 5, 7, 11, 13)
INITIAL_PRIME_BOUND = 1000


class IndependenceUnresolved(RuntimeError):
    """The finite witness budget did not establish independence."""


class RankContradiction(RuntimeError):
    """The supplied pool contains more witnessed rank than the rank upper bound."""


class SaturationUnresolved(RuntimeError):
    """The qualified all-prime saturation result cannot be admitted."""


SATURATION_MAX_PRIME = -1
SATURATION_MIN_PRIME = 2


def _run_with_native_output(callback):
    """Capture C/C++ eclib output without contaminating the JSON channel."""

    sys_stdout = os.dup(1)
    sys_stderr = os.dup(2)
    with tempfile.TemporaryFile() as capture:
        try:
            os.dup2(capture.fileno(), 1)
            os.dup2(capture.fileno(), 2)
            result = callback()
        finally:
            try:
                os.fsync(capture.fileno())
            except OSError:
                pass
            os.dup2(sys_stdout, 1)
            os.dup2(sys_stderr, 2)
            os.close(sys_stdout)
            os.close(sys_stderr)
            capture.seek(0)
        return result, capture.read().decode("utf-8", errors="replace")


def _rational_key(value):
    value = QQ(value)
    return (int(value.numerator()), int(value.denominator()))


def _point_key(point):
    if point.is_zero():
        return ("infinity",)
    return (_rational_key(point[0]), _rational_key(point[1]))


def _point_coordinates(point):
    if point.is_zero():
        return {"infinity": True}
    return {
        "x": f"{point[0].numerator()}/{point[0].denominator()}",
        "y": f"{point[1].numerator()}/{point[1].denominator()}",
    }


def _validate_affine_pool(curve, points):
    result = []
    for point in list(points):
        if point.is_zero():
            raise ValueError("candidate pool contains the point at infinity")
        x, y = QQ(point[0]), QQ(point[1])
        checked = curve([x, y])
        if checked.is_zero() or _point_key(checked) != _point_key(point):
            raise ValueError("candidate pool contains a point from another model")
        result.append(checked)
    return result


def _direct_equation_count(curve, p):
    """Count affine solutions directly, independently of Sage point lists."""

    coefficients = [QQ(value) for value in curve.a_invariants()]
    if any(value.denominator() % p == 0 for value in coefficients):
        raise IndependenceUnresolved("INDEPENDENCE_UNRESOLVED: nonintegral reduction")
    a1, a2, a3, a4, a6 = [int(value) % p for value in coefficients]
    affine = 0
    for x in range(p):
        for y in range(p):
            left = (y * y + a1 * x * y + a3 * y) % p
            right = (x**3 + a2 * x * x + a4 * x + a6) % p
            affine += left == right
    return affine + 1


def _finite_curve_data(curve, p, ell, points):
    """Return exact finite-group data or ``None`` for unusable reduction."""

    if int(ZZ(curve.discriminant())) % p == 0:
        return None
    try:
        finite_curve = curve.change_ring(GF(p))
        group = list(finite_curve.points())
        direct_count = _direct_equation_count(curve, p)
    except Exception as error:
        raise IndependenceUnresolved(
            f"INDEPENDENCE_UNRESOLVED: finite-field enumeration failed at p={p}"
        ) from error
    if len(group) != direct_count:
        raise IndependenceUnresolved(
            f"INDEPENDENCE_UNRESOLVED: group count mismatch at p={p}"
        )

    reduced = []
    for point in points:
        x, y = QQ(point[0]), QQ(point[1])
        if x.denominator() % p == 0 or y.denominator() % p == 0:
            return {
                "curve": finite_curve,
                "group": group,
                "group_order": len(group),
                "direct_count": direct_count,
                "reduced": None,
                "multiples": None,
            }
        try:
            field = GF(p)
            reduced.append(
                finite_curve([
                    field(x.numerator()) / field(x.denominator()),
                    field(y.numerator()) / field(y.denominator()),
                ])
            )
        except Exception as error:
            raise IndependenceUnresolved(
                f"INDEPENDENCE_UNRESOLVED: point reduction failed at p={p}"
            ) from error
    multiples = {
        ("infinity",) if (ell * point).is_zero() else
        (int((ell * point)[0]), int((ell * point)[1]))
        for point in group
    }
    return {
        "curve": finite_curve,
        "group": group,
        "group_order": len(group),
        "direct_count": direct_count,
        "reduced": reduced,
        "multiples": multiples,
    }


def _finite_key(point):
    if point.is_zero():
        return ("infinity",)
    return (int(point[0]), int(point[1]))


def _directions(rank, ell):
    if rank == 1:
        return [(1,)]
    if rank == 2:
        return [(1, b) for b in range(ell)] + [(0, 1)]
    if rank == 3:
        return (
            [(1, b, c) for b in range(ell) for c in range(ell)]
            + [(0, 1, c) for c in range(ell)]
            + [(0, 0, 1)]
        )
    raise ValueError("MW-02 finite witness supports rank one, two or three")


def independence_witness(
    curve,
    points,
    rank,
    *,
    ells=INITIAL_ELL_VALUES,
    prime_bound=INITIAL_PRIME_BOUND,
):
    """Find an exact finite-field independence witness for one/two points.

    The returned dictionary is replayable evidence, not a rank claim by
    itself.  It records a fresh exact group count for every used reduction and
    the prime eliminating each projective coefficient direction.  If no
    witness is found, ``IndependenceUnresolved`` is raised.
    """

    rank = int(rank)
    points = _validate_affine_pool(curve, points)
    if len(points) != rank or rank not in (1, 2, 3):
        raise ValueError("independence witness needs one, two or three points")

    attempts = []
    for ell in tuple(int(value) for value in ells):
        if ell < 2:
            raise ValueError("ell must be at least two")
        directions = set(_directions(rank, ell))
        eliminators = {}
        torsion_exclusion = None
        reductions = []

        for p in prime_range(3, int(prime_bound) + 1):
            p = int(p)
            if p == ell:
                continue
            data = _finite_curve_data(curve, p, ell, points)
            if data is None:
                continue
            if data["group_order"] % ell != 0 and torsion_exclusion is None:
                torsion_exclusion = {"prime": p, "group_order": data["group_order"]}

            record = {
                "prime": p,
                "group_order": data["group_order"],
                "direct_equation_count": data["direct_count"],
                "reduced": data["reduced"] is not None,
                "eliminated": [],
            }
            if data["reduced"] is not None and directions:
                for direction in sorted(directions):
                    combination = data["curve"](0)
                    for coefficient, point in zip(direction, data["reduced"]):
                        combination += int(coefficient) * point
                    if _finite_key(combination) not in data["multiples"]:
                        eliminators[direction] = p
                        record["eliminated"].append(list(direction))
                directions = set(directions) - set(eliminators)
            reductions.append(record)

            if not directions and torsion_exclusion is not None:
                witness = {
                    "rank": rank,
                    "ell": ell,
                    "points": [_point_coordinates(point) for point in points],
                    "torsion_exclusion": torsion_exclusion,
                    "eliminators": {
                        ",".join(str(value) for value in direction): prime
                        for direction, prime in sorted(eliminators.items())
                    },
                    "reductions": reductions,
                    "direct_group_counts_verified": all(
                        item["group_order"] == item["direct_equation_count"]
                        for item in reductions
                    ),
                    "attempts": attempts + [{
                        "ell": ell,
                        "status": "success",
                        "torsion_exclusion": torsion_exclusion,
                    }],
                }
                return witness

        attempts.append({
            "ell": ell,
            "status": "unresolved",
            "torsion_exclusion": torsion_exclusion,
            "remaining_directions": [list(direction) for direction in sorted(directions)],
            "reductions_checked": len(reductions),
        })

    raise IndependenceUnresolved(
        "INDEPENDENCE_UNRESOLVED: no finite-field witness within the declared budget"
    )


def select_independent_subset(
    curve, candidate_pool, rank, *, prime_bound=INITIAL_PRIME_BOUND
):
    """Select a witnessed full-rank subset without truncating the pool.

    Independence is checked on the minimal model.  The complete original pool
    remains represented by the returned metadata; only the selected subset is
    sent to saturation.  A successful witness for ``rank + 1`` pool points is
    an explicit contradiction with the fresh PARI upper bound.
    """

    rank = int(rank)
    if rank not in (1, 2):
        raise ValueError("candidate selection supports positive rank one or two")
    pool = _validate_affine_pool(curve, candidate_pool)
    minimal = curve.minimal_model()
    to_minimal = curve.isomorphism_to(minimal)
    minimal_pool = [to_minimal(point) for point in pool]

    if len(minimal_pool) < rank:
        raise IndependenceUnresolved(
            "INDEPENDENCE_UNRESOLVED: candidate pool has fewer points than rank"
        )

    # This is deliberately a witness-only contradiction check.  A failed
    # bounded test here is not evidence that the larger subset is dependent.
    for indices in combinations(range(len(minimal_pool)), rank + 1):
        try:
            independence_witness(
                minimal,
                [minimal_pool[index] for index in indices],
                rank + 1,
                prime_bound=prime_bound,
            )
        except (IndependenceUnresolved, ValueError):
            continue
        raise RankContradiction(
            f"RANK_CONTRADICTION: pool contains witnessed rank {rank + 1}"
        )

    for indices in combinations(range(len(minimal_pool)), rank):
        try:
            witness = independence_witness(
                minimal,
                [minimal_pool[index] for index in indices],
                rank,
                prime_bound=prime_bound,
            )
        except (IndependenceUnresolved, ValueError):
            continue
        witness = dict(witness)
        witness["selected_indices"] = list(indices)
        witness["pool_size"] = len(pool)
        witness["minimal_model"] = [str(value) for value in minimal.a_invariants()]
        return [pool[index] for index in indices], witness

    raise IndependenceUnresolved(
        "INDEPENDENCE_UNRESOLVED: no witnessed full-rank subset in candidate pool"
    )


def _minimal_triple(point):
    x, y = QQ(point[0]), QQ(point[1])
    denominator = x.denominator().lcm(y.denominator())
    if denominator <= 0:
        raise SaturationUnresolved("invalid minimal-model denominator")
    return (ZZ(x * denominator), ZZ(y * denominator), ZZ(denominator))


def _point_from_minimal_triple(minimal, triple):
    if not isinstance(triple, (tuple, list)) or len(triple) != 3:
        raise SaturationUnresolved("malformed saturated basis point")
    try:
        x, y, denominator = (ZZ(value) for value in triple)
    except Exception as error:
        raise SaturationUnresolved("non-integer saturated basis point") from error
    if denominator <= 0:
        raise SaturationUnresolved("saturated basis denominator is not positive")
    point = minimal([QQ(x) / denominator, QQ(y) / denominator])
    if point.is_zero() or not _curve_equation_holds(minimal, point[0], point[1]):
        raise SaturationUnresolved("saturated basis point is off the minimal model")
    return point


def _curve_equation_holds(curve, x, y):
    x, y = QQ(x), QQ(y)
    a1, a2, a3, a4, a6 = curve.a_invariants()
    return y * y + a1 * x * y + a3 * y == x**3 + a2 * x * x + a4 * x + a6


def _parse_unresolved_primes(value):
    if not isinstance(value, str):
        raise ValueError("eclib unresolved-prime result is not text")
    text = value.strip()
    if not (text.startswith("[") and text.endswith("]")):
        raise ValueError("malformed eclib unresolved-prime result")
    body = text[1:-1].strip()
    if not body:
        return ()
    try:
        values = tuple(int(token.strip()) for token in body.split(","))
    except Exception as error:
        raise ValueError("malformed eclib unresolved-prime result") from error
    if any(value < 2 for value in values) or values != tuple(sorted(set(values))):
        raise ValueError("unresolved-prime result is not sorted and distinct")
    return values


def validate_saturation_result(result):
    """Require the exact successful all-prime eclib result shape."""

    if not isinstance(result, (tuple, list)) or len(result) != 3:
        raise ValueError("unexpected eclib saturation result shape")
    ok, index, unresolved = result
    if not isinstance(ok, bool):
        raise ValueError("eclib saturation success flag is not boolean")
    try:
        index = int(ZZ(index))
    except Exception as error:
        raise ValueError("malformed eclib saturation index") from error
    unresolved = _parse_unresolved_primes(unresolved)
    if not ok:
        raise SaturationUnresolved("eclib full saturation returned failure")
    if index < 1:
        raise ValueError("eclib saturation index must be positive")
    if unresolved:
        raise SaturationUnresolved(
            f"eclib reported unresolved saturation primes: {unresolved}"
        )
    return index, unresolved


def full_saturate_basis(curve, candidate_points, rank, *, prime_bound=INITIAL_PRIME_BOUND):
    """Run qualified full saturation after an independently witnessed basis.

    The finite-field witness is repeated on the minimal model for the input
    and returned points.  eclib's rank is retained only as a consistency check;
    it never replaces the witness.  Backend errors, malformed output and
    unresolved primes all fail closed as ``SaturationUnresolved``.
    """

    rank = int(rank)
    if rank not in (1, 2):
        raise ValueError("full saturation supports positive rank one or two")
    points = _validate_affine_pool(curve, candidate_points)
    if len(points) != rank:
        raise ValueError("saturation input cardinality does not equal rank")

    minimal = curve.minimal_model()
    to_minimal = curve.isomorphism_to(minimal)
    from_minimal = minimal.isomorphism_to(curve)
    minimal_points = [to_minimal(point) for point in points]
    try:
        input_witness = independence_witness(
            minimal, minimal_points, rank, prime_bound=prime_bound
        )
    except (IndependenceUnresolved, ValueError) as error:
        raise SaturationUnresolved(
            "input basis independence is unresolved"
        ) from error

    backend_log = io.StringIO()
    try:
        from sage.libs.eclib.all import mwrank_MordellWeil

        # True preserves the full backend transcript for qualification; it is
        # not used as a mathematical predicate.
        def run_backend():
            mw = mwrank_MordellWeil(minimal.mwrank_curve(), True)
            triples = [_minimal_triple(point) for point in minimal_points]
            mw.process(triples, saturation_bound=0)
            processed_rank = int(mw.rank())
            if processed_rank != rank:
                raise SaturationUnresolved(
                    f"eclib rank {processed_rank} differs from established rank {rank}"
                )
            raw_result = mw.saturate(
                max_prime=SATURATION_MAX_PRIME,
                min_prime=SATURATION_MIN_PRIME,
            )
            index, unresolved = validate_saturation_result(raw_result)
            raw_points = mw.points()
            return index, unresolved, raw_points

        (index, unresolved, raw_points), native_log = _run_with_native_output(run_backend)
        backend_log.write(native_log)
    except SaturationUnresolved:
        raise
    except (ValueError, TypeError, ArithmeticError) as error:
        raise SaturationUnresolved("malformed or unsupported eclib result") from error
    except Exception as error:
        raise SaturationUnresolved("eclib full saturation did not complete") from error

    if not isinstance(raw_points, (tuple, list)) or len(raw_points) != rank:
        raise SaturationUnresolved("eclib returned an incomplete saturated basis")
    try:
        saturated_minimal = [
            _point_from_minimal_triple(minimal, triple) for triple in raw_points
        ]
        saturated_original = [from_minimal(point) for point in saturated_minimal]
        saturated_original = _validate_affine_pool(curve, saturated_original)
        output_witness = independence_witness(
            minimal,
            [to_minimal(point) for point in saturated_original],
            rank,
            prime_bound=prime_bound,
        )
    except (IndependenceUnresolved, ValueError, ArithmeticError) as error:
        raise SaturationUnresolved(
            "returned saturated basis failed exact validation or independence"
        ) from error

    return saturated_original, {
        "status": "complete",
        "index": index,
        "unresolved_primes": list(unresolved),
        "max_prime": SATURATION_MAX_PRIME,
        "min_prime": SATURATION_MIN_PRIME,
        "input_points": [_point_coordinates(point) for point in points],
        "input_independence": input_witness,
        "output_points": [_point_coordinates(point) for point in saturated_original],
        "output_independence": output_witness,
        "minimal_model": [str(value) for value in minimal.a_invariants()],
        "backend_log": backend_log.getvalue(),
    }
