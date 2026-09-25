"""MW-01 isolated Sage-side validator for discovery-point request data.

This is a qualification utility, not the production proof helper.  It checks
the request's optional discovery_points with Sage's exact QQ arithmetic and
returns one small JSON record.  It never establishes rank, a basis, or family
completeness.
"""

from __future__ import annotations

import json
import sys
from math import gcd

from sage.all import EllipticCurve, Integer, QQ


def canonical_integer(value: object) -> int:
    if not isinstance(value, str):
        raise ValueError("integer must be a JSON string")
    integer = Integer(value)
    if str(integer) != value:
        raise ValueError("integer is not canonical")
    return int(integer)


def canonical_rational(value: object):
    if not isinstance(value, str):
        raise ValueError("rational must be a JSON string")
    parts = value.split("/")
    if len(parts) > 2 or any(part == "" for part in parts):
        raise ValueError("rational must be p or p/q")
    numerator = canonical_integer(parts[0])
    denominator = 1 if len(parts) == 1 else canonical_integer(parts[1])
    if denominator <= 0:
        raise ValueError("rational denominator must be positive")
    if len(parts) == 2 and denominator == 1:
        raise ValueError("denominator one must be omitted")
    if gcd(abs(numerator), denominator) != 1:
        raise ValueError("rational is not reduced")
    rational = QQ(numerator) / QQ(denominator)
    rendered = str(rational.numerator())
    if rational.denominator() != 1:
        rendered += f"/{rational.denominator()}"
    if rendered != value:
        raise ValueError("rational is not canonical")
    return rational


def validate(request: dict) -> dict:
    problem = request.get("problem")
    if not isinstance(problem, dict):
        raise ValueError("request.problem must be an object")
    raw_coefficients = problem.get("curve_coefficients")
    if not isinstance(raw_coefficients, list) or len(raw_coefficients) != 5:
        raise ValueError("problem.curve_coefficients must contain five integers")
    coefficients = [canonical_integer(value) for value in raw_coefficients]
    curve = EllipticCurve(coefficients)
    raw_points = request.get("discovery_points")
    if raw_points is None:
        return {"ok": True, "discovery_points_present": False, "accepted_points": 0}
    if not isinstance(raw_points, list):
        raise ValueError("discovery_points must be a list")
    a1, a2, a3, a4, a6 = curve.a_invariants()

    for index, raw_point in enumerate(raw_points):
        if not isinstance(raw_point, dict) or set(raw_point) != {"x", "y"}:
            raise ValueError(f"point {index} has an unexpected shape")
        x = canonical_rational(raw_point["x"])
        y = canonical_rational(raw_point["y"])
        if y * y + a1 * x * y + a3 * y != x**3 + a2 * x * x + a4 * x + a6:
            raise ValueError(f"point {index} is off the exact original curve")

    return {
        "ok": True,
        "discovery_points_present": True,
        "accepted_points": len(raw_points),
        "curve_coefficients": [str(value) for value in coefficients],
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": "expected one request path"}))
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as request_file:
            request = json.load(request_file)
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        result = validate(request)
    except Exception as error:  # qualification utility reports structured failure
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 0
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
