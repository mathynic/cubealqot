"""Independent pure-Python replay of the frozen MW-02 N=19 witnesses.

This intentionally does not import Sage, PARI or eclib.  It is a differential
check of finite-field equation counts, the group law and exact ell-multiple
images; it is not production proof-generation code.
"""

from __future__ import annotations

import json


COEFFICIENTS = (0, 7240, 0, 7240 * 381, 7240 * 381**2)
P = (-3666, 197412)
Q = (-46, 30648)


def add(left, right, p):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    _, a2, _, a4, _ = COEFFICIENTS
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if left == right:
        denominator = (2 * y1) % p
        if denominator == 0:
            return None
        numerator = (3 * x1 * x1 + 2 * a2 * x1 + a4) % p
    else:
        denominator = (x2 - x1) % p
        if denominator == 0:
            raise AssertionError("invalid distinct finite-field pair")
        numerator = (y2 - y1) % p
    slope = numerator * pow(denominator, -1, p) % p
    x3 = (slope * slope - a2 - x1 - x2) % p
    y3 = (-y1 + slope * (x1 - x3)) % p
    return x3, y3


def multiply(point, scalar, p):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = add(result, addend, p)
        addend = add(addend, addend, p)
        scalar >>= 1
    return result


def on_curve(point, p):
    if point is None:
        return True
    x, y = point
    _, a2, _, a4, a6 = COEFFICIENTS
    return (y * y - (x**3 + a2 * x * x + a4 * x + a6)) % p == 0


def enumerate_group(p):
    group = [None]
    for x in range(p):
        for y in range(p):
            if on_curve((x, y), p):
                group.append((x, y))
    return group


def directions(rank, ell):
    if rank == 1:
        return [(1,)]
    return [(1, b) for b in range(ell)] + [(0, 1)]


def combine(points, coefficients, p):
    result = None
    for coefficient, point in zip(coefficients, points):
        result = add(result, multiply(point, coefficient, p), p)
    return result


def replay(points, multipliers, ell, torsion_prime, expected_order, eliminations):
    torsion_group = enumerate_group(torsion_prime)
    torsion_direct = 1 + sum(
        on_curve((x, y), torsion_prime)
        for x in range(torsion_prime)
        for y in range(torsion_prime)
    )
    assert len(torsion_group) == torsion_direct == expected_order
    assert len(torsion_group) % ell != 0
    records = []
    for p, required in eliminations:
        group = enumerate_group(p)
        direct = 1 + sum(
            on_curve((x, y), p) for x in range(p) for y in range(p)
        )
        assert len(group) == direct
        multiples = {multiply(point, ell, p) for point in group}
        reduced_points = [
            multiply((point[0] % p, point[1] % p), multiplier, p)
            for point, multiplier in zip(points, multipliers)
        ]
        eliminated = []
        for direction in required:
            assert combine(reduced_points, direction, p) not in multiples
            eliminated.append(list(direction))
        records.append({
            "prime": p,
            "group_order": len(group),
            "direct_equation_count": direct,
            "eliminated": eliminated,
        })
    return {
        "torsion_exclusion": {
            "prime": torsion_prime,
            "group_order": expected_order,
            "direct_equation_count": torsion_direct,
        },
        "eliminations": records,
    }


def main():
    first = replay(
        [P, Q],
        (1, 1),
        2,
        17,
        25,
        [(19, [(1, 0), (0, 1)]), (23, [(1, 1)])],
    )
    doubled = replay(
        [P, Q],
        (2, 2),
        3,
        31,
        28,
        [(11, [(1, 0), (1, 1), (0, 1)]), (41, [(1, 2)])],
    )
    print(json.dumps({
        "ok": True,
        "status": "PASSED",
        "implementation": "independent-pure-python",
        "witnesses": {
            "P_Q_ell2": first,
            "2P_2Q_ell3": doubled,
        },
        "warning": "differential qualification evidence; not a family theorem",
    }, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
