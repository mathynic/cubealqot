#!/usr/bin/env python3
"""Independent bounded oracle for fixed-cofactor cube aliquot families.

This script deliberately computes the original quantity
    sigma((N*q)**3) - (N*q)**3
instead of importing or reproducing the Rust family polynomial.  For tiny
arguments it enumerates divisors directly.  Larger arguments use separately
implemented trial factorization and the multiplicative prime-power formula.
Every result is explicitly bounded by the inclusive q_max and is never a
completeness claim.
"""

from __future__ import annotations

import argparse
import json
import math
import sys


# The switch is on the actual integer whose sigma is requested, not on q or N.
DIRECT_CUBE_LIMIT = 1_000_000


def sigma_by_direct_divisors(value: int) -> int:
    total = 0
    divisor = 1
    while divisor * divisor <= value:
        if value % divisor == 0:
            total += divisor
            pair = value // divisor
            if pair != divisor:
                total += pair
        divisor += 1
    return total


def factorize_by_trial_division(value: int) -> list[tuple[int, int]]:
    factors: list[tuple[int, int]] = []
    remainder = value
    divisor = 2
    while divisor * divisor <= remainder:
        if remainder % divisor == 0:
            exponent = 0
            while remainder % divisor == 0:
                remainder //= divisor
                exponent += 1
            factors.append((divisor, exponent))
        divisor += 1
    if remainder > 1:
        factors.append((remainder, 1))
    return factors


def sigma_from_factors(factors: list[tuple[int, int]]) -> int:
    result = 1
    for prime, exponent in factors:
        result *= sum(prime**power for power in range(3 * exponent + 1))
    return result


def sigma_cube(value: int) -> tuple[int, str]:
    cube = value**3
    if cube <= DIRECT_CUBE_LIMIT:
        return sigma_by_direct_divisors(cube), "direct"
    return sigma_from_factors(factorize_by_trial_division(value)), "multiplicative"


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def family_record(n: int, q: int) -> tuple[int, bool, str]:
    m = n * q
    sigma, method = sigma_cube(m)
    aliquot_sum = sigma - m**3
    root = math.isqrt(aliquot_sum) if aliquot_sum >= 0 else -1
    return aliquot_sum, root >= 0 and root * root == aliquot_sum, method


def bounded_family(n: int, q_max: int) -> dict[str, object]:
    if n <= 1:
        raise ValueError("N must be greater than one")
    if q_max < 0:
        raise ValueError("q_max must be nonnegative")

    candidates: list[str] = []
    excluded_dividing_n: list[str] = []
    methods = {"direct": 0, "multiplicative": 0}
    records: list[dict[str, object]] = []
    tested_prime_count = 0
    for q in range(2, q_max + 1):
        if not is_prime(q):
            continue
        tested_prime_count += 1
        if n % q == 0:
            excluded_dividing_n.append(str(q))
            continue
        _, square, method = family_record(n, q)
        methods[method] += 1
        records.append({"q": str(q), "is_square": square, "method": method})
        if square:
            candidates.append(str(q))

    return {
        "n": str(n),
        "q_max": str(q_max),
        "candidates": candidates,
        "tested_prime_count": tested_prime_count,
        "excluded_dividing_n": excluded_dividing_n,
        "methods": methods,
        "records": records,
        "bounded": True,
        "global_completeness": False,
    }


def self_test() -> None:
    """Check the two sigma paths on an overlap without using Rust code."""
    for value in range(1, 101):
        direct = sigma_by_direct_divisors(value**3)
        multiplicative = sigma_from_factors(factorize_by_trial_division(value))
        if direct != multiplicative:
            raise AssertionError(f"oracle methods disagree for m={value}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int)
    parser.add_argument("--q-max", type=int)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    if args.n is None or args.q_max is None:
        parser.error("--n and --q-max are required unless --self-test is used")
    try:
        result = bounded_family(args.n, args.q_max)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
