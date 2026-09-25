#!/usr/bin/env python3
"""Independent exact oracle for the cube aliquot-sum baseline.

For m <= 1_000, sigma(m**3) is computed by direct divisor enumeration. Above
that boundary, sigma is computed from a separately written prime-factorization
and prime-power formula. The script intentionally does not import or mirror
the Rust implementation.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass


DIRECT_LIMIT = 1_000


@dataclass(frozen=True)
class OracleRecord:
    m: int
    sigma_m3: int
    s: int
    is_square: bool
    method: str


def sigma_by_direct_divisors(n: int) -> int:
    """Return sigma(n) by enumerating divisor pairs, not multiplicativity."""
    total = 0
    divisor = 1
    while divisor * divisor <= n:
        if n % divisor == 0:
            total += divisor
            pair = n // divisor
            if pair != divisor:
                total += pair
        divisor += 1
    return total


def primes_up_to(limit: int) -> list[int]:
    sieve = bytearray(b"\x01") * (limit + 1)
    if limit >= 0:
        sieve[0] = 0
    if limit >= 1:
        sieve[1] = 0
    for value in range(2, math.isqrt(limit) + 1):
        if sieve[value]:
            sieve[value * value : limit + 1 : value] = b"\x00" * (
                ((limit - value * value) // value) + 1
            )
    return [value for value in range(2, limit + 1) if sieve[value]]


def factorize_by_trial_division(n: int, primes: list[int]) -> list[tuple[int, int]]:
    factors: list[tuple[int, int]] = []
    remainder = n
    for prime in primes:
        if prime * prime > remainder:
            break
        if remainder % prime == 0:
            exponent = 0
            while remainder % prime == 0:
                remainder //= prime
                exponent += 1
            factors.append((prime, exponent))
    if remainder > 1:
        factors.append((remainder, 1))
    return factors


def sigma_from_factors(factors: list[tuple[int, int]]) -> int:
    result = 1
    for prime, exponent in factors:
        prime_power_sum = sum(prime**power for power in range(3 * exponent + 1))
        result *= prime_power_sum
    return result


def record_for(m: int, primes: list[int] | None = None) -> OracleRecord:
    cube = m**3
    if m <= DIRECT_LIMIT:
        sigma = sigma_by_direct_divisors(cube)
        method = "direct"
    else:
        if primes is None:
            primes = primes_up_to(math.isqrt(m))
        sigma = sigma_from_factors(factorize_by_trial_division(m, primes))
        method = "multiplicative"
    aliquot_sum = sigma - cube
    return OracleRecord(m, sigma, aliquot_sum, math.isqrt(aliquot_sum) ** 2 == aliquot_sum, method)


def records(max_m: int):
    if max_m < 2:
        raise ValueError("--max must be at least 2")
    primes = primes_up_to(math.isqrt(max_m))
    for m in range(2, max_m + 1):
        yield record_for(m, primes)


def self_test() -> None:
    primes = primes_up_to(math.isqrt(DIRECT_LIMIT))
    for m in range(1, DIRECT_LIMIT + 1):
        direct = sigma_by_direct_divisors(m**3)
        multiplicative = sigma_from_factors(factorize_by_trial_division(m, primes))
        if direct != multiplicative:
            raise AssertionError(f"oracle methods disagree for m={m}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max", type=int, help="inclusive maximum m to emit")
    parser.add_argument(
        "--values", type=int, nargs="+", help="emit selected exact m values"
    )
    parser.add_argument(
        "--factor-values", type=int, nargs="+", help="emit selected factorizations"
    )
    parser.add_argument("--self-test", action="store_true", help="cross-check both oracle algorithms")
    args = parser.parse_args(argv)

    if args.self_test:
        self_test()
        return 0
    if args.values is not None:
        for value in args.values:
            if value < 2:
                parser.error("--values entries must be at least 2")
            print(json.dumps(asdict(record_for(value)), separators=(",", ":")))
        return 0
    if args.factor_values is not None:
        if any(value < 2 for value in args.factor_values):
            parser.error("--factor-values entries must be at least 2")
        primes = primes_up_to(math.isqrt(max(args.factor_values)))
        for value in args.factor_values:
            print(
                json.dumps(
                    {"m": value, "factors": factorize_by_trial_division(value, primes)},
                    separators=(",", ":"),
                )
            )
        return 0
    if args.max is None:
        parser.error("--max or --values is required unless --self-test is used")

    for record in records(args.max):
        json.dump(asdict(record), sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
