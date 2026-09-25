"""Independent fixture check for M7-05.

This is a validation oracle only.  It is not imported by the Rust crate and
does not provide the production primality decision.
"""

from sympy import factorint, isprime


FIXTURES = (
    ("largest-known-32-bit-prime", 4_294_967_291, True),
    ("prime-2^32-plus-15", 4_294_967_311, True),
    ("prime-2^64-minus-59", 18_446_744_073_709_551_557, True),
    ("composite-2^32-minus-1", 4_294_967_295, False),
    ("composite-2^32", 4_294_967_296, False),
    ("composite-2^64-minus-1", 18_446_744_073_709_551_615, False),
    ("strong-pseudoprime-341550071728321", 341_550_071_728_321, False),
)


def main() -> None:
    for name, value, expected in FIXTURES:
        actual = bool(isprime(value))
        if actual != expected:
            raise SystemExit(f"fixture disagreement: {name}: {actual} != {expected}")
        if actual:
            print(f"{name}: prime")
        else:
            print(f"{name}: composite factors={factorint(value)}")


if __name__ == "__main__":
    main()
