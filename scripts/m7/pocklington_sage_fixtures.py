"""Independent proof-enabled Sage check for M7-06 positive fixtures."""

from sage.all import Integer, proof


FIXTURES = {
    "child": 18_446_744_073_709_551_629,
    "child_factor": 658_812_288_346_769_701,
    "root": 811_656_739_243_220_271_677,
}


proof.all(True)
for name, value in FIXTURES.items():
    integer = Integer(value)
    if not integer.is_prime(proof=True):
        raise SystemExit(f"Sage rejected positive fixture {name}={value}")
    print(f"{name}: proven-prime")
