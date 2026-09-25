//! M7-05 tests for the independently bounded u64 primality contract.

use cubealqot::family::primality::{
    DETERMINISTIC_BASES, PROVEN_U64_MAX, PrimeStatus, classify_u64,
};

fn independent_sieve(limit: usize) -> Vec<bool> {
    let mut prime = vec![true; limit + 1];
    prime[0] = false;
    prime[1] = false;

    let mut p = 2usize;
    while p * p <= limit {
        if prime[p] {
            for multiple in (p * p..=limit).step_by(p) {
                prime[multiple] = false;
            }
        }
        p += 1;
    }
    prime
}

fn assert_composite_with_witness(n: u64) {
    match classify_u64(n) {
        PrimeStatus::ProvenComposite(witness) => {
            assert!(witness.verifies(n), "witness does not verify for {n}");
        }
        other => panic!("expected a checkable composite decision for {n}, got {other:?}"),
    }
}

#[test]
fn exhaustive_small_interval_agrees_with_an_independent_sieve() {
    let limit = 1_000_000usize;
    let expected = independent_sieve(limit);

    for n in 0..=limit {
        match (expected[n], classify_u64(n as u64)) {
            (true, PrimeStatus::ProvenPrime(prime)) => assert_eq!(prime.value(), n as u64),
            (false, PrimeStatus::ProvenComposite(witness)) if n >= 2 => {
                assert!(witness.verifies(n as u64));
            }
            (false, PrimeStatus::NotPrime(_)) if n < 2 => {}
            (expected, actual) => {
                panic!("sieve disagreement at {n}: expected {expected}, got {actual:?}")
            }
        }
    }
}

#[test]
fn zero_and_one_are_not_misreported_as_composite_or_prime() {
    assert!(matches!(classify_u64(0), PrimeStatus::NotPrime(_)));
    assert!(matches!(classify_u64(1), PrimeStatus::NotPrime(_)));
    assert!(matches!(classify_u64(2), PrimeStatus::ProvenPrime(_)));
    assert_composite_with_witness(4);
    assert_composite_with_witness(6);
}

#[test]
fn carmichael_and_strong_pseudoprime_fixtures_are_rejected() {
    for n in [
        341u64,
        561,
        1105,
        1729,
        2465,
        2821,
        6601,
        8911,
        3215031751,
        341550071728321,
    ] {
        assert_composite_with_witness(n);
    }
}

#[test]
fn boundaries_and_large_independent_fixtures_have_exact_decisions() {
    for n in [4294967291u64, 4294967311, 18446744073709551557] {
        match classify_u64(n) {
            PrimeStatus::ProvenPrime(prime) => assert_eq!(prime.value(), n),
            other => panic!("known prime {n} was not proven prime: {other:?}"),
        }
    }

    for n in [
        4294967295u64,
        4294967296,
        18446744073709551615,
        u64::MAX - 1,
    ] {
        assert_composite_with_witness(n);
    }
}

#[test]
fn declared_range_and_basis_are_explicit() {
    assert_eq!(PROVEN_U64_MAX, u64::MAX);
    assert_eq!(
        DETERMINISTIC_BASES,
        [2, 325, 9375, 28178, 450775, 9780504, 1795265022]
    );
    assert!(matches!(classify_u64(41), PrimeStatus::ProvenPrime(_)));
}
