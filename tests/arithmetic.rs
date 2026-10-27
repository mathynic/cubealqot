//! Differential/property coverage for the arithmetic primitives.

use cubealqot::{exact::isqrt, numth, tables::pow_sum};

fn naive_pow_sum(a: u64, n: u64, modulus: u64) -> (u64, u64) {
    let mut power = 1 % modulus;
    let mut sum = 0;

    for _ in 0..n {
        sum = ((sum as u128 + power as u128) % modulus as u128) as u64;
        power = ((power as u128 * a as u128) % modulus as u128) as u64;
    }

    (power, sum)
}

fn next_u64(state: &mut u64) -> u64 {
    // A deterministic generator keeps this test reproducible without adding
    // a production dependency or relying on ambient randomness.
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

#[test]
fn pow_sum_matches_naive_arithmetic() {
    for modulus in 1..=32 {
        for a in 0..=32 {
            for n in 0..=32 {
                assert_eq!(
                    pow_sum(a, n, modulus),
                    naive_pow_sum(a, n, modulus),
                    "a={a}, n={n}, modulus={modulus}"
                );
            }
        }
    }

    let mut state = 0x_c0be_a710_1234_5678;
    for _ in 0..10_000 {
        let modulus = next_u64(&mut state) % 1_000_000 + 1;
        let a = next_u64(&mut state) % 1_000_000;
        let n = next_u64(&mut state) % 256;
        assert_eq!(pow_sum(a, n, modulus), naive_pow_sum(a, n, modulus));
    }

    for _ in 0..1_000 {
        let modulus = next_u64(&mut state) | 1;
        let a = next_u64(&mut state);
        let n = next_u64(&mut state) % 64;
        assert_eq!(pow_sum(a, n, modulus), naive_pow_sum(a, n, modulus));
    }
}

#[test]
fn modular_multiply_and_pow_match_naive_arithmetic() {
    for modulus in 1..=64 {
        for a in 0..=64 {
            for b in 0..=64 {
                let expected = ((a as u128 * b as u128) % modulus as u128) as u64;
                assert_eq!(numth::mod_mul(a, b, modulus), expected);
            }
        }
    }

    let mut state = 0x_5eed_1234_9876_abcd;
    for _ in 0..10_000 {
        let modulus = next_u64(&mut state) % 1_000_000 + 1;
        let base = next_u64(&mut state) % 1_000_000;
        let exponent = next_u64(&mut state) % 256;
        let mut expected = 1 % modulus;
        let reduced_base = base % modulus;
        for _ in 0..exponent {
            expected = ((expected as u128 * reduced_base as u128) % modulus as u128) as u64;
        }

        assert_eq!(numth::mod_pow(base, exponent, modulus), expected);
    }

    for _ in 0..1_000 {
        let modulus = next_u64(&mut state) | 1;
        let base = next_u64(&mut state);
        let exponent = next_u64(&mut state) % 128;
        let mut expected = 1 % modulus;
        let reduced_base = base % modulus;
        for _ in 0..exponent {
            expected = ((expected as u128 * reduced_base as u128) % modulus as u128) as u64;
        }

        assert_eq!(numth::modpow(base, exponent, modulus), expected);
    }
}

#[test]
fn valuation_helpers_match_repeated_division() {
    for n in 1..=10_000u128 {
        for p in 2..=20u128 {
            let mut remainder = n;
            let mut expected = 0;
            while remainder % p == 0 {
                remainder /= p;
                expected += 1;
            }

            assert_eq!(numth::valuation(n, p), expected, "n={n}, p={p}");
        }
    }

    for n in 1..=10_000u128 {
        assert_eq!(numth::v2(n), numth::valuation(n, 2));
        assert_eq!(numth::v3(n), numth::valuation(n, 3));
    }
}

#[test]
fn binary_valuations_cover_the_full_u128_width() {
    for exponent in 0..128u32 {
        for odd in [1u128, 3, 5, u128::from(u64::MAX), u128::MAX] {
            if odd <= u128::MAX >> exponent {
                // An odd multiple of 2^exponent has exactly this valuation,
                // including values whose low 64 bits are all zero.
                let n = odd << exponent;
                assert_eq!(numth::valuation(n, 2), exponent, "n={n}");
                assert_eq!(numth::v2(n), exponent, "n={n}");
                assert_eq!(numth::v_p(n, 2), exponent, "n={n}");
            }
        }
    }
}

#[test]
fn integer_square_root_matches_bruteforce_boundary() {
    for n in 0..=100_000u128 {
        let root = isqrt(n);
        assert!(root * root <= n);
        assert!(root == u64::MAX as u128 || (root + 1) * (root + 1) > n);
    }

    for n in [
        0,
        1,
        2,
        3,
        4,
        u64::MAX as u128,
        (u64::MAX as u128) * (u64::MAX as u128),
        u128::MAX,
    ] {
        let root = isqrt(n);
        assert!(root * root <= n, "root={root}, n={n}");
        assert!(root == u64::MAX as u128 || (root + 1) * (root + 1) > n);
    }
}

#[test]
#[should_panic(expected = "modulus must be non-zero")]
fn modular_operations_reject_zero_modulus() {
    let _ = numth::mod_mul(1, 1, 0);
}

#[test]
#[should_panic(expected = "valuation is undefined for zero")]
fn valuation_rejects_zero() {
    let _ = numth::valuation(0, 2);
}
