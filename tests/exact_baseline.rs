//! Differential tests for the exact sigma and square baseline.

use cubealqot::{Candidate, build_spf, exact};

fn direct_sigma(n: u32) -> u128 {
    (1..=n)
        .filter(|divisor| n % divisor == 0)
        .map(u128::from)
        .sum()
}

fn direct_sigma_cube(m: u32) -> u128 {
    direct_sigma(m.pow(3))
}

fn candidate(m: u32, spf: &[u16]) -> Candidate {
    Candidate::new(m, spf)
}

#[test]
fn exact_sigma_matches_direct_divisor_summation() {
    let spf = build_spf(1_000);

    for m in 1..=10 {
        let c = candidate(m, &spf);
        assert_eq!(exact::exact_sigma(&c), direct_sigma_cube(m), "m={m}");
        assert_eq!(
            exact::aliquot_sum(&c),
            direct_sigma_cube(m) - u128::from(m).pow(3)
        );
    }

    // This remains an independent divisor-sum oracle while exercising a
    // wider set of repeated and mixed prime factors.
    for m in 11..=100 {
        let c = candidate(m, &spf);
        assert_eq!(exact::exact_sigma(&c), direct_sigma_cube(m), "m={m}");
    }
}

#[test]
fn exact_baseline_matches_direct_summation_on_deterministic_random_inputs() {
    let limit = 100;
    let spf = build_spf(limit);
    let mut state: u64 = 0x_eac7_1234_5678_9abc;

    for _ in 0..250 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let m = state as u32 % limit + 1;
        let c = candidate(m, &spf);
        let expected_s = direct_sigma_cube(m) - u128::from(m).pow(3);

        assert_eq!(exact::aliquot_sum(&c), expected_s, "m={m}");
        assert_eq!(
            exact::aliquot_sum_is_square(&c),
            exact::is_square(expected_s)
        );
    }
}

#[test]
fn reviewed_smoke_values_match_exact_baseline() {
    let spf = build_spf(21);
    let expected = [(2, 15, 7), (6, 600, 384), (7, 400, 57), (15, 6240, 2865)];

    for (m, sigma, sum) in expected {
        let c = candidate(m, &spf);
        assert_eq!(exact::exact_sigma(&c), sigma);
        assert_eq!(exact::aliquot_sum(&c), sum);
    }
}

#[test]
fn square_test_is_exact_at_boundaries() {
    for n in 0..=100_000u128 {
        let expected = (0..=316u128).any(|root| root * root == n);
        assert_eq!(exact::is_square(n), expected, "n={n}");
    }

    for n in [
        0,
        1,
        2,
        3,
        4,
        9,
        u64::MAX as u128,
        (u64::MAX as u128) * (u64::MAX as u128),
        u128::MAX,
    ] {
        let root = exact::isqrt(n);
        assert_eq!(exact::is_square(n), root * root == n);
    }
}
