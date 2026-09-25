//! Differential coverage for the flat SPF factorization scaffold.

use cubealqot::{factor, filters::Stage, spf, survivors};

fn trial_division(mut n: u32) -> Vec<(u32, u32)> {
    assert!(n > 0);
    let mut factors = Vec::new();
    let mut p = 2;
    while p <= n / p {
        if n % p == 0 {
            let mut exponent = 0;
            while n % p == 0 {
                n /= p;
                exponent += 1;
            }
            factors.push((p, exponent));
        }
        p += if p == 2 { 1 } else { 2 };
    }
    if n > 1 {
        factors.push((n, 1));
    }
    factors
}

fn is_prime(n: u32) -> bool {
    n >= 2 && trial_division(n).len() == 1 && trial_division(n)[0] == (n, 1)
}

fn factor_pairs(factors: &[factor::Factor; factor::MAX_OMEGA], omega: u8) -> Vec<(u32, u32)> {
    factors[..omega as usize]
        .iter()
        .map(|factor| {
            (
                u32::try_from(factor.p).expect("old test factor fits u32"),
                factor.e,
            )
        })
        .collect()
}

#[test]
fn flat_spf_marks_composites_with_their_smallest_prime_factor() {
    let limit = 10_000;
    let table = spf::build_spf(limit);

    assert_eq!(table.len(), limit as usize + 1);
    assert_eq!(table[0], 0);
    assert_eq!(table[1], 0);

    for n in 2..=limit {
        if is_prime(n) {
            assert_eq!(table[n as usize], 0, "prime {n} should remain unmarked");
        } else {
            let expected = trial_division(n)[0].0;
            assert_eq!(table[n as usize] as u32, expected, "n={n}");
        }
    }
}

#[test]
fn factor_into_matches_trial_division_exhaustively() {
    let limit = 50_000;
    let table = spf::build_spf(limit);
    let mut output = [factor::Factor::default(); factor::MAX_OMEGA];

    for n in 1..=limit {
        let omega = factor::factor_into(n, &table, &mut output);
        assert_eq!(
            factor_pairs(&output, omega),
            trial_division(n),
            "factorization mismatch for {n}"
        );

        let active = &output[..omega as usize];
        assert!(active.windows(2).all(|pair| pair[0].p < pair[1].p));
    }
}

#[test]
fn factor_into_matches_trial_division_on_deterministic_random_inputs() {
    let limit = 1_000_000;
    let table = spf::build_spf(limit);
    let mut output = [factor::Factor::default(); factor::MAX_OMEGA];
    let mut state: u64 = 0x_fa_c7_0123_4567_89ab;

    for _ in 0..10_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let n = state as u32 % (limit - 1) + 2;
        let omega = factor::factor_into(n, &table, &mut output);

        assert_eq!(factor_pairs(&output, omega), trial_division(n), "n={n}");
    }
}

#[test]
fn segmented_factorization_matches_flat_spf_across_segment_boundaries() {
    let flat_limit = 1_000_000;
    let flat = spf::build_spf(flat_limit);
    let ranges = [(2, 511), (65_530, 66_100), (900_000, flat_limit)];

    for (start, end) in ranges {
        let segmented = spf::SegmentedSpf::new(start, end);
        let mut flat_output = [factor::Factor::default(); factor::MAX_OMEGA];
        let mut segmented_output = [factor::Factor::default(); factor::MAX_OMEGA];

        for n in start..=end {
            let flat_omega = factor::factor_into(n, &flat, &mut flat_output);
            let segmented_omega = segmented.factor_into(n, &mut segmented_output);
            assert_eq!(segmented_omega, flat_omega, "omega mismatch for {n}");
            assert_eq!(segmented_output, flat_output, "factor mismatch for {n}");
        }
    }
}

#[test]
fn segmented_factorization_preserves_full_u32_prime_power_exponents() {
    let n = 1u32 << 31;
    let segmented = spf::SegmentedSpf::new(n, n + 3);
    let mut output = [factor::Factor::default(); factor::MAX_OMEGA];

    let omega = segmented.factor_into(n, &mut output);

    assert_eq!(omega, 1);
    assert_eq!(output[0], factor::Factor { p: 2, e: 31 });
}

#[test]
fn large_range_collection_uses_segmented_factorization() {
    let output = survivors::collect_range(100_000_000, 100_000_020, 2, Stage::F8)
        .expect("bounded range above the flat threshold should run");

    assert_eq!(output.stats.tested, 21);
}

#[test]
fn candidate_initializes_factorization_and_worker_scratch() {
    let table = spf::build_spf(100);
    let candidate = factor::Candidate::new(72u64, &table);

    assert_eq!(candidate.m, 72);
    assert_eq!(candidate.omega, 2);
    assert_eq!(candidate.a2, 3);
    assert_eq!(
        factor_pairs(&candidate.f, candidate.omega),
        [(2, 3), (3, 2)]
    );
    assert!(candidate.s_mod_sieve.is_empty());
    assert!(candidate.foreign_zeros.is_empty());
    assert_eq!(candidate.cross_val, [0; factor::MAX_OMEGA]);
    assert_eq!(candidate.s_cache, None);
}

#[test]
#[should_panic(expected = "factorization input must be positive")]
fn factor_into_rejects_zero() {
    let table = spf::build_spf(10);
    let mut output = [factor::Factor::default(); factor::MAX_OMEGA];
    factor::factor_into(0u64, &table, &mut output);
}
