//! F4 tests in ungated and normal-pipeline modes.

use cubealqot::{Candidate, build_spf, exact, filters, tables::init_residues};

const SIEVE_PRIMES: [u32; 23] = [
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

fn candidate(m: u32, spf: &[u16]) -> Candidate {
    Candidate::new(m, spf)
}

#[test]
fn ungated_f4_rejections_are_all_exact_nonsquares() {
    let max = 10_000;
    let spf = build_spf(max);
    let context = filters::F4Context::new(&SIEVE_PRIMES, 20);
    let mut rejection_count = 0;

    for m in 2u32..=max {
        let mut c = candidate(m, &spf);
        let residues = init_residues(&SIEVE_PRIMES, m);
        let rejection = filters::f4(&context, &mut c, &residues);

        assert_eq!(c.s_mod_sieve.len(), SIEVE_PRIMES.len());
        for (index, &q) in SIEVE_PRIMES.iter().enumerate() {
            assert_eq!(
                c.s_mod_sieve[index],
                (exact::aliquot_sum(&c) % u128::from(q)) as u32,
                "stored residue mismatch for m={m}, q={q}"
            );
        }

        if rejection.is_some() {
            rejection_count += 1;
            assert!(
                !exact::aliquot_sum_is_square(&c),
                "F4 was unsound for m={m}"
            );
        }
    }

    assert!(
        rejection_count > 0,
        "test range did not exercise F4 rejection"
    );
}

#[test]
fn normal_f1_f4_pipeline_matches_exact_baseline() {
    let max = 10_000;
    let spf = build_spf(max);
    let context = filters::F4Context::new(&SIEVE_PRIMES, 20);

    for m in 2u32..=max {
        let mut c = candidate(m, &spf);
        let residues = init_residues(&SIEVE_PRIMES, m);
        let exact_sum = exact::aliquot_sum(&c);
        let expected = if c.omega == 1 {
            filters::Outcome::rejected_f1()
        } else if filters::f4(&context, &mut c, &residues).is_some() {
            filters::Outcome::rejected_f4()
        } else if exact::is_square(exact_sum) {
            filters::Outcome::solution(exact::isqrt(exact_sum))
        } else {
            filters::Outcome::exact_nonsquare()
        };

        let mut pipeline_candidate = candidate(m, &spf);
        assert_eq!(
            filters::run_with_f4(&context, &mut pipeline_candidate, &residues),
            expected,
            "pipeline mismatch for m={m}"
        );
    }
}

#[test]
fn f4_keeps_zero_residues_for_later_refinement() {
    let spf = build_spf(7);
    let context = filters::F4Context::new(&[7], 3);
    let mut c = candidate(2, &spf);
    let residues = init_residues(&[7], 2u64);

    assert_eq!(filters::f4(&context, &mut c, &residues), None);
    assert_eq!(c.s_mod_sieve, [0]);
    assert_eq!(c.foreign_zeros, [0]);

    let spf = build_spf(10);
    let context = filters::F4Context::new(&[5], 3);
    let mut c = candidate(10, &spf);
    let residues = init_residues(&[5], 10u64);
    assert_eq!(filters::f4(&context, &mut c, &residues), None);
    assert_eq!(c.s_mod_sieve, [0]);
    assert!(c.foreign_zeros.is_empty());
}
