use cubealqot::filters::f4b_foreign::{self, F4bAnalysis};
use cubealqot::filters::{self, Rejection, Stage};
use cubealqot::numth::valuation;
use cubealqot::tables::init_residues;
use cubealqot::{Candidate, build_spf, exact};

const SIEVE_PRIMES: [u32; 23] = [
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

fn expected_unit(s: u128, q: u32, v: u32) -> u32 {
    let mut unit = s;
    for _ in 0..v {
        unit /= u128::from(q);
    }
    (unit % u128::from(q)) as u32
}

#[test]
fn foreign_zero_analysis_matches_exact_valuation_and_unit() {
    let max = 10_000;
    let spf = build_spf(max);
    let context = filters::F4Context::new(&SIEVE_PRIMES, 20);
    let mut checks = 0;

    for m in 2u32..=max {
        let mut candidate = Candidate::new(m, &spf);
        let residues = init_residues(&SIEVE_PRIMES, m);
        assert!(
            filters::f4(&context, &mut candidate, &residues).is_none()
                || !candidate.foreign_zeros.is_empty()
                || candidate.s_mod_sieve.iter().any(|&s| s != 0)
        );
        let analyses: Vec<F4bAnalysis> = f4b_foreign::analyze(&context, &mut candidate);
        let s = exact::aliquot_sum(&candidate);

        for analysis in analyses {
            checks += 1;
            assert!(candidate.foreign_zeros.contains(&analysis.index));
            assert_eq!(analysis.q, SIEVE_PRIMES[analysis.index]);
            let v = valuation(s, u128::from(analysis.q));
            assert_eq!(analysis.v, v, "m={m}, q={}", analysis.q);
            assert_eq!(
                analysis.unit,
                expected_unit(s, analysis.q, v),
                "m={m}, q={}",
                analysis.q
            );
        }
    }

    assert!(checks > 0);
}

#[test]
fn explicit_foreign_zero_rejections_cover_both_refinement_rules() {
    let spf = build_spf(44);
    let odd_context = filters::F4Context::new(&[7], 3);
    let mut odd_candidate = Candidate::new(2u64, &spf);
    let odd_residues = init_residues(&[7], 2u64);
    assert_eq!(
        filters::f4(&odd_context, &mut odd_candidate, &odd_residues),
        None
    );
    assert_eq!(odd_candidate.foreign_zeros, [0]);
    assert_eq!(
        f4b_foreign::f4b(&odd_context, &mut odd_candidate),
        Some(Rejection::ModZeroOddVal)
    );

    let bad_context = filters::F4Context::new(&[7], 3);
    let mut bad_candidate = Candidate::new(44u64, &spf);
    let bad_residues = init_residues(&[7], 44u64);
    assert_eq!(
        filters::f4(&bad_context, &mut bad_candidate, &bad_residues),
        None
    );
    assert_eq!(bad_candidate.foreign_zeros, [0]);
    assert_eq!(
        f4b_foreign::f4b(&bad_context, &mut bad_candidate),
        Some(Rejection::ModZeroBadUnit)
    );
}

#[test]
fn ungated_f4b_rejections_are_exactly_sound() {
    let max = 10_000;
    let spf = build_spf(max);
    let context = filters::F4Context::new(&SIEVE_PRIMES, 20);
    let mut rejected = 0;

    for m in 2u32..=max {
        let mut candidate = Candidate::new(m, &spf);
        let residues = init_residues(&SIEVE_PRIMES, m);
        let _ = filters::f4(&context, &mut candidate, &residues);
        if let Some(rejection) = f4b_foreign::f4b(&context, &mut candidate) {
            rejected += 1;
            assert!(
                !exact::aliquot_sum_is_square(&candidate),
                "m={m}: {rejection:?}"
            );
        }
    }

    assert!(rejected > 0);
}

#[test]
fn normal_f4b_pipeline_preserves_first_rejection_order() {
    let max = 10_000;
    let spf = build_spf(max);
    let context = filters::F4Context::new(&SIEVE_PRIMES, 20);
    let f3_context = filters::F3Context::default();

    for m in 2u32..=max {
        let residues = init_residues(&SIEVE_PRIMES, m);
        let mut expected_candidate = Candidate::new(m, &spf);
        let expected = if let Some(rejection) = filters::f1(&expected_candidate) {
            filters::Outcome::Rejected {
                stage: Stage::F1,
                rejection,
            }
        } else if let Some(rejection) = filters::f2(&mut expected_candidate) {
            filters::Outcome::rejected_f2(rejection)
        } else if let Some(rejection) =
            filters::f3_adic3::f3_with_context(&f3_context, &mut expected_candidate)
        {
            filters::Outcome::Rejected {
                stage: Stage::F3,
                rejection,
            }
        } else if let Some(rejection) = filters::f4(&context, &mut expected_candidate, &residues) {
            filters::Outcome::Rejected {
                stage: Stage::F4,
                rejection,
            }
        } else if let Some(rejection) = f4b_foreign::f4b(&context, &mut expected_candidate) {
            filters::Outcome::Rejected {
                stage: Stage::F4b,
                rejection,
            }
        } else {
            let s = exact::aliquot_sum(&expected_candidate);
            if exact::is_square(s) {
                filters::Outcome::solution(exact::isqrt(s))
            } else {
                filters::Outcome::exact_nonsquare()
            }
        };

        let mut actual_candidate = Candidate::new(m, &spf);
        assert_eq!(
            filters::run_with_f3_f4_f4b(&f3_context, &context, &mut actual_candidate, &residues),
            expected,
            "m={m}"
        );
    }
}
