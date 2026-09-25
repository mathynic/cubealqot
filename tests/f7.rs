use cubealqot::filters::f7_special::{self, F7Analysis, FamilyTag};
use cubealqot::filters::{self, Rejection, Stage};
use cubealqot::numth::valuation;
use cubealqot::tables::init_residues;
use cubealqot::{Candidate, build_spf, exact};

const SIEVE_PRIMES: [u32; 23] = [
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

fn independent_tag(candidate: &Candidate) -> Option<FamilyTag> {
    let factors = &candidate.f[..candidate.omega as usize];
    if factors.iter().all(|factor| factor.e % 2 == 0) {
        return Some(FamilyTag::Sq);
    }
    if candidate.a2 == 1
        && factors
            .iter()
            .filter(|factor| factor.p != 2)
            .all(|factor| factor.e % 2 == 0)
    {
        return Some(FamilyTag::TwoSq);
    }
    if factors.len() == 2
        && factors
            .iter()
            .all(|factor| factor.p % 2 == 1 && factor.e == 1)
    {
        return Some(FamilyTag::PqHandoff);
    }
    None
}

#[test]
fn tags_match_independent_factor_structure_exhaustively() {
    let max = 10_000;
    let spf = build_spf(max);
    let context = filters::F7Context::default();
    let mut tag_counts = [0u32; 3];

    for m in 2u32..=max {
        let candidate = Candidate::new(m, &spf);
        let analysis = f7_special::analyze(&context, &candidate);
        assert_eq!(analysis.family, independent_tag(&candidate), "m={m}");
        match analysis.family {
            Some(FamilyTag::Sq) => tag_counts[0] += 1,
            Some(FamilyTag::TwoSq) => tag_counts[1] += 1,
            Some(FamilyTag::PqHandoff) => tag_counts[2] += 1,
            None => {}
        }
    }

    assert!(tag_counts.iter().all(|&count| count > 0));
}

#[test]
fn every_f7_rejection_has_exact_valuation_one() {
    let max = 10_000;
    let spf = build_spf(max);
    let context = filters::F7Context::default();
    let mut rejected = 0;

    for m in 2u32..=max {
        let candidate = Candidate::new(m, &spf);
        let analysis: F7Analysis = f7_special::analyze(&context, &candidate);
        if analysis.checks.iter().any(|check| check.rejects) {
            rejected += 1;
            let sigma = exact::exact_sigma(&candidate);
            for check in analysis.checks.iter().filter(|check| check.rejects) {
                assert_eq!(valuation(sigma, u128::from(check.prime)), 1, "m={m}");
            }
            assert_eq!(
                f7_special::f7(&context, &candidate),
                Some(Rejection::SpecialSumTwoSquares)
            );
        }
    }

    assert!(rejected > 0);
}

#[test]
fn explicit_family_and_rejection_witnesses_are_present() {
    let spf = build_spf(121);
    let context = filters::F7Context::default();
    assert_eq!(
        f7_special::analyze(&context, &Candidate::new(36u64, &spf)).family,
        Some(FamilyTag::Sq)
    );
    assert_eq!(
        f7_special::analyze(&context, &Candidate::new(18u64, &spf)).family,
        Some(FamilyTag::TwoSq)
    );
    assert_eq!(
        f7_special::analyze(&context, &Candidate::new(15u64, &spf)).family,
        Some(FamilyTag::PqHandoff)
    );
    assert_eq!(
        f7_special::f7(&context, &Candidate::new(121u64, &spf)),
        Some(Rejection::SpecialSumTwoSquares)
    );
}

#[test]
fn normal_f7_pipeline_preserves_first_rejection_order() {
    let max = 10_000;
    let spf = build_spf(max);
    let f3_context = filters::F3Context::default();
    let f4_context = filters::F4Context::new(&SIEVE_PRIMES, 20);
    let f7_context = filters::F7Context::default();

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
        } else if let Some(rejection) = filters::f4(&f4_context, &mut expected_candidate, &residues)
        {
            filters::Outcome::Rejected {
                stage: Stage::F4,
                rejection,
            }
        } else if let Some(rejection) =
            filters::f4b_foreign::f4b(&f4_context, &mut expected_candidate)
        {
            filters::Outcome::rejected_f4b(rejection)
        } else if let Some(rejection) = filters::f56(&mut expected_candidate) {
            filters::Outcome::Rejected {
                stage: Stage::F56,
                rejection,
            }
        } else if let Some(rejection) = f7_special::f7(&f7_context, &expected_candidate) {
            filters::Outcome::Rejected {
                stage: Stage::F7,
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
            filters::run_with_f3_f4_f56_f7(
                &f3_context,
                &f4_context,
                &f7_context,
                &mut actual_candidate,
                &residues,
            ),
            expected,
            "m={m}"
        );
    }
}
