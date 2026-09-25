use cubealqot::filters::f2_adic2::{self, F2Analysis};
use cubealqot::filters::{self, Rejection, Stage};
use cubealqot::numth::valuation;
use cubealqot::{Candidate, build_spf, exact};

fn expected_unit8(s: u128, v: u32) -> u8 {
    let divisor = 1u128 << v;
    ((s / divisor) % 8) as u8
}

#[test]
fn v2_sigma_formula_matches_exact_sigma() {
    let spf = build_spf(10_000);

    for m in 2u32..=10_000 {
        let candidate = Candidate::new(m, &spf);
        let expected = valuation(exact::exact_sigma(&candidate), 2);
        assert_eq!(f2_adic2::v2_sigma(&candidate), expected, "m={m}");
    }
}

#[test]
fn analysis_matches_exact_s_and_exercises_equal_valuation_fallback() {
    let spf = build_spf(2_000);
    let mut equal_cases = 0;

    for m in 2u32..=2_000 {
        let mut candidate = Candidate::new(m, &spf);
        let analysis = f2_adic2::analyze(&mut candidate);
        let s = exact::aliquot_sum(&candidate);
        let expected_v = valuation(s, 2);

        assert_eq!(analysis.v2_s, expected_v, "m={m}");
        assert_eq!(analysis.unit8, expected_unit8(s, expected_v), "m={m}");
        assert_eq!(analysis.equal_valuation, analysis.v_sigma == analysis.k);
        if analysis.equal_valuation {
            equal_cases += 1;
        }
    }

    assert!(
        equal_cases > 0,
        "the equal-valuation cascade was never exercised"
    );
}

#[test]
fn ungated_f2_rejections_are_exactly_sound() {
    let spf = build_spf(10_000);
    let mut rejected = 0;

    for m in 2u32..=10_000 {
        let mut candidate = Candidate::new(m, &spf);
        if let Some(rejection) = f2_adic2::f2(&mut candidate) {
            rejected += 1;
            assert!(
                !exact::aliquot_sum_is_square(&candidate),
                "F2 rejected a square at m={m}: {rejection:?}"
            );
        }
    }

    assert!(rejected > 0, "F2 did not reject any candidate");
}

#[test]
fn f2_pipeline_matches_exact_baseline_after_f1() {
    let spf = build_spf(10_000);

    for m in 2u32..=10_000 {
        let mut candidate = Candidate::new(m, &spf);
        let expected = if candidate.omega == 1 {
            filters::Outcome::Rejected {
                stage: Stage::F1,
                rejection: Rejection::PrimePower,
            }
        } else {
            let mut f2_candidate = Candidate::new(m, &spf);
            match f2_adic2::f2(&mut f2_candidate) {
                Some(rejection) => filters::Outcome::Rejected {
                    stage: Stage::F2,
                    rejection,
                },
                None => {
                    let s = exact::aliquot_sum(&f2_candidate);
                    if exact::is_square(s) {
                        filters::Outcome::solution(exact::isqrt(s))
                    } else {
                        filters::Outcome::exact_nonsquare()
                    }
                }
            }
        };

        assert_eq!(filters::run_with_f2(&mut candidate), expected, "m={m}");
    }
}

#[test]
fn known_equal_valuation_candidate_uses_cached_exact_fallback() {
    let spf = build_spf(9);
    let mut candidate = Candidate::new(9u64, &spf);
    let analysis: F2Analysis = f2_adic2::analyze(&mut candidate);

    assert!(analysis.equal_valuation);
    assert!(!analysis.used_exact_s_fallback);
    assert!(candidate.s_cache.is_none());

    let mut fallback_candidate = Candidate::new(9u64, &spf);
    assert_eq!(f2_adic2::v_of_s_at(&mut fallback_candidate, 2, 1, 2), 2);
    assert!(fallback_candidate.s_cache.is_some());
}
