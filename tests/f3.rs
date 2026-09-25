use cubealqot::filters::f3_adic3::{self, F3Analysis};
use cubealqot::filters::{self, Rejection, Stage};
use cubealqot::numth::valuation;
use cubealqot::{Candidate, build_spf, exact};

fn expected_unit3(s: u128, v: u32) -> u8 {
    let mut divisor = 1u128;
    for _ in 0..v {
        divisor *= 3;
    }
    ((s / divisor) % 3) as u8
}

#[test]
fn v3_sigma_formula_matches_exact_sigma() {
    let spf = build_spf(10_000);

    for m in 2u32..=10_000 {
        let candidate = Candidate::new(m, &spf);
        let expected = valuation(exact::exact_sigma(&candidate), 3);
        assert_eq!(f3_adic3::v3_sigma(&candidate), expected, "m={m}");
    }
}

#[test]
fn analysis_matches_exact_s_and_extracts_positive_even_units() {
    let spf = build_spf(10_000);

    for m in 2u32..=10_000 {
        let mut candidate = Candidate::new(m, &spf);
        let analysis: F3Analysis = f3_adic3::analyze(&mut candidate);
        let s = exact::aliquot_sum(&candidate);

        assert_eq!(analysis.s_mod3, (s % 3) as u8, "m={m}");
        if analysis.s_mod3 == 0 {
            let expected_v = valuation(s, 3);
            assert_eq!(analysis.v3_s, expected_v, "m={m}");
            assert_eq!(analysis.unit3, expected_unit3(s, expected_v), "m={m}");
        } else {
            assert_eq!(analysis.v3_s, 0, "m={m}");
            assert_eq!(analysis.unit3, analysis.s_mod3, "m={m}");
        }
    }

    for (m, expected_unit) in [(4u64, 1), (16, 2), (25, 2)] {
        let mut candidate = Candidate::new(m, &spf);
        let analysis = f3_adic3::analyze(&mut candidate);
        assert_eq!(analysis.v3_s, 2, "m={m}");
        assert_eq!(analysis.unit3, expected_unit, "m={m}");
    }
}

#[test]
fn ungated_f3_rejections_are_exactly_sound() {
    let spf = build_spf(10_000);
    let mut rejected = 0;

    for m in 2u32..=10_000 {
        let mut candidate = Candidate::new(m, &spf);
        if let Some(rejection) = f3_adic3::f3(&mut candidate) {
            rejected += 1;
            assert!(
                !exact::aliquot_sum_is_square(&candidate),
                "F3 rejected a square at m={m}: {rejection:?}"
            );
        }
    }

    assert!(rejected > 0, "F3 did not reject any candidate");
}

#[test]
fn f3_pipeline_matches_exact_baseline_after_f1_and_f2() {
    let spf = build_spf(10_000);

    for m in 2u32..=10_000 {
        let mut candidate = Candidate::new(m, &spf);
        let expected = if candidate.omega == 1 {
            filters::Outcome::Rejected {
                stage: Stage::F1,
                rejection: Rejection::PrimePower,
            }
        } else {
            let mut preceding = Candidate::new(m, &spf);
            match filters::f2(&mut preceding) {
                Some(rejection) => filters::Outcome::Rejected {
                    stage: Stage::F2,
                    rejection,
                },
                None => match f3_adic3::f3(&mut preceding) {
                    Some(rejection) => filters::Outcome::Rejected {
                        stage: Stage::F3,
                        rejection,
                    },
                    None => {
                        let s = exact::aliquot_sum(&preceding);
                        if exact::is_square(s) {
                            filters::Outcome::solution(exact::isqrt(s))
                        } else {
                            filters::Outcome::exact_nonsquare()
                        }
                    }
                },
            }
        };

        assert_eq!(filters::run_with_f3(&mut candidate), expected, "m={m}");
    }
}
