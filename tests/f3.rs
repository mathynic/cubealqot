use cubealqot::filters::f3_adic3::{self, F3Analysis, F3Context};
use cubealqot::filters::{self, Rejection, Stage};
use cubealqot::numth::valuation;
use cubealqot::{Candidate, Factor, MAX_OMEGA, build_spf, exact};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

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

fn direct_v3_and_unit(mut value: BigUint) -> (u32, u8) {
    let mut v = 0;
    while (&value % 3u8).is_zero() {
        value /= 3u8;
        v += 1;
    }
    (v, (&value % 3u8).to_u8().unwrap())
}

fn check_predicate_and_analysis(context: &F3Context, mut candidate: Candidate) {
    let s = exact::exact_s_big(&candidate);
    let (v, unit) = direct_v3_and_unit(s.clone());
    let (v_sigma, _) = direct_v3_and_unit(exact::exact_sigma_big(&candidate));
    let s_mod3 = (&s % 3u8).to_u8().unwrap();
    let expected = if s_mod3 == 2 {
        Some(Rejection::Adic3Nonsquare)
    } else if v % 2 == 1 {
        Some(Rejection::Adic3OddVal)
    } else if unit != 1 {
        Some(Rejection::Adic3BadUnit)
    } else {
        None
    };
    let mut analysis_candidate = Candidate::from_factors(candidate.m, candidate.f, candidate.omega);
    let mut full = F3Analysis {
        s_mod3,
        v_sigma,
        v3_s: v,
        unit3: unit,
        entered_zero_branch: s_mod3 == 0,
        used_exact_s_fallback: v >= f3_adic3::CAP3 && s.to_u128().is_some(),
    };
    assert_eq!(
        f3_adic3::analyze_with_context(context, &mut analysis_candidate),
        full,
        "fresh analysis: m={}",
        candidate.m
    );
    assert_eq!(
        f3_adic3::f3_with_context(context, &mut candidate),
        expected,
        "cold predicate: m={}",
        candidate.m
    );
    // A predicate fallback may warm the exact cache. Analysis must still
    // extract every diagnostic, including the unit for odd valuations.
    full.used_exact_s_fallback = false;
    assert_eq!(
        f3_adic3::analyze_with_context(context, &mut candidate),
        full,
        "analysis after predicate: m={}",
        candidate.m
    );
    candidate.s_cache = s.to_u128();
    candidate.exact_s_cache = Some(exact::ExactNat::from_biguint(s));
    assert_eq!(f3_adic3::f3(&mut candidate), expected);
    assert_eq!(f3_adic3::analyze(&mut candidate), full);
}

#[test]
fn lean_predicate_matches_exact_condition_and_complete_analysis() {
    let spf = build_spf(10_000);
    let context = F3Context::default();
    for m in 2u64..=10_000 {
        check_predicate_and_analysis(&context, Candidate::new(m, &spf));
    }
}

#[test]
fn lean_predicate_preserves_wide_and_exact_fallback_cases() {
    let context = F3Context::default();
    let cases: &[&[(u64, u32)]] = &[
        &[(2, 63)],
        &[(3, 40)],
        &[(2, 60), (5, 1)],
        &[(641, 1), (6_700_417, 1)],
        &[(18_446_744_073_709_551_557, 1)],
        // S has (v3, unit) = (12, 2), (13, 1), (13, 2), (14, 2),
        // and (16, 1), exercising every decision beyond the modular cap.
        &[(3, 1), (15_707_789, 1)],
        &[(3, 1), (7_204_733, 1)],
        &[(3, 1), (48_657_131, 1)],
        &[(3, 1), (99_675_467, 1)],
        &[(3, 1), (23_147_963, 1)],
    ];
    for factors in cases {
        let mut slots = [Factor::default(); MAX_OMEGA];
        let mut m = 1u64;
        for (slot, &(p, e)) in slots.iter_mut().zip(*factors) {
            *slot = Factor { p, e };
            m = m.checked_mul(p.checked_pow(e).unwrap()).unwrap();
        }
        check_predicate_and_analysis(
            &context,
            Candidate::from_factors(m, slots, factors.len() as u8),
        );
    }
}
