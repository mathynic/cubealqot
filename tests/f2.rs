use cubealqot::filters::f2_adic2::{self, F2Analysis};
use cubealqot::filters::{self, Rejection, Stage};
use cubealqot::numth::valuation;
use cubealqot::{Candidate, Factor, MAX_OMEGA, build_spf, exact};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

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

#[test]
fn predicate_preserves_rejection_precedence_and_complete_analysis() {
    let spf = build_spf(10_000);
    let mut odd_bad_unit = 0;
    let mut even_bad_unit = 0;
    let mut passed = 0;
    for m in 2u64..=10_000 {
        let analysis = f2_adic2::analyze(&mut Candidate::new(m, &spf));
        let expected = if analysis.v2_s % 2 == 1 {
            odd_bad_unit += usize::from(analysis.unit8 != 1);
            Some(Rejection::Adic2OddVal)
        } else if analysis.unit8 != 1 {
            even_bad_unit += 1;
            Some(Rejection::Adic2BadUnit)
        } else {
            passed += 1;
            None
        };
        let mut candidate = Candidate::new(m, &spf);
        assert_eq!(f2_adic2::f2(&mut candidate), expected, "m={m}");
        // A predicate rejection must not prevent a retained record from
        // recovering the complete unit and valuation diagnostics.
        assert_eq!(f2_adic2::analyze(&mut candidate), analysis, "m={m}");
    }
    assert!(odd_bad_unit > 0 && even_bad_unit > 0 && passed > 0);
}

fn direct_binary_valuation(mut value: BigUint) -> u32 {
    let mut v = 0;
    while (&value % 2u8).is_zero() {
        value >>= 1usize;
        v += 1;
    }
    v
}

#[test]
fn odd_root_shortcut_and_remaining_paths_match_biguint_with_cold_and_warm_caches() {
    let cases: &[&[(u64, u32)]] = &[
        &[(3, 1), (5, 1)],
        &[(3, 1), (7, 1)],
        &[(3, 2), (5, 1)],
        &[(3, 2), (5, 2)],
        &[(3, 39)],
        &[(3, 40)],
        &[(5, 26)],
        &[(3, 1), (2_305_843_041_732_208_837, 1)],
        &[(18_446_744_073_709_551_557, 1)],
        &[(2, 63)],
        // These even roots retain the equal-valuation exact fallback,
        // including odd valuations and even valuations with bad units.
        &[(2, 1), (13_532_306_340_803, 1)],
        &[(2, 1), (14_082_062_154_691, 1)],
        &[(2, 1), (19_029_864_479_683, 1)],
        &[(2, 1), (134_478_585_396_163, 1)],
        &[(2, 1), (385_167_236_529_091, 1)],
    ];
    let mut eligible_passes = 0;
    let mut eligible_rejections = 0;
    let mut exact_fallbacks = 0;
    for factors in cases {
        let mut slots = [Factor::default(); MAX_OMEGA];
        let mut m = 1u64;
        for (slot, &(p, e)) in slots.iter_mut().zip(*factors) {
            *slot = Factor { p, e };
            m = m.checked_mul(p.checked_pow(e).unwrap()).unwrap();
        }
        let row = Candidate::from_factors(m, slots, factors.len() as u8);
        let sigma = exact::exact_sigma_big(&row);
        let s = &sigma - BigUint::from(m).pow(3);
        let v = direct_binary_valuation(s.clone());
        let unit = ((&s >> v) % 8u8).to_u8().unwrap();
        let v_sigma = direct_binary_valuation(sigma);
        let expected = if v % 2 == 1 {
            Some(Rejection::Adic2OddVal)
        } else if unit != 1 {
            Some(Rejection::Adic2BadUnit)
        } else {
            None
        };
        let eligible = m % 2 == 1 && factors.iter().any(|&(_, e)| e % 2 == 1);
        if eligible {
            assert_eq!(v, 0);
            eligible_passes += usize::from(expected.is_none());
            eligible_rejections += usize::from(expected.is_some());
        }
        for warm in [false, true] {
            let mut candidate = Candidate::from_factors(m, slots, factors.len() as u8);
            if warm {
                candidate.s_cache = s.to_u128();
                candidate.exact_s_cache = Some(exact::ExactNat::from_biguint(s.clone()));
            }
            assert_eq!(f2_adic2::f2(&mut candidate), expected, "m={m}, warm={warm}");
            if !warm && v >= f2_adic2::CAP2 {
                assert!(candidate.exact_s_cache.is_some(), "m={m}");
                exact_fallbacks += 1;
            }
            let analysis = f2_adic2::analyze(&mut candidate);
            assert_eq!(analysis.v_sigma, v_sigma, "m={m}");
            assert_eq!(analysis.k, 3 * u32::from(candidate.a2));
            assert_eq!(analysis.v2_s, v, "m={m}");
            assert_eq!(analysis.unit8, unit, "m={m}");
            assert_eq!(analysis.equal_valuation, v_sigma == analysis.k);
            assert!(!analysis.used_exact_s_fallback);
        }
    }
    assert!(eligible_passes > 0 && eligible_rejections > 0);
    assert_eq!(exact_fallbacks, 5);
}
