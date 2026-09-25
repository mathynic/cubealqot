use cubealqot::filters::f56_local::{self, LocalAnalysis, LocalCase};
use cubealqot::filters::{self, Rejection, Stage};
use cubealqot::numth::valuation;
use cubealqot::{Candidate, build_spf, exact};

fn exact_unit(s: u128, p: u64, v: u32) -> u32 {
    let mut unit = s;
    for _ in 0..v {
        unit /= u128::from(p);
    }
    (unit % u128::from(p)) as u32
}

fn local_for<'a>(locals: &'a [LocalAnalysis], target: u32) -> &'a LocalAnalysis {
    locals
        .iter()
        .find(|local| local.target == u64::from(target))
        .expect("target local analysis is present")
}

#[test]
fn every_local_v_and_unit_matches_exact_s() {
    let spf = build_spf(10_000);
    let mut saw_zero_v = false;

    for m in 2u32..=10_000 {
        let mut candidate = Candidate::new(m, &spf);
        let sigma = exact::exact_sigma(&candidate);
        let s = exact::aliquot_sum(&candidate);
        let locals = f56_local::analyze(&mut candidate);

        for local in locals {
            let exact_v_sigma = valuation(sigma, u128::from(local.target));
            let exact_v_s = valuation(s, u128::from(local.target));
            assert_eq!(local.v_sigma, exact_v_sigma, "m={m}, p={}", local.target);
            assert_eq!(local.v_s, exact_v_s, "m={m}, p={}", local.target);
            assert_eq!(
                local.unit,
                exact_unit(s, local.target, exact_v_s),
                "m={m}, p={}",
                local.target
            );
            assert_eq!(
                local.case,
                match local.v_sigma.cmp(&local.threshold) {
                    std::cmp::Ordering::Less => LocalCase::Less,
                    std::cmp::Ordering::Equal => LocalCase::Equal,
                    std::cmp::Ordering::Greater => LocalCase::Greater,
                }
            );
            saw_zero_v |= local.v_s == 0;
        }
    }

    assert!(saw_zero_v, "the unified v=0 unit case was not exercised");
}

#[test]
fn all_three_branch_cases_have_concrete_witnesses() {
    let spf = build_spf(2_215);
    let less = f56_local::analyze(&mut Candidate::new(10u64, &spf));
    let equal = f56_local::analyze(&mut Candidate::new(965u64, &spf));
    let greater = f56_local::analyze(&mut Candidate::new(2_215u64, &spf));

    assert_eq!(local_for(&less, 5).case, LocalCase::Less);
    assert_eq!(local_for(&equal, 5).case, LocalCase::Equal);
    assert_eq!(local_for(&greater, 5).case, LocalCase::Greater);

    let greater_local = local_for(&greater, 5);
    assert_eq!(greater_local.v_sigma, 4);
    assert_eq!(greater_local.threshold, 3);
    assert_eq!(greater_local.v_s, 3);
    let reduced = 2_215u128 / 5;
    assert_eq!(greater_local.unit, ((5 - (reduced.pow(3) % 5) as u32) % 5));
}

#[test]
fn ungated_f56_rejections_are_exactly_sound() {
    let spf = build_spf(10_000);
    let mut rejected = 0;

    for m in 2u32..=10_000 {
        let mut candidate = Candidate::new(m, &spf);
        if let Some(rejection) = f56_local::f56(&mut candidate) {
            rejected += 1;
            assert!(
                !exact::aliquot_sum_is_square(&candidate),
                "F5/F6 rejected a square at m={m}: {rejection:?}"
            );
        }
    }

    assert!(rejected > 0);
}

#[test]
fn normal_f56_pipeline_preserves_first_rejection_order() {
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
                Some(rejection) => filters::Outcome::rejected_f2(rejection),
                None => match filters::f3(&mut preceding) {
                    Some(rejection) => filters::Outcome::Rejected {
                        stage: Stage::F3,
                        rejection,
                    },
                    None => match f56_local::f56(&mut preceding) {
                        Some(rejection) => filters::Outcome::Rejected {
                            stage: Stage::F56,
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
                },
            }
        };

        assert_eq!(filters::run_with_f56(&mut candidate), expected, "m={m}");
    }
}
