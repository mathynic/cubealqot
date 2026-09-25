//! F1 tests in both ungated and normal-pipeline modes.

use cubealqot::{Candidate, build_spf, exact, filters};

fn candidate(m: u32, spf: &[u16]) -> Candidate {
    Candidate::new(m, spf)
}

#[test]
fn ungated_f1_rejects_exactly_prime_powers_and_only_nonsquares() {
    let max = 10_000;
    let spf = build_spf(max);

    for m in 2..=max {
        let c = candidate(m, &spf);
        let rejection = filters::f1(&c);
        assert_eq!(rejection.is_some(), c.omega == 1, "m={m}");

        // This is deliberately ungated: F1 is evaluated even for candidates
        // that a future earlier filter might reject.
        if rejection.is_some() {
            assert!(
                !exact::aliquot_sum_is_square(&c),
                "F1 was unsound for m={m}"
            );
        }
    }
}

#[test]
fn normal_f1_pipeline_matches_exact_baseline() {
    let max = 10_000;
    let spf = build_spf(max);

    for m in 2..=max {
        let mut c = candidate(m, &spf);
        let exact_sum = exact::aliquot_sum(&c);
        let expected = if c.omega == 1 {
            filters::Outcome::rejected_f1()
        } else if exact::is_square(exact_sum) {
            filters::Outcome::solution(exact::isqrt(exact_sum))
        } else {
            filters::Outcome::exact_nonsquare()
        };

        assert_eq!(
            filters::run(&mut c),
            expected,
            "pipeline mismatch for m={m}"
        );
    }
}

#[test]
fn f1_is_the_first_and_only_enabled_filter() {
    let spf = build_spf(21);

    for m in [2, 7] {
        let mut c = candidate(m, &spf);
        assert_eq!(filters::run(&mut c), filters::Outcome::rejected_f1());
    }

    let mut composite = candidate(6, &spf);
    assert_eq!(filters::f1(&composite), None);
    assert_eq!(
        filters::run(&mut composite),
        filters::Outcome::exact_nonsquare()
    );
}

#[test]
fn reusable_validation_harness_checks_ungated_and_pipeline_modes() {
    let summary = cubealqot::validate::validate_f1_range(10_000)
        .expect("F1 validation should agree with the exact baseline");

    assert_eq!(summary.checked, 9_999);
    assert_eq!(
        summary.ungated_prime_power_rejections,
        summary.pipeline_prime_power_rejections
    );
    assert!(summary.ungated_prime_power_rejections > 0);
}
