//! End-to-end differential validation against the independent Python oracle.

use cubealqot::validate::{
    CrossValidationSummary, F2ValidationSummary, F3ValidationSummary, F4bValidationSummary,
    F7ValidationSummary, F56ValidationSummary, ValidationSummary, validate_cross_range,
    validate_f2_range, validate_f3_range, validate_f4b_range, validate_f7_range,
    validate_f56_range, validate_pipeline_range, validate_range,
};

fn assert_summary(summary: ValidationSummary, max: u32) {
    assert_eq!(summary.max, max);
    assert_eq!(summary.checked, u64::from(max - 1));
    assert_eq!(summary.direct_checked, u64::from(999.min(max - 1)));
    assert_eq!(
        summary.multiplicative_checked,
        u64::from(max.saturating_sub(1_000))
    );
}

#[test]
fn rust_baseline_matches_direct_python_oracle_range() {
    let summary = validate_range(100).expect("Python oracle validation should pass");
    assert_summary(summary, 100);
}

#[test]
fn rust_baseline_matches_both_python_oracle_algorithms() {
    let summary = validate_range(1_005).expect("Python oracle validation should pass");
    assert_summary(summary, 1_005);
}

#[test]
fn f2_validation_harness_checks_ungated_and_pipeline_modes() {
    let summary: F2ValidationSummary =
        validate_f2_range(10_000).expect("F2 validation should pass");
    assert_eq!(summary.max, 10_000);
    assert_eq!(summary.checked, 9_999);
    assert!(summary.ungated_rejections > 0);
    assert!(summary.pipeline_rejections > 0);
    assert!(summary.equal_valuation_cases > 0);
}

#[test]
fn f3_validation_harness_exercises_positive_even_units() {
    let summary: F3ValidationSummary =
        validate_f3_range(10_000).expect("F3 validation should pass");
    assert_eq!(summary.max, 10_000);
    assert_eq!(summary.checked, 9_999);
    assert!(summary.ungated_rejections > 0);
    assert!(summary.pipeline_rejections > 0);
    assert!(summary.positive_even_valuation_cases > 0);
}

#[test]
fn cross_validation_harness_checks_every_ordered_pair() {
    let summary: CrossValidationSummary =
        validate_cross_range(10_000).expect("cross validation should pass");
    assert_eq!(summary.max, 10_000);
    assert_eq!(summary.checked, 9_999);
    assert!(summary.pairs > 0);
    assert!(summary.hits > 0);
}

#[test]
fn f56_validation_harness_checks_branches_and_exact_local_values() {
    let summary: F56ValidationSummary =
        validate_f56_range(10_000).expect("F5/F6 validation should pass");
    assert_eq!(summary.max, 10_000);
    assert_eq!(summary.checked, 9_999);
    assert!(summary.local_decisions > 0);
    assert!(summary.less_cases > 0);
    assert!(summary.equal_cases > 0);
    assert!(summary.greater_cases > 0);
    assert!(summary.ungated_rejections > 0);
}

#[test]
fn f4b_validation_harness_reports_rejection_per_cycle() {
    let summary: F4bValidationSummary =
        validate_f4b_range(10_000).expect("F4b validation should pass");
    assert_eq!(summary.max, 10_000);
    assert_eq!(summary.checked, 9_999);
    assert!(summary.foreign_zero_checks > 0);
    assert!(summary.ungated_rejections > 0);
    assert!(summary.rejection_per_cycle > 0.0);
    assert!(summary.elapsed_nanos > 0);
}

#[test]
fn f7_validation_harness_verifies_rejections_and_tags() {
    let summary: F7ValidationSummary =
        validate_f7_range(10_000).expect("F7 validation should pass");
    assert_eq!(summary.max, 10_000);
    assert_eq!(summary.checked, 9_999);
    assert!(summary.sq_tags > 0);
    assert!(summary.two_sq_tags > 0);
    assert!(summary.pq_handoff_tags > 0);
    assert!(summary.ungated_rejections > 0);
}

#[test]
fn canonical_pipeline_validation_checks_trace_and_accounting() {
    let summary = validate_pipeline_range(2_000).expect("pipeline validation should pass");
    assert_eq!(summary.max, 2_000);
    assert_eq!(summary.checked, 1_999);
    assert!(summary.ungated_predicate_rejections >= summary.short_circuit_rejections);
    summary
        .stats
        .check_invariants()
        .expect("pipeline stats should balance");
}
