use cubealqot::{filters::Stage, profile::profile_range};

#[test]
fn profiler_reports_all_stages_in_canonical_order() {
    let report = profile_range(2, 100, 1).expect("profiling range should be valid");

    assert_eq!(report.start, 2);
    assert_eq!(report.end, 100);
    assert_eq!(report.threads, 1);
    assert_eq!(report.tested, 99);
    assert_eq!(
        report
            .stages
            .iter()
            .map(|stage| stage.stage)
            .collect::<Vec<_>>(),
        Stage::ALL
    );
    assert!(report.stages.iter().all(|stage| stage.calls == 99));
    assert!(report.stages.iter().all(|stage| stage.elapsed_nanos > 0));
    for (profile, reached) in report.normal_stages.iter().zip(report.stats.reached_stages) {
        assert_eq!(profile.calls, reached);
    }
    report
        .stats
        .check_invariants()
        .expect("profiling stats should preserve pipeline accounting");
}
