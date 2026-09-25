//! Measurement-only stage profiler for scale preparation.

use std::time::Instant;

use serde::Serialize;

use crate::{Candidate, build_spf, exact, filters, stats::PipelineStats, tables};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StageProfile {
    pub stage: filters::Stage,
    pub calls: u64,
    pub rejections: u64,
    pub elapsed_nanos: u128,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileReport {
    pub start: u64,
    pub end: u64,
    pub threads: usize,
    pub tested: u64,
    pub elapsed_nanos: u128,
    pub stages: Vec<StageProfile>,
    pub normal_stages: Vec<StageProfile>,
    pub stats: PipelineStats,
}

/// Profiles one sequential worker while evaluating every implemented stage.
///
/// The stage timings are ungated measurements: later predicates are measured
/// even when an earlier predicate rejects. Short-circuit statistics are
/// collected separately from the canonical runner.
pub fn profile_range(start: u64, end: u64, threads: usize) -> Result<ProfileReport, String> {
    if start < 2 {
        return Err("profile start must be at least 2".to_owned());
    }
    if end < start {
        return Err("profile end must not precede start".to_owned());
    }
    if threads != 1 {
        return Err("stage profiler currently measures one worker; use --threads 1".to_owned());
    }
    if end > u64::from(u32::MAX) {
        return Err(
            "stage profiler currently supports roots through u32::MAX; widened profiling is deferred"
                .to_owned(),
        );
    }

    const SIEVE_PRIMES: [u32; 23] = [
        5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    ];
    let spf = build_spf(u32::try_from(end).expect("profile guard keeps end within u32"));
    let context = filters::CanonicalContext::new(&SIEVE_PRIMES, 20);
    let mut stats = PipelineStats::default();
    let mut stages = filters::Stage::ALL
        .into_iter()
        .map(|stage| StageProfile {
            stage,
            calls: 0,
            rejections: 0,
            elapsed_nanos: 0,
        })
        .collect::<Vec<_>>();
    let mut normal_stages = filters::Stage::ALL
        .into_iter()
        .map(|stage| StageProfile {
            stage,
            calls: 0,
            rejections: 0,
            elapsed_nanos: 0,
        })
        .collect::<Vec<_>>();
    let wall_start = Instant::now();

    for m in start..=end {
        let residues = tables::init_residues(&SIEVE_PRIMES, m);

        let mut canonical_candidate = Candidate::new(m, &spf);
        let trace = filters::run_canonical(&context, &mut canonical_candidate, &residues);
        stats.record(&trace);

        let mut normal_candidate = Candidate::new(m, &spf);
        profile_normal_candidate(
            &context,
            &mut normal_candidate,
            &residues,
            &mut normal_stages,
        );

        let mut candidate = Candidate::new(m, &spf);
        measure(&mut stages, filters::Stage::F1, || {
            filters::f1(&candidate).is_some()
        });
        measure(&mut stages, filters::Stage::F2, || {
            filters::f2(&mut candidate).is_some()
        });
        measure(&mut stages, filters::Stage::F3, || {
            filters::f3_adic3::f3_with_context(&context.f3, &mut candidate).is_some()
        });
        measure(&mut stages, filters::Stage::F4, || {
            filters::f4(&context.f4, &mut candidate, &residues).is_some()
        });
        measure(&mut stages, filters::Stage::F4b, || {
            filters::f4b_foreign::f4b(&context.f4, &mut candidate).is_some()
        });
        measure(&mut stages, filters::Stage::F56, || {
            filters::f56(&mut candidate).is_some()
        });
        measure(&mut stages, filters::Stage::F7, || {
            filters::f7_special::f7(&context.f7, &candidate).is_some()
        });
        measure(&mut stages, filters::Stage::F8, || {
            !exact::is_square(exact::aliquot_sum(&candidate))
        });
    }

    stats.check_invariants()?;
    Ok(ProfileReport {
        start,
        end,
        threads,
        tested: end - start + 1,
        elapsed_nanos: wall_start.elapsed().as_nanos(),
        stages,
        normal_stages,
        stats,
    })
}

fn profile_normal_candidate(
    context: &filters::CanonicalContext,
    candidate: &mut Candidate,
    residues: &[u32],
    stages: &mut [StageProfile],
) {
    if measure(stages, filters::Stage::F1, || {
        filters::f1(candidate).is_some()
    }) {
        return;
    }
    if measure(stages, filters::Stage::F2, || {
        filters::f2(candidate).is_some()
    }) {
        return;
    }
    if measure(stages, filters::Stage::F3, || {
        filters::f3_adic3::f3_with_context(&context.f3, candidate).is_some()
    }) {
        return;
    }
    if measure(stages, filters::Stage::F4, || {
        filters::f4(&context.f4, candidate, residues).is_some()
    }) {
        return;
    }
    if measure(stages, filters::Stage::F4b, || {
        filters::f4b_foreign::f4b(&context.f4, candidate).is_some()
    }) {
        return;
    }
    if measure(stages, filters::Stage::F56, || {
        filters::f56(candidate).is_some()
    }) {
        return;
    }
    if measure(stages, filters::Stage::F7, || {
        filters::f7_special::f7(&context.f7, candidate).is_some()
    }) {
        return;
    }
    let _ = measure(stages, filters::Stage::F8, || {
        !exact::is_square(exact::aliquot_sum(candidate))
    });
}

fn measure(
    stages: &mut [StageProfile],
    stage: filters::Stage,
    operation: impl FnOnce() -> bool,
) -> bool {
    let start = Instant::now();
    let rejected = operation();
    let profile = &mut stages[stage.index()];
    profile.calls += 1;
    profile.rejections += if rejected { 1 } else { 0 };
    profile.elapsed_nanos += start.elapsed().as_nanos();
    rejected
}
