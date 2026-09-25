use cubealqot::filters::{
    self, CanonicalContext, Outcome, Rejection, Stage, evaluate_ungated, run_canonical,
};
use cubealqot::stats::PipelineStats;
use cubealqot::tables::init_residues;
use cubealqot::{Candidate, build_spf};

const SIEVE_PRIMES: [u32; 23] = [
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

#[test]
fn canonical_trace_matches_earliest_ungated_rejection() {
    let max = 2_000;
    let spf = build_spf(max);
    let context = CanonicalContext::new(&SIEVE_PRIMES, 20);

    for m in 2u32..=max {
        let residues = init_residues(&SIEVE_PRIMES, m);
        let mut ungated_candidate = Candidate::new(m, &spf);
        let ungated = evaluate_ungated(&context, &mut ungated_candidate, &residues);

        let mut traced_candidate = Candidate::new(m, &spf);
        let trace = run_canonical(&context, &mut traced_candidate, &residues);
        assert_eq!(trace.evaluated.first(), Some(&Stage::F1), "m={m}");
        assert!(
            trace.evaluated.windows(2).all(|pair| pair[0] < pair[1]),
            "m={m}"
        );

        let expected = ungated.first_rejection().map_or_else(
            || ungated.exact,
            |(stage, rejection)| Outcome::Rejected { stage, rejection },
        );
        assert_eq!(trace.outcome, expected, "m={m}");
    }
}

#[test]
fn ungated_mode_reaches_later_predicates_even_when_earlier_filters_reject() {
    let spf = build_spf(121);
    let context = CanonicalContext::new(&SIEVE_PRIMES, 20);
    let residues = init_residues(&SIEVE_PRIMES, 6u64);
    let mut candidate = Candidate::new(6u64, &spf);
    let ungated = evaluate_ungated(&context, &mut candidate, &residues);

    assert_eq!(ungated.f1, None);
    assert!(ungated.f2.is_some(), "F2 must remain observable after F1");
    assert!(ungated.evaluated_all());
}

#[test]
fn pipeline_stats_satisfy_accounting_invariants() {
    let max = 2_000;
    let spf = build_spf(max);
    let context = CanonicalContext::new(&SIEVE_PRIMES, 20);
    let mut stats = PipelineStats::default();

    for m in 2u32..=max {
        let residues = init_residues(&SIEVE_PRIMES, m);
        let mut candidate = Candidate::new(m, &spf);
        let trace = run_canonical(&context, &mut candidate, &residues);
        stats.record(&trace);
    }

    assert_eq!(stats.tested, u64::from(max - 1));
    stats
        .check_invariants()
        .expect("pipeline accounting must balance");
    assert!(
        stats
            .rejection_reasons
            .get(&Rejection::PrimePower)
            .copied()
            .unwrap_or(0)
            > 0
    );
}

#[test]
fn canonical_order_is_explicit_and_stable() {
    assert_eq!(
        Stage::ALL,
        [
            Stage::F1,
            Stage::F2,
            Stage::F3,
            Stage::F4,
            Stage::F4b,
            Stage::F56,
            Stage::F7,
            Stage::F8,
        ]
    );
    assert_eq!(filters::CANONICAL_STAGES, Stage::ALL);
}
