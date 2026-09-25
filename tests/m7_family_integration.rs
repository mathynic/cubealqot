//! M7-16 opt-in family-stage integration tests.

use cubealqot::family::admission::{
    CertificateVerification, build_local_family_certificate, verify_family_certificate,
};
use cubealqot::family::pocklington::UntrustedPrimeCertificate;
use cubealqot::family::problem::{self, UntrustedCofactorFactor};
use cubealqot::family::{
    LocalSearchResult, TheoremMap, UntrustedFamilyCertificate, search_local_certificate,
};
use cubealqot::filters::{self, Outcome, Stage};
use cubealqot::survivors::{
    self, CheckpointSchedule, read_checkpoint,
    resume_stream_jsonl_range_with_family_map_and_cancel,
    stream_jsonl_range_checkpointed_with_family_map_and_cancel,
    stream_jsonl_range_checkpointed_with_family_map_and_schedule_and_cancel,
};
use cubealqot::{Candidate, build_spf, tables};
use std::fs;
use std::path::PathBuf;

fn integer(value: &str) -> cubealqot::family::CanonicalInt {
    cubealqot::family::CanonicalInt::from_decimal(value).unwrap()
}

fn n14_certificate() -> UntrustedFamilyCertificate {
    let input = problem::UntrustedProblem {
        n: integer("14"),
        factors: vec![
            UntrustedCofactorFactor {
                prime: integer("2"),
                exponent: 1,
                certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("2") }),
            },
            UntrustedCofactorFactor {
                prime: integer("7"),
                exponent: 1,
                certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("7") }),
            },
        ],
    };
    let problem = match problem::validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified N=14 problem, got {other:?}"),
    };
    let local = match search_local_certificate(&input, &problem, &(2..=16).collect::<Vec<_>>()) {
        LocalSearchResult::Found(certificate) => certificate,
        other => panic!("expected local certificate, got {other:?}"),
    };
    build_local_family_certificate(&input, &problem, local).unwrap()
}

fn n14_map() -> TheoremMap {
    let certificate = n14_certificate();
    let verified = match verify_family_certificate(&certificate) {
        CertificateVerification::Verified(value) => value,
        other => panic!("expected verified local theorem, got {other:?}"),
    };
    let mut map = TheoremMap::new();
    map.insert_verified(&certificate, &verified).unwrap();
    map
}

fn temp_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cubealqot-m7-17-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    path
}

#[test]
fn real_n14_family_map_is_opt_in_and_does_not_change_earlier_rejection() {
    let map = n14_map();
    let spf = build_spf(42);
    let context = filters::CanonicalContext::new(&[5, 7, 11, 13], 31);
    let mut candidate = Candidate::new(42u64, &spf);
    let residues = tables::init_residues(&context.f4.sieve_primes, candidate.m);

    let trace =
        filters::run_canonical_with_family_map(&context, &mut candidate, &residues, Some(&map));
    assert_eq!(trace.evaluated, vec![Stage::F1, Stage::F2]);
    assert!(matches!(
        trace.outcome,
        Outcome::Rejected {
            stage: Stage::F2,
            ..
        }
    ));
    assert!(trace.family_witness.is_none());
}

#[test]
fn no_map_is_byte_for_byte_the_legacy_pipeline_and_ungated_family_is_visible() {
    let map = n14_map();
    let spf = build_spf(42);
    let context = filters::CanonicalContext::new(&[5, 7, 11, 13], 31);
    let residues = tables::init_residues(&context.f4.sieve_primes, 42u64);

    let mut legacy_candidate = Candidate::new(42u64, &spf);
    let legacy = filters::run_canonical(&context, &mut legacy_candidate, &residues);
    let mut opt_in_none_candidate = Candidate::new(42u64, &spf);
    let opt_in_none = filters::run_canonical_with_family_map(
        &context,
        &mut opt_in_none_candidate,
        &residues,
        None,
    );
    assert_eq!(legacy, opt_in_none);
    assert!(opt_in_none.family_witness.is_none());

    let mut ungated_candidate = Candidate::new(42u64, &spf);
    let ungated = filters::evaluate_ungated_wide_with_family_map(
        &context,
        &mut ungated_candidate,
        &residues,
        Some(&map),
    );
    assert_eq!(
        ungated
            .family
            .as_ref()
            .map(|witness| witness.q().to_string()),
        Some("3".to_owned())
    );
}

#[test]
fn map_enabled_collection_preserves_no_map_results_when_no_exclusion_is_reached() {
    let map = n14_map();
    let legacy = cubealqot::survivors::collect_range(2, 100, 1, Stage::F8).unwrap();
    let mapped =
        cubealqot::survivors::collect_range_with_family_map(2, 100, 1, Stage::F8, &map).unwrap();
    assert_eq!(mapped.records, legacy.records);
    assert_eq!(mapped.stats.reached_stages, legacy.stats.reached_stages);
    assert_eq!(mapped.stats.rejected_stages, legacy.stats.rejected_stages);
    assert_eq!(
        mapped.stats.rejection_reasons,
        legacy.stats.rejection_reasons
    );
    assert_eq!(mapped.stats.solutions, legacy.stats.solutions);
    assert_eq!(mapped.stats.family.unwrap().reached, 12);
}

#[test]
fn map_snapshot_binds_interrupted_resume_and_worker_count() {
    let map = n14_map();
    let full_path = temp_path("full");
    let resumed_path = temp_path("resumed");
    let checkpoint_path = temp_path("checkpoint");
    let config = "m7-17;range=2..=100;dump=F1";

    let full =
        survivors::stream_jsonl_range_with_family_map(&full_path, 2, 100, 1, Stage::F1, &map)
            .unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_for_progress = stop.clone();
    let partial = stream_jsonl_range_checkpointed_with_family_map_and_schedule_and_cancel(
        &resumed_path,
        &checkpoint_path,
        2,
        100,
        1,
        Stage::F1,
        config,
        CheckpointSchedule::new(Some(16), None).unwrap(),
        &map,
        move |progress| {
            if progress.completed_through < 100 {
                stop_for_progress.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        },
        || stop.load(std::sync::atomic::Ordering::SeqCst),
    )
    .unwrap();
    assert!(partial.interrupted);
    let checkpoint = read_checkpoint(&checkpoint_path).unwrap();
    assert_eq!(
        checkpoint.schema_version,
        survivors::RUN_METADATA_SCHEMA_VERSION
    );
    let premises = checkpoint.premises.clone().unwrap();
    assert_eq!(
        premises.theorem_map_digest,
        Some(map.snapshot_digest().unwrap())
    );
    assert_eq!(premises.enabled_stages, filters::FAMILY_STAGES.to_vec());

    resume_stream_jsonl_range_with_family_map_and_cancel(
        &resumed_path,
        &checkpoint_path,
        100,
        4,
        Stage::F1,
        config,
        Some(&map),
        |_| {},
        || false,
    )
    .unwrap();
    assert_eq!(
        fs::read(&full_path).unwrap(),
        fs::read(&resumed_path).unwrap()
    );
    assert_eq!(full.stats, read_checkpoint(&checkpoint_path).unwrap().stats);

    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(resumed_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn changed_snapshot_missing_snapshot_and_forged_witness_are_rejected() {
    let map = n14_map();
    let empty_map = TheoremMap::new();
    let output = temp_path("records");
    let checkpoint = temp_path("records-checkpoint");
    let config = "m7-17;forged-witness";
    stream_jsonl_range_checkpointed_with_family_map_and_cancel(
        &output,
        &checkpoint,
        2,
        100,
        1,
        Stage::F1,
        config,
        &map,
        |_| {},
        || false,
    )
    .unwrap();

    let changed = resume_stream_jsonl_range_with_family_map_and_cancel(
        &output,
        &checkpoint,
        100,
        1,
        Stage::F1,
        config,
        Some(&empty_map),
        |_| {},
        || false,
    )
    .expect_err("changing map contents must invalidate resume");
    assert!(changed.contains("premises") || changed.contains("digest"));

    let missing = resume_stream_jsonl_range_with_family_map_and_cancel(
        &output,
        &checkpoint,
        100,
        1,
        Stage::F1,
        config,
        None,
        |_| {},
        || false,
    )
    .expect_err("missing theorem snapshot must not resume");
    assert!(missing.contains("snapshot"));

    let mut lines = fs::read_to_string(&output)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let index = 0;
    let mut forged: serde_json::Value = serde_json::from_str(&lines[index]).unwrap();
    let witness = match map.lookup(&integer("42"), &integer("14"), &integer("3")) {
        cubealqot::family::LookupDecision::Excluded(witness) => witness,
        other => panic!("expected a real admitted witness, got {other:?}"),
    };
    forged["family_witness"] = serde_json::to_value(witness).unwrap();
    lines[index] = serde_json::to_string(&forged).unwrap();
    fs::write(&output, format!("{}\n", lines.join("\n"))).unwrap();
    let forged_error = resume_stream_jsonl_range_with_family_map_and_cancel(
        &output,
        &checkpoint,
        100,
        1,
        Stage::F1,
        config,
        Some(&map),
        |_| {},
        || false,
    )
    .expect_err("forged historical witness must not resume");
    assert!(forged_error.contains("witness"));

    let _ = fs::remove_file(output);
    let _ = fs::remove_file(checkpoint);
}
