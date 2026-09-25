//! PP-05 two-phase migration tests.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use cubealqot::family::{
    AdmissionLoad, ImportDisposition, RECORDED_LOCAL_CAMPAIGN_POLICY_ID, StoreReader,
    commit_legacy_proof_library, inspect_legacy_proof_library, parse_legacy_migration_report,
    serialize_legacy_migration_report,
};

fn library_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("out/m7-proof-library")
}

fn store_root(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cubealqot-pp05-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    path
}

fn copy_tree(source: &std::path::Path, destination: &std::path::Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn inspection_accounts_reviewed_families_and_is_repeatable() {
    let first = inspect_legacy_proof_library(&library_root()).unwrap();
    let second = inspect_legacy_proof_library(&library_root()).unwrap();
    assert_eq!(first.digest(), second.digest());
    let report_bytes = serialize_legacy_migration_report(&first.report).unwrap();
    let parsed = parse_legacy_migration_report(&report_bytes, first.digest()).unwrap();
    assert_eq!(parsed, first);
    assert_eq!(first.admitted_count(), 7);
    let admitted = first
        .report
        .entries
        .iter()
        .filter(|entry| entry.disposition == ImportDisposition::Admitted)
        .map(|entry| entry.n.as_ref().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        admitted,
        ["2", "3", "4", "5", "9", "21", "35"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert!(
        first
            .report
            .entries
            .iter()
            .all(|entry| entry.initial_transcript.is_some() && entry.replay_transcript.is_some())
    );
}

#[test]
fn migration_commits_all_reviewed_entries_and_reloads_without_sage() {
    let inspection = inspect_legacy_proof_library(&library_root()).unwrap();
    let root = store_root("commit");
    let committed =
        commit_legacy_proof_library(&root, &inspection, "2026-09-20T00:00:00Z").unwrap();
    assert_eq!(
        committed
            .entries
            .iter()
            .filter(|entry| entry.disposition == ImportDisposition::Admitted)
            .count(),
        7
    );
    let reader = StoreReader::open(&root).unwrap();
    for entry in committed
        .entries
        .iter()
        .filter(|entry| entry.admission_id.is_some())
    {
        let admission_id = entry.admission_id.as_ref().unwrap();
        let AdmissionLoad::Loaded(loaded) = reader.load_admission(admission_id).unwrap() else {
            panic!("migrated admission did not load: {admission_id}");
        };
        assert_eq!(
            loaded.committed().record().policy.policy_id,
            RECORDED_LOCAL_CAMPAIGN_POLICY_ID
        );
        assert_eq!(
            loaded.committed().record().provenance,
            cubealqot::family::AdmissionProvenance::MigratedRecordedLocalCampaign
        );
        assert_eq!(loaded.n(), entry.n.as_ref().unwrap());
    }
    let ids = committed
        .entries
        .iter()
        .filter_map(|entry| entry.admission_id.as_deref())
        .collect::<Vec<_>>()
        .join(",");
    let child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("fresh_process_loads_migrated_admissions_without_backend")
        .arg("--nocapture")
        .env("CUBEALQOT_PP05_STORE", &root)
        .env("CUBEALQOT_PP05_IDS", ids)
        .output()
        .unwrap();
    assert!(child.status.success(), "fresh process output: {:?}", child);
    let second = commit_legacy_proof_library(&root, &inspection, "2026-09-20T00:00:01Z").unwrap();
    assert_eq!(second.entries.len(), committed.entries.len());
    assert_eq!(
        second.entries[0].destination_record_sha256,
        committed.entries[0].destination_record_sha256
    );
    let first_id = committed.entries[0].admission_id.as_ref().unwrap();
    let loaded = StoreReader::open(&root)
        .unwrap()
        .load_admission(first_id)
        .unwrap();
    let AdmissionLoad::Loaded(loaded) = loaded else {
        panic!("idempotent migration lost the original admission")
    };
    assert_eq!(
        loaded
            .committed()
            .record()
            .source
            .as_ref()
            .and_then(|source| source.migration_date.as_deref()),
        Some("2026-09-20T00:00:00Z")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn misleading_receipt_and_replay_mutation_are_not_grandfathered() {
    let source = std::env::temp_dir().join(format!("cubealqot-pp05-source-{}", std::process::id()));
    let _ = fs::remove_dir_all(&source);
    copy_tree(&library_root(), &source);

    let receipt_path = source.join("receipts/N2.json");
    let original_receipt = fs::read(&receipt_path).unwrap();
    let mut receipt: serde_json::Value = serde_json::from_slice(&original_receipt).unwrap();
    receipt["status"] = serde_json::Value::String("CERTIFIED_SOLUTIONS".to_owned());
    fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let report = inspect_legacy_proof_library(&source).unwrap();
    let n2 = report
        .report
        .entries
        .iter()
        .find(|entry| entry.n.as_ref().is_some_and(|n| n.to_string() == "2"))
        .unwrap();
    assert_eq!(n2.disposition, ImportDisposition::Rejected);

    fs::write(&receipt_path, original_receipt).unwrap();
    let replay_path = source
        .join("certificates/m7-adapter-evidence/m7-sage-41796-1789757189221348300-1/response.json");
    let mut response: serde_json::Value =
        serde_json::from_slice(&fs::read(&replay_path).unwrap()).unwrap();
    response["points"][0]["y"] = serde_json::Value::String("0".to_owned());
    fs::write(&replay_path, serde_json::to_vec(&response).unwrap()).unwrap();
    let report = inspect_legacy_proof_library(&source).unwrap();
    let n2 = report
        .report
        .entries
        .iter()
        .find(|entry| entry.n.as_ref().is_some_and(|n| n.to_string() == "2"))
        .unwrap();
    assert_eq!(n2.disposition, ImportDisposition::IncompleteEvidence);
    assert!(n2.reason.contains("replay"));
    let _ = fs::remove_dir_all(source);
}

#[test]
fn fresh_process_loads_migrated_admissions_without_backend() {
    let Ok(root) = std::env::var("CUBEALQOT_PP05_STORE") else {
        return;
    };
    let ids = std::env::var("CUBEALQOT_PP05_IDS").unwrap();
    let reader = StoreReader::open(std::path::Path::new(&root)).unwrap();
    for id in ids.split(',') {
        assert!(matches!(
            reader.load_admission(id).unwrap(),
            AdmissionLoad::Loaded(_)
        ));
    }
}

#[test]
fn changed_report_cannot_be_committed_under_old_digest() {
    let mut inspection = inspect_legacy_proof_library(&library_root()).unwrap();
    inspection.report.entries[0].reason.push_str(" tampered");
    let root = store_root("tampered-report");
    let error =
        commit_legacy_proof_library(&root, &inspection, "2026-09-20T00:00:00Z").unwrap_err();
    assert!(matches!(
        error,
        cubealqot::family::PersistenceError::IntegrityFailure { .. }
    ));
    assert!(!root.exists());
}
