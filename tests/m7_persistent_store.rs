//! PP-02 durable object-store and publication-boundary tests.

use std::fs;
use std::path::PathBuf;

use cubealqot::family::persistence::{
    AdmissionPolicy, AdmissionProvenance, AdmissionRecord, CompletenessTrust, FailurePoint,
    PERSISTED_ADMISSION_POLICY_ID, PersistenceError, PublishResult, StoreManifest, StoreObject,
    StorePolicy, StoreReader, StoreWriter, TheoremBinding, canonical_json_sha256,
    json_content_reference,
};
use cubealqot::family::{CanonicalInt, CertificateProofKind, FamilyCertificateStatus};

fn temp_store(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cubealqot-pp02-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    path
}

fn policy() -> StorePolicy {
    StorePolicy {
        policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
        verifier_version: 1,
        certificate_schema_version: 1,
        rhs_version: 1,
        accepted_trust: CompletenessTrust::SelfContainedLocal,
        revoked_policy_ids: Vec::new(),
    }
}

fn fixture() -> (AdmissionRecord, StoreObject) {
    let certificate_bytes = br#"{"certificate":"pp02-fixture","status":"CertifiedEmpty"}"#.to_vec();
    let certificate = json_content_reference(&certificate_bytes, "application/json").unwrap();
    let record = AdmissionRecord {
        schema_version: 1,
        admission_id: "admission-pp02".to_owned(),
        operation_id: "operation-pp02".to_owned(),
        theorem: TheoremBinding {
            n: CanonicalInt::from_decimal("2").unwrap(),
            status: FamilyCertificateStatus::CertifiedEmpty,
            proof_kind: CertificateProofKind::Local,
            certificate_schema_version: 1,
            rhs_version: 1,
            raw_certificate_sha256: certificate.raw_sha256.clone(),
            canonical_certificate_sha256: certificate.canonical_sha256.clone(),
            solution_set_sha256: canonical_json_sha256(&Vec::<String>::new()).unwrap(),
            solution_count: 0,
        },
        proof_kind: CertificateProofKind::Local,
        provenance: AdmissionProvenance::FreshLocalVerification,
        policy: AdmissionPolicy {
            policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
            verifier_version: 1,
            certificate_schema_version: 1,
            rhs_version: 1,
            completeness: CompletenessTrust::SelfContainedLocal,
            backend: None,
        },
        certificate: certificate.clone(),
        evidence: Vec::new(),
        backend: None,
        source: None,
    };
    (record, StoreObject::new(certificate, certificate_bytes))
}

fn manifest() -> StoreManifest {
    StoreManifest::new("pp02-test-store".to_owned(), policy())
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_dir_all(path);
}

fn copy_tree(source: &PathBuf, destination: &PathBuf) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn committed_record_survives_writer_drop_and_reader_restart() {
    let root = temp_store("restart");
    let (record, certificate) = fixture();
    let mut writer = StoreWriter::create(&root, manifest()).unwrap();
    assert_eq!(
        writer.publish(&record, &[certificate]).unwrap(),
        PublishResult::Committed {
            admission_id: "admission-pp02".to_owned()
        }
    );
    drop(writer);

    let relocated = temp_store("relocated");
    copy_tree(&root, &relocated);
    let reader = StoreReader::open(&relocated).unwrap();
    assert_eq!(
        reader.read_committed_record("admission-pp02").unwrap(),
        Some(record)
    );
    cleanup(&relocated);
    cleanup(&root);
}

#[test]
fn staged_or_uncommitted_records_are_not_readable() {
    let root = temp_store("commit-boundary");
    let (record, certificate) = fixture();
    let mut writer = StoreWriter::create(&root, manifest()).unwrap();
    let error = writer
        .publish_with_failure(&record, &[certificate], FailurePoint::BeforeCommitPublish)
        .expect_err("injected commit boundary must interrupt publication");
    assert!(matches!(error, PersistenceError::InjectedFailure { .. }));
    assert_eq!(
        StoreReader::open(&root)
            .unwrap()
            .read_committed_record("admission-pp02")
            .unwrap(),
        None
    );

    assert_eq!(
        writer.publish(&record, &[]).unwrap(),
        PublishResult::Committed {
            admission_id: "admission-pp02".to_owned()
        }
    );
    cleanup(&root);
}

#[test]
fn duplicate_is_idempotent_but_changed_content_is_rejected() {
    let root = temp_store("retry");
    let (record, certificate) = fixture();
    let mut writer = StoreWriter::create(&root, manifest()).unwrap();
    writer.publish(&record, &[certificate.clone()]).unwrap();
    assert_eq!(
        writer.publish(&record, &[certificate]).unwrap(),
        PublishResult::AlreadyCommitted {
            admission_id: "admission-pp02".to_owned()
        }
    );

    let mut changed = record;
    changed.operation_id = "different-operation".to_owned();
    assert!(matches!(
        writer.publish(&changed, &[]),
        Err(PersistenceError::IncompatibleReplacement { .. })
    ));
    cleanup(&root);
}

#[test]
fn corruption_and_missing_objects_fail_explicitly() {
    let root = temp_store("corruption");
    let (record, certificate) = fixture();
    let mut writer = StoreWriter::create(&root, manifest()).unwrap();
    writer.publish(&record, &[certificate]).unwrap();
    let object_path = root.join("objects").join(&record.certificate.object_digest);
    fs::write(&object_path, b"changed").unwrap();
    assert!(matches!(
        StoreReader::open(&root)
            .unwrap()
            .read_committed_record("admission-pp02"),
        Err(PersistenceError::IntegrityFailure { .. })
    ));
    fs::remove_file(&object_path).unwrap();
    assert!(matches!(
        StoreReader::open(&root)
            .unwrap()
            .read_committed_record("admission-pp02"),
        Err(PersistenceError::MissingObject { .. })
    ));
    cleanup(&root);
}

#[test]
fn failure_injection_before_and_after_object_write_is_recoverable() {
    for point in [
        FailurePoint::BeforeObjectWrite,
        FailurePoint::AfterObjectWrite,
    ] {
        let root = temp_store(&format!("object-{point:?}"));
        let (record, certificate) = fixture();
        let mut writer = StoreWriter::create(&root, manifest()).unwrap();
        assert!(matches!(
            writer.publish_with_failure(&record, &[certificate.clone()], point),
            Err(PersistenceError::InjectedFailure { .. })
        ));
        assert_eq!(
            StoreReader::open(&root)
                .unwrap()
                .read_committed_record("admission-pp02")
                .unwrap(),
            None
        );
        writer.publish(&record, &[certificate]).unwrap();
        cleanup(&root);
    }
}

#[test]
fn failure_after_commit_is_visible_and_retry_does_not_rewrite() {
    let root = temp_store("after-commit");
    let (record, certificate) = fixture();
    let mut writer = StoreWriter::create(&root, manifest()).unwrap();
    assert!(matches!(
        writer.publish_with_failure(
            &record,
            &[certificate.clone()],
            FailurePoint::AfterCommitPublish
        ),
        Err(PersistenceError::InjectedFailure { .. })
    ));
    assert!(
        StoreReader::open(&root)
            .unwrap()
            .read_committed_record("admission-pp02")
            .unwrap()
            .is_some()
    );
    assert_eq!(
        writer.publish(&record, &[certificate]).unwrap(),
        PublishResult::AlreadyCommitted {
            admission_id: "admission-pp02".to_owned()
        }
    );
    cleanup(&root);
}

#[test]
fn record_publication_interruptions_leave_no_readable_admission() {
    for point in [
        FailurePoint::BeforeRecordPublish,
        FailurePoint::AfterRecordPublish,
    ] {
        let root = temp_store(&format!("record-{point:?}"));
        let (record, certificate) = fixture();
        let mut writer = StoreWriter::create(&root, manifest()).unwrap();
        assert!(matches!(
            writer.publish_with_failure(&record, &[certificate.clone()], point),
            Err(PersistenceError::InjectedFailure { .. })
        ));
        assert_eq!(
            StoreReader::open(&root)
                .unwrap()
                .read_committed_record("admission-pp02")
                .unwrap(),
            None
        );
        writer.publish(&record, &[certificate]).unwrap();
        cleanup(&root);
    }
}

#[test]
fn writers_are_serialized_and_staging_is_outside_reader_namespace() {
    let root = temp_store("lock");
    let writer = StoreWriter::create(&root, manifest()).unwrap();
    assert!(matches!(
        StoreWriter::create(&root, manifest()),
        Err(PersistenceError::WriterBusy)
    ));
    assert!(root.join("staging").is_dir());
    assert!(StoreReader::open(&root).is_ok());
    drop(writer);
    cleanup(&root);
}

#[test]
fn stale_lock_from_unclean_exit_is_recoverable() {
    let root = temp_store("stale-lock");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("stale_writer_child")
        .arg("--nocapture")
        .env("CUBEALQOT_PP02_CRASH_STORE", &root)
        .output()
        .unwrap();
    assert!(child.status.success(), "child output: {child:?}");
    let writer = StoreWriter::create(&root, manifest()).unwrap();
    drop(writer);
    cleanup(&root);
}

#[test]
fn stale_writer_child() {
    let Ok(root) = std::env::var("CUBEALQOT_PP02_CRASH_STORE") else {
        return;
    };
    let _writer = StoreWriter::create(PathBuf::from(root).as_path(), manifest()).unwrap();
    std::process::exit(0);
}
