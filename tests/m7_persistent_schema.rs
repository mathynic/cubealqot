//! PP-01 persistence schema and authority-boundary tests.
//!
//! These tests cover schema identity and state separation only.  Durable
//! publication and offline theorem loading belong to PP-02/PP-03.

use std::path::PathBuf;

use cubealqot::family::persistence::{
    AdmissionLoadState, AdmissionPolicy, AdmissionProvenance, AdmissionRecord,
    BackendEvidenceBinding, BackendPolicyIdentity, CanonicalJsonIdentity, CompletenessTrust,
    ContentReference, PERSISTED_ADMISSION_POLICY_ID, PersistenceError, PointSetComparison,
    RegisteredStore, StoreManifest, StorePolicy, TheoremBinding, TranscriptReference,
    canonical_json_identity, conflict_state, parse_admission_record, validate_admission_schema,
};
use cubealqot::family::{CanonicalInt, CertificateProofKind, FamilyCertificateStatus};

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

fn manifest() -> StoreManifest {
    StoreManifest::new("test-store".to_owned(), policy())
}

fn theorem() -> TheoremBinding {
    TheoremBinding {
        n: CanonicalInt::from_decimal("2").unwrap(),
        status: FamilyCertificateStatus::CertifiedEmpty,
        proof_kind: CertificateProofKind::Local,
        certificate_schema_version: 1,
        rhs_version: 1,
        raw_certificate_sha256: "a".repeat(64),
        canonical_certificate_sha256: "b".repeat(64),
        solution_set_sha256: "c".repeat(64),
        solution_count: 0,
    }
}

fn record() -> AdmissionRecord {
    AdmissionRecord {
        schema_version: 1,
        admission_id: "admission-1".to_owned(),
        operation_id: "operation-1".to_owned(),
        theorem: theorem(),
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
        certificate: ContentReference {
            object_digest: "d".repeat(64),
            raw_sha256: "a".repeat(64),
            canonical_sha256: "b".repeat(64),
            encoding: "json-sorted-keys-utf8-v1".to_owned(),
            media_type: "application/json".to_owned(),
        },
        evidence: Vec::new(),
        backend: None,
        source: None,
    }
}

#[test]
fn canonical_identity_ignores_json_formatting_but_raw_digest_does_not() {
    let compact = br#"{"b":2,"a":{"y":false,"x":1}}"#;
    let formatted = br#"{ "a": { "x": 1, "y": false }, "b": 2 }"#;
    let left = canonical_json_identity(compact).unwrap();
    let right = canonical_json_identity(formatted).unwrap();

    assert_eq!(left.canonical_sha256, right.canonical_sha256);
    assert_ne!(left.raw_sha256, right.raw_sha256);
    assert_eq!(left.canonical_encoding, "json-sorted-keys-utf8-v1");
}

#[test]
fn unknown_versions_fail_closed_during_store_registration() {
    let mut value = manifest();
    value.schema_version += 1;
    assert!(matches!(
        RegisteredStore::register(PathBuf::from("store"), value),
        Err(PersistenceError::UnsupportedSchema { .. })
    ));

    let mut admission = record();
    admission.schema_version += 1;
    assert!(matches!(
        validate_admission_schema(&admission),
        Err(PersistenceError::UnsupportedSchema { .. })
    ));

    let mut unknown_policy_version = manifest();
    unknown_policy_version.policy.verifier_version = 999;
    assert!(matches!(
        cubealqot::family::persistence::validate_manifest(&unknown_policy_version),
        Err(PersistenceError::UnsupportedPolicy { .. })
    ));
}

#[test]
fn unsupported_and_revoked_policies_are_distinct_states() {
    let store = RegisteredStore::register(PathBuf::from("store"), manifest()).unwrap();
    assert_eq!(
        store.policy_state("unregistered-policy"),
        AdmissionLoadState::UnsupportedPolicy
    );

    let mut revoked = policy();
    revoked.revoked_policy_ids.push(revoked.policy_id.clone());
    let store = RegisteredStore::register(
        PathBuf::from("store"),
        StoreManifest::new("test-store".to_owned(), revoked),
    )
    .unwrap();
    assert_eq!(
        store.policy_state(PERSISTED_ADMISSION_POLICY_ID),
        AdmissionLoadState::Revoked
    );
}

#[test]
fn untrusted_json_is_only_a_wire_record_and_missing_commit_is_not_admitted() {
    let original = record();
    let bytes = serde_json::to_vec(&original).unwrap();
    let parsed = parse_admission_record(&bytes).unwrap();
    assert_eq!(parsed, original);

    let store = RegisteredStore::register(PathBuf::from("store"), manifest()).unwrap();
    assert_eq!(
        store.assess_record(&parsed, None),
        AdmissionLoadState::NotAdmitted
    );
    assert_eq!(
        store.assess_record(&parsed, Some("forged-commit-marker")),
        AdmissionLoadState::NotAdmitted
    );
}

#[test]
fn incomplete_evidence_is_not_a_loaded_admission() {
    let mut store_policy = policy();
    store_policy.accepted_trust = CompletenessTrust::HistoricalBackend;
    let store = RegisteredStore::register(
        PathBuf::from("store"),
        StoreManifest::new("test-store".to_owned(), store_policy),
    )
    .unwrap();
    let mut value = record();
    value.provenance = AdmissionProvenance::FreshBackendReplay;
    value.proof_kind = CertificateProofKind::TrustedIntegralPoints;
    value.theorem.proof_kind = CertificateProofKind::TrustedIntegralPoints;
    value.policy.completeness = CompletenessTrust::HistoricalBackend;
    let backend_policy = BackendPolicyIdentity {
        backend_name: "fixture".to_owned(),
        sage_version: "10.8".to_owned(),
        python_version: "3.14".to_owned(),
        environment_manifest_sha256: None,
        helper_sha256: "d".repeat(64),
        model_semantics: "original_integral_model".to_owned(),
        proof_settings: vec!["proof_all".to_owned()],
    };
    value.policy.backend = Some(backend_policy.clone());
    value.backend = Some(BackendEvidenceBinding {
        policy: backend_policy,
        initial: TranscriptReference {
            job_id: "initial".to_owned(),
            request_sha256: "a".repeat(64),
            response_sha256: "b".repeat(64),
            stderr_sha256: "c".repeat(64),
            exit_code: Some(0),
            timed_out: false,
        },
        replay: TranscriptReference {
            job_id: "replay".to_owned(),
            request_sha256: "e".repeat(64),
            response_sha256: "f".repeat(64),
            stderr_sha256: "0".repeat(64),
            exit_code: Some(0),
            timed_out: false,
        },
        point_set_sha256: "1".repeat(64),
        derived_solution_set_sha256: "2".repeat(64),
        comparison: PointSetComparison::Exact,
    });
    assert_eq!(
        store.assess_record(&value, Some("commit-digest")),
        AdmissionLoadState::IncompleteEvidence
    );
}

#[test]
fn canonical_record_round_trip_is_stable() {
    let value = record();
    let encoded = serde_json::to_vec(&value).unwrap();
    let parsed = parse_admission_record(&encoded).unwrap();
    let first = canonical_json_identity(&encoded).unwrap();
    let second = canonical_json_identity(&serde_json::to_vec(&parsed).unwrap()).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first,
        CanonicalJsonIdentity {
            raw_sha256: first.raw_sha256.clone(),
            canonical_sha256: first.canonical_sha256.clone(),
            canonical_encoding: "json-sorted-keys-utf8-v1".to_owned(),
        }
    );
}

#[test]
fn conflicting_complete_content_is_not_silently_selected() {
    let left = record();
    let mut right = record();
    right.admission_id = "admission-2".to_owned();
    right.theorem.solution_set_sha256 = "e".repeat(64);
    assert_eq!(conflict_state(&[left, right]), AdmissionLoadState::Conflict);
}
