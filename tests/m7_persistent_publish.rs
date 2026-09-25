//! PP-04 publication tests: successful proofs become durable admissions.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cubealqot::family::CanonicalInt;
use cubealqot::family::admission::{
    SageTranscriptEvidence, UntrustedFamilyCertificate, build_local_family_certificate,
    build_trusted_family_certificate,
};
use cubealqot::family::pocklington::UntrustedPrimeCertificate;
use cubealqot::family::problem::{self, validate_problem};
use cubealqot::family::sage::{
    SageAdapter, SageAdapterConfig, SageAdapterResult, SageBackendPolicy, SageRequest,
    SageResponse, SageRunEvidence, validate_sage_response,
};
use cubealqot::family::{
    AdmissionLoad, CompletenessTrust, FamilyCertificateStatus, LocalSearchResult,
    PERSISTED_ADMISSION_POLICY_ID, PersistenceError, PublishResult, StoreReader,
    admit_trusted_backend_certificate_with_evidence, json_content_reference,
    persist_local_admission, persist_trusted_backend_admission, raw_content_reference,
};

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).unwrap()
}

fn n14_input() -> problem::UntrustedProblem {
    problem::UntrustedProblem {
        n: integer("14"),
        factors: vec![
            problem::UntrustedCofactorFactor {
                prime: integer("2"),
                exponent: 1,
                certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("2") }),
            },
            problem::UntrustedCofactorFactor {
                prime: integer("7"),
                exponent: 1,
                certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("7") }),
            },
        ],
    }
}

fn n14_certificate() -> UntrustedFamilyCertificate {
    let input = n14_input();
    let problem = match validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified N=14 problem, got {other:?}"),
    };
    let local = match cubealqot::family::search_local_certificate(
        &input,
        &problem,
        &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    ) {
        LocalSearchResult::Found(value) => value,
        other => panic!("expected local proof, got {other:?}"),
    };
    build_local_family_certificate(&input, &problem, local).unwrap()
}

fn temp_root(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cubealqot-pp04-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

#[test]
fn local_success_publishes_idempotently_and_reloads_without_backend() {
    let root = temp_root("local");
    let certificate = n14_certificate();
    let first = persist_local_admission(&root, &certificate).unwrap();
    assert!(matches!(first.result(), PublishResult::Committed { .. }));
    let second = persist_local_admission(&root, &certificate).unwrap();
    assert!(matches!(
        second.result(),
        PublishResult::AlreadyCommitted { .. }
    ));

    let reader = StoreReader::open(&root).unwrap();
    let AdmissionLoad::Loaded(loaded) = reader.load_admission(first.admission_id()).unwrap() else {
        panic!("published local proof must be loadable")
    };
    assert_eq!(loaded.status(), &FamilyCertificateStatus::CertifiedEmpty);
    assert_eq!(
        loaded.committed().record().policy.policy_id,
        PERSISTED_ADMISSION_POLICY_ID
    );
    assert_eq!(
        loaded.committed().record().policy.completeness,
        CompletenessTrust::SelfContainedLocal
    );
    cleanup(&root);
}

#[test]
fn inconclusive_certificate_is_not_published() {
    let root = temp_root("inconclusive");
    let mut certificate = n14_certificate();
    certificate.status = FamilyCertificateStatus::Inconclusive;
    let result = persist_local_admission(&root, &certificate);
    assert!(matches!(
        result,
        Err(PersistenceError::InvalidRecord { .. })
    ));
    assert!(!root.exists(), "inconclusive proof must not create a store");
}

fn n3_certificate_and_initial_evidence() -> (UntrustedFamilyCertificate, SageRunEvidence) {
    let input = problem::UntrustedProblem {
        n: integer("3"),
        factors: vec![problem::UntrustedCofactorFactor {
            prime: integer("3"),
            exponent: 1,
            certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("3") }),
        }],
    };
    let problem = match validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified N=3 problem, got {other:?}"),
    };
    let policy = SageBackendPolicy {
        distribution: "Ubuntu-26.04".to_owned(),
        environment: "cubealqot-m7".to_owned(),
        conda_executable: "conda".to_owned(),
        sage_version: "10.8".to_owned(),
        python_version: "3.14.7".to_owned(),
        script_sha256: "script-hash".to_owned(),
    };
    let request = SageRequest::for_problem("job-1".to_owned(), &problem, &policy);
    let response: SageResponse =
        serde_json::from_str(include_str!("fixtures/m7/adapter_complete_response.json")).unwrap();

    let root = temp_root("initial-evidence");
    fs::create_dir_all(&root).unwrap();
    let request_path = root.join("request.json");
    let response_path = root.join("response.json");
    let stderr_path = root.join("stderr.log");
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let response_bytes = serde_json::to_vec(&response).unwrap();
    let stderr_bytes = b"initial backend transcript\n";
    fs::write(&request_path, &request_bytes).unwrap();
    fs::write(&response_path, &response_bytes).unwrap();
    fs::write(&stderr_path, stderr_bytes).unwrap();
    let request_digest = json_content_reference(&request_bytes, "application/json")
        .unwrap()
        .raw_sha256;
    let response_digest = json_content_reference(&response_bytes, "application/json")
        .unwrap()
        .raw_sha256;
    let stderr_digest = raw_content_reference(stderr_bytes, "text/plain").raw_sha256;
    let initial = SageRunEvidence {
        job_id: "job-1".to_owned(),
        request_path,
        stdout_path: response_path,
        stderr_path,
        request_sha256: request_digest.clone(),
        stdout_sha256: response_digest.clone(),
        stderr_sha256: stderr_digest.clone(),
        exit_code: Some(0),
        timed_out: false,
    };
    let completion = validate_sage_response(&problem, &request, response, &policy).unwrap();
    let certificate = build_trusted_family_certificate(
        &input,
        &problem,
        &completion,
        SageTranscriptEvidence {
            job_id: initial.job_id.clone(),
            request_sha256: request_digest,
            response_sha256: response_digest,
            stderr_sha256: stderr_digest,
            exit_code: initial.exit_code,
            timed_out: initial.timed_out,
        },
    )
    .unwrap();
    (certificate, initial)
}

fn fake_adapter(evidence_dir: &Path) -> SageAdapter {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    SageAdapter::new(SageAdapterConfig {
        launcher: root.join("tests/fixtures/m7/adapter_complete.ps1"),
        helper: root.join("scripts/m7/sage_smoke.py"),
        powershell_executable: "powershell.exe".to_owned(),
        distribution: "Ubuntu-26.04".to_owned(),
        conda_executable: "conda".to_owned(),
        environment: "cubealqot-m7".to_owned(),
        timeout: Duration::from_secs(10),
        evidence_dir: evidence_dir.to_path_buf(),
        policy: SageBackendPolicy {
            distribution: "Ubuntu-26.04".to_owned(),
            environment: "cubealqot-m7".to_owned(),
            conda_executable: "conda".to_owned(),
            sage_version: "10.8".to_owned(),
            python_version: "3.14.7".to_owned(),
            script_sha256: "script-hash".to_owned(),
        },
        extra_launcher_args: Vec::new(),
    })
}

#[test]
fn trusted_success_persists_initial_and_replay_transcripts() {
    let evidence_root = temp_root("trusted-evidence");
    let (certificate, initial) = n3_certificate_and_initial_evidence();
    let adapter = fake_adapter(&evidence_root);
    let admission = match admit_trusted_backend_certificate_with_evidence(&certificate, &adapter) {
        cubealqot::family::TrustedBackendAdmissionVerification::Verified(value) => value,
        other => panic!("expected successful replay admission, got {other:?}"),
    };
    let store_root = temp_root("trusted-store");
    let published =
        persist_trusted_backend_admission(&store_root, &certificate, &initial, &admission).unwrap();
    let reader = StoreReader::open(&store_root).unwrap();
    let AdmissionLoad::Loaded(loaded) = reader.load_admission(published.admission_id()).unwrap()
    else {
        panic!("trusted publication must load offline")
    };
    let record = loaded.committed().record();
    assert_eq!(
        record.provenance,
        cubealqot::family::AdmissionProvenance::FreshBackendReplay
    );
    assert_eq!(record.evidence.len(), 6);
    assert_eq!(
        record.backend.as_ref().unwrap().initial.job_id,
        initial.job_id
    );
    assert_ne!(
        record.backend.as_ref().unwrap().replay.job_id,
        initial.job_id
    );
    cleanup(&store_root);
    cleanup(&evidence_root);
    cleanup(&temp_root("initial-evidence"));
}

#[test]
#[ignore = "requires the pinned production WSL Sage environment"]
fn real_sage_completion_persists_and_reloads_without_a_third_backend_run() {
    let input = problem::UntrustedProblem {
        n: integer("3"),
        factors: vec![problem::UntrustedCofactorFactor {
            prime: integer("3"),
            exponent: 1,
            certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("3") }),
        }],
    };
    let problem = match validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified N=3 problem, got {other:?}"),
    };
    let evidence_root = temp_root("real-sage-evidence");
    let config = SageAdapterConfig::m7_default(evidence_root.clone()).unwrap();
    let adapter = SageAdapter::new(config);
    let (completion, initial_evidence) = match adapter.enumerate(&problem) {
        SageAdapterResult::Complete {
            completion,
            evidence,
        } => (completion, evidence),
        other => panic!("real Sage initial completion was not complete: {other:?}"),
    };
    let certificate = build_trusted_family_certificate(
        &input,
        &problem,
        &completion,
        SageTranscriptEvidence::from(&initial_evidence),
    )
    .unwrap();
    let admission = match admit_trusted_backend_certificate_with_evidence(&certificate, &adapter) {
        cubealqot::family::TrustedBackendAdmissionVerification::Verified(value) => value,
        other => panic!("real Sage replay admission failed: {other:?}"),
    };
    let store_root = temp_root("real-sage-store");
    let published =
        persist_trusted_backend_admission(&store_root, &certificate, &initial_evidence, &admission)
            .unwrap();
    assert!(matches!(
        StoreReader::open(&store_root)
            .unwrap()
            .load_admission(published.admission_id())
            .unwrap(),
        AdmissionLoad::Loaded(_)
    ));
    cleanup(&store_root);
    cleanup(&evidence_root);
}
