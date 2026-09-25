//! PP-03 offline persisted-admission loader tests.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use cubealqot::family::admission::{
    SageTranscriptEvidence, UntrustedFamilyCertificate, build_local_family_certificate,
    build_trusted_family_certificate, serialize_family_certificate,
};
use cubealqot::family::persistence::{
    AdmissionLoad, AdmissionPolicy, AdmissionProvenance, AdmissionRecord, BackendEvidenceBinding,
    BackendPolicyIdentity, CompletenessTrust, PERSISTED_ADMISSION_POLICY_ID, PersistenceError,
    PointSetComparison, StoreManifest, StoreObject, StorePolicy, StoreReader, StoreWriter,
    TheoremBinding, TranscriptReference, canonical_solution_set_sha256, json_content_reference,
};
use cubealqot::family::pocklington::UntrustedPrimeCertificate;
use cubealqot::family::sage::{
    SageBackendPolicy, SageRequest, SageResponse, SageValidatedCompletion, validate_sage_response,
};
use cubealqot::family::{CanonicalInt, FamilyCertificateStatus, LocalSearchResult, problem};

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).expect("fixture integer is canonical")
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

fn n14_problem() -> problem::Problem {
    match problem::validate_problem(&n14_input()) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified fixture problem, got {other:?}"),
    }
}

fn local_certificate() -> UntrustedFamilyCertificate {
    let input = n14_input();
    let problem = n14_problem();
    let local = match cubealqot::family::search_local_certificate(
        &input,
        &problem,
        &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    ) {
        LocalSearchResult::Found(value) => value,
        other => panic!("expected local fixture certificate, got {other:?}"),
    };
    build_local_family_certificate(&input, &problem, local).expect("local certificate builds")
}

fn policy(revoked: bool) -> StorePolicy {
    StorePolicy {
        policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
        verifier_version: 1,
        certificate_schema_version: 1,
        rhs_version: 1,
        accepted_trust: CompletenessTrust::SelfContainedLocal,
        revoked_policy_ids: if revoked {
            vec![PERSISTED_ADMISSION_POLICY_ID.to_owned()]
        } else {
            Vec::new()
        },
    }
}

fn admission_for(certificate: &UntrustedFamilyCertificate) -> (AdmissionRecord, StoreObject) {
    let bytes = serialize_family_certificate(certificate).expect("certificate serializes");
    let reference = json_content_reference(&bytes, "application/vnd.cubealqot.family+json")
        .expect("certificate reference");
    let record = AdmissionRecord {
        schema_version: 1,
        admission_id: "admission-pp03".to_owned(),
        operation_id: "operation-pp03".to_owned(),
        theorem: TheoremBinding {
            n: certificate.problem.n.clone(),
            status: certificate.status.clone(),
            proof_kind: certificate.proof_kind.clone(),
            certificate_schema_version: certificate.schema_version,
            rhs_version: certificate.rhs_version,
            raw_certificate_sha256: reference.raw_sha256.clone(),
            canonical_certificate_sha256: reference.canonical_sha256.clone(),
            solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions).unwrap(),
            solution_count: certificate.solutions.len() as u64,
        },
        proof_kind: certificate.proof_kind.clone(),
        provenance: AdmissionProvenance::FreshLocalVerification,
        policy: AdmissionPolicy {
            policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
            verifier_version: 1,
            certificate_schema_version: 1,
            rhs_version: 1,
            completeness: CompletenessTrust::SelfContainedLocal,
            backend: None,
        },
        certificate: reference.clone(),
        evidence: Vec::new(),
        backend: None,
        source: None,
    };
    (record, StoreObject::new(reference, bytes))
}

fn store_path(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("cubealqot-pp03-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    path
}

fn cleanup(path: &PathBuf) {
    let _ = fs::remove_dir_all(path);
}

fn n3_completion() -> (
    problem::Problem,
    problem::UntrustedProblem,
    SageValidatedCompletion,
) {
    let input = problem::UntrustedProblem {
        n: integer("3"),
        factors: vec![problem::UntrustedCofactorFactor {
            prime: integer("3"),
            exponent: 1,
            certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("3") }),
        }],
    };
    let problem = match problem::validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified N=3 fixture, got {other:?}"),
    };
    let backend_policy = SageBackendPolicy {
        distribution: "Ubuntu-26.04".to_owned(),
        environment: "cubealqot-m7".to_owned(),
        conda_executable: "conda".to_owned(),
        sage_version: "10.8".to_owned(),
        python_version: "3.14.7".to_owned(),
        script_sha256: "script-hash".to_owned(),
    };
    let request = SageRequest::for_problem("job-1".to_owned(), &problem, &backend_policy);
    let response: SageResponse =
        serde_json::from_str(include_str!("fixtures/m7/adapter_complete_response.json")).unwrap();
    let completion = validate_sage_response(&problem, &request, response, &backend_policy).unwrap();
    (problem, input, completion)
}

fn transcript(value: &SageTranscriptEvidence) -> TranscriptReference {
    TranscriptReference {
        job_id: value.job_id.clone(),
        request_sha256: value.request_sha256.clone(),
        response_sha256: value.response_sha256.clone(),
        stderr_sha256: value.stderr_sha256.clone(),
        exit_code: value.exit_code,
        timed_out: value.timed_out,
    }
}

fn backend_admission() -> (AdmissionRecord, Vec<StoreObject>) {
    let (problem, input, completion) = n3_completion();
    let evidence = SageTranscriptEvidence {
        job_id: "job-pp03".to_owned(),
        request_sha256: "0".repeat(64),
        response_sha256: "1".repeat(64),
        stderr_sha256: "2".repeat(64),
        exit_code: Some(0),
        timed_out: false,
    };
    let certificate =
        build_trusted_family_certificate(&input, &problem, &completion, evidence.clone())
            .expect("trusted fixture certificate");
    let certificate_bytes = serialize_family_certificate(&certificate).unwrap();
    let certificate_reference =
        json_content_reference(&certificate_bytes, "application/vnd.cubealqot.family+json")
            .unwrap();
    let backend = match &certificate.proof {
        cubealqot::family::UntrustedCompletenessProof::TrustedIntegralPoints { backend } => backend,
        _ => panic!("expected trusted backend proof"),
    };
    let backend_policy = BackendPolicyIdentity {
        backend_name: backend.response.backend.name.clone(),
        sage_version: backend.request.policy.sage_version.clone(),
        python_version: backend.request.policy.python_version.clone(),
        environment_manifest_sha256: None,
        helper_sha256: backend.request.policy.script_sha256.clone(),
        model_semantics: backend.request.policy.model_semantics.clone(),
        proof_settings: vec![
            "both_signs".to_owned(),
            "generators_proof".to_owned(),
            "proof_all".to_owned(),
            "rank_proof".to_owned(),
            "require_gens_certain".to_owned(),
        ],
    };
    let initial = transcript(&backend.evidence);
    let replay = TranscriptReference {
        job_id: "replay-pp03".to_owned(),
        ..initial.clone()
    };
    let evidence_bytes = br#"{"transcript":"retained-by-pp03"}"#.to_vec();
    let evidence_reference = json_content_reference(&evidence_bytes, "application/json").unwrap();
    let record = AdmissionRecord {
        schema_version: 1,
        admission_id: "admission-pp03-backend".to_owned(),
        operation_id: "operation-pp03-backend".to_owned(),
        theorem: TheoremBinding {
            n: certificate.problem.n.clone(),
            status: certificate.status.clone(),
            proof_kind: certificate.proof_kind.clone(),
            certificate_schema_version: certificate.schema_version,
            rhs_version: certificate.rhs_version,
            raw_certificate_sha256: certificate_reference.raw_sha256.clone(),
            canonical_certificate_sha256: certificate_reference.canonical_sha256.clone(),
            solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions).unwrap(),
            solution_count: certificate.solutions.len() as u64,
        },
        proof_kind: certificate.proof_kind.clone(),
        provenance: AdmissionProvenance::FreshBackendReplay,
        policy: AdmissionPolicy {
            policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
            verifier_version: 1,
            certificate_schema_version: 1,
            rhs_version: 1,
            completeness: CompletenessTrust::HistoricalBackend,
            backend: Some(backend_policy.clone()),
        },
        certificate: certificate_reference.clone(),
        evidence: vec![evidence_reference.clone()],
        backend: Some(BackendEvidenceBinding {
            policy: backend_policy,
            initial,
            replay,
            point_set_sha256: backend.point_list_sha256.clone(),
            derived_solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions)
                .unwrap(),
            comparison: PointSetComparison::Exact,
        }),
        source: None,
    };
    (
        record,
        vec![
            StoreObject::new(certificate_reference, certificate_bytes),
            StoreObject::new(evidence_reference, evidence_bytes),
        ],
    )
}

fn persisted_backend_record_for(
    certificate: &UntrustedFamilyCertificate,
    admission_id: &str,
) -> (AdmissionRecord, Vec<StoreObject>) {
    let certificate_bytes = serialize_family_certificate(certificate).unwrap();
    let certificate_reference =
        json_content_reference(&certificate_bytes, "application/vnd.cubealqot.family+json")
            .unwrap();
    let backend = match &certificate.proof {
        cubealqot::family::UntrustedCompletenessProof::TrustedIntegralPoints { backend } => backend,
        _ => panic!("expected trusted backend proof"),
    };
    let backend_policy = BackendPolicyIdentity {
        backend_name: backend.response.backend.name.clone(),
        sage_version: backend.request.policy.sage_version.clone(),
        python_version: backend.request.policy.python_version.clone(),
        environment_manifest_sha256: None,
        helper_sha256: backend.request.policy.script_sha256.clone(),
        model_semantics: backend.request.policy.model_semantics.clone(),
        proof_settings: vec![
            "both_signs".to_owned(),
            "generators_proof".to_owned(),
            "proof_all".to_owned(),
            "rank_proof".to_owned(),
            "require_gens_certain".to_owned(),
        ],
    };
    let initial = transcript(&backend.evidence);
    let replay = TranscriptReference {
        job_id: format!("{}-replay", initial.job_id),
        ..initial.clone()
    };
    let evidence_bytes = br#"{"transcript":"retained-by-pp03"}"#.to_vec();
    let evidence_reference = json_content_reference(&evidence_bytes, "application/json").unwrap();
    let record = AdmissionRecord {
        schema_version: 1,
        admission_id: admission_id.to_owned(),
        operation_id: format!("operation-{admission_id}"),
        theorem: TheoremBinding {
            n: certificate.problem.n.clone(),
            status: certificate.status.clone(),
            proof_kind: certificate.proof_kind.clone(),
            certificate_schema_version: certificate.schema_version,
            rhs_version: certificate.rhs_version,
            raw_certificate_sha256: certificate_reference.raw_sha256.clone(),
            canonical_certificate_sha256: certificate_reference.canonical_sha256.clone(),
            solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions).unwrap(),
            solution_count: certificate.solutions.len() as u64,
        },
        proof_kind: certificate.proof_kind.clone(),
        provenance: AdmissionProvenance::FreshBackendReplay,
        policy: AdmissionPolicy {
            policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
            verifier_version: 1,
            certificate_schema_version: 1,
            rhs_version: 1,
            completeness: CompletenessTrust::HistoricalBackend,
            backend: Some(backend_policy.clone()),
        },
        certificate: certificate_reference.clone(),
        evidence: vec![evidence_reference.clone()],
        backend: Some(BackendEvidenceBinding {
            policy: backend_policy,
            initial,
            replay,
            point_set_sha256: backend.point_list_sha256.clone(),
            derived_solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions)
                .unwrap(),
            comparison: PointSetComparison::Exact,
        }),
        source: None,
    };
    (
        record,
        vec![
            StoreObject::new(certificate_reference, certificate_bytes),
            StoreObject::new(evidence_reference, evidence_bytes),
        ],
    )
}

#[test]
fn committed_local_admission_loads_offline_and_missing_is_not_admitted() {
    let root = store_path("local");
    let certificate = local_certificate();
    let (record, object) = admission_for(&certificate);
    let mut writer = StoreWriter::create(
        &root,
        StoreManifest::new("pp03-store".to_owned(), policy(false)),
    )
    .unwrap();
    writer.publish(&record, &[object]).unwrap();
    drop(writer);

    let reader = StoreReader::open(&root).unwrap();
    let loaded = reader.load_admission(&record.admission_id).unwrap();
    let AdmissionLoad::Loaded(loaded) = loaded else {
        panic!("committed local admission must load")
    };
    assert_eq!(loaded.n(), &integer("14"));
    assert_eq!(loaded.status(), &FamilyCertificateStatus::CertifiedEmpty);
    assert_eq!(loaded.committed().admission_id(), record.admission_id);
    let mut map = cubealqot::family::TheoremMap::new();
    map.insert_persisted(&loaded)
        .expect("only a loaded capability enters the theorem map");
    assert_eq!(
        reader.load_admission("missing").unwrap(),
        AdmissionLoad::NotAdmitted
    );
    cleanup(&root);
}

#[test]
fn recomputed_object_identity_does_not_rescue_invalid_certificate_math() {
    let root = store_path("mutated");
    let mut certificate = local_certificate();
    certificate.a = integer("6001");
    let (record, object) = admission_for(&certificate);
    let mut writer = StoreWriter::create(
        &root,
        StoreManifest::new("pp03-store".to_owned(), policy(false)),
    )
    .unwrap();
    writer.publish(&record, &[object]).unwrap();
    drop(writer);

    assert!(matches!(
        StoreReader::open(&root)
            .unwrap()
            .load_admission(&record.admission_id),
        Err(PersistenceError::IntegrityFailure { .. })
    ));
    cleanup(&root);
}

#[test]
fn unknown_and_revoked_policies_never_load_as_theorems() {
    let certificate = local_certificate();
    let (record, object) = admission_for(&certificate);

    let unknown_root = store_path("unknown-policy");
    let mut writer = StoreWriter::create(
        &unknown_root,
        StoreManifest::new(
            "pp03-store".to_owned(),
            StorePolicy {
                policy_id: "other-policy".to_owned(),
                ..policy(false)
            },
        ),
    )
    .unwrap();
    writer.publish(&record, &[object.clone()]).unwrap();
    drop(writer);
    assert!(matches!(
        StoreReader::open(&unknown_root)
            .unwrap()
            .load_admission(&record.admission_id),
        Err(PersistenceError::UnsupportedPolicy { .. })
    ));
    cleanup(&unknown_root);

    let revoked_root = store_path("revoked-policy");
    let mut writer = StoreWriter::create(
        &revoked_root,
        StoreManifest::new("pp03-store".to_owned(), policy(true)),
    )
    .unwrap();
    writer.publish(&record, &[object]).unwrap();
    drop(writer);
    assert!(matches!(
        StoreReader::open(&revoked_root)
            .unwrap()
            .load_admission(&record.admission_id),
        Err(PersistenceError::Revoked { .. })
    ));
    cleanup(&revoked_root);
}

#[test]
fn persisted_backend_admission_replays_exactly_without_launching_backend() {
    let root = store_path("backend");
    let (record, objects) = backend_admission();
    let mut writer = StoreWriter::create(
        &root,
        StoreManifest::new(
            "pp03-backend-store".to_owned(),
            StorePolicy {
                policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
                verifier_version: 1,
                certificate_schema_version: 1,
                rhs_version: 1,
                accepted_trust: CompletenessTrust::HistoricalBackend,
                revoked_policy_ids: Vec::new(),
            },
        ),
    )
    .unwrap();
    assert!(matches!(
        writer.publish(&record, &objects),
        Err(PersistenceError::InvalidRecord { .. })
    ));
    drop(writer);

    assert_eq!(
        StoreReader::open(&root)
            .unwrap()
            .load_admission(&record.admission_id)
            .unwrap(),
        AdmissionLoad::NotAdmitted
    );
    cleanup(&root);
}

#[test]
fn fresh_process_load_uses_only_the_committed_store() {
    let root = store_path("fresh-process");
    let certificate = local_certificate();
    let (record, object) = admission_for(&certificate);
    let mut writer = StoreWriter::create(
        &root,
        StoreManifest::new("pp03-store".to_owned(), policy(false)),
    )
    .unwrap();
    writer.publish(&record, &[object]).unwrap();
    drop(writer);

    let child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("fresh_process_loader_child")
        .arg("--nocapture")
        .env("CUBEALQOT_PP03_STORE", &root)
        .env("CUBEALQOT_PP03_NO_BACKEND", "1")
        .output()
        .unwrap();
    assert!(child.status.success(), "child output: {:?}", child);
    cleanup(&root);
}

#[test]
fn fresh_process_loader_child() {
    let Ok(root) = std::env::var("CUBEALQOT_PP03_STORE") else {
        return;
    };
    assert_eq!(
        std::env::var("CUBEALQOT_PP03_NO_BACKEND").as_deref(),
        Ok("1")
    );
    let loaded = StoreReader::open(PathBuf::from(root).as_path())
        .unwrap()
        .load_admission("admission-pp03")
        .unwrap();
    assert!(matches!(loaded, AdmissionLoad::Loaded(_)));
}

#[test]
fn backend_proof_flags_and_referenced_evidence_are_checked_offline() {
    let (record, mut objects) = backend_admission();
    let certificate: UntrustedFamilyCertificate =
        cubealqot::family::parse_family_certificate(&objects[0].bytes).unwrap();
    let mut changed = certificate.clone();
    if let cubealqot::family::UntrustedCompletenessProof::TrustedIntegralPoints { backend } =
        &mut changed.proof
    {
        backend.request.policy.proof_all = false;
    } else {
        panic!("expected trusted proof");
    }
    let changed_bytes = serialize_family_certificate(&changed).unwrap();
    let changed_reference =
        json_content_reference(&changed_bytes, "application/vnd.cubealqot.family+json").unwrap();
    objects[0] = StoreObject::new(changed_reference.clone(), changed_bytes);
    let mut changed_record = record.clone();
    changed_record.certificate = changed_reference.clone();
    changed_record.theorem.raw_certificate_sha256 = changed_reference.raw_sha256.clone();
    changed_record.theorem.canonical_certificate_sha256 =
        changed_reference.canonical_sha256.clone();

    let root = store_path("backend-flags");
    let mut writer = StoreWriter::create(
        &root,
        StoreManifest::new(
            "pp03-backend-store".to_owned(),
            StorePolicy {
                policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
                verifier_version: 1,
                certificate_schema_version: 1,
                rhs_version: 1,
                accepted_trust: CompletenessTrust::HistoricalBackend,
                revoked_policy_ids: Vec::new(),
            },
        ),
    )
    .unwrap();
    assert!(matches!(
        writer.publish(&changed_record, &objects),
        Err(PersistenceError::InvalidRecord { .. })
    ));
    drop(writer);
    assert_eq!(
        StoreReader::open(&root)
            .unwrap()
            .load_admission(&changed_record.admission_id)
            .unwrap(),
        AdmissionLoad::NotAdmitted
    );
    cleanup(&root);
}

#[test]
fn reviewed_proof_library_backend_certificate_loads_without_sage() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "out/m7-proof-library/certificates/N3-limit120-20260918T184611Z-0ce6eceacc8b47b78636f39efdf6fee5.json",
    );
    let envelope: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let certificate = cubealqot::family::parse_family_certificate(
        &serde_json::to_vec(&envelope["certificate"]).unwrap(),
    )
    .unwrap();
    let (record, objects) = persisted_backend_record_for(&certificate, "admission-library-n3");
    let root = store_path("library-backend");
    let mut writer = StoreWriter::create(
        &root,
        StoreManifest::new(
            "pp03-backend-store".to_owned(),
            StorePolicy {
                policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
                verifier_version: 1,
                certificate_schema_version: 1,
                rhs_version: 1,
                accepted_trust: CompletenessTrust::HistoricalBackend,
                revoked_policy_ids: Vec::new(),
            },
        ),
    )
    .unwrap();
    assert!(matches!(
        writer.publish(&record, &objects),
        Err(PersistenceError::InvalidRecord { .. })
    ));
    drop(writer);
    assert_eq!(
        StoreReader::open(&root)
            .unwrap()
            .load_admission(&record.admission_id)
            .unwrap(),
        AdmissionLoad::NotAdmitted
    );
    cleanup(&root);
}
