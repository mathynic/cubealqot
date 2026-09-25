//! M7-13 tests for certificate verification and trusted admission.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use cubealqot::family::admission::{
    CertificateProofKind, CertificateVerification, FamilyCertificateStatus, SageTranscriptEvidence,
    UntrustedCompletenessProof, UntrustedFamilyCertificate, UntrustedFamilySolution,
    admit_trusted_backend_certificate, build_local_family_certificate,
    build_trusted_family_certificate, canonical_point_list_sha256, parse_family_certificate,
    serialize_family_certificate, verify_family_certificate,
};
use cubealqot::family::sage::{
    SageAdapter, SageAdapterConfig, SageBackendPolicy, SageRequest, SageResponse,
    SageValidatedCompletion, validate_sage_response,
};
use cubealqot::family::{CanonicalInt, FamilyStatus};
use cubealqot::family::{pocklington::UntrustedPrimeCertificate, problem};

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).expect("fixture integer is canonical")
}

fn factor(prime: &str, exponent: u32) -> problem::UntrustedCofactorFactor {
    problem::UntrustedCofactorFactor {
        prime: integer(prime),
        exponent,
        certificate: Some(UntrustedPrimeCertificate::U64 { n: integer(prime) }),
    }
}

fn n14_input() -> problem::UntrustedProblem {
    problem::UntrustedProblem {
        n: integer("14"),
        factors: vec![factor("2", 1), factor("7", 1)],
    }
}

fn n14_problem() -> problem::Problem {
    match problem::validate_problem(&n14_input()) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified N=14 problem, got {other:?}"),
    }
}

fn real_local_certificate() -> cubealqot::family::UntrustedLocalCertificate {
    match cubealqot::family::search_local_certificate(
        &n14_input(),
        &n14_problem(),
        &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    ) {
        cubealqot::family::LocalSearchResult::Found(certificate) => certificate,
        other => panic!("expected local certificate, got {other:?}"),
    }
}

fn local_certificate() -> UntrustedFamilyCertificate {
    build_local_family_certificate(&n14_input(), &n14_problem(), real_local_certificate())
        .expect("local family certificate should build")
}

#[test]
fn local_certificate_verifies_offline_and_serializes_canonically() {
    let certificate = local_certificate();
    assert_eq!(certificate.status, FamilyCertificateStatus::CertifiedEmpty);
    assert_eq!(certificate.proof_kind, CertificateProofKind::Local);

    let bytes = serialize_family_certificate(&certificate).expect("canonical certificate JSON");
    assert_eq!(bytes, serialize_family_certificate(&certificate).unwrap());
    let reparsed = parse_family_certificate(&bytes).expect("certificate round trip");
    assert_eq!(reparsed, certificate);

    assert!(matches!(
        verify_family_certificate(&reparsed),
        CertificateVerification::Verified(verified)
            if verified.status() == FamilyStatus::CertifiedEmpty
    ));
}

#[test]
fn local_mutations_and_forged_bounded_claims_never_verify() {
    let certificate = local_certificate();

    let mut changed_n = certificate.clone();
    changed_n.problem.n = integer("15");
    assert!(matches!(
        verify_family_certificate(&changed_n),
        CertificateVerification::Rejected { .. }
    ));

    let mut changed_exponent = certificate.clone();
    changed_exponent.problem.factors[0].exponent = 2;
    assert!(matches!(
        verify_family_certificate(&changed_exponent),
        CertificateVerification::Rejected { .. }
    ));

    let mut changed_a = certificate.clone();
    changed_a.a = integer("6001");
    assert!(matches!(
        verify_family_certificate(&changed_a),
        CertificateVerification::Rejected { .. }
    ));

    let mut changed_d = certificate.clone();
    changed_d.d = integer("3257");
    assert!(matches!(
        verify_family_certificate(&changed_d),
        CertificateVerification::Rejected { .. }
    ));

    let mut changed_curve = certificate.clone();
    changed_curve.curve_coefficients[4] = integer("6761");
    assert!(matches!(
        verify_family_certificate(&changed_curve),
        CertificateVerification::Rejected { .. }
    ));

    let mut changed_version = certificate.clone();
    changed_version.schema_version += 1;
    assert!(matches!(
        verify_family_certificate(&changed_version),
        CertificateVerification::Rejected { .. }
    ));

    let mut changed_kind = certificate.clone();
    changed_kind.proof_kind = CertificateProofKind::TrustedIntegralPoints;
    assert!(matches!(
        verify_family_certificate(&changed_kind),
        CertificateVerification::Rejected { .. }
    ));

    let mut changed_status = certificate.clone();
    changed_status.status = FamilyCertificateStatus::CertifiedSolutions;
    assert!(matches!(
        verify_family_certificate(&changed_status),
        CertificateVerification::Rejected { .. }
    ));

    let mut appended_solution = certificate.clone();
    appended_solution.solutions.push(UntrustedFamilySolution {
        q: integer("2"),
        y: integer("1"),
        curve_x: integer("6512"),
        curve_y: integer("3256"),
        q_prime: Some(UntrustedPrimeCertificate::U64 { n: integer("2") }),
    });
    assert!(matches!(
        verify_family_certificate(&appended_solution),
        CertificateVerification::Rejected { .. }
    ));

    let forged_bounded = serde_json::json!({
        "schema_version": 1,
        "rhs_version": 1,
        "proof_kind": "bounded",
        "status": "CertifiedEmpty",
        "problem": n14_input(),
        "a": "6000",
        "d": "3256",
        "curve_coefficients": ["0", "6000", "0", "19536000", "636?"],
        "solutions": [],
        "proof": {"kind": "bounded", "complete": true}
    });
    assert!(parse_family_certificate(forged_bounded.to_string().as_bytes()).is_err());
}

#[test]
fn fresh_process_verifier_accepts_local_and_rejects_mutation() {
    let certificate = local_certificate();
    let bytes = serialize_family_certificate(&certificate).unwrap();
    let verifier =
        std::env::var("CARGO_BIN_EXE_cubealqot-family-verify").expect("fresh verifier binary path");
    let mut child = Command::new(&verifier)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("fresh verifier process");
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("VERIFIED"));

    let mut mutated = certificate;
    mutated.schema_version += 1;
    let bytes = serialize_family_certificate(&mutated).unwrap();
    let mut child = Command::new(verifier)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("fresh verifier process for mutation");
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("REJECTED"));
}

#[test]
fn trusted_content_is_not_offline_admitted_and_replay_checks_full_points() {
    let (problem, input, completion) = n3_completion();
    let evidence = SageTranscriptEvidence {
        job_id: "test-job".to_owned(),
        request_sha256: "0".repeat(64),
        response_sha256: "1".repeat(64),
        stderr_sha256: "2".repeat(64),
        exit_code: Some(0),
        timed_out: false,
    };
    let certificate = build_trusted_family_certificate(&input, &problem, &completion, evidence)
        .expect("trusted fixture certificate");
    assert!(matches!(
        verify_family_certificate(&certificate),
        CertificateVerification::Inconclusive { .. }
    ));

    let adapter = SageAdapter::new(fake_adapter_config("adapter_complete.ps1"));
    assert!(matches!(
        admit_trusted_backend_certificate(&certificate, &adapter),
        CertificateVerification::Verified(_)
    ));

    let mut deleted_point = certificate.clone();
    if let UntrustedCompletenessProof::TrustedIntegralPoints { backend } = &mut deleted_point.proof
    {
        backend.response.points.pop();
        backend.point_list_sha256 = canonical_point_list_sha256(&backend.response.points).unwrap();
    } else {
        panic!("expected trusted proof");
    }
    assert!(matches!(
        admit_trusted_backend_certificate(&deleted_point, &adapter),
        CertificateVerification::Rejected { .. }
    ));
}

#[test]
fn trusted_replay_reuses_embedded_discovery_points_not_an_external_file() {
    let (problem, input) = n3_input_problem();
    let point_file = serde_json::from_str::<serde_json::Value>(include_str!(
        "fixtures/m7/mw_points_valid_request.json"
    ))
    .unwrap();
    let points = point_file["discovery_points"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| serde_json::from_value(value.clone()).unwrap())
        .collect::<Vec<_>>();
    let policy = fake_adapter_config("adapter_complete.ps1").policy;
    let request = SageRequest {
        schema_version: 1,
        request_id: "job-1".to_owned(),
        problem: SageRequest::for_problem("unused".to_owned(), &problem, &policy).problem,
        policy: SageRequest::for_problem("unused".to_owned(), &problem, &policy).policy,
        discovery_points: Some(points),
    };
    let response: SageResponse =
        serde_json::from_str(include_str!("fixtures/m7/adapter_complete_response.json")).unwrap();
    let completion = validate_sage_response(&problem, &request, response, &policy).unwrap();
    let certificate = build_trusted_family_certificate(
        &input,
        &problem,
        &completion,
        SageTranscriptEvidence {
            job_id: "initial".to_owned(),
            request_sha256: "0".repeat(64),
            response_sha256: "1".repeat(64),
            stderr_sha256: "2".repeat(64),
            exit_code: Some(0),
            timed_out: false,
        },
    )
    .unwrap();
    let adapter = SageAdapter::new(fake_adapter_config("adapter_complete.ps1"));
    let replay =
        cubealqot::family::admit_trusted_backend_certificate_with_evidence(&certificate, &adapter);
    let replay = match replay {
        cubealqot::family::TrustedBackendAdmissionVerification::Verified(value) => value,
        other => panic!("expected hinted replay to verify: {other:?}"),
    };
    let request: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&replay.replay_evidence().request_path).unwrap())
            .unwrap();
    assert_eq!(request["discovery_points"].as_array().unwrap().len(), 4);
}

#[test]
#[ignore = "requires the pinned production WSL Sage environment"]
fn real_sage_certificate_replay_is_required_for_admission() {
    let (problem, input) = n3_input_problem();
    let evidence_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("out/m7-sage/adapter-runs/m7-13-admission");
    let config = SageAdapterConfig::m7_default(evidence_dir).expect("M7 Sage configuration");
    let adapter = SageAdapter::new(config);
    let (completion, evidence) = match adapter.enumerate(&problem) {
        cubealqot::family::SageAdapterResult::Complete {
            completion,
            evidence,
        } => (completion, evidence),
        other => panic!("real N=3 adapter run was not complete: {other:?}"),
    };
    let certificate = build_trusted_family_certificate(
        &input,
        &problem,
        &completion,
        SageTranscriptEvidence::from(&evidence),
    )
    .expect("trusted certificate from the production adapter");
    assert!(matches!(
        verify_family_certificate(&certificate),
        CertificateVerification::Inconclusive { .. }
    ));
    assert!(matches!(
        admit_trusted_backend_certificate(&certificate, &adapter),
        CertificateVerification::Verified(_)
    ));
}

fn n3_completion() -> (
    problem::Problem,
    problem::UntrustedProblem,
    SageValidatedCompletion,
) {
    let (problem, input) = n3_input_problem();
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
    let completion = validate_sage_response(&problem, &request, response, &policy).unwrap();
    (problem, input, completion)
}

fn n3_input_problem() -> (problem::Problem, problem::UntrustedProblem) {
    let input = problem::UntrustedProblem {
        n: integer("3"),
        factors: vec![factor("3", 1)],
    };
    let problem = match problem::validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected N=3 problem, got {other:?}"),
    };
    (problem, input)
}

fn fake_adapter_config(script: &str) -> SageAdapterConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    SageAdapterConfig {
        launcher: root.join("tests/fixtures/m7").join(script),
        helper: root.join("scripts/m7/sage_smoke.py"),
        powershell_executable: "powershell.exe".to_owned(),
        distribution: "Ubuntu-26.04".to_owned(),
        conda_executable: "conda".to_owned(),
        environment: "cubealqot-m7".to_owned(),
        timeout: Duration::from_secs(10),
        evidence_dir: std::env::temp_dir()
            .join(format!("cubealqot-m7-admit-{}", std::process::id())),
        policy: SageBackendPolicy {
            distribution: "Ubuntu-26.04".to_owned(),
            environment: "cubealqot-m7".to_owned(),
            conda_executable: "conda".to_owned(),
            sage_version: "10.8".to_owned(),
            python_version: "3.14.7".to_owned(),
            script_sha256: "script-hash".to_owned(),
        },
        extra_launcher_args: Vec::new(),
    }
}
