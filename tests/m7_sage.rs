//! M7-12 tests for the structured Sage subprocess boundary.

use std::path::PathBuf;
use std::time::Duration;

use cubealqot::family::CanonicalInt;
use cubealqot::family::problem::{Problem, ProblemBuildResult};
use cubealqot::family::sage::{
    SageBackendPolicy, SageGenerator, SageRational, SageRequest, SageResponseBackend,
    SageResponseModel, SageResponseProof, SageValidationError, UntrustedSageResponse,
    parse_sage_response, validate_sage_response,
};
use cubealqot::family::{pocklington::UntrustedPrimeCertificate, problem};
use serde_json::json;

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).expect("fixture integer is canonical")
}

fn n3() -> Problem {
    let input = problem::UntrustedProblem {
        n: integer("3"),
        factors: vec![problem::UntrustedCofactorFactor {
            prime: integer("3"),
            exponent: 1,
            certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("3") }),
        }],
    };
    match problem::validate_problem(&input) {
        ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified N=3 problem, got {other:?}"),
    }
}

fn policy() -> SageBackendPolicy {
    SageBackendPolicy {
        distribution: "Ubuntu-26.04".to_owned(),
        environment: "cubealqot-m7".to_owned(),
        conda_executable: "conda".to_owned(),
        sage_version: "10.8".to_owned(),
        python_version: "3.14.7".to_owned(),
        script_sha256: "script-hash".to_owned(),
    }
}

fn request(problem: &Problem) -> SageRequest {
    SageRequest::for_problem("job-1".to_owned(), problem, &policy())
}

fn valid_response(request: &SageRequest) -> UntrustedSageResponse {
    UntrustedSageResponse {
        schema_version: 1,
        request_id: request.request_id.clone(),
        ok: true,
        complete: true,
        problem: request.problem.clone(),
        proof: SageResponseProof {
            proof_all: true,
            rank_proven: true,
            rank: integer("2"),
            generators: vec![
                SageGenerator {
                    x: SageRational::new("-26"),
                    y: SageRational::new("52"),
                },
                SageGenerator {
                    x: SageRational::new("-934/49"),
                    y: SageRational::new("22896/343"),
                },
            ],
            gens_certain: true,
            both_signs: true,
            integral_points_complete: true,
            torsion_order: integer("1"),
        },
        model: SageResponseModel {
            semantics: "original_integral_model".to_owned(),
            curve_coefficients: request.problem.curve_coefficients.clone(),
        },
        points: vec![
            cubealqot::family::UntrustedIntegralPoint {
                x: integer("-26"),
                y: integer("52"),
            },
            cubealqot::family::UntrustedIntegralPoint {
                x: integer("-26"),
                y: integer("-52"),
            },
        ],
        backend: SageResponseBackend {
            name: "SageMath".to_owned(),
            sage_version: "10.8".to_owned(),
            python_version: "3.14.7".to_owned(),
            environment: "cubealqot-m7".to_owned(),
            distribution: "Ubuntu-26.04".to_owned(),
            script_sha256: "script-hash".to_owned(),
        },
    }
}

#[test]
fn complete_response_requires_exact_problem_and_proof_contract() {
    let problem = n3();
    let request = request(&problem);
    let response = valid_response(&request);
    let completion = validate_sage_response(&problem, &request, response, &policy())
        .expect("qualified response should validate");
    assert_eq!(completion.points().len(), 2);
    assert!(completion.proof().gens_certain);

    let mut wrong_coefficients = valid_response(&request);
    wrong_coefficients.problem.a = integer("41");
    assert!(matches!(
        validate_sage_response(&problem, &request, wrong_coefficients, &policy()),
        Err(SageValidationError::ProblemIdentityMismatch { .. })
    ));

    let mut wrong_model = valid_response(&request);
    wrong_model.model.semantics = "minimal_model".to_owned();
    assert!(matches!(
        validate_sage_response(&problem, &request, wrong_model, &policy()),
        Err(SageValidationError::UnsupportedModelSemantics { .. })
    ));
}

#[test]
fn uncertain_generators_partial_output_and_stale_request_are_inconclusive() {
    let problem = n3();
    let request = request(&problem);

    let mut uncertain = valid_response(&request);
    uncertain.proof.gens_certain = false;
    assert!(validate_sage_response(&problem, &request, uncertain, &policy()).is_err());

    let mut partial = valid_response(&request);
    partial.complete = false;
    assert!(validate_sage_response(&problem, &request, partial, &policy()).is_err());

    let mut stale = valid_response(&request);
    stale.request_id = "expired-job".to_owned();
    assert!(matches!(
        validate_sage_response(&problem, &request, stale, &policy()),
        Err(SageValidationError::RequestIdentityMismatch { .. })
    ));
}

#[test]
fn embedded_discovery_points_are_revalidated_against_the_exact_problem() {
    let problem = n3();
    let ordinary = request(&problem);
    let mut value = serde_json::to_value(&ordinary).expect("request JSON");
    value["discovery_points"] = json!([{"x": "-26", "y": "52"}]);
    let hinted: SageRequest = serde_json::from_value(value).expect("canonical hint point");
    validate_sage_response(&problem, &hinted, valid_response(&hinted), &policy())
        .expect("on-curve embedded point should validate");

    let mut invalid_value = serde_json::to_value(&hinted).expect("hinted request JSON");
    invalid_value["discovery_points"][0]["y"] = json!("51");
    let invalid: SageRequest =
        serde_json::from_value(invalid_value).expect("off-curve point has valid syntax");
    assert!(matches!(
        validate_sage_response(&problem, &invalid, valid_response(&invalid), &policy()),
        Err(SageValidationError::DiscoveryPointMismatch { index: 0, .. })
    ));
}

#[test]
fn malformed_integers_and_missing_backend_version_never_parse_as_complete() {
    let problem = n3();
    let request = request(&problem);
    let response = valid_response(&request);
    let mut value = serde_json::to_value(&response).expect("response JSON");
    value["points"][0]["x"] = serde_json::Value::String("1/2".to_owned());
    assert!(parse_sage_response(value.to_string().as_bytes()).is_err());

    let mut missing_version = serde_json::to_value(valid_response(&request)).unwrap();
    missing_version["backend"]
        .as_object_mut()
        .unwrap()
        .remove("sage_version");
    assert!(parse_sage_response(missing_version.to_string().as_bytes()).is_err());
}

#[test]
fn adapter_policy_keeps_launcher_and_environment_explicit() {
    let config = cubealqot::family::sage::SageAdapterConfig {
        launcher: PathBuf::from("scripts/m7/invoke-sage.ps1"),
        helper: PathBuf::from("scripts/m7/sage_integral_points.py"),
        powershell_executable: "powershell.exe".to_owned(),
        distribution: "Ubuntu-26.04".to_owned(),
        conda_executable: "conda".to_owned(),
        environment: "cubealqot-m7".to_owned(),
        timeout: Duration::from_secs(60),
        evidence_dir: PathBuf::from("out/m7-sage/adapter-runs"),
        policy: policy(),
        extra_launcher_args: Vec::new(),
    };
    assert_eq!(config.distribution, policy().distribution);
    assert_eq!(config.environment, policy().environment);
    assert_eq!(config.policy.sage_version, "10.8");
}

#[test]
fn default_adapter_requires_the_qualified_helper_digest() {
    let config = cubealqot::family::sage::SageAdapterConfig::m7_default(PathBuf::from(
        "out/m7-sage/qualified-digest",
    ))
    .expect("production adapter must use the qualified helper");
    assert_eq!(
        config.policy.script_sha256,
        cubealqot::family::sage::QUALIFIED_SAGE_HELPER_SHA256
    );
}

#[test]
fn process_failures_and_deadlines_retain_evidence_and_stay_inconclusive() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let evidence = std::env::temp_dir().join(format!("cubealqot-m7-sage-{}", std::process::id()));
    let helper = root.join("scripts/m7/sage_smoke.py");

    let mut nonzero = process_config(
        root.join("tests/fixtures/m7/adapter_nonzero.ps1"),
        helper.clone(),
        evidence.join("nonzero"),
        Duration::from_secs(10),
    );
    let result = cubealqot::family::sage::SageAdapter::new(nonzero.clone()).enumerate(&n3());
    match result {
        cubealqot::family::sage::SageAdapterResult::Inconclusive {
            evidence, reason, ..
        } => {
            assert!(reason.contains("unsuccessfully"));
            assert_eq!(evidence.unwrap().exit_code, Some(7));
        }
        other => panic!("nonzero fake backend unexpectedly completed: {other:?}"),
    }

    nonzero.launcher = root.join("tests/fixtures/m7/adapter_timeout.ps1");
    nonzero.evidence_dir = evidence.join("timeout");
    nonzero.timeout = Duration::from_millis(100);
    let result = cubealqot::family::sage::SageAdapter::new(nonzero).enumerate(&n3());
    match result {
        cubealqot::family::sage::SageAdapterResult::Inconclusive {
            evidence, reason, ..
        } => {
            assert!(reason.contains("deadline"));
            assert!(evidence.unwrap().timed_out);
        }
        other => panic!("timed-out fake backend unexpectedly completed: {other:?}"),
    }

    let malformed = process_config(
        root.join("tests/fixtures/m7/adapter_malformed.ps1"),
        helper,
        evidence.join("malformed"),
        Duration::from_secs(10),
    );
    let result = cubealqot::family::sage::SageAdapter::new(malformed).enumerate(&n3());
    match result {
        cubealqot::family::sage::SageAdapterResult::Inconclusive { reason, .. } => {
            assert!(
                reason.contains("malformed") || reason.contains("unsuccessfully"),
                "unexpected malformed-process reason: {reason}"
            );
        }
        other => panic!("malformed fake backend unexpectedly completed: {other:?}"),
    }
}

fn process_config(
    launcher: PathBuf,
    helper: PathBuf,
    evidence_dir: PathBuf,
    timeout: Duration,
) -> cubealqot::family::sage::SageAdapterConfig {
    cubealqot::family::sage::SageAdapterConfig {
        launcher,
        helper,
        powershell_executable: "powershell.exe".to_owned(),
        distribution: "Ubuntu-26.04".to_owned(),
        conda_executable: "conda".to_owned(),
        environment: "cubealqot-m7".to_owned(),
        timeout,
        evidence_dir,
        policy: policy(),
        extra_launcher_args: Vec::new(),
    }
}

#[test]
#[ignore = "requires the pinned WSL Sage environment"]
fn real_target_families_are_reported_without_predetermined_empty_sets() {
    let config = cubealqot::family::sage::SageAdapterConfig::m7_default(PathBuf::from(
        "out/m7-sage/adapter-runs",
    ))
    .expect("M7 policy files should exist");
    let adapter = cubealqot::family::sage::SageAdapter::new(config);
    for problem in [n3(), family_n9(), family_n33()] {
        let result = adapter.enumerate(&problem);
        assert!(matches!(
            result,
            cubealqot::family::sage::SageAdapterResult::Complete { .. }
                | cubealqot::family::sage::SageAdapterResult::Inconclusive { .. }
        ));
    }
}

fn family_n9() -> Problem {
    family_from_factors("9", [("3", 2)])
}

fn family_n33() -> Problem {
    family_from_factors("33", [("3", 1), ("11", 1)])
}

fn family_from_factors<const N: usize>(n: &str, factors: [(&str, u32); N]) -> Problem {
    let input = problem::UntrustedProblem {
        n: integer(n),
        factors: factors
            .into_iter()
            .map(|(prime, exponent)| problem::UntrustedCofactorFactor {
                prime: integer(prime),
                exponent,
                certificate: Some(UntrustedPrimeCertificate::U64 { n: integer(prime) }),
            })
            .collect(),
    };
    match problem::validate_problem(&input) {
        ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified family problem, got {other:?}"),
    }
}
