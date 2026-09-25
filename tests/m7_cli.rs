//! M7-14 end-to-end CLI contract tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cubealqot::family::CanonicalInt;
use cubealqot::family::admission::{
    SageTranscriptEvidence, build_trusted_family_certificate, serialize_family_certificate,
};
use cubealqot::family::pocklington::UntrustedPrimeCertificate;
use cubealqot::family::problem::{self, validate_problem};
use cubealqot::family::sage::{
    SageBackendPolicy, SageRequest, SageResponse, validate_sage_response,
};
use serde_json::Value;

fn binary() -> String {
    std::env::var("CARGO_BIN_EXE_cubealqot-family").expect("family CLI binary")
}

fn temp_path(label: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "cubealqot-m7-14-{label}-{}.{extension}",
        std::process::id()
    ))
}

fn write_factors(label: &str, factors: &[(&str, u32)]) -> PathBuf {
    let path = temp_path(label, "json");
    let value = factors
        .iter()
        .map(|(prime, exponent)| {
            serde_json::json!({
                "prime": prime,
                "exponent": exponent,
                "certificate": {"kind": "u64", "n": prime}
            })
        })
        .collect::<Vec<_>>();
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path
}

fn run(args: &[&str]) -> (i32, Value, String) {
    let output = Command::new(binary()).args(args).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!("CLI did not emit one JSON object: {error}; stdout={stdout:?}")
    });
    (
        output.status.code().unwrap_or(128),
        value,
        String::from_utf8_lossy(&output.stderr).into(),
    )
}

#[test]
fn help_freezes_commands_and_completeness_language() {
    let output = Command::new(binary()).arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for command in ["doctor", "bounded", "prove", "verify", "export-map"] {
        assert!(help.contains(command), "missing command {command}");
    }
    assert!(help.contains("self-contained"));
    assert!(help.contains("backend-trusted"));
    let prove_help = Command::new(binary())
        .args(["prove", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&prove_help.stdout).contains("mw-points"));
}

#[test]
fn explicit_missing_mw_points_file_is_invalid_input() {
    let factors = write_factors("missing-mw-points", &[("2", 1), ("7", 1)]);
    let factors = factors.to_string_lossy().to_string();
    let output = temp_path("missing-mw-points-proof", "json");
    let missing = temp_path("missing-mw-points-source", "json");
    let output = output.to_string_lossy().to_string();
    let missing = missing.to_string_lossy().to_string();
    let (code, result, _) = run(&[
        "prove",
        "--n",
        "14",
        "--factors",
        &factors,
        "--backend",
        "none",
        "--mw-points",
        &missing,
        "--output",
        &output,
    ]);
    assert_eq!(code, 3);
    assert_eq!(result["status"], "INVALID_INPUT");
    assert!(
        result["reason"]
            .as_str()
            .unwrap()
            .contains("point file I/O error")
    );
}

#[test]
fn bounded_completion_is_success_but_not_a_theorem() {
    let factors = write_factors("bounded", &[("3", 1)]);
    let factors = factors.to_string_lossy().to_string();
    let (code, result, _) = run(&[
        "bounded",
        "--n",
        "3",
        "--factors",
        &factors,
        "--q-max",
        "20",
    ]);
    assert_eq!(code, 0);
    assert_eq!(result["status"], "BOUNDED");
    assert_eq!(result["completeness"], "bounded-only");
    assert_eq!(result["global_completeness"], false);
}

#[test]
fn local_prove_verify_and_immutable_output_are_end_to_end() {
    let factors = write_factors("local", &[("2", 1), ("7", 1)]);
    let factors = factors.to_string_lossy().to_string();
    let artifact = temp_path("local-proof", "json");
    let artifact_text = artifact.to_string_lossy().to_string();
    let (code, result, _) = run(&[
        "prove",
        "--n",
        "14",
        "--factors",
        &factors,
        "--backend",
        "none",
        "--output",
        &artifact_text,
    ]);
    assert_eq!(code, 0);
    assert_eq!(result["status"], "CERTIFIED_EMPTY");
    assert_eq!(result["completeness"], "self-contained");
    assert!(result["admission_id"].as_str().is_some());
    assert!(result["store_root"].as_str().is_some());
    let original = fs::read(&artifact).unwrap();

    let (code, result, _) = run(&["verify", &artifact_text]);
    assert_eq!(code, 0);
    assert_eq!(result["status"], "CERTIFIED_EMPTY");
    assert_eq!(result["completeness"], "self-contained");

    let (code, result, _) = run(&[
        "prove",
        "--n",
        "14",
        "--factors",
        &factors,
        "--backend",
        "none",
        "--output",
        &artifact_text,
    ]);
    assert_eq!(code, 3);
    assert_eq!(result["status"], "INVALID_INPUT");
    assert_eq!(fs::read(&artifact).unwrap(), original);
}

#[test]
fn missing_backend_and_timeout_are_inconclusive_without_partial_artifacts() {
    let factors = write_factors("missing", &[("3", 1)]);
    let factors = factors.to_string_lossy().to_string();
    let artifact = temp_path("missing-proof", "json");
    let artifact_text = artifact.to_string_lossy().to_string();
    // Do not consult the repository's default proof store: its historical
    // N=3 admission is intentionally allowed to make this test stateful only
    // when explicitly requested.  This test exercises the no-backend path.
    let store = temp_path("missing-proof-store", "dir");
    let store_text = store.to_string_lossy().to_string();
    let (code, result, _) = run(&[
        "prove",
        "--n",
        "3",
        "--factors",
        &factors,
        "--backend",
        "none",
        "--output",
        &artifact_text,
        "--store",
        &store_text,
    ]);
    assert_eq!(code, 2);
    assert_eq!(result["status"], "INCONCLUSIVE");
    assert!(!artifact.exists());

    let (code, result, _) = run(&[
        "prove",
        "--n",
        "3",
        "--factors",
        &factors,
        "--backend",
        "sage",
        "--timeout-seconds",
        "0",
        "--output",
        &artifact_text,
        "--store",
        &store_text,
    ]);
    assert_eq!(code, 2);
    assert_eq!(result["status"], "INCONCLUSIVE");
    assert!(!artifact.exists());
}

#[test]
fn malformed_input_is_invalid_and_never_inconclusive() {
    let factors = temp_path("malformed", "json");
    fs::write(&factors, b"not-json").unwrap();
    let factors = factors.to_string_lossy().to_string();
    let (code, result, _) = run(&["bounded", "--n", "3", "--factors", &factors, "--q-max", "5"]);
    assert_eq!(code, 3);
    assert_eq!(result["status"], "INVALID_INPUT");
}

#[test]
fn doctor_and_export_map_have_explicit_self_contained_contracts() {
    let (code, result, _) = run(&["doctor", "--backend", "none"]);
    assert_eq!(code, 0);
    assert_eq!(result["status"], "READY");
    assert_eq!(result["completeness"], "none");
    assert_eq!(result["backend"], "UNSELECTED");

    let factors = write_factors("map", &[("2", 1), ("7", 1)]);
    let factors = factors.to_string_lossy().to_string();
    let artifact = temp_path("map-proof", "json");
    let artifact_text = artifact.to_string_lossy().to_string();
    let (code, _, _) = run(&[
        "prove",
        "--n",
        "14",
        "--factors",
        &factors,
        "--backend",
        "none",
        "--output",
        &artifact_text,
    ]);
    assert_eq!(code, 0);
    let directory = temp_path("map-directory", "dir");
    fs::create_dir_all(&directory).unwrap();
    fs::copy(&artifact, directory.join("n14.json")).unwrap();
    let snapshot = temp_path("map-snapshot", "json");
    let directory_text = directory.to_string_lossy().to_string();
    let snapshot_text = snapshot.to_string_lossy().to_string();
    let (code, result, _) = run(&[
        "export-map",
        "--certificates",
        &directory_text,
        "--output",
        &snapshot_text,
    ]);
    assert_eq!(code, 0);
    assert_eq!(result["status"], "EXPORTED");
    assert_eq!(result["completeness"], "self-contained");
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(snapshot).unwrap()).unwrap()["entries"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn external_trusted_certificate_is_inconclusive_without_backend() {
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
    let completion = validate_sage_response(&problem, &request, response, &policy).unwrap();
    let certificate = build_trusted_family_certificate(
        &input,
        &problem,
        &completion,
        SageTranscriptEvidence {
            job_id: "cli-job".to_owned(),
            request_sha256: "0".repeat(64),
            response_sha256: "1".repeat(64),
            stderr_sha256: "2".repeat(64),
            exit_code: Some(0),
            timed_out: false,
        },
    )
    .unwrap();
    let certificate_path = temp_path("external-trusted", "json");
    fs::write(
        &certificate_path,
        serialize_family_certificate(&certificate).unwrap(),
    )
    .unwrap();
    let path = certificate_path.to_string_lossy().to_string();
    let (code, result, _) = run(&["verify", &path]);
    assert_eq!(code, 2);
    assert_eq!(result["status"], "INCONCLUSIVE");
    assert_eq!(result["completeness"], "backend-trusted");
}

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).unwrap()
}

#[allow(dead_code)]
fn assert_exists(path: &Path) {
    assert!(path.exists(), "expected {}", path.display());
}
