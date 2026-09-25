//! MW-01 exact point-file parsing and immutable request transport.

use std::fs;

use cubealqot::family::mw_points::{
    MwPointFileError, MwPointFileLimits, parse_mw_point_file, parse_mw_point_file_with_limits,
};
use cubealqot::family::problem::{
    Problem, ProblemBuildResult, UntrustedCofactorFactor, UntrustedProblem,
};
use cubealqot::family::sage::{SageBackendPolicy, SageRequest};
use cubealqot::family::{CanonicalInt, pocklington::UntrustedPrimeCertificate};
use serde_json::json;

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).expect("fixture integer is canonical")
}

fn n3() -> Problem {
    let input = UntrustedProblem {
        n: integer("3"),
        factors: vec![UntrustedCofactorFactor {
            prime: integer("3"),
            exponent: 1,
            certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("3") }),
        }],
    };
    match cubealqot::family::problem::validate_problem(&input) {
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

fn point_file(problem: &Problem, points: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "kind": "m7_mw_point_candidates",
        "schema_version": 1,
        "n": problem.n(),
        "curve_coefficients": problem.curve().coefficients(),
        "points": points,
    }))
    .expect("point file JSON")
}

#[test]
fn accepts_exact_negative_fractional_duplicate_and_opposite_points() {
    let problem = n3();
    let bytes = point_file(
        &problem,
        json!([
            { "x": "-26", "y": "52" },
            { "x": "-26", "y": "-52" },
            { "x": "-934/49", "y": "22896/343" },
            { "x": "-26", "y": "52" }
        ]),
    );

    let parsed = parse_mw_point_file(&bytes, &problem).expect("valid exact points");
    assert_eq!(parsed.points().len(), 4);
    assert_eq!(parsed.points()[2].x().as_str(), "-934/49");
    assert_eq!(parsed.points()[2].y().as_str(), "22896/343");
}

#[test]
fn rejects_wrong_identity_off_curve_and_noncanonical_rationals() {
    let problem = n3();

    let mut wrong_n = serde_json::from_slice::<serde_json::Value>(&point_file(
        &problem,
        json!([{ "x": "-26", "y": "52" }]),
    ))
    .unwrap();
    wrong_n["n"] = json!("5");
    assert!(matches!(
        parse_mw_point_file(&serde_json::to_vec(&wrong_n).unwrap(), &problem),
        Err(MwPointFileError::ProblemIdentity { .. })
    ));

    let mut wrong_model = serde_json::from_slice::<serde_json::Value>(&point_file(
        &problem,
        json!([{ "x": "-26", "y": "52" }]),
    ))
    .unwrap();
    wrong_model["curve_coefficients"][1] = json!("41");
    assert!(matches!(
        parse_mw_point_file(&serde_json::to_vec(&wrong_model).unwrap(), &problem),
        Err(MwPointFileError::ProblemIdentity { .. })
    ));

    for point in [
        json!({ "x": "-26", "y": "51" }),
        json!({ "x": "01", "y": "52" }),
        json!({ "x": "-26/1", "y": "52" }),
        json!({ "x": "2/4", "y": "52" }),
        json!({ "x": "-26", "y": "52/0" }),
        json!({ "x": "-26", "y": "1.0" }),
        json!({ "x": "-26", "y": "1+2" }),
    ] {
        let result = parse_mw_point_file(&point_file(&problem, json!([point])), &problem);
        assert!(
            result.is_err(),
            "invalid point unexpectedly accepted: {point}"
        );
    }
}

#[test]
fn request_has_optional_frozen_points_and_old_request_bytes_have_no_new_field() {
    let problem = n3();
    let bytes = point_file(&problem, json!([{ "x": "-26", "y": "52" }]));
    let parsed = parse_mw_point_file(&bytes, &problem).expect("valid point file");

    let ordinary = SageRequest::for_problem("ordinary".to_owned(), &problem, &policy());
    let ordinary_bytes = serde_json::to_vec_pretty(&ordinary).expect("ordinary request JSON");
    assert!(
        !ordinary_bytes
            .windows(b"discovery_points".len())
            .any(|window| { window == b"discovery_points" })
    );
    let expected_legacy = concat!(
        "{\n",
        "  \"schema_version\": 1,\n",
        "  \"request_id\": \"ordinary\",\n",
        "  \"problem\": {\n",
        "    \"n\": \"3\",\n",
        "    \"factors\": [\n",
        "      {\n",
        "        \"prime\": \"3\",\n",
        "        \"exponent\": 1\n",
        "      }\n",
        "    ],\n",
        "    \"a\": \"40\",\n",
        "    \"d\": \"13\",\n",
        "    \"curve_coefficients\": [\n",
        "      \"0\",\n",
        "      \"40\",\n",
        "      \"0\",\n",
        "      \"520\",\n",
        "      \"6760\"\n",
        "    ]\n",
        "  },\n",
        "  \"policy\": {\n",
        "    \"distribution\": \"Ubuntu-26.04\",\n",
        "    \"environment\": \"cubealqot-m7\",\n",
        "    \"conda_executable\": \"conda\",\n",
        "    \"sage_version\": \"10.8\",\n",
        "    \"python_version\": \"3.14.7\",\n",
        "    \"script_sha256\": \"script-hash\",\n",
        "    \"proof_all\": true,\n",
        "    \"rank_proof\": true,\n",
        "    \"generators_proof\": true,\n",
        "    \"require_gens_certain\": true,\n",
        "    \"both_signs\": true,\n",
        "    \"model_semantics\": \"original_integral_model\"\n",
        "  }\n",
        "}"
    );
    assert_eq!(
        String::from_utf8(ordinary_bytes.clone()).expect("UTF-8 request JSON"),
        expected_legacy
    );
    let ordinary_round_trip: SageRequest =
        serde_json::from_slice(&ordinary_bytes).expect("old request remains readable");
    assert_eq!(ordinary, ordinary_round_trip);

    let hinted = SageRequest::for_problem_with_discovery_points(
        "hinted".to_owned(),
        &problem,
        &policy(),
        Some(parsed.points()),
    );
    let hinted_bytes = serde_json::to_vec_pretty(&hinted).expect("hinted request JSON");
    assert!(
        hinted_bytes
            .windows(b"discovery_points".len())
            .any(|window| { window == b"discovery_points" })
    );
    let hinted_round_trip: SageRequest =
        serde_json::from_slice(&hinted_bytes).expect("hinted request round trip");
    assert_eq!(hinted, hinted_round_trip);
}

#[test]
fn point_file_limit_is_explicit_and_does_not_turn_into_empty() {
    let problem = n3();
    let bytes = point_file(
        &problem,
        json!([{ "x": "-26", "y": "52" }, { "x": "-26", "y": "-52" }]),
    );
    assert!(matches!(
        parse_mw_point_file_with_limits(&bytes, &problem, MwPointFileLimits { max_points: 1 }),
        Err(MwPointFileError::ResourceLimit {
            actual: 2,
            maximum: 1
        })
    ));
}

#[test]
fn loading_freezes_points_before_source_file_changes() {
    let problem = n3();
    let path = std::env::temp_dir().join(format!(
        "cubealqot-mw-01-points-{}-{}.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let original = point_file(&problem, json!([{ "x": "-26", "y": "52" }]));
    fs::write(&path, &original).expect("write point file");
    let loaded = cubealqot::family::mw_points::load_mw_point_file(&path, &problem)
        .expect("load exact points");
    fs::write(&path, point_file(&problem, json!([]))).expect("mutate source file");

    let request = SageRequest::for_problem_with_discovery_points(
        "frozen".to_owned(),
        &problem,
        &policy(),
        Some(loaded.points()),
    );
    let request_json = serde_json::to_string(&request).expect("frozen request JSON");
    assert!(request_json.contains("\"x\":\"-26\""));
    assert!(request_json.contains("\"y\":\"52\""));
    fs::remove_file(path).expect("remove temporary point file");
}
