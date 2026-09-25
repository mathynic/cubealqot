//! M7-04 schema and state-boundary tests.
//!
//! These tests deliberately exercise the family subsystem independently of
//! the native search pipeline.  They are the executable form of the
//! uncertainty and serialization boundaries required before any backend is
//! connected.

use std::fs;

use cubealqot::family::{
    certificate::{AdmissionError, UntrustedCertificate, admit},
    integer_io::CanonicalInt,
    oracle::{
        FamilyProblem, FamilyStatus, IntegralPointsOracle, OracleError, OracleResult,
        status_from_oracle,
    },
};

struct MissingBackend;

impl IntegralPointsOracle for MissingBackend {
    fn integral_points(&self, _problem: &FamilyProblem) -> Result<OracleResult, OracleError> {
        Err(OracleError::BackendUnavailable {
            backend: "test-missing-backend".to_owned(),
            reason: "not installed".to_owned(),
        })
    }
}

#[test]
fn missing_backend_cannot_produce_certified_status() {
    let problem = FamilyProblem::from_decimal("3").expect("test problem is valid");
    let result = MissingBackend.integral_points(&problem);

    assert_eq!(status_from_oracle(result), FamilyStatus::Inconclusive);
}

#[test]
fn serialized_complete_claim_is_untrusted_without_verified_theorem() {
    let certificate: UntrustedCertificate = serde_json::from_str(
        r#"{
            "schema_version": 1,
            "n": "340282366920938463463374607431768211456",
            "backend": "missing-backend",
            "complete": true,
            "points": [{"x": "129", "y": "-383"}],
            "proof": null
        }"#,
    )
    .expect("well-formed JSON remains deserializable as untrusted data");

    assert!(certificate.complete);
    assert!(matches!(
        admit(certificate),
        Err(AdmissionError::CompletenessUnverified)
    ));
}

#[test]
fn canonical_decimal_round_trips_large_n_and_negative_y() {
    let input = r#"{
        "schema_version": 1,
        "n": "340282366920938463463374607431768211456",
        "backend": "fixture",
        "complete": false,
        "points": [{"x": "129", "y": "-383"}],
        "proof": null
    }"#;

    let certificate: UntrustedCertificate = serde_json::from_str(input).unwrap();
    assert_eq!(
        certificate.n,
        CanonicalInt::from_decimal("340282366920938463463374607431768211456").unwrap()
    );
    assert_eq!(certificate.points[0].y.to_string(), "-383");

    let encoded = serde_json::to_string(&certificate).unwrap();
    assert!(encoded.contains("\"n\":\"340282366920938463463374607431768211456\""));
    assert!(encoded.contains("\"y\":\"-383\""));
    let reparsed: UntrustedCertificate = serde_json::from_str(&encoded).unwrap();
    assert_eq!(reparsed, certificate);
}

#[test]
fn old_cargo_run_default_remains_the_search_binary() {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("Cargo manifest is present");
    assert!(manifest.contains("default-run = \"cubealqot\""));
}
