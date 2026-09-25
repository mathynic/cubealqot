//! M7-08 tests for independent bounded family discovery.

use std::process::Command;

use cubealqot::family::bounded::{self, BoundedDiscoveryResult, PrimeProofOracle};
use cubealqot::family::{
    CanonicalInt, PrimeStatus, pocklington::UntrustedPrimeCertificate, problem,
};
use serde_json::Value;

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

fn family(n: &str, factors: Vec<problem::UntrustedCofactorFactor>) -> problem::Problem {
    match problem::validate_problem(&problem::UntrustedProblem {
        n: integer(n),
        factors,
    }) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified problem, got {other:?}"),
    }
}

fn candidate_strings(result: &BoundedDiscoveryResult) -> Vec<String> {
    match result {
        BoundedDiscoveryResult::Bounded(discovery) => discovery
            .candidates()
            .iter()
            .map(ToString::to_string)
            .collect(),
        BoundedDiscoveryResult::Inconclusive { partial, .. } => partial
            .candidates()
            .iter()
            .map(ToString::to_string)
            .collect(),
    }
}

fn python_candidates(n: &str, bound: u64) -> (Vec<String>, Value) {
    let script = format!(
        "{}/scripts/m7/oracle_family.py",
        env!("CARGO_MANIFEST_DIR").replace('\\', "/")
    );
    let output = Command::new("python")
        .args([&script, "--n", n, "--q-max", &bound.to_string()])
        .output()
        .expect("M7-08 Python oracle must be installed");
    assert!(
        output.status.success(),
        "Python oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("oracle JSON");
    let candidates = value["candidates"]
        .as_array()
        .expect("oracle candidates array")
        .iter()
        .map(|value| value.as_str().expect("canonical q string").to_owned())
        .collect();
    (candidates, value)
}

#[test]
fn rust_and_python_candidate_sets_match_for_frozen_n_and_bounds() {
    for (n, factors) in [
        ("3", vec![factor("3", 1)]),
        ("9", vec![factor("3", 2)]),
        ("33", vec![factor("3", 1), factor("11", 1)]),
    ] {
        let problem = family(n, factors);
        for bound in [2, 3, 50, 200] {
            let rust = bounded::discover_bounded(&problem, bound);
            let (python, metadata) = python_candidates(n, bound);
            assert_eq!(candidate_strings(&rust), python, "N={n}, B={bound}");
            assert_eq!(metadata["bounded"], true);
            assert_eq!(metadata["q_max"], bound.to_string());
            assert_eq!(metadata["global_completeness"], false);
        }
    }
}

#[test]
fn bounds_are_inclusive_cover_q_less_than_n_and_exclude_q_dividing_n() {
    let problem = family("9", vec![factor("3", 2)]);
    let result = bounded::discover_bounded(&problem, 3);
    let discovery = match result {
        BoundedDiscoveryResult::Bounded(discovery) => discovery,
        other => panic!("expected bounded result, got {other:?}"),
    };
    assert_eq!(discovery.q_max(), 3);
    assert_eq!(discovery.tested_prime_count(), 2); // q=2 and q=3
    assert_eq!(discovery.excluded_dividing_n_count(), 1); // q=3
    assert!(discovery.q_was_tested(2)); // q<N is in the domain
    assert!(!discovery.candidates().iter().any(|q| q == &integer("3")));
}

#[test]
fn empty_bounded_runs_are_not_global_completeness_claims() {
    let problem = family("3", vec![factor("3", 1)]);
    for bound in [0, 1, 2] {
        let result = bounded::discover_bounded(&problem, bound);
        let discovery = match result {
            BoundedDiscoveryResult::Bounded(discovery) => discovery,
            other => panic!("expected bounded result, got {other:?}"),
        };
        assert!(discovery.candidates().is_empty());
        assert_eq!(discovery.q_max(), bound);
        assert!(!discovery.claims_global_completeness());
    }
}

struct MissingProofAt(u64);

impl PrimeProofOracle for MissingProofAt {
    fn classify(&self, value: u64) -> PrimeStatus {
        if value == self.0 {
            PrimeStatus::Inconclusive("test-only missing prime proof".to_owned())
        } else {
            cubealqot::family::classify_u64(value)
        }
    }
}

#[test]
fn missing_prime_proof_is_inconclusive_not_rejection_or_empty() {
    let problem = family("3", vec![factor("3", 1)]);
    let result = bounded::discover_bounded_with(&problem, 7, &MissingProofAt(5));
    match result {
        BoundedDiscoveryResult::Inconclusive { partial, reason } => {
            assert_eq!(partial.q_max(), 7);
            assert!(reason.contains("q=5"));
            assert!(!partial.claims_global_completeness());
        }
        other => panic!("missing prime proof was not surfaced: {other:?}"),
    }
}

#[test]
fn frozen_signed_cancellation_and_boundary_rhs_vectors_remain_exact() {
    for (n, factors, expected) in [
        (
            "3",
            vec![factor("3", 1)],
            [("-2", "16"), ("-1", "27"), ("0", "40"), ("1", "133")],
        ),
        (
            "9",
            vec![factor("3", 2)],
            [("-2", "367"), ("-1", "729"), ("0", "1093"), ("1", "3643")],
        ),
        (
            "33",
            vec![factor("3", 1), factor("11", 1)],
            [
                ("-2", "-5304"),
                ("-1", "35937"),
                ("0", "58560"),
                ("1", "198303"),
            ],
        ),
    ] {
        let problem = family(n, factors);
        for (q, rhs) in expected {
            assert_eq!(problem.rhs(&integer(q)), integer(rhs), "N={n}, q={q}");
        }
    }
}
