//! M7-10 tests for complete bounded local certificates.

use std::process::Command;

use cubealqot::family::local_certificate::{
    LocalCertificateStatus, LocalSearchResult, UntrustedLocalCertificate, UntrustedUnitResidue,
    search_local_certificate, verify_local_certificate,
};
use cubealqot::family::{
    CanonicalInt, SquareResidueTable, pocklington::UntrustedPrimeCertificate, problem,
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

fn input(n: &str, factors: Vec<problem::UntrustedCofactorFactor>) -> problem::UntrustedProblem {
    problem::UntrustedProblem {
        n: integer(n),
        factors,
    }
}

fn problem(n: &str, factors: Vec<problem::UntrustedCofactorFactor>) -> problem::Problem {
    match problem::validate_problem(&input(n, factors)) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified problem, got {other:?}"),
    }
}

fn real_n14_certificate() -> UntrustedLocalCertificate {
    let request = input("14", vec![factor("2", 1), factor("7", 1)]);
    let validated = problem("14", request.factors.clone());
    match search_local_certificate(
        &request,
        &validated,
        &[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    ) {
        LocalSearchResult::Found(certificate) => certificate,
        other => panic!("expected the frozen N=14 local certificate, got {other:?}"),
    }
}

#[test]
fn real_n14_local_certificate_is_produced_and_verified() {
    let certificate = real_n14_certificate();
    assert_eq!(certificate.modulus, 16);
    assert_eq!(certificate.exceptional_primes, vec![integer("2")]);
    assert!(certificate.solutions.is_empty());
    match verify_local_certificate(&certificate) {
        LocalCertificateStatus::Verified(verified) => {
            assert_eq!(verified.n(), &integer("14"));
            assert_eq!(verified.modulus(), 16);
            assert!(verified.solutions().is_empty());
        }
        other => panic!("frozen local certificate was not verified: {other:?}"),
    }
}

#[test]
fn unresolved_real_families_remain_inconclusive_when_budget_finds_no_modulus() {
    let request = input("3", vec![factor("3", 1)]);
    let validated = problem("3", request.factors.clone());
    match search_local_certificate(&request, &validated, &[2, 3, 4, 8, 16]) {
        LocalSearchResult::Inconclusive { reason } => {
            assert!(reason.contains("no complete local modulus"));
        }
        other => panic!("bounded search incorrectly produced a theorem: {other:?}"),
    }
}

#[test]
fn certificate_mutations_fail_fresh_verification() {
    let certificate = real_n14_certificate();

    let mut changed_modulus = certificate.clone();
    changed_modulus.modulus = 32;
    assert!(matches!(
        verify_local_certificate(&changed_modulus),
        LocalCertificateStatus::Rejected { .. }
    ));

    let mut omitted_unit = certificate.clone();
    omitted_unit.unit_residues.pop();
    assert!(matches!(
        verify_local_certificate(&omitted_unit),
        LocalCertificateStatus::Rejected { .. }
    ));

    let mut false_square_table = certificate.clone();
    false_square_table.unit_residues[0].rhs_residue ^= 1;
    assert!(matches!(
        verify_local_certificate(&false_square_table),
        LocalCertificateStatus::Rejected { .. }
    ));

    let mut omitted_factor = certificate.clone();
    omitted_factor.modulus_factors.clear();
    assert!(matches!(
        verify_local_certificate(&omitted_factor),
        LocalCertificateStatus::Rejected { .. }
    ));

    let mut omitted_exceptional = certificate.clone();
    omitted_exceptional.exceptional_primes.clear();
    assert!(matches!(
        verify_local_certificate(&omitted_exceptional),
        LocalCertificateStatus::Rejected { .. }
    ));

    let mut changed_result = certificate;
    changed_result.solutions.push(integer("2"));
    assert!(matches!(
        verify_local_certificate(&changed_result),
        LocalCertificateStatus::Rejected { .. }
    ));
}

#[test]
fn incomplete_or_invalid_proof_state_never_becomes_certified_empty() {
    let mut certificate = real_n14_certificate();
    certificate.proof_version += 1;
    assert!(matches!(
        verify_local_certificate(&certificate),
        LocalCertificateStatus::Rejected { .. }
    ));

    let mut missing_factor_proof = real_n14_certificate();
    missing_factor_proof.factors[0].certificate = None;
    assert!(matches!(
        verify_local_certificate(&missing_factor_proof),
        LocalCertificateStatus::Inconclusive { .. }
    ));
}

#[test]
fn local_result_matches_independent_python_bounded_oracle() {
    let script = format!(
        "{}/scripts/m7/oracle_family.py",
        env!("CARGO_MANIFEST_DIR").replace('\\', "/")
    );
    let output = Command::new("python")
        .args([&script, "--n", "14", "--q-max", "500"])
        .output()
        .expect("Python oracle must be installed");
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).expect("oracle JSON");
    assert_eq!(json["candidates"], Value::Array(Vec::new()));
    let table = SquareResidueTable::new(16).unwrap();
    for record in json["records"].as_array().expect("oracle records") {
        let q = record["q"].as_str().unwrap().parse::<u64>().unwrap();
        assert_eq!(record["is_square"], false, "q={q}");
        assert!(q % 16 != 0);
        let rhs_mod = problem("14", vec![factor("2", 1), factor("7", 1)])
            .rhs_mod(&integer(&q.to_string()), 16)
            .unwrap();
        assert!(
            !table.contains(rhs_mod),
            "local proof did not exclude q={q}"
        );
    }
    let verified = match verify_local_certificate(&real_n14_certificate()) {
        LocalCertificateStatus::Verified(verified) => verified,
        other => panic!("expected verified N=14 certificate, got {other:?}"),
    };
    assert!(verified.solutions().is_empty());
}

#[test]
fn frozen_n14_artifact_round_trips_and_verifies() {
    let path = format!(
        "{}/out/m7/m7-10-N14-M16.json",
        env!("CARGO_MANIFEST_DIR").replace('\\', "/")
    );
    let bytes = std::fs::read(path).expect("frozen local certificate artifact");
    let certificate: UntrustedLocalCertificate =
        serde_json::from_slice(&bytes).expect("certificate JSON schema");
    assert!(matches!(
        verify_local_certificate(&certificate),
        LocalCertificateStatus::Verified(_)
    ));
}

#[test]
fn unit_residue_claim_type_remains_structured() {
    let claim = UntrustedUnitResidue {
        residue: 1,
        rhs_residue: 3,
    };
    assert_eq!(claim.residue, 1);
    assert_eq!(claim.rhs_residue, 3);
}
