//! M7-15 immutable theorem-map and decomposition-kernel tests.

use cubealqot::family::admission::{
    CertificateVerification, build_local_family_certificate, verify_family_certificate,
};
use cubealqot::family::pocklington::UntrustedPrimeCertificate;
use cubealqot::family::problem::{self, UntrustedCofactorFactor};
use cubealqot::family::theorem_map::{
    DecompositionEligibility, LookupDecision, TheoremMap, eligible_decompositions,
    import_certificates,
};
use cubealqot::family::{CanonicalInt, LocalSearchResult, search_local_certificate};

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).unwrap()
}

fn factor(prime: &str, exponent: u32) -> UntrustedCofactorFactor {
    UntrustedCofactorFactor {
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

fn n14_certificate() -> cubealqot::family::UntrustedFamilyCertificate {
    let input = n14_input();
    let problem = n14_problem();
    let local = match search_local_certificate(&input, &problem, &(2..=16).collect::<Vec<_>>()) {
        LocalSearchResult::Found(certificate) => certificate,
        other => panic!("expected local certificate, got {other:?}"),
    };
    build_local_family_certificate(&input, &problem, local).unwrap()
}

#[test]
fn verified_empty_theorem_and_malformed_decompositions_continue() {
    let certificate = n14_certificate();
    let verified = match verify_family_certificate(&certificate) {
        CertificateVerification::Verified(value) => value,
        other => panic!("expected verified local theorem, got {other:?}"),
    };
    let mut map = TheoremMap::new();
    map.insert_verified(&certificate, &verified).unwrap();

    assert!(matches!(
        map.lookup(&integer("14"), &integer("14"), &integer("2")),
        LookupDecision::Continue { .. }
    ));
    assert!(matches!(
        map.lookup(&integer("99"), &integer("99"), &integer("2")),
        LookupDecision::Continue { .. }
    ));
    // This missing-N case has a valid exact relation and therefore reaches
    // theorem membership rather than being masked by the decomposition guard.
    assert!(matches!(
        map.lookup(&integer("33"), &integer("11"), &integer("3")),
        LookupDecision::Continue { .. }
    ));
    let snapshot = map.snapshot();
    assert_eq!(snapshot.entries().len(), 1);
    assert_eq!(snapshot.entries()[0].allowed_q().len(), 0);
}

#[test]
fn real_n14_empty_theorem_excludes_valid_unlisted_decomposition() {
    let certificate = n14_certificate();
    let verified = match verify_family_certificate(&certificate) {
        CertificateVerification::Verified(value) => value,
        other => panic!("expected verified local theorem, got {other:?}"),
    };
    let mut map = TheoremMap::new();
    map.insert_verified(&certificate, &verified).unwrap();

    // This is an eligible decomposition: q=3 is prime, gcd(14, 3)=1,
    // q occurs to exponent one in m=42, and 42=14*3 exactly.  The
    // admitted N=14 theorem has S_14 empty, so q is absent and must be
    // excluded by the theorem map.
    let witness = match map.lookup(&integer("42"), &integer("14"), &integer("3")) {
        LookupDecision::Excluded(witness) => witness,
        other => panic!("real empty theorem failed to exclude q=3: {other:?}"),
    };
    assert_eq!(witness.m(), &integer("42"));
    assert_eq!(witness.n(), &integer("14"));
    assert_eq!(witness.q(), &integer("3"));
    let snapshot = map.snapshot();
    assert_eq!(
        witness.certificate_digest(),
        snapshot.entries()[0].certificate_digest()
    );
    assert_eq!(witness.proof_kind(), &certificate.proof_kind);
}

#[test]
fn incomplete_backend_entries_are_reported_and_never_imported_as_empty() {
    let certificate = n14_certificate();
    let (map, report) = import_certificates(&[certificate]).unwrap();
    assert_eq!(map.len(), 1);
    assert!(report.skipped().is_empty());

    // A certificate with an unsupported proof version is an import error,
    // rather than an empty theorem entry.
    let mut invalid = n14_certificate();
    if let cubealqot::family::admission::UntrustedCompletenessProof::Local { certificate } =
        &mut invalid.proof
    {
        certificate.proof_version += 1;
    }
    assert!(import_certificates(&[invalid]).is_err());
}

#[test]
fn decomposition_eligibility_freezes_m12_and_m18() {
    let m12 = match eligible_decompositions(&integer("12"), &[factor("2", 2), factor("3", 1)]) {
        DecompositionEligibility::Eligible { decompositions, .. } => decompositions,
        other => panic!("unexpected m=12 eligibility: {other:?}"),
    };
    assert_eq!(
        m12.iter()
            .map(|item| (item.n(), item.q()))
            .collect::<Vec<_>>(),
        vec![(&integer("4"), &integer("3"))]
    );

    let m18 = match eligible_decompositions(&integer("18"), &[factor("2", 1), factor("3", 2)]) {
        DecompositionEligibility::Eligible { decompositions, .. } => decompositions,
        other => panic!("unexpected m=18 eligibility: {other:?}"),
    };
    assert_eq!(
        m18.iter()
            .map(|item| (item.n(), item.q()))
            .collect::<Vec<_>>(),
        vec![(&integer("9"), &integer("2"))]
    );
}

#[test]
fn multiple_exponent_one_factors_are_all_considered() {
    let result = eligible_decompositions(
        &integer("30"),
        &[factor("2", 1), factor("3", 1), factor("5", 1)],
    );
    let decompositions = match result {
        DecompositionEligibility::Eligible { decompositions, .. } => decompositions,
        other => panic!("unexpected m=30 eligibility: {other:?}"),
    };
    let pairs = decompositions
        .iter()
        .map(|item| (item.n().to_string(), item.q().to_string()))
        .collect::<Vec<_>>();
    assert_eq!(
        pairs,
        vec![
            ("15".to_owned(), "2".to_owned()),
            ("10".to_owned(), "3".to_owned()),
            ("6".to_owned(), "5".to_owned())
        ]
    );
}

#[test]
fn n_one_and_uncertain_factor_proofs_are_not_eligible() {
    let one = eligible_decompositions(&integer("2"), &[factor("2", 1)]);
    match one {
        DecompositionEligibility::Eligible {
            decompositions,
            skipped,
        } => {
            assert!(decompositions.is_empty());
            assert!(!skipped.is_empty());
        }
        other => panic!("N=1 should be skipped, got {other:?}"),
    }

    let uncertain = eligible_decompositions(
        &integer("6"),
        &[
            UntrustedCofactorFactor {
                prime: integer("2"),
                exponent: 1,
                certificate: None,
            },
            factor("3", 1),
        ],
    );
    assert!(matches!(
        uncertain,
        DecompositionEligibility::Inconclusive { .. }
    ));
}
