//! M7-06 tests for recursive Pocklington certificate verification.

use cubealqot::family::{CanonicalInt, pocklington};

const CHILD: &str = "18446744073709551629";
const CHILD_FACTOR: &str = "658812288346769701";
const ROOT: &str = "811656739243220271677";

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).expect("fixture integer is canonical")
}

fn leaf(value: &str) -> Box<pocklington::UntrustedPrimeCertificate> {
    Box::new(pocklington::UntrustedPrimeCertificate::U64 { n: integer(value) })
}

fn factor(
    prime: &str,
    exponent: u32,
    certificate: Option<Box<pocklington::UntrustedPrimeCertificate>>,
) -> pocklington::UntrustedPrimeFactor {
    pocklington::UntrustedPrimeFactor {
        prime: integer(prime),
        exponent,
        certificate,
    }
}

fn witness(prime: &str, value: &str) -> pocklington::UntrustedPocklingtonWitness {
    pocklington::UntrustedPocklingtonWitness {
        prime: integer(prime),
        witness: integer(value),
    }
}

fn child_certificate() -> pocklington::UntrustedPrimeCertificate {
    pocklington::UntrustedPrimeCertificate::Pocklington {
        n: integer(CHILD),
        factors: vec![
            factor("2", 2, Some(leaf("2"))),
            factor("7", 1, Some(leaf("7"))),
            factor(CHILD_FACTOR, 1, Some(leaf(CHILD_FACTOR))),
        ],
        remainder: integer("1"),
        witnesses: vec![
            witness("2", "2"),
            witness("7", "2"),
            witness(CHILD_FACTOR, "2"),
        ],
    }
}

fn root_certificate() -> pocklington::UntrustedPrimeCertificate {
    pocklington::UntrustedPrimeCertificate::Pocklington {
        n: integer(ROOT),
        factors: vec![
            factor("2", 2, Some(leaf("2"))),
            factor(CHILD, 1, Some(Box::new(child_certificate()))),
        ],
        remainder: integer("11"),
        witnesses: vec![witness("2", "2"), witness(CHILD, "2")],
    }
}

#[test]
fn recursively_verifies_a_prime_above_u64() {
    let result = pocklington::verify_prime_certificate(&root_certificate());

    match result {
        pocklington::PrimeCertificateStatus::ProvenPrime(prime) => {
            assert_eq!(prime.value().to_string(), ROOT);
        }
        other => panic!("valid recursive certificate was not admitted: {other:?}"),
    }
}

#[test]
fn corrupted_product_and_factor_recursion_are_rejected() {
    let mut wrong_product = root_certificate();
    if let pocklington::UntrustedPrimeCertificate::Pocklington { remainder, .. } =
        &mut wrong_product
    {
        *remainder = integer("12");
    }
    assert!(matches!(
        pocklington::verify_prime_certificate(&wrong_product),
        pocklington::PrimeCertificateStatus::Rejected { .. }
    ));

    let mut wrong_child = root_certificate();
    if let pocklington::UntrustedPrimeCertificate::Pocklington { factors, .. } = &mut wrong_child {
        if let Some(pocklington::UntrustedPrimeCertificate::Pocklington { n, .. }) =
            factors[1].certificate.as_deref_mut()
        {
            *n = integer("18446744073709551631");
        }
    }
    assert!(matches!(
        pocklington::verify_prime_certificate(&wrong_child),
        pocklington::PrimeCertificateStatus::Rejected { .. }
    ));
}

#[test]
fn fermat_only_witness_is_rejected_without_the_second_pocklington_condition() {
    let mut certificate = root_certificate();
    if let pocklington::UntrustedPrimeCertificate::Pocklington { witnesses, .. } = &mut certificate
    {
        // For the root prime, 4^(n-1) == 1 (mod n), but the gcd condition for
        // q=2 is n rather than 1.  Fermat's congruence alone is insufficient.
        witnesses[0] = witness("2", "4");
    }

    assert!(matches!(
        pocklington::verify_prime_certificate(&certificate),
        pocklington::PrimeCertificateStatus::Rejected { .. }
    ));
}

#[test]
fn insufficient_factorization_and_exhausted_recursion_are_inconclusive() {
    let incomplete = pocklington::UntrustedPrimeCertificate::Pocklington {
        n: integer(ROOT),
        factors: vec![factor("2", 2, Some(leaf("2")))],
        remainder: integer("202914184810805067919"),
        witnesses: vec![witness("2", "2")],
    };
    assert!(matches!(
        pocklington::verify_prime_certificate(&incomplete),
        pocklington::PrimeCertificateStatus::Inconclusive { .. }
    ));

    let mut no_witness = root_certificate();
    if let pocklington::UntrustedPrimeCertificate::Pocklington { witnesses, .. } = &mut no_witness {
        witnesses.clear();
    }
    assert!(matches!(
        pocklington::verify_prime_certificate(&no_witness),
        pocklington::PrimeCertificateStatus::Inconclusive { .. }
    ));

    let limits = pocklington::VerificationLimits {
        max_depth: 0,
        max_nodes: 100,
    };
    assert!(matches!(
        pocklington::verify_prime_certificate_with_limits(&root_certificate(), limits),
        pocklington::PrimeCertificateStatus::Inconclusive { .. }
    ));
}

#[test]
fn exact_f_squared_boundary_is_not_accepted() {
    let f = "18446744073709551617";
    let n = "340282366920938463500268095579187314689"; // f^2
    let boundary = pocklington::UntrustedPrimeCertificate::Pocklington {
        n: integer(n),
        factors: vec![factor(f, 1, None)],
        remainder: integer("1"),
        witnesses: vec![],
    };

    assert!(matches!(
        pocklington::verify_prime_certificate(&boundary),
        pocklington::PrimeCertificateStatus::Rejected { .. }
    ));
}
