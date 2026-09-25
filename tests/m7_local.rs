//! M7-09 tests for exact bounded-modulus square predicates.

use cubealqot::family::local::{
    MAX_SUPPORTED_MODULUS, ModulusError, SquareResidueTable, is_square_mod_composite,
    is_square_mod_prime_power,
};
use cubealqot::family::{CanonicalInt, pocklington::UntrustedPrimeCertificate, problem};
use num_bigint::{BigInt, Sign};

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

fn direct_square_residues(modulus: u64) -> Vec<bool> {
    let mut residues = vec![false; modulus as usize];
    for value in 0..modulus {
        residues[((u128::from(value) * u128::from(value)) % u128::from(modulus)) as usize] = true;
    }
    residues
}

#[test]
fn tables_equal_the_exhaustive_square_residue_set() {
    for modulus in [2, 3, 4, 5, 7, 8, 9, 11, 13, 16, 25, 27, 49, 64, 81] {
        let table = SquareResidueTable::new(modulus).expect("fixture modulus is supported");
        assert_eq!(
            table.residues(),
            direct_square_residues(modulus),
            "M={modulus}"
        );
        for residue in 0..modulus {
            assert_eq!(
                table.contains(residue),
                direct_square_residues(modulus)[residue as usize],
                "M={modulus}, residue={residue}"
            );
        }
    }
}

#[test]
fn prime_power_and_crt_predicates_match_tables_exhaustively() {
    for (prime, exponent) in [
        (2u64, 1u32),
        (2, 2),
        (2, 3),
        (2, 4),
        (2, 6),
        (3, 1),
        (3, 2),
        (3, 3),
        (5, 2),
        (7, 2),
    ] {
        let modulus = prime.pow(exponent);
        let table = SquareResidueTable::new(modulus).unwrap();
        for residue in 0..modulus {
            assert_eq!(
                is_square_mod_prime_power(residue, prime, exponent).unwrap(),
                table.contains(residue),
                "p={prime}, e={exponent}, residue={residue}"
            );
        }
    }

    for factors in [
        &[(2u64, 3u32), (3, 2)][..],
        &[(2, 4), (5, 1)][..],
        &[(3, 2), (5, 1)][..],
        &[(2, 3), (3, 1), (5, 1)][..],
    ] {
        let modulus = factors.iter().fold(1u64, |product, (prime, exponent)| {
            product * prime.pow(*exponent)
        });
        let table = SquareResidueTable::new(modulus).unwrap();
        for residue in 0..modulus {
            assert_eq!(
                is_square_mod_composite(residue, &factors).unwrap(),
                table.contains(residue),
                "factors={factors:?}, residue={residue}"
            );
        }
    }
}

#[test]
fn zero_and_positive_even_valuation_good_bad_units_are_explicit() {
    assert!(is_square_mod_prime_power(0, 3, 3).unwrap());
    assert!(is_square_mod_prime_power(9, 3, 3).unwrap()); // 3^2 * 1
    assert!(!is_square_mod_prime_power(18, 3, 3).unwrap()); // 3^2 * 2
    assert!(is_square_mod_prime_power(25, 5, 3).unwrap()); // 5^2 * 1
    assert!(!is_square_mod_prime_power(50, 5, 3).unwrap()); // 5^2 * 2
    assert!(is_square_mod_prime_power(4, 2, 5).unwrap()); // 2^2 * 1
    assert!(!is_square_mod_prime_power(12, 2, 5).unwrap()); // 2^2 * 3
    assert!(is_square_mod_prime_power(16, 2, 5).unwrap()); // valuation reaches the reduced precision
}

#[test]
fn unsupported_moduli_are_not_treated_as_nonsquares() {
    assert_eq!(
        SquareResidueTable::new(0),
        Err(ModulusError::TooSmall { modulus: 0 })
    );
    assert_eq!(
        SquareResidueTable::new(1),
        Err(ModulusError::TooSmall { modulus: 1 })
    );
    assert_eq!(
        SquareResidueTable::new(MAX_SUPPORTED_MODULUS + 1),
        Err(ModulusError::TooLarge {
            modulus: MAX_SUPPORTED_MODULUS + 1,
            maximum: MAX_SUPPORTED_MODULUS,
        })
    );
}

#[test]
fn modular_rhs_uses_an_independent_exact_reduction_before_table_lookup() {
    let problem = family("33", vec![factor("3", 1), factor("11", 1)]);
    for modulus in [2, 8, 9, 15, 16, 25, 72] {
        let table = SquareResidueTable::new(modulus).unwrap();
        for residue in 0..modulus {
            let q = BigInt::from(residue);
            let a = problem.a().as_bigint();
            let d = problem.d().as_bigint();
            let exact = d * q.pow(3) + a * q.pow(2) + a * &q + a;
            let expected = normalize_mod(&exact, modulus);
            assert_eq!(
                problem
                    .rhs_mod(&integer(&residue.to_string()), modulus)
                    .unwrap(),
                expected
            );
            assert_eq!(
                table.contains(expected),
                is_exact_square_mod(&exact, modulus)
            );
        }
    }
}

fn normalize_mod(value: &BigInt, modulus: u64) -> u64 {
    let modulus_big = BigInt::from(modulus);
    let mut residue = value % &modulus_big;
    if residue.sign() == Sign::Minus {
        residue += modulus_big;
    }
    residue.to_biguint().unwrap().try_into().unwrap()
}

fn is_exact_square_mod(value: &BigInt, modulus: u64) -> bool {
    let residue = normalize_mod(value, modulus);
    (0..modulus).any(|root| root * root % modulus == residue)
}
