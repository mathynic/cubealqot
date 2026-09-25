//! M7-07 tests for validated cofactor problems and exact family arithmetic.

use cubealqot::family::{CanonicalInt, pocklington::UntrustedPrimeCertificate, problem};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Zero};

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

fn certified(input: problem::UntrustedProblem) -> problem::Problem {
    match problem::validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified problem, got {other:?}"),
    }
}

fn is_square(value: &BigUint) -> bool {
    if *value < BigUint::from(2u8) {
        return true;
    }
    let mut low = BigUint::zero();
    let mut high = BigUint::one() << (value.bits().div_ceil(2) + 1);
    while low < high {
        let mid = (&low + &high + BigUint::one()) >> 1;
        if &mid * &mid <= *value {
            low = mid;
        } else {
            high = mid - BigUint::one();
        }
    }
    &low * &low == *value
}

#[test]
fn frozen_problems_reconstruct_n_a_and_d() {
    for (n, factors, expected_a, expected_d) in [
        ("2", vec![factor("2", 1)], "15", "7"),
        ("3", vec![factor("3", 1)], "40", "13"),
        (
            "33",
            vec![factor("3", 1), factor("11", 1)],
            "58560",
            "22623",
        ),
        ("14", vec![factor("2", 1), factor("7", 1)], "6000", "3256"),
    ] {
        let problem = certified(input(n, factors));
        assert_eq!(problem.n(), &integer(n));
        assert_eq!(problem.a(), &integer(expected_a));
        assert_eq!(problem.d(), &integer(expected_d));
    }
}

#[test]
fn invalid_factorizations_and_uncertain_proofs_never_certify_a_problem() {
    assert!(matches!(
        problem::validate_problem(&input("1", vec![])),
        problem::ProblemBuildResult::Rejected { .. }
    ));
    assert!(matches!(
        problem::validate_problem(&input("6", vec![factor("2", 1), factor("2", 1)])),
        problem::ProblemBuildResult::Rejected { .. }
    ));
    assert!(matches!(
        problem::validate_problem(&input("6", vec![factor("2", 0), factor("3", 1)])),
        problem::ProblemBuildResult::Rejected { .. }
    ));
    assert!(matches!(
        problem::validate_problem(&input("10", vec![factor("2", 1), factor("3", 1)])),
        problem::ProblemBuildResult::Rejected { .. }
    ));
    assert!(matches!(
        problem::validate_problem(&input("1", vec![factor("1", 1)])),
        problem::ProblemBuildResult::Rejected { .. }
    ));

    let mut composite = factor("9", 1);
    composite.certificate = Some(UntrustedPrimeCertificate::U64 { n: integer("9") });
    assert!(matches!(
        problem::validate_problem(&input("9", vec![composite])),
        problem::ProblemBuildResult::Rejected { .. }
    ));

    let uncertain = problem::UntrustedCofactorFactor {
        prime: integer("2"),
        exponent: 1,
        certificate: None,
    };
    assert!(matches!(
        problem::validate_problem(&input("2", vec![uncertain])),
        problem::ProblemBuildResult::Inconclusive { .. }
    ));
}

#[test]
fn exponent_limit_is_checked_without_wrapping_three_e_plus_one() {
    let result = problem::validate_problem(&input("2", vec![factor("2", u32::MAX)]));
    assert!(matches!(
        result,
        problem::ProblemBuildResult::Inconclusive { .. }
    ));

    let result = problem::validate_problem_with_limits(
        &input("2", vec![factor("2", u32::MAX)]),
        problem::ProblemLimits {
            max_sigma_terms: u64::MAX,
        },
    );
    assert!(matches!(
        result,
        problem::ProblemBuildResult::Inconclusive { .. }
    ));
}

#[test]
fn n14_q43_rhs_is_the_frozen_nonsquare_regression() {
    let problem = certified(input("14", vec![factor("2", 1), factor("7", 1)]));
    let rhs = problem.rhs(&integer("43"));
    assert_eq!(rhs, integer("270232792"));
    let false_identity = BigInt::from(3256) * BigInt::from(44) * BigInt::from(43u32.pow(2) + 1);
    assert_ne!(rhs.as_bigint(), &false_identity);
    assert!(!is_square(
        &rhs.as_bigint()
            .to_biguint()
            .expect("positive regression RHS")
    ));
}

#[test]
fn rhs_matches_independent_direct_divisor_sums_for_small_prime_q() {
    for (n, factors, qs) in [
        ("2", vec![factor("2", 1)], vec![3u64, 5, 7]),
        ("3", vec![factor("3", 1)], vec![2, 5, 7]),
        (
            "14",
            vec![factor("2", 1), factor("7", 1)],
            vec![3, 5, 11, 13],
        ),
    ] {
        let problem = certified(input(n, factors));
        let n_value: u64 = n.parse().unwrap();
        for q in qs {
            if gcd_u64(n_value, q) != 1 {
                continue;
            }
            let m = n_value * q;
            let direct = direct_sigma(m.pow(3)) - u128::from(m).pow(3);
            assert_eq!(
                problem.rhs(&integer(&q.to_string())),
                integer(&direct.to_string())
            );
        }
    }
}

#[test]
fn wide_rhs_and_negative_modular_arguments_remain_exact() {
    let problem = certified(input("14", vec![factor("2", 1), factor("7", 1)]));
    let q = 1_000_000_000_039u64;
    let rhs = problem.rhs(&integer(&q.to_string()));
    let q_big = BigUint::from(q);
    let n_big = BigUint::from(14u8) * &q_big;
    let independent_sigma =
        BigUint::from(6000u32) * (BigUint::one() + &q_big + q_big.pow(2) + q_big.pow(3));
    let independent_direct = independent_sigma - n_big.pow(3);
    assert_eq!(rhs.as_bigint().to_biguint().unwrap(), independent_direct);
    assert!(rhs.as_bigint().to_biguint().unwrap().bits() > 128);

    let negative_q = integer("-43");
    let modulus = u64::MAX - 58;
    let expected = normalize_mod(problem.rhs(&negative_q).as_bigint(), modulus);
    assert_eq!(problem.rhs_mod(&negative_q, modulus).unwrap(), expected);
}

#[test]
fn curve_transformation_and_discriminants_are_exact() {
    let problem = certified(input("3", vec![factor("3", 1)]));
    let curve = problem.curve();
    assert_eq!(
        curve.coefficients(),
        [
            integer("0"),
            integer("40"),
            integer("0"),
            integer("520"),
            integer("6760")
        ]
    );

    let q = integer("5");
    let x = problem.curve_x(&q);
    let left = problem.curve_rhs(&x);
    let scaled = problem.d().as_bigint().pow(2) * problem.rhs(&q).as_bigint();
    assert_eq!(left.as_bigint(), &scaled);

    let a = problem.a().as_bigint();
    let d = problem.d().as_bigint();
    let cubic = a.pow(2) * d.pow(2) * (-3 * a.pow(2) + 14 * a * d - 27 * d.pow(2));
    assert_eq!(problem.cubic_discriminant().as_bigint(), &cubic);
    assert_eq!(problem.curve_discriminant().as_bigint(), &(16 * cubic));
}

#[test]
fn modular_rhs_matches_exact_reduction_near_u64_max() {
    let problem = certified(input("33", vec![factor("3", 1), factor("11", 1)]));
    for q in ["-17", "2", "43", "1000000000039"] {
        let q = integer(q);
        for modulus in [2u64, 8, 1_000_003, u64::MAX - 58, u64::MAX] {
            assert_eq!(
                problem.rhs_mod(&q, modulus).unwrap(),
                normalize_mod(problem.rhs(&q).as_bigint(), modulus),
                "q={q}, modulus={modulus}"
            );
        }
    }
}

fn gcd_u64(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left
}

fn direct_sigma(mut n: u64) -> u128 {
    let original = n;
    let mut sigma = 1u128;
    let mut divisor = 2u64;
    while divisor <= n / divisor {
        if n % divisor == 0 {
            let mut term = 1u128;
            let mut power = 1u128;
            while n % divisor == 0 {
                n /= divisor;
                power *= u128::from(divisor);
                term += power;
            }
            sigma *= term;
        }
        divisor += 1;
    }
    if n > 1 {
        sigma *= 1 + u128::from(n);
    }
    assert!(original > 0);
    sigma
}

fn normalize_mod(value: &BigInt, modulus: u64) -> u64 {
    let modulus = BigInt::from(modulus);
    let mut residue = value % &modulus;
    if residue.sign() == Sign::Minus {
        residue += &modulus;
    }
    residue.to_biguint().unwrap().try_into().unwrap()
}
