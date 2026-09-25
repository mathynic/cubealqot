//! Production and fresh verification of bounded local family certificates.
//!
//! A certificate proves only the stated local covering argument: every unit
//! residue modulo M is excluded, and the exceptional prime divisors of M are
//! checked exactly.  It is not a proof that a different modulus exists or
//! that an unsearched family is empty.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

use super::{
    CanonicalInt, PrimeStatus, classify_u64,
    local::{MAX_SUPPORTED_MODULUS, ModulusError, SquareResidueTable},
    problem::{
        Problem, ProblemBuildResult, UntrustedCofactorFactor, UntrustedProblem, validate_problem,
    },
};

pub const LOCAL_CERTIFICATE_SCHEMA_VERSION: u32 = 1;
pub const LOCAL_PROOF_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedModulusFactor {
    pub prime: u64,
    pub exponent: u32,
}

/// A stored unit-residue claim is evidence for reproducibility only.  The
/// verifier reconstructs the complete unit list and recomputes this residue.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedUnitResidue {
    pub residue: u64,
    pub rhs_residue: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedLocalCertificate {
    pub schema_version: u32,
    pub proof_version: u32,
    pub n: CanonicalInt,
    pub factors: Vec<UntrustedCofactorFactor>,
    pub modulus: u64,
    pub modulus_factors: Vec<UntrustedModulusFactor>,
    pub unit_residues: Vec<UntrustedUnitResidue>,
    pub exceptional_primes: Vec<CanonicalInt>,
    pub solutions: Vec<CanonicalInt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLocalCertificate {
    problem: Problem,
    modulus: u64,
    exceptional_primes: Vec<CanonicalInt>,
    solutions: Vec<CanonicalInt>,
}

impl VerifiedLocalCertificate {
    pub fn n(&self) -> &CanonicalInt {
        self.problem.n()
    }

    pub fn problem(&self) -> &Problem {
        &self.problem
    }

    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    pub fn exceptional_primes(&self) -> &[CanonicalInt] {
        &self.exceptional_primes
    }

    pub fn solutions(&self) -> &[CanonicalInt] {
        &self.solutions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalCertificateStatus {
    Verified(VerifiedLocalCertificate),
    Rejected { reason: String },
    Inconclusive { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalSearchResult {
    Found(UntrustedLocalCertificate),
    Rejected { reason: String },
    Inconclusive { reason: String },
}

/// Search the caller-supplied deterministic modulus list in order.  A found
/// certificate is still untrusted until `verify_local_certificate` succeeds.
pub fn search_local_certificate(
    input: &UntrustedProblem,
    problem: &Problem,
    moduli: &[u64],
) -> LocalSearchResult {
    let rebuilt = match validate_problem(input) {
        ProblemBuildResult::Certified(problem) => problem,
        ProblemBuildResult::Rejected { reason } => return LocalSearchResult::Rejected { reason },
        ProblemBuildResult::Inconclusive { reason } => {
            return LocalSearchResult::Inconclusive { reason };
        }
    };
    if &rebuilt != problem {
        return LocalSearchResult::Rejected {
            reason: "search input does not match the validated Problem".to_owned(),
        };
    }
    if moduli.is_empty() {
        return LocalSearchResult::Inconclusive {
            reason: "no complete local modulus in deterministic budget".to_owned(),
        };
    }

    for &modulus in moduli {
        let table = match SquareResidueTable::new(modulus) {
            Ok(table) => table,
            Err(error) => {
                return LocalSearchResult::Inconclusive {
                    reason: format!("local modulus {modulus} is unsupported: {error:?}"),
                };
            }
        };
        let modulus_factors = match factor_modulus_for_producer(modulus) {
            Ok(factors) => factors,
            Err(reason) => return LocalSearchResult::Inconclusive { reason },
        };
        let unit_residues = match unit_claims(problem, modulus) {
            Ok(claims) => claims,
            Err(reason) => return LocalSearchResult::Inconclusive { reason },
        };
        if unit_residues
            .iter()
            .any(|claim| table.contains(claim.rhs_residue))
        {
            continue;
        }

        let exceptional_primes = modulus_factors
            .iter()
            .map(|factor| canonical_u64(factor.prime))
            .collect::<Vec<_>>();
        let solutions = derive_solutions(problem, &exceptional_primes);
        return LocalSearchResult::Found(UntrustedLocalCertificate {
            schema_version: LOCAL_CERTIFICATE_SCHEMA_VERSION,
            proof_version: LOCAL_PROOF_VERSION,
            n: problem.n().clone(),
            factors: input.factors.clone(),
            modulus,
            modulus_factors,
            unit_residues,
            exceptional_primes,
            solutions,
        });
    }

    LocalSearchResult::Inconclusive {
        reason: format!(
            "no complete local modulus in deterministic budget: {}",
            moduli
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// Verify every certificate field from the mathematical inputs.  Stored
/// residue tables, modulus factors, and solution lists are never authorities.
pub fn verify_local_certificate(certificate: &UntrustedLocalCertificate) -> LocalCertificateStatus {
    if certificate.schema_version != LOCAL_CERTIFICATE_SCHEMA_VERSION {
        return rejected("unsupported local certificate schema version");
    }
    if certificate.proof_version != LOCAL_PROOF_VERSION {
        return rejected("unsupported local proof version");
    }

    let input = UntrustedProblem {
        n: certificate.n.clone(),
        factors: certificate.factors.clone(),
    };
    let problem = match validate_problem(&input) {
        ProblemBuildResult::Certified(problem) => problem,
        ProblemBuildResult::Rejected { reason } => return rejected(reason),
        ProblemBuildResult::Inconclusive { reason } => return inconclusive(reason),
    };

    let table = match SquareResidueTable::new(certificate.modulus) {
        Ok(table) => table,
        Err(error) if modulus_error_is_inconclusive(&error) => {
            return inconclusive(format!("local modulus is unsupported: {error:?}"));
        }
        Err(error) => return rejected(format!("invalid local modulus: {error:?}")),
    };

    let expected_factors = match factor_modulus_for_verifier(certificate.modulus) {
        Ok(factors) => factors,
        Err(reason) => return rejected(reason),
    };
    if certificate.modulus_factors != expected_factors {
        return rejected("stored modulus factorization is not canonical or is incomplete");
    }

    let expected_units = match unit_claims(&problem, certificate.modulus) {
        Ok(claims) => claims,
        Err(reason) => return inconclusive(reason),
    };
    if certificate.unit_residues != expected_units {
        return rejected("unit-residue coverage is omitted, duplicated, or changed");
    }
    if certificate
        .unit_residues
        .iter()
        .any(|claim| table.contains(claim.rhs_residue))
    {
        return rejected("a stored unit residue is a square residue");
    }

    let expected_exceptional = expected_factors
        .iter()
        .map(|factor| canonical_u64(factor.prime))
        .collect::<Vec<_>>();
    if certificate.exceptional_primes != expected_exceptional {
        return rejected("exceptional prime list does not match an independent factorization of M");
    }

    let expected_solutions = derive_solutions(&problem, &expected_exceptional);
    if certificate.solutions != expected_solutions {
        return rejected("derived exceptional solution set does not match exact checking");
    }

    LocalCertificateStatus::Verified(VerifiedLocalCertificate {
        problem,
        modulus: certificate.modulus,
        exceptional_primes: expected_exceptional,
        solutions: expected_solutions,
    })
}

fn unit_claims(problem: &Problem, modulus: u64) -> Result<Vec<UntrustedUnitResidue>, String> {
    let mut claims = Vec::new();
    for residue in 0..modulus {
        if gcd_u64(residue, modulus) == 1 {
            let q = canonical_u64(residue);
            let rhs_residue = problem
                .rhs_mod(&q, modulus)
                .map_err(|error| format!("RHS modular evaluation failed: {error:?}"))?;
            claims.push(UntrustedUnitResidue {
                residue,
                rhs_residue,
            });
        }
    }
    Ok(claims)
}

fn derive_solutions(problem: &Problem, exceptional_primes: &[CanonicalInt]) -> Vec<CanonicalInt> {
    exceptional_primes
        .iter()
        .filter(|prime| {
            let q = prime
                .as_bigint()
                .to_biguint()
                .expect("exceptional prime is positive");
            let n = problem.n().as_bigint().to_biguint().expect("N is positive");
            (&n % &q).is_zero() == false && is_nonnegative_square(problem.rhs(prime).as_bigint())
        })
        .cloned()
        .collect()
}

fn factor_modulus_for_producer(modulus: u64) -> Result<Vec<UntrustedModulusFactor>, String> {
    let mut remainder = modulus;
    let mut divisor = 2u64;
    let mut factors = Vec::new();
    while divisor <= remainder / divisor {
        if remainder % divisor == 0 {
            let mut exponent = 0u32;
            while remainder % divisor == 0 {
                remainder /= divisor;
                exponent += 1;
            }
            factors.push(UntrustedModulusFactor {
                prime: divisor,
                exponent,
            });
        }
        divisor += 1;
    }
    if remainder > 1 {
        factors.push(UntrustedModulusFactor {
            prime: remainder,
            exponent: 1,
        });
    }
    if factors.is_empty() {
        return Err("local modulus factorization is empty".to_owned());
    }
    for factor in &factors {
        if !matches!(classify_u64(factor.prime), PrimeStatus::ProvenPrime(_)) {
            return Err("local modulus factor was not proven prime".to_owned());
        }
    }
    Ok(factors)
}

/// Independent verifier factorization: generate primes with a sieve, then
/// divide the supplied modulus.  This does not trust certificate metadata or
/// reuse the producer's trial-divisor walk.
fn factor_modulus_for_verifier(modulus: u64) -> Result<Vec<UntrustedModulusFactor>, String> {
    if modulus < 2 || modulus > MAX_SUPPORTED_MODULUS {
        return Err("verifier modulus is outside the supported bound".to_owned());
    }
    let limit = integer_sqrt_u64(modulus) as usize;
    let mut sieve = vec![true; limit + 1];
    if !sieve.is_empty() {
        sieve[0] = false;
    }
    if sieve.len() > 1 {
        sieve[1] = false;
    }
    for value in 2..=limit {
        if sieve[value] && value <= limit / value {
            for composite in (value * value..=limit).step_by(value) {
                sieve[composite] = false;
            }
        }
    }

    let mut remainder = modulus;
    let mut factors = Vec::new();
    for value in 2..=limit {
        if sieve[value] {
            let prime = value as u64;
            if remainder % prime == 0 {
                let mut exponent = 0u32;
                while remainder % prime == 0 {
                    remainder /= prime;
                    exponent += 1;
                }
                factors.push(UntrustedModulusFactor { prime, exponent });
            }
        }
    }
    if remainder > 1 {
        factors.push(UntrustedModulusFactor {
            prime: remainder,
            exponent: 1,
        });
    }
    Ok(factors)
}

fn modulus_error_is_inconclusive(error: &ModulusError) -> bool {
    matches!(
        error,
        ModulusError::TooLarge { .. } | ModulusError::PowerOverflow { .. }
    )
}

fn is_nonnegative_square(value: &BigInt) -> bool {
    let Some(value) = value.to_biguint() else {
        return false;
    };
    if value < BigUint::from(2u8) {
        return true;
    }
    let mut low = BigUint::zero();
    let mut high = BigUint::one() << (value.bits().div_ceil(2) + 1);
    while low < high {
        let mid = (&low + &high + BigUint::one()) >> 1;
        if &mid * &mid <= value {
            low = mid;
        } else {
            high = mid - BigUint::one();
        }
    }
    &low * &low == value
}

fn integer_sqrt_u64(value: u64) -> u64 {
    let mut root = (value as f64).sqrt() as u64;
    while (root + 1) <= value / (root + 1) {
        root += 1;
    }
    while root > value / root {
        root -= 1;
    }
    root
}

fn gcd_u64(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        (left, right) = (right, left % right);
    }
    left
}

fn canonical_u64(value: u64) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("u64 formatting is canonical")
}

fn rejected(reason: impl Into<String>) -> LocalCertificateStatus {
    LocalCertificateStatus::Rejected {
        reason: reason.into(),
    }
}

fn inconclusive(reason: impl Into<String>) -> LocalCertificateStatus {
    LocalCertificateStatus::Inconclusive {
        reason: reason.into(),
    }
}
