//! Validated fixed-cofactor family inputs and exact mathematical core.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};

use super::{CanonicalInt, pocklington};

/// The lightweight request identity used by the backend oracle boundary.
/// It intentionally remains separate from the verified `Problem` below.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamilyProblem {
    n: CanonicalInt,
}

impl FamilyProblem {
    pub fn from_decimal(
        n: &str,
    ) -> Result<Self, crate::family::integer_io::ParseCanonicalIntError> {
        Ok(Self {
            n: CanonicalInt::from_decimal(n)?,
        })
    }

    pub fn n(&self) -> &CanonicalInt {
        &self.n
    }
}

/// Untrusted input for a fixed-cofactor problem.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedProblem {
    pub n: CanonicalInt,
    pub factors: Vec<UntrustedCofactorFactor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedCofactorFactor {
    pub prime: CanonicalInt,
    pub exponent: u32,
    pub certificate: Option<pocklington::UntrustedPrimeCertificate>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProblemLimits {
    /// Maximum number of terms in each exact geometric sigma sum.
    pub max_sigma_terms: u64,
}

impl Default for ProblemLimits {
    fn default() -> Self {
        Self {
            max_sigma_terms: 1_000_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProblemBuildResult {
    Certified(Problem),
    Rejected { reason: String },
    Inconclusive { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCofactorFactor {
    prime: CanonicalInt,
    exponent: u32,
}

impl VerifiedCofactorFactor {
    pub fn prime(&self) -> &CanonicalInt {
        &self.prime
    }

    pub fn exponent(&self) -> u32 {
        self.exponent
    }
}

/// A fully validated cofactor family and its exact canonical polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Problem {
    n: CanonicalInt,
    factors: Vec<VerifiedCofactorFactor>,
    a: CanonicalInt,
    d: CanonicalInt,
}

impl Problem {
    pub fn n(&self) -> &CanonicalInt {
        &self.n
    }

    pub fn factors(&self) -> &[VerifiedCofactorFactor] {
        &self.factors
    }

    pub fn a(&self) -> &CanonicalInt {
        &self.a
    }

    pub fn d(&self) -> &CanonicalInt {
        &self.d
    }

    /// Evaluate `F_N(q) = Dq^3 + Aq^2 + Aq + A` exactly for signed q.
    pub fn rhs(&self, q: &CanonicalInt) -> CanonicalInt {
        let q = q.as_bigint();
        let a = self.a.as_bigint();
        let d = self.d.as_bigint();
        canonical_bigint(d * q.pow(3) + a * q.pow(2) + a * q + a)
    }

    /// Evaluate the canonical polynomial modulo a nonzero u64 modulus without
    /// narrowing q, A, or D. Negative q is normalized into [0, modulus).
    pub fn rhs_mod(&self, q: &CanonicalInt, modulus: u64) -> Result<u64, ModulusError> {
        if modulus == 0 {
            return Err(ModulusError::Zero);
        }
        let q = positive_mod(q.as_bigint(), modulus);
        let a = positive_mod(self.a.as_bigint(), modulus);
        let d = positive_mod(self.d.as_bigint(), modulus);
        let q_squared = mod_mul(q, q, modulus);
        let q_cubed = mod_mul(q_squared, q, modulus);
        let sum = u128::from(mod_mul(d, q_cubed, modulus))
            + u128::from(mod_mul(a, q_squared, modulus))
            + u128::from(mod_mul(a, q, modulus))
            + u128::from(a);
        Ok((sum % u128::from(modulus)) as u64)
    }

    /// Construct `[a1, a2, a3, a4, a6]` for
    /// `Y^2 = X^3 + A X^2 + A D X + A D^2`.
    pub fn curve(&self) -> CurveCoefficients {
        let a = self.a.as_bigint();
        let d = self.d.as_bigint();
        let ad = a * d;
        let ad_squared = &ad * d;
        CurveCoefficients {
            coefficients: [
                integer(0),
                self.a.clone(),
                integer(0),
                canonical_bigint(ad),
                canonical_bigint(ad_squared),
            ],
        }
    }

    pub fn curve_x(&self, q: &CanonicalInt) -> CanonicalInt {
        canonical_bigint(self.d.as_bigint() * q.as_bigint())
    }

    pub fn curve_rhs(&self, x: &CanonicalInt) -> CanonicalInt {
        let x = x.as_bigint();
        let a = self.a.as_bigint();
        let d = self.d.as_bigint();
        canonical_bigint(x.pow(3) + a * x.pow(2) + a * d * x + a * d.pow(2))
    }

    pub fn cubic_discriminant(&self) -> CanonicalInt {
        let a = self.a.as_bigint();
        let d = self.d.as_bigint();
        canonical_bigint(a.pow(2) * d.pow(2) * (-3 * a.pow(2) + 14 * a * d - 27 * d.pow(2)))
    }

    pub fn curve_discriminant(&self) -> CanonicalInt {
        canonical_bigint(BigInt::from(16) * self.cubic_discriminant().as_bigint())
    }
}

#[cfg(test)]
pub(crate) fn test_problem(n: &str, a: &str, d: &str) -> Problem {
    Problem {
        n: CanonicalInt::from_decimal(n).expect("test N is canonical"),
        factors: Vec::new(),
        a: CanonicalInt::from_decimal(a).expect("test A is canonical"),
        d: CanonicalInt::from_decimal(d).expect("test D is canonical"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurveCoefficients {
    coefficients: [CanonicalInt; 5],
}

impl CurveCoefficients {
    pub fn coefficients(&self) -> [CanonicalInt; 5] {
        self.coefficients.clone()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModulusError {
    Zero,
}

pub fn validate_problem(input: &UntrustedProblem) -> ProblemBuildResult {
    validate_problem_with_limits(input, ProblemLimits::default())
}

pub fn validate_problem_with_limits(
    input: &UntrustedProblem,
    limits: ProblemLimits,
) -> ProblemBuildResult {
    let claimed_n = match positive(&input.n, "N") {
        Ok(value) => value,
        Err(reason) => return ProblemBuildResult::Rejected { reason },
    };
    if claimed_n <= BigUint::one() {
        return ProblemBuildResult::Rejected {
            reason: "N must be greater than one".to_owned(),
        };
    }
    if input.factors.is_empty() {
        return ProblemBuildResult::Rejected {
            reason: "at least one cofactor factor is required".to_owned(),
        };
    }

    let mut product = BigUint::one();
    let mut sigma = BigUint::one();
    let mut previous: Option<BigUint> = None;
    let mut verified_factors = Vec::with_capacity(input.factors.len());

    for factor in &input.factors {
        if factor.exponent == 0 {
            return ProblemBuildResult::Rejected {
                reason: "cofactor exponents must be positive".to_owned(),
            };
        }
        let prime = match positive(&factor.prime, "cofactor prime") {
            Ok(value) => value,
            Err(reason) => return ProblemBuildResult::Rejected { reason },
        };
        if prime <= BigUint::one() {
            return ProblemBuildResult::Rejected {
                reason: "cofactor primes must be greater than one".to_owned(),
            };
        }
        if previous.as_ref().is_some_and(|old| old >= &prime) {
            return ProblemBuildResult::Rejected {
                reason: "cofactor primes must be distinct and strictly increasing".to_owned(),
            };
        }
        previous = Some(prime.clone());

        let certificate = match factor.certificate.as_ref() {
            Some(certificate) => certificate,
            None => {
                return ProblemBuildResult::Inconclusive {
                    reason: "cofactor prime proof is unavailable".to_owned(),
                };
            }
        };
        if certificate_n(certificate) != &factor.prime {
            return ProblemBuildResult::Rejected {
                reason: "cofactor prime proof claims a different value".to_owned(),
            };
        }
        match pocklington::verify_prime_certificate(certificate) {
            pocklington::PrimeCertificateStatus::ProvenPrime(verified) => {
                if verified.value() != &factor.prime {
                    return ProblemBuildResult::Rejected {
                        reason: "verified cofactor prime value mismatch".to_owned(),
                    };
                }
            }
            pocklington::PrimeCertificateStatus::Rejected { reason } => {
                return ProblemBuildResult::Rejected { reason };
            }
            pocklington::PrimeCertificateStatus::Inconclusive { reason } => {
                return ProblemBuildResult::Inconclusive { reason };
            }
        }

        let sigma_terms = match u64::from(factor.exponent)
            .checked_mul(3)
            .and_then(|value| value.checked_add(1))
        {
            Some(value) => value,
            None => {
                return ProblemBuildResult::Inconclusive {
                    reason: "3e+1 exponent count overflowed its checked representation".to_owned(),
                };
            }
        };
        if sigma_terms > limits.max_sigma_terms || sigma_terms > u64::from(u32::MAX) {
            return ProblemBuildResult::Inconclusive {
                reason: format!("sigma exponent count {sigma_terms} exceeds the exact-work limit"),
            };
        }

        product *= prime.pow(factor.exponent);
        let numerator = prime.pow(sigma_terms as u32) - BigUint::one();
        let denominator = &prime - BigUint::one();
        if &numerator % &denominator != BigUint::zero() {
            return ProblemBuildResult::Rejected {
                reason: "prime-power sigma division was not exact".to_owned(),
            };
        }
        sigma *= numerator / denominator;
        verified_factors.push(VerifiedCofactorFactor {
            prime: canonical(prime),
            exponent: factor.exponent,
        });
    }

    if product != claimed_n {
        return ProblemBuildResult::Rejected {
            reason: "cofactor factor product does not equal N".to_owned(),
        };
    }

    let n_cube = claimed_n.pow(3);
    if sigma <= n_cube {
        return ProblemBuildResult::Rejected {
            reason: "sigma(N^3) did not exceed N^3".to_owned(),
        };
    }
    let d = &sigma - &n_cube;
    ProblemBuildResult::Certified(Problem {
        n: canonical(claimed_n),
        factors: verified_factors,
        a: canonical(sigma),
        d: canonical(d),
    })
}

fn certificate_n(certificate: &pocklington::UntrustedPrimeCertificate) -> &CanonicalInt {
    match certificate {
        pocklington::UntrustedPrimeCertificate::U64 { n }
        | pocklington::UntrustedPrimeCertificate::Pocklington { n, .. } => n,
    }
}

fn positive(value: &CanonicalInt, label: &str) -> Result<BigUint, String> {
    let value = value
        .as_bigint()
        .to_biguint()
        .ok_or_else(|| format!("{label} must be a positive integer"))?;
    if value.is_zero() {
        return Err(format!("{label} must be a positive integer"));
    }
    Ok(value)
}

fn canonical(value: BigUint) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("BigUint formatting is canonical")
}

fn canonical_bigint(value: BigInt) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("BigInt formatting is canonical")
}

fn integer(value: i64) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("literal is canonical")
}

fn positive_mod(value: &BigInt, modulus: u64) -> u64 {
    let modulus = BigInt::from(modulus);
    let mut residue = value % &modulus;
    if residue.sign() == Sign::Minus {
        residue += &modulus;
    }
    residue.to_u64().expect("residue is below the u64 modulus")
}

fn mod_mul(left: u64, right: u64, modulus: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(modulus)) as u64
}
