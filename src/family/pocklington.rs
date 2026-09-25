//! Offline verification of recursive Pocklington prime certificates.
//!
//! For `n > 1`, write `n - 1 = F R`, where `F` is completely factored into
//! already verified distinct primes and `F^2 > n`.  Pocklington's theorem
//! says that if, for every distinct prime `q | F`, a witness `a` satisfies
//!
//! ```text
//! a^(n-1) = 1 (mod n)
//! gcd(a^((n-1)/q) - 1, n) = 1,
//! ```
//!
//! then `n` is prime.  This module verifies that theorem's hypotheses using
//! exact `BigUint` arithmetic.  It does not generate factors or witnesses.

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};

use super::{CanonicalInt, PrimeStatus, classify_u64};

/// An untrusted recursive certificate received from a file or a future
/// producer.  Its fields never directly construct a verified prime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UntrustedPrimeCertificate {
    U64 {
        n: CanonicalInt,
    },
    Pocklington {
        n: CanonicalInt,
        /// Strictly increasing distinct prime factors of F.
        factors: Vec<UntrustedPrimeFactor>,
        remainder: CanonicalInt,
        witnesses: Vec<UntrustedPocklingtonWitness>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedPrimeFactor {
    pub prime: CanonicalInt,
    pub exponent: u32,
    /// `None` represents an unfinished recursive proof and is therefore
    /// inconclusive, not composite.
    pub certificate: Option<Box<UntrustedPrimeCertificate>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedPocklingtonWitness {
    pub prime: CanonicalInt,
    pub witness: CanonicalInt,
}

/// A prime admitted only after all recursive Pocklington conditions have been
/// recomputed.  There is no public constructor or deserializer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLargePrime {
    value: CanonicalInt,
}

impl VerifiedLargePrime {
    pub fn value(&self) -> &CanonicalInt {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrimeCertificateStatus {
    ProvenPrime(VerifiedLargePrime),
    Rejected { reason: String },
    Inconclusive { reason: String },
}

/// Resource limits are safety limits, not mathematical rejection criteria.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationLimits {
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self {
            max_depth: 128,
            max_nodes: 100_000,
        }
    }
}

pub fn verify_prime_certificate(certificate: &UntrustedPrimeCertificate) -> PrimeCertificateStatus {
    verify_prime_certificate_with_limits(certificate, VerificationLimits::default())
}

pub fn verify_prime_certificate_with_limits(
    certificate: &UntrustedPrimeCertificate,
    limits: VerificationLimits,
) -> PrimeCertificateStatus {
    let mut state = VerificationState { limits, nodes: 0 };
    match state.verify(certificate, 0) {
        Ok(value) => PrimeCertificateStatus::ProvenPrime(VerifiedLargePrime {
            value: canonical(value),
        }),
        Err(VerificationFailure::Rejected(reason)) => PrimeCertificateStatus::Rejected { reason },
        Err(VerificationFailure::Inconclusive(reason)) => {
            PrimeCertificateStatus::Inconclusive { reason }
        }
    }
}

struct VerificationState {
    limits: VerificationLimits,
    nodes: usize,
}

enum VerificationFailure {
    Rejected(String),
    Inconclusive(String),
}

impl VerificationState {
    fn verify(
        &mut self,
        certificate: &UntrustedPrimeCertificate,
        depth: usize,
    ) -> Result<BigUint, VerificationFailure> {
        if depth > self.limits.max_depth {
            return Err(VerificationFailure::Inconclusive(
                "verification depth limit exhausted".to_owned(),
            ));
        }
        if self.nodes >= self.limits.max_nodes {
            return Err(VerificationFailure::Inconclusive(
                "verification node limit exhausted".to_owned(),
            ));
        }
        self.nodes += 1;

        match certificate {
            UntrustedPrimeCertificate::U64 { n } => self.verify_u64_leaf(n),
            UntrustedPrimeCertificate::Pocklington {
                n,
                factors,
                remainder,
                witnesses,
            } => self.verify_pocklington(n, factors, remainder, witnesses, depth),
        }
    }

    fn verify_u64_leaf(&self, claimed: &CanonicalInt) -> Result<BigUint, VerificationFailure> {
        let value = positive(claimed, "u64 leaf")?;
        let raw = value.to_u64().ok_or_else(|| {
            VerificationFailure::Rejected("u64 leaf exceeds the u64 domain".to_owned())
        })?;

        match classify_u64(raw) {
            PrimeStatus::ProvenPrime(_) => Ok(value),
            PrimeStatus::ProvenComposite(_) | PrimeStatus::NotPrime(_) => Err(
                VerificationFailure::Rejected("u64 leaf is not prime".to_owned()),
            ),
            PrimeStatus::Inconclusive(reason) => Err(VerificationFailure::Inconclusive(reason)),
        }
    }

    fn verify_pocklington(
        &mut self,
        claimed: &CanonicalInt,
        factors: &[UntrustedPrimeFactor],
        remainder: &CanonicalInt,
        witnesses: &[UntrustedPocklingtonWitness],
        depth: usize,
    ) -> Result<BigUint, VerificationFailure> {
        let n = positive(claimed, "Pocklington n")?;
        let u64_max = BigUint::from(u64::MAX);
        if n <= u64_max {
            return Err(VerificationFailure::Rejected(
                "Pocklington certificate must use the deterministic u64 base case".to_owned(),
            ));
        }

        let n_minus_one = &n - BigUint::one();
        let r = positive(remainder, "Pocklington remainder")?;
        let mut f = BigUint::one();
        let mut previous: Option<BigUint> = None;
        let mut factor_values = Vec::with_capacity(factors.len());

        for factor in factors {
            if factor.exponent == 0 {
                return Err(VerificationFailure::Rejected(
                    "factor exponent must be positive".to_owned(),
                ));
            }
            let p = positive(&factor.prime, "Pocklington factor")?;
            if p <= BigUint::one() {
                return Err(VerificationFailure::Rejected(
                    "Pocklington factor must exceed one".to_owned(),
                ));
            }
            if p >= n {
                return Err(VerificationFailure::Rejected(
                    "recursive factor is not smaller than its parent".to_owned(),
                ));
            }
            if previous.as_ref().is_some_and(|old| old >= &p) {
                return Err(VerificationFailure::Rejected(
                    "Pocklington factors must be strictly increasing".to_owned(),
                ));
            }
            previous = Some(p.clone());
            f *= p.pow(factor.exponent);
            factor_values.push(p);
        }

        if &f * &r != n_minus_one {
            return Err(VerificationFailure::Rejected(
                "Pocklington product does not equal n-1".to_owned(),
            ));
        }

        if &f * &f <= n {
            return Err(VerificationFailure::Inconclusive(
                "factored F does not satisfy F^2 > n".to_owned(),
            ));
        }

        let witness_values = self.verify_witnesses(&n, &n_minus_one, &factor_values, witnesses)?;

        for (factor, p) in factors.iter().zip(factor_values.iter()) {
            let child = factor.certificate.as_deref().ok_or_else(|| {
                VerificationFailure::Inconclusive(
                    "recursive prime certificate is incomplete".to_owned(),
                )
            })?;
            if claimed_n(child) != &factor.prime {
                return Err(VerificationFailure::Rejected(
                    "recursive certificate claims a different prime".to_owned(),
                ));
            }
            let verified_child = self.verify(child, depth + 1)?;
            if &verified_child != p {
                return Err(VerificationFailure::Rejected(
                    "recursive certificate value mismatch".to_owned(),
                ));
            }
        }

        // Keep the computed witnesses live in this scope: every factor has
        // exactly one checked witness, and no witness can be silently ignored.
        debug_assert_eq!(witness_values.len(), factor_values.len());
        Ok(n)
    }

    fn verify_witnesses(
        &self,
        n: &BigUint,
        n_minus_one: &BigUint,
        factors: &[BigUint],
        witnesses: &[UntrustedPocklingtonWitness],
    ) -> Result<Vec<BigUint>, VerificationFailure> {
        let mut checked = Vec::with_capacity(factors.len());

        for witness in witnesses {
            let q = positive(&witness.prime, "Pocklington witness prime")?;
            if !factors.iter().any(|factor| factor == &q) {
                return Err(VerificationFailure::Rejected(
                    "witness is supplied for a non-factor".to_owned(),
                ));
            }
            if checked.iter().any(|factor: &BigUint| factor == &q) {
                return Err(VerificationFailure::Rejected(
                    "duplicate Pocklington witness".to_owned(),
                ));
            }

            let a = positive(&witness.witness, "Pocklington witness")?;
            if a <= BigUint::one() || a >= *n {
                return Err(VerificationFailure::Rejected(
                    "Pocklington witness is outside (1,n)".to_owned(),
                ));
            }
            if a.modpow(n_minus_one, n) != BigUint::one() {
                return Err(VerificationFailure::Rejected(
                    "Pocklington Fermat congruence failed".to_owned(),
                ));
            }
            let exponent = n_minus_one / &q;
            let residue = a.modpow(&exponent, n);
            if gcd(&(&residue - BigUint::one()), n) != BigUint::one() {
                return Err(VerificationFailure::Rejected(
                    "Pocklington gcd condition failed".to_owned(),
                ));
            }
            checked.push(q);
        }

        if checked.len() != factors.len() {
            return Err(VerificationFailure::Inconclusive(
                "no checked witness is available for every distinct factor".to_owned(),
            ));
        }
        Ok(checked)
    }
}

fn claimed_n(certificate: &UntrustedPrimeCertificate) -> &CanonicalInt {
    match certificate {
        UntrustedPrimeCertificate::U64 { n } | UntrustedPrimeCertificate::Pocklington { n, .. } => {
            n
        }
    }
}

fn positive(value: &CanonicalInt, label: &str) -> Result<BigUint, VerificationFailure> {
    let result = value.as_bigint().to_biguint().ok_or_else(|| {
        VerificationFailure::Rejected(format!("{label} must be a positive decimal integer"))
    })?;
    if result.is_zero() {
        return Err(VerificationFailure::Rejected(format!(
            "{label} must be a positive decimal integer"
        )));
    }
    Ok(result)
}

fn canonical(value: BigUint) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("BigUint formatting is canonical")
}

fn gcd(left: &BigUint, right: &BigUint) -> BigUint {
    let mut a = left.clone();
    let mut b = right.clone();
    while !b.is_zero() {
        let remainder = &a % &b;
        a = b;
        b = remainder;
    }
    a
}
