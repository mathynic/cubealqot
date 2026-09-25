//! Explicitly bounded prime-q discovery for a validated fixed-cofactor problem.
//!
//! This module is a discovery/oracle aid only.  A `Bounded` result records the
//! inclusive q interval that was searched; it is never a completeness claim
//! for the infinite family.  An unavailable prime proof is surfaced as
//! `Inconclusive`, not as a rejection or an empty result.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Zero};

use super::{CanonicalInt, PrimeStatus, classify_u64, problem::Problem};

/// Injectable prime-proof boundary used to test uncertainty without changing
/// the production deterministic-u64 path.
pub trait PrimeProofOracle {
    fn classify(&self, value: u64) -> PrimeStatus;
}

/// The production bounded enumerator's u64 prime-proof provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicU64PrimeOracle;

impl PrimeProofOracle for DeterministicU64PrimeOracle {
    fn classify(&self, value: u64) -> PrimeStatus {
        classify_u64(value)
    }
}

/// A finite discovery result.  The `q_max` field is part of the result so an
/// empty result cannot be mistaken for `CERTIFIED_EMPTY`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDiscovery {
    n: CanonicalInt,
    q_max: u64,
    last_examined_q: Option<u64>,
    candidates: Vec<CanonicalInt>,
    tested_prime_count: u64,
    excluded_dividing_n_count: u64,
}

impl BoundedDiscovery {
    pub fn n(&self) -> &CanonicalInt {
        &self.n
    }

    pub fn q_max(&self) -> u64 {
        self.q_max
    }

    pub fn last_examined_q(&self) -> Option<u64> {
        self.last_examined_q
    }

    pub fn candidates(&self) -> &[CanonicalInt] {
        &self.candidates
    }

    pub fn tested_prime_count(&self) -> u64 {
        self.tested_prime_count
    }

    pub fn excluded_dividing_n_count(&self) -> u64 {
        self.excluded_dividing_n_count
    }

    /// Whether this q was within the finite scan interval already examined.
    /// This describes coverage only; it is not a primality claim.
    pub fn q_was_tested(&self, q: u64) -> bool {
        q >= 2 && self.last_examined_q.is_some_and(|last| q <= last)
    }

    /// Always false: bounded discovery does not establish a global theorem.
    pub fn claims_global_completeness(&self) -> bool {
        false
    }
}

/// The bounded scan either completed its declared finite interval or became
/// inconclusive before that interval could be classified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundedDiscoveryResult {
    Bounded(BoundedDiscovery),
    Inconclusive {
        partial: BoundedDiscovery,
        reason: String,
    },
}

/// Discover square-producing prime q values for every q in `[2, q_max]`.
/// `q_max` is inclusive, and q values dividing N are excluded after their
/// primality has been proven.  The canonical `Problem::rhs` is the only
/// production RHS evaluator used here.
pub fn discover_bounded(problem: &Problem, q_max: u64) -> BoundedDiscoveryResult {
    discover_bounded_with(problem, q_max, &DeterministicU64PrimeOracle)
}

/// Testable form of bounded discovery with an explicit prime-proof boundary.
/// This is also the uncertainty-preserving seam for a future proof provider.
pub fn discover_bounded_with<P: PrimeProofOracle>(
    problem: &Problem,
    q_max: u64,
    prime_oracle: &P,
) -> BoundedDiscoveryResult {
    let n = problem.n().clone();
    let n_big = n
        .as_bigint()
        .to_biguint()
        .expect("validated Problem has positive N");
    let mut discovery = BoundedDiscovery {
        n,
        q_max,
        last_examined_q: None,
        candidates: Vec::new(),
        tested_prime_count: 0,
        excluded_dividing_n_count: 0,
    };

    if q_max < 2 {
        return BoundedDiscoveryResult::Bounded(discovery);
    }

    for q in 2..=q_max {
        discovery.last_examined_q = Some(q);
        match prime_oracle.classify(q) {
            PrimeStatus::ProvenPrime(_) => {
                discovery.tested_prime_count += 1;
                if (&n_big % BigUint::from(q)).is_zero() {
                    discovery.excluded_dividing_n_count += 1;
                    continue;
                }

                let q_integer = canonical_u64(q);
                let rhs = problem.rhs(&q_integer);
                if is_nonnegative_square(rhs.as_bigint()) {
                    discovery.candidates.push(q_integer);
                }
            }
            PrimeStatus::ProvenComposite(_) | PrimeStatus::NotPrime(_) => {}
            PrimeStatus::Inconclusive(reason) => {
                return BoundedDiscoveryResult::Inconclusive {
                    partial: discovery,
                    reason: format!("prime proof for q={q} is inconclusive: {reason}"),
                };
            }
        }
    }

    BoundedDiscoveryResult::Bounded(discovery)
}

fn canonical_u64(value: u64) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("u64 formatting is canonical")
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
