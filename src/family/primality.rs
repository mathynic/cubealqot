//! Deterministic primality decisions for the complete `u64` domain.
//!
//! The strong Miller--Rabin theorem used here is the fixed-base result for
//! `n < 2^64` with bases
//! `2, 325, 9375, 28178, 450775, 9780504, 1795265022`.  See M. Forisek and
//! J. Jančina, *Fast Primality Testing for Integer Arithmetic*,
//! <https://ceur-ws.org/Vol-1326/020-Forisek.pdf>, and the recorded theorem
//! statement in the M7-05 evidence document.
//!
//! `classify_u64` is the only constructor for `ProvenPrime`.  The internal
//! Miller--Rabin computation is not exposed as a probable-prime API, so an
//! unverified probable-prime result cannot be treated as a prime certificate.

/// The largest input covered by the deterministic theorem: every `u64` is
/// strictly less than `2^64`.
pub const PROVEN_U64_MAX: u64 = u64::MAX;

/// Fixed bases for the deterministic strong Miller--Rabin theorem on
/// `0 < n < 2^64`.  Bases are reduced modulo `n` before use.
pub const DETERMINISTIC_BASES: [u64; 7] = [2, 325, 9375, 28178, 450775, 9780504, 1795265022];

const SMALL_PRIMES: [u64; 11] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotPrimeReason {
    Zero,
    One,
}

/// A directly checkable certificate that an input is composite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositeWitness {
    SmallFactor { factor: u64 },
    MillerRabin { base: u64 },
}

impl CompositeWitness {
    /// Recheck this witness against the supplied input.
    pub fn verifies(self, n: u64) -> bool {
        match self {
            Self::SmallFactor { factor } => factor > 1 && factor < n && n % factor == 0,
            Self::MillerRabin { base } => {
                n > 3 && n % 2 == 1 && base > 1 && base < n && is_strong_witness(n, base)
            }
        }
    }
}

/// A prime decision backed by the deterministic theorem documented above.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvenPrime {
    value: u64,
}

impl ProvenPrime {
    pub fn value(self) -> u64 {
        self.value
    }
}

/// The tri-state result used by the offline proof subsystem, with an explicit
/// non-prime state for 0 and 1 because neither is composite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrimeStatus {
    ProvenPrime(ProvenPrime),
    ProvenComposite(CompositeWitness),
    NotPrime(NotPrimeReason),
    Inconclusive(String),
}

/// Classify any `u64` without probabilistic or overflow-prone arithmetic.
pub fn classify_u64(n: u64) -> PrimeStatus {
    if n == 0 {
        return PrimeStatus::NotPrime(NotPrimeReason::Zero);
    }
    if n == 1 {
        return PrimeStatus::NotPrime(NotPrimeReason::One);
    }
    if n == 2 {
        return PrimeStatus::ProvenPrime(ProvenPrime { value: n });
    }
    if n % 2 == 0 {
        return PrimeStatus::ProvenComposite(CompositeWitness::SmallFactor { factor: 2 });
    }

    for factor in SMALL_PRIMES {
        if n == factor {
            return PrimeStatus::ProvenPrime(ProvenPrime { value: n });
        }
        if n % factor == 0 {
            return PrimeStatus::ProvenComposite(CompositeWitness::SmallFactor { factor });
        }
    }

    for basis in DETERMINISTIC_BASES {
        let base = basis % n;
        if base < 2 {
            continue;
        }
        if is_strong_witness(n, base) {
            return PrimeStatus::ProvenComposite(CompositeWitness::MillerRabin { base });
        }
    }

    PrimeStatus::ProvenPrime(ProvenPrime { value: n })
}

fn is_strong_witness(n: u64, base: u64) -> bool {
    debug_assert!(n > 3 && n % 2 == 1 && base > 1 && base < n);

    let mut odd_part = n - 1;
    let powers_of_two = odd_part.trailing_zeros();
    odd_part >>= powers_of_two;

    let mut value = mod_pow(base, odd_part, n);
    if value == 1 || value == n - 1 {
        return false;
    }

    for _ in 1..powers_of_two {
        value = mod_mul(value, value, n);
        if value == n - 1 {
            return false;
        }
    }
    true
}

fn mod_pow(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        base = mod_mul(base, base, modulus);
        exponent >>= 1;
    }
    result
}

/// A product of two reduced u64 values is strictly below 2^128, so the u128
/// intermediate is sufficient for every modulus in the declared u64 domain.
fn mod_mul(left: u64, right: u64, modulus: u64) -> u64 {
    ((left as u128 * right as u128) % modulus as u128) as u64
}
