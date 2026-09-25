//! Exact square-residue predicates for explicitly bounded moduli.
//!
//! `MAX_SUPPORTED_MODULUS` is an operational bound for this offline helper,
//! not a mathematical bound on q.  A modulus above it returns an error and
//! therefore cannot reject any candidate.

use super::{PrimeStatus, classify_u64};

/// Largest modulus for which this module constructs a complete residue table.
/// The bound is deliberately explicit and keeps table allocation bounded.
pub const MAX_SUPPORTED_MODULUS: u64 = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModulusError {
    TooSmall { modulus: u64 },
    TooLarge { modulus: u64, maximum: u64 },
    ExponentZero,
    PowerOverflow { prime: u64, exponent: u32 },
    PrimeNotProven { prime: u64 },
    PrimeProofInconclusive { prime: u64, reason: String },
    FactorsEmpty,
    FactorsNotCanonical,
    FactorProductOverflow,
}

/// Complete square-residue membership for one supported modulus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SquareResidueTable {
    modulus: u64,
    residues: Vec<bool>,
}

impl SquareResidueTable {
    pub fn new(modulus: u64) -> Result<Self, ModulusError> {
        validate_modulus(modulus)?;
        let mut residues = vec![false; modulus as usize];
        for value in 0..modulus {
            let square = (u128::from(value) * u128::from(value)) % u128::from(modulus);
            residues[square as usize] = true;
        }
        Ok(Self { modulus, residues })
    }

    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    pub fn residues(&self) -> &[bool] {
        &self.residues
    }

    /// Test any integer representative after reducing it modulo this table's
    /// modulus.  Zero is represented in the table like every other residue.
    pub fn contains(&self, value: u64) -> bool {
        self.residues[(value % self.modulus) as usize]
    }
}

pub fn is_square_residue_mod(value: u64, modulus: u64) -> Result<bool, ModulusError> {
    Ok(SquareResidueTable::new(modulus)?.contains(value))
}

/// Apply the exact prime-power square criterion, including the reduced
/// precision rules for powers of two.
pub fn is_square_mod_prime_power(
    value: u64,
    prime: u64,
    exponent: u32,
) -> Result<bool, ModulusError> {
    if exponent == 0 {
        return Err(ModulusError::ExponentZero);
    }
    prove_prime(prime)?;
    let modulus = checked_prime_power(prime, exponent)?;
    let residue = value % modulus;
    if residue == 0 {
        return Ok(true);
    }

    let mut reduced = residue;
    let mut valuation = 0u32;
    while valuation < exponent && reduced % prime == 0 {
        reduced /= prime;
        valuation += 1;
    }
    if valuation % 2 == 1 {
        return Ok(false);
    }

    if prime == 2 {
        return Ok(match exponent - valuation {
            1 => true,
            2 => reduced % 4 == 1,
            _ => reduced % 8 == 1,
        });
    }

    Ok(mod_pow(reduced % prime, (prime - 1) / 2, prime) == 1)
}

/// Apply the prime-power criterion componentwise.  The strictly increasing
/// distinct prime factors make the components coprime, so this is the CRT
/// square predicate for the represented composite modulus.
pub fn is_square_mod_composite(value: u64, factors: &[(u64, u32)]) -> Result<bool, ModulusError> {
    let modulus = factor_product(factors)?;
    let reduced = value % modulus;
    for &(prime, exponent) in factors {
        if !is_square_mod_prime_power(reduced, prime, exponent)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_modulus(modulus: u64) -> Result<(), ModulusError> {
    if modulus < 2 {
        return Err(ModulusError::TooSmall { modulus });
    }
    if modulus > MAX_SUPPORTED_MODULUS {
        return Err(ModulusError::TooLarge {
            modulus,
            maximum: MAX_SUPPORTED_MODULUS,
        });
    }
    Ok(())
}

fn prove_prime(prime: u64) -> Result<(), ModulusError> {
    match classify_u64(prime) {
        PrimeStatus::ProvenPrime(_) => Ok(()),
        PrimeStatus::Inconclusive(reason) => {
            Err(ModulusError::PrimeProofInconclusive { prime, reason })
        }
        PrimeStatus::ProvenComposite(_) | PrimeStatus::NotPrime(_) => {
            Err(ModulusError::PrimeNotProven { prime })
        }
    }
}

fn checked_prime_power(prime: u64, exponent: u32) -> Result<u64, ModulusError> {
    let mut power = 1u64;
    for _ in 0..exponent {
        power = power
            .checked_mul(prime)
            .ok_or(ModulusError::PowerOverflow { prime, exponent })?;
        if power > MAX_SUPPORTED_MODULUS {
            return Err(ModulusError::TooLarge {
                modulus: power,
                maximum: MAX_SUPPORTED_MODULUS,
            });
        }
    }
    validate_modulus(power)?;
    Ok(power)
}

fn factor_product(factors: &[(u64, u32)]) -> Result<u64, ModulusError> {
    if factors.is_empty() {
        return Err(ModulusError::FactorsEmpty);
    }
    let mut product = 1u64;
    let mut previous = None;
    for &(prime, exponent) in factors {
        if exponent == 0 || previous.is_some_and(|old| old >= prime) {
            return Err(ModulusError::FactorsNotCanonical);
        }
        prove_prime(prime)?;
        let power = checked_prime_power(prime, exponent)?;
        product = product
            .checked_mul(power)
            .ok_or(ModulusError::FactorProductOverflow)?;
        if product > MAX_SUPPORTED_MODULUS {
            return Err(ModulusError::TooLarge {
                modulus: product,
                maximum: MAX_SUPPORTED_MODULUS,
            });
        }
        previous = Some(prime);
    }
    validate_modulus(product)?;
    Ok(product)
}

fn mod_pow(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = ((u128::from(result) * u128::from(base)) % u128::from(modulus)) as u64;
        }
        base = ((u128::from(base) * u128::from(base)) % u128::from(modulus)) as u64;
        exponent >>= 1;
    }
    result
}
