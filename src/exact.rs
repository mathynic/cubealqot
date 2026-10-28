//! Exact integer helpers with a small `u128` tier and a widened `BigUint` tier.

use num_bigint::BigUint;
use num_traits::{CheckedSub, One, ToPrimitive, Zero};

use crate::factor::Candidate;

/// Representation-neutral exact nonnegative integer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactNat {
    Small(u128),
    Big(BigUint),
}

impl ExactNat {
    pub fn from_biguint(value: BigUint) -> Self {
        value.to_u128().map_or(Self::Big(value), Self::Small)
    }

    pub fn as_u128(&self) -> Option<u128> {
        match self {
            Self::Small(value) => Some(*value),
            Self::Big(_) => None,
        }
    }

    pub fn to_biguint(&self) -> BigUint {
        match self {
            Self::Small(value) => BigUint::from(*value),
            Self::Big(value) => value.clone(),
        }
    }

    pub fn is_big(&self) -> bool {
        matches!(self, Self::Big(_))
    }

    /// Returns `v_q(self)` by repeated exact division.
    pub fn valuation(&self, q: u64) -> u32 {
        assert!(q >= 2, "valuation prime must be at least two");
        match self {
            Self::Small(value) => crate::numth::valuation(*value, u128::from(q)),
            Self::Big(value) => valuation_big(value, q),
        }
    }

    /// Returns the unit `self / q^valuation mod q`.
    pub fn unit_mod(&self, q: u64, valuation: u32) -> u64 {
        self.unit_modulus(q, valuation, q)
    }

    /// Returns the unit `self / q^valuation mod modulus`.
    pub fn unit_modulus(&self, q: u64, valuation: u32, modulus: u64) -> u64 {
        assert!(q >= 2, "unit prime must be at least two");
        assert!(modulus != 0, "unit modulus must be non-zero");
        match self {
            Self::Small(value) => {
                let mut unit = *value;
                for _ in 0..valuation {
                    unit /= u128::from(q);
                }
                (unit % u128::from(modulus)) as u64
            }
            Self::Big(value) => {
                let divisor = BigUint::from(q).pow(valuation);
                (value / divisor % BigUint::from(modulus))
                    .to_u64()
                    .expect("unit residue fits in its modulus")
            }
        }
    }
}

/// Existing validated u128 exact path for the original search domain.
pub fn exact_sigma(candidate: &Candidate) -> u128 {
    candidate.f[..candidate.omega as usize]
        .iter()
        .map(|factor| sigma_prime_power(factor.p, factor.e))
        .fold(1u128, |product, factor_sigma| {
            product
                .checked_mul(factor_sigma)
                .expect("sigma(m^3) does not fit in u128")
        })
}

/// Tiered exact `sigma(m^3)`, dispatching to the old fast path when possible.
pub fn exact_sigma_exact(candidate: &Candidate) -> ExactNat {
    if candidate.m <= u64::from(u32::MAX) {
        ExactNat::Small(exact_sigma(candidate))
    } else {
        ExactNat::from_biguint(exact_sigma_big(candidate))
    }
}

/// Forces the arbitrary-precision sigma computation, for differential tests.
pub fn exact_sigma_big(candidate: &Candidate) -> BigUint {
    candidate.f[..candidate.omega as usize]
        .iter()
        .map(|factor| exact_sigma_factor_big(factor.p, factor.e))
        .fold(BigUint::one(), |product, factor_sigma| {
            product * factor_sigma
        })
}

/// Computes `S = sigma(m^3) - m^3` through the existing u128 path.
pub fn aliquot_sum(candidate: &Candidate) -> u128 {
    exact_sigma(candidate)
        .checked_sub(candidate.m3())
        .expect("sigma(m^3) must be at least m^3")
}

/// Tiered exact aliquot sum for factored u64-domain candidates.
pub fn exact_s_exact(candidate: &Candidate) -> ExactNat {
    if candidate.m <= u64::from(u32::MAX) {
        ExactNat::Small(aliquot_sum(candidate))
    } else {
        ExactNat::from_biguint(exact_s_big(candidate))
    }
}

/// Forces the arbitrary-precision aliquot-sum computation.
pub fn exact_s_big(candidate: &Candidate) -> BigUint {
    let sigma = exact_sigma_big(candidate);
    let cube = BigUint::from(candidate.m).pow(3);
    sigma
        .checked_sub(&cube)
        .expect("sigma(m^3) must be at least m^3")
}

/// Computes `sigma(m^3) mod modulus` without narrowing the candidate factors.
pub fn sigma_mod(candidate: &Candidate, modulus: u128) -> u128 {
    assert!(modulus != 0, "exact modulus must be non-zero");
    if modulus <= u128::from(u64::MAX) {
        let modulus = modulus as u64;
        return candidate.f[..candidate.omega as usize]
            .iter()
            .map(|factor| sigma_prime_power_mod_small(factor.p, factor.e, modulus))
            .fold(1u64, |product, term| mod_mul_small(product, term, modulus))
            as u128;
    }
    let modulus_big = BigUint::from(modulus);
    candidate.f[..candidate.omega as usize]
        .iter()
        .map(|factor| exact_sigma_factor_big(factor.p, factor.e) % &modulus_big)
        .fold(BigUint::one(), |product, term| {
            product * term % &modulus_big
        })
        .to_u128()
        .expect("exact residue fits in its modulus")
}

/// Computes `m^3 mod modulus` exactly for a root-domain candidate.
pub fn m3_mod(candidate: &Candidate, modulus: u128) -> u128 {
    assert!(modulus != 0, "exact modulus must be non-zero");
    if modulus <= u128::from(u64::MAX) {
        let modulus = modulus as u64;
        let root = candidate.m % modulus;
        return mod_mul_small(mod_mul_small(root, root, modulus), root, modulus) as u128;
    }
    (BigUint::from(candidate.m).pow(3) % BigUint::from(modulus))
        .to_u128()
        .expect("exact residue fits in its modulus")
}

/// Computes a u64 root cube modulo a u64 modulus without overflow.
pub fn cube_mod(root: u64, modulus: u64) -> u64 {
    assert!(modulus != 0, "exact modulus must be non-zero");
    mod_mul_small(
        mod_mul_small(root % modulus, root % modulus, modulus),
        root % modulus,
        modulus,
    )
}

/// Computes `(sigma(m^3) - m^3) mod modulus` exactly.
pub fn s_mod(candidate: &Candidate, modulus: u128) -> u128 {
    if modulus.is_power_of_two() && modulus <= u128::from(u64::MAX) {
        // Wrapping modulo 2^64 preserves the low bits required modulo 2^k.
        // Keep sigma intermediates unmasked until the final residue.
        // Wider moduli continue through the existing exact arithmetic below.
        let mask = modulus as u64 - 1;
        let mut sigma = 1u64;
        for factor in &candidate.f[..candidate.omega as usize] {
            let sum = if factor.e == 1 {
                // sigma(p^3) = (p + 1)(p^2 + 1), also modulo 2^64.
                factor
                    .p
                    .wrapping_add(1)
                    .wrapping_mul(factor.p.wrapping_mul(factor.p).wrapping_add(1))
            } else {
                let mut term = 1u64;
                let mut sum = 0u64;
                for _ in 0..=3 * factor.e {
                    sum = sum.wrapping_add(term);
                    term = term.wrapping_mul(factor.p);
                }
                sum
            };
            sigma = sigma.wrapping_mul(sum);
        }
        let cube = candidate
            .m
            .wrapping_mul(candidate.m)
            .wrapping_mul(candidate.m)
            & mask;
        return u128::from(sigma.wrapping_sub(cube) & mask);
    }
    let sigma = sigma_mod(candidate, modulus);
    let cube = m3_mod(candidate, modulus);
    // Compute the modular difference without forming `sigma + modulus`:
    // that sum can overflow when `modulus` is near `u128::MAX`.
    if sigma >= cube {
        sigma - cube
    } else {
        modulus - (cube - sigma)
    }
}

/// Alias matching the mathematical name used by the original baseline.
pub fn exact_s(candidate: &Candidate) -> u128 {
    aliquot_sum(candidate)
}

/// Exact sigma contribution of one factor `p^e || m`.
pub fn exact_sigma_factor(p: u64, exponent_in_m: u32) -> ExactNat {
    ExactNat::from_biguint(exact_sigma_factor_big(p, exponent_in_m))
}

/// Arbitrary-precision `T_j = sigma(p^(3e))`.
pub fn exact_sigma_factor_big(p: u64, exponent_in_m: u32) -> BigUint {
    let term_count = 3u32
        .checked_mul(exponent_in_m)
        .and_then(|value| value.checked_add(1))
        .expect("prime exponent is too large");
    let mut term = BigUint::one();
    let mut sum = BigUint::zero();
    let base = BigUint::from(p);
    for index in 0..term_count {
        sum += &term;
        if index + 1 < term_count {
            term *= &base;
        }
    }
    sum
}

/// Returns whether a u128 is a perfect square.
pub fn is_square(n: u128) -> bool {
    let root = isqrt(n);
    root * root == n
}

/// Returns whether an exact tiered integer is a perfect square.
pub fn is_square_exact(n: &ExactNat) -> bool {
    let root = isqrt_exact(n).to_biguint();
    &root * &root == n.to_biguint()
}

/// Returns whether the candidate's original u128 aliquot sum is square.
pub fn aliquot_sum_is_square(candidate: &Candidate) -> bool {
    is_square(aliquot_sum(candidate))
}

/// Exact square decision for a factored u64-domain candidate.
pub fn aliquot_sum_is_square_exact(candidate: &Candidate) -> bool {
    is_square_exact(&exact_s_exact(candidate))
}

/// Exact integer square root for a tiered value.
pub fn isqrt_exact(n: &ExactNat) -> ExactNat {
    match n {
        ExactNat::Small(value) => ExactNat::Small(isqrt(*value)),
        ExactNat::Big(value) => ExactNat::from_biguint(isqrt_big(value)),
    }
}

/// Returns `floor(sqrt(n))` for a `u128` without floating-point rounding.
pub fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }

    let bit_length = 128 - n.leading_zeros();
    let mut estimate = 1u128 << bit_length.div_ceil(2);

    loop {
        let next = (estimate + n / estimate) / 2;
        if next >= estimate {
            return estimate;
        }
        estimate = next;
    }
}

fn isqrt_big(n: &BigUint) -> BigUint {
    if *n < BigUint::from(2u8) {
        return n.clone();
    }

    let mut estimate = BigUint::one() << n.bits().div_ceil(2);
    loop {
        let next = (&estimate + n / &estimate) >> 1;
        if next >= estimate {
            return estimate;
        }
        estimate = next;
    }
}

fn valuation_big(value: &BigUint, q: u64) -> u32 {
    let divisor = BigUint::from(q);
    let mut remainder = value.clone();
    let mut valuation = 0u32;
    while !remainder.is_zero() && &remainder % &divisor == BigUint::zero() {
        remainder /= &divisor;
        valuation += 1;
    }
    valuation
}

fn sigma_prime_power_mod_small(p: u64, exponent_in_m: u32, modulus: u64) -> u64 {
    let base = p % modulus;
    if exponent_in_m == 1 {
        // sigma(p^3) = (p + 1)(p^2 + 1). Each reduced factor is at most
        // modulus <= u64::MAX, so their product fits in u128.
        let square = mod_mul_small(base, base, modulus);
        return ((u128::from(base) + 1) * (u128::from(square) + 1) % u128::from(modulus)) as u64;
    }
    let mut term = 1u64 % modulus;
    let mut sum = 0u64;
    let last = 3 * exponent_in_m;
    for index in 0..=last {
        sum = if sum >= modulus - term {
            sum - (modulus - term)
        } else {
            sum + term
        };
        if index != last {
            term = mod_mul_small(term, base, modulus);
        }
    }
    sum
}

fn mod_mul_small(a: u64, b: u64, modulus: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(modulus)) as u64
}

fn sigma_prime_power(p: u64, exponent_in_m: u32) -> u128 {
    let term_count = 3u32
        .checked_mul(exponent_in_m)
        .and_then(|value| value.checked_add(1))
        .expect("prime exponent is too large");
    let p = u128::from(p);
    let mut term = 1u128;
    let mut sum = 0u128;

    for index in 0..term_count {
        sum = sum
            .checked_add(term)
            .expect("sigma prime-power term sum does not fit in u128");
        if index + 1 < term_count {
            term = term
                .checked_mul(p)
                .expect("sigma prime-power term does not fit in u128");
        }
    }

    sum
}

#[cfg(test)]
mod tests {
    use super::{ExactNat, isqrt, isqrt_exact};

    #[test]
    fn handles_zero_and_one() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
    }

    #[test]
    fn big_root_handles_small_values() {
        assert_eq!(
            isqrt_exact(&ExactNat::from_biguint(16u8.into())).as_u128(),
            Some(4)
        );
    }
}
