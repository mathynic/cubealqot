//! Cross-factor divisibility and valuation primitives.

use crate::{
    Candidate,
    numth::{modpow, multiplicative_order, valuation},
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// A source factor's contribution to a target prime's valuation in
/// `sigma(m^3)`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossHit {
    pub target: u64,
    pub source: u64,
    pub e_source: u32,
    pub val: u32,
}

/// Computes one cross hit using the LTE/order decomposition.
pub fn cross_hit(target: u64, source: u64, e_source: u32) -> Option<CrossHit> {
    assert!(
        target >= 5 && target % 2 == 1,
        "cross target must be an odd prime"
    );
    assert!(source != target, "cross source and target must differ");

    let n = 3u32
        .checked_mul(e_source)
        .and_then(|value| value.checked_add(1))
        .expect("cross exponent is too large");

    if target > u64::from(u32::MAX) || source > u64::from(u32::MAX) {
        // The optimized order/LTE path below uses u32 number-theory helpers.
        // Wide primes still receive a complete diagnostic through exact T_j
        // division rather than being reported as an unqualified non-hit.
        return exact_cross_hit_value(target, source, e_source).map(|val| CrossHit {
            target,
            source,
            e_source,
            val,
        });
    }

    // The order implementation remains a u32-era optimization until the
    // later widened-filter audit. Wide factors therefore defer rather than
    // narrowing or guessing.
    let (target32, source32) = (u32::try_from(target).ok()?, u32::try_from(source).ok()?);
    let value = if source % target == 1 {
        let value = valuation(u128::from(n), u128::from(target));
        (value > 0).then_some(value)
    } else {
        let order = multiplicative_order(target32, source32);
        if n % order != 0 {
            None
        } else {
            base_valuation(target32, source32, order).map_or_else(
                || exact_cross_hit_value(target, source, e_source),
                |base| Some(base + valuation(u128::from(n / order), u128::from(target))),
            )
        }
    }?;

    Some(CrossHit {
        target,
        source,
        e_source,
        val: value,
    })
}

/// Computes all ordered target/source hits for the candidate, targeting only
/// the prime factors owned by the later local-factor stage (`p >= 5`). The
/// aggregate target valuations are also written into `candidate.cross_val`.
pub fn cross_hits(candidate: &mut Candidate) -> Vec<CrossHit> {
    candidate.cross_val = [0; crate::MAX_OMEGA];
    let factors = candidate.f[..candidate.omega as usize].to_vec();
    let mut hits = Vec::new();

    for target in factors.iter().filter(|factor| factor.p >= 5) {
        for source in factors.iter().filter(|factor| factor.p != target.p) {
            if let Some(hit) = cross_hit(target.p, source.p, source.e) {
                candidate.cross_val[target_index(candidate, target.p)] += hit.val;
                hits.push(hit);
            }
        }
    }

    hits
}

/// Computes the exact prime-power sigma term used as the independent oracle
/// for cross-hit validation.
pub fn exact_t_j(source: u64, e_source: u32) -> u128 {
    let mut power = 1u128;
    let mut sum = 0u128;
    for index in 0..=3 * e_source {
        sum = sum
            .checked_add(power)
            .expect("exact cross term does not fit in u128");
        if index < 3 * e_source {
            power = power
                .checked_mul(u128::from(source))
                .expect("exact cross term does not fit in u128");
        }
    }
    sum
}

/// Tiered exact source term for widened candidates.
pub fn exact_t_j_exact(source: u64, e_source: u32) -> crate::exact::ExactNat {
    crate::exact::exact_sigma_factor(source, e_source)
}

/// Arbitrary-precision source term used by the independent valuation checks.
pub fn exact_t_j_big(source: u64, e_source: u32) -> BigUint {
    crate::exact::exact_sigma_factor_big(source, e_source)
}

/// Returns the exact valuation of a source term at `target`, if it is a hit.
pub fn exact_cross_hit_value(target: u64, source: u64, e_source: u32) -> Option<u32> {
    let term = exact_t_j_exact(source, e_source);
    if let Some(term) = term.as_u128() {
        return (term % u128::from(target) == 0).then(|| valuation(term, u128::from(target)));
    }
    (term.valuation(target) > 0).then(|| term.valuation(target))
}

fn base_valuation(target: u32, source: u32, order: u32) -> Option<u32> {
    let target_u64 = u64::from(target);
    let mut modulus = target_u64 * target_u64;
    let mut value = 1;

    loop {
        if modpow(u64::from(source), u64::from(order), modulus) != 1 {
            return Some(value);
        }
        value += 1;
        let Some(next_modulus) = modulus.checked_mul(target_u64) else {
            // Actual candidates have an exact u128 T_j fallback available;
            // signal the caller to use it for the complete term valuation.
            return None;
        };
        modulus = next_modulus;
    }
}

fn target_index(candidate: &Candidate, target: u64) -> usize {
    candidate.f[..candidate.omega as usize]
        .iter()
        .position(|factor| factor.p == target)
        .expect("cross target must belong to candidate")
}

#[cfg(test)]
mod tests {
    use super::{cross_hit, exact_cross_hit_value};

    #[test]
    fn lte_witnesses_match_exact_terms() {
        for (target, source, exponent) in [(5, 11, 3), (5, 2, 1), (7, 2, 2)] {
            assert_eq!(
                cross_hit(target, source, exponent).map(|hit| hit.val),
                exact_cross_hit_value(target, source, exponent)
            );
        }
    }
}
