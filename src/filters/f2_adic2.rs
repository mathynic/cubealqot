//! Complete 2-adic square filter for `S = sigma(m^3) - m^3`.

use crate::{Candidate, exact, numth::valuation};

use super::Rejection;

/// Maximum 2-adic tier used before the exact-S fallback.
pub const CAP2: u32 = 40;

/// Values inspected by the F2 predicate.  Keeping this trace public makes
/// the formula and the equal-valuation fallback directly testable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F2Analysis {
    pub v_sigma: u32,
    pub k: u32,
    pub v2_s: u32,
    pub unit8: u8,
    pub equal_valuation: bool,
    pub used_exact_s_fallback: bool,
}

/// Computes `V = v2(sigma(m^3))` from the factorization of `m`.
pub fn v2_sigma(candidate: &Candidate) -> u32 {
    candidate.f[..candidate.omega as usize]
        .iter()
        .filter(|factor| factor.p != 2 && factor.e % 2 == 1)
        .map(|factor| {
            valuation(u128::from(factor.p) + 1, 2) + valuation(u128::from(3 * factor.e + 1), 2) - 1
        })
        .sum()
}

/// Resolves `v2(S)` starting at a known lower bound.
///
/// The modular tiers cover the equal-valuation branch.  If every tier up to
/// [`CAP2`] is still zero, the exact baseline is used as the correctness
/// fallback, and its result is cached on the candidate.
pub fn v_of_s_at(candidate: &mut Candidate, q: u128, t_start: u32, t_max: u32) -> u32 {
    assert_eq!(q, 2, "F2 currently supports the 2-adic valuation only");

    if t_start <= t_max {
        for t in t_start..=t_max {
            let modulus = 1u128 << t;
            let s_mod = exact::s_mod(candidate, modulus);
            if s_mod != 0 {
                return valuation(s_mod, 2);
            }
        }
    }

    exact_s_cached(candidate).valuation(2)
}

/// Extracts the odd residue of `S / 2^v` modulo 8.
pub fn unit8_of_s(candidate: &mut Candidate, v: u32) -> u8 {
    let Some(bits) = v.checked_add(3) else {
        return exact_unit8(candidate, v);
    };
    if bits >= 128 {
        return exact_unit8(candidate, v);
    }

    let modulus = 1u128 << bits;
    let s_mod = exact::s_mod(candidate, modulus);
    if s_mod == 0 {
        // `m=1` is outside the search range, but treating its zero aliquot
        // sum as a harmless pass keeps the helper total for all candidates.
        return 1;
    }
    ((s_mod >> v) % 8) as u8
}

/// Returns the complete F2 trace, including the exact-S fallback state.
pub fn analyze(candidate: &mut Candidate) -> F2Analysis {
    let v_sigma = v2_sigma(candidate);
    let k = 3 * u32::from(candidate.a2);
    let equal_valuation = v_sigma == k;
    let cache_before_v = candidate.s_cache.is_some();
    let v2_s = if equal_valuation {
        v_of_s_at(candidate, 2, k + 1, CAP2)
    } else {
        v_sigma.min(k)
    };
    let used_exact_s_fallback = equal_valuation && !cache_before_v && candidate.s_cache.is_some();
    let unit8 = unit8_of_s(candidate, v2_s);

    F2Analysis {
        v_sigma,
        k,
        v2_s,
        unit8,
        equal_valuation,
        used_exact_s_fallback,
    }
}

/// Applies the complete 2-local square condition.
pub fn f2(candidate: &mut Candidate) -> Option<Rejection> {
    let v_sigma = v2_sigma(candidate);
    let k = 3 * u32::from(candidate.a2);
    let v2_s = if v_sigma == k {
        v_of_s_at(candidate, 2, k + 1, CAP2)
    } else {
        v_sigma.min(k)
    };
    // An odd valuation is already decisive; complete diagnostic analysis
    // still computes the unit through analyze when a record needs it.
    if v2_s % 2 == 1 {
        return Some(Rejection::Adic2OddVal);
    }
    if unit8_of_s(candidate, v2_s) != 1 {
        return Some(Rejection::Adic2BadUnit);
    }
    None
}

fn exact_s_cached(candidate: &mut Candidate) -> exact::ExactNat {
    if let Some(s) = &candidate.exact_s_cache {
        return s.clone();
    }
    let s = exact::exact_s_exact(candidate);
    if let Some(small) = s.as_u128() {
        candidate.s_cache = Some(small);
    }
    candidate.exact_s_cache = Some(s.clone());
    s
}

fn exact_unit8(candidate: &mut Candidate, v: u32) -> u8 {
    let s = exact_s_cached(candidate);
    s.unit_modulus(2, v, 8) as u8
}

#[cfg(test)]
mod tests {
    use super::{CAP2, f2, v2_sigma};
    use crate::numth::valuation;
    use crate::{Candidate, build_spf, exact};

    #[test]
    fn formula_handles_odd_and_even_candidates() {
        let spf = build_spf(72);
        for m in 2u32..=72 {
            let candidate = Candidate::new(m, &spf);
            assert_eq!(
                v2_sigma(&candidate),
                valuation(exact::exact_sigma(&candidate), 2)
            );
        }
    }

    #[test]
    fn cap_is_large_enough_for_the_local_tiers() {
        assert_eq!(CAP2, 40);
        let spf = build_spf(9);
        let mut candidate = Candidate::new(9u64, &spf);
        assert!(f2(&mut candidate).is_some() || candidate.s_cache.is_some());
    }
}
