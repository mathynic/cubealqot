//! F5/F6 local-factor decision over the cross-analysis aggregates.

use std::cmp::Ordering;

use crate::{
    Candidate, cross, exact,
    numth::{legendre, valuation},
};

use super::Rejection;

/// Maximum local-prime cascade tier before exact-S fallback.
pub const CAP_P: u32 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalCase {
    Less,
    Equal,
    Greater,
}

/// Trace for one target prime factor `p_i >= 5`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAnalysis {
    pub target: u64,
    pub exponent: u32,
    pub v_sigma: u32,
    pub threshold: u32,
    pub case: LocalCase,
    pub v_s: u32,
    pub unit: u32,
    pub used_exact_s_fallback: bool,
}

/// Computes `(S / p^v) mod p`, using modular arithmetic when the requested
/// tier fits and exact S otherwise.
pub fn unit_of_s_at(candidate: &mut Candidate, p: u64, v: u32) -> u32 {
    assert!(
        p <= u64::from(u32::MAX),
        "F5/F6 local unit helper does not support wide prime outputs"
    );
    let Some(modulus) = prime_power(p, v.saturating_add(1)) else {
        return exact_unit(candidate, p, v);
    };
    let s_mod = s_mod(candidate, modulus);
    if s_mod == 0 {
        return 1;
    }
    let prime = u32::try_from(p).expect("local prime does not fit legacy unit type");
    (s_mod / u128::from(p).pow(v)) as u32 % prime
}

/// Resolves a local valuation from the supplied starting tier through the
/// configured cap, then falls back to exact S if all tiers remain zero.
pub fn v_of_s_at(candidate: &mut Candidate, p: u64, t_start: u32, t_max: u32) -> u32 {
    assert!(
        p >= 5 && p % 2 == 1,
        "local target must be an odd prime >= 5"
    );

    if t_start <= t_max {
        for tier in t_start..=t_max {
            let Some(modulus) = prime_power(p, tier) else {
                break;
            };
            let residue = s_mod(candidate, modulus);
            if residue != 0 {
                return valuation(residue, u128::from(p));
            }
        }
    }

    exact_s_cached(candidate).valuation(p)
}

/// Produces the local analysis for all target factors `p_i >= 5`.
pub fn analyze(candidate: &mut Candidate) -> Vec<LocalAnalysis> {
    if candidate.f[..candidate.omega as usize]
        .iter()
        .any(|factor| factor.p > u64::from(u32::MAX))
    {
        // The legacy local-analysis record stores units in u32 and the
        // order/LTE fast path is not yet widened for arbitrary prime inputs.
        // Returning no local decisions is an explicit defer, never a guess.
        return Vec::new();
    }
    let _ = cross::cross_hits(candidate);
    let factors = candidate.f[..candidate.omega as usize].to_vec();
    let mut analysis = Vec::new();

    for (index, target) in factors
        .iter()
        .enumerate()
        .filter(|(_, factor)| factor.p >= 5)
    {
        let threshold = 3 * target.e;
        let v_sigma = candidate.cross_val[index];
        let case = match v_sigma.cmp(&threshold) {
            Ordering::Less => LocalCase::Less,
            Ordering::Equal => LocalCase::Equal,
            Ordering::Greater => LocalCase::Greater,
        };
        let cache_before = candidate.s_cache.is_some();
        let v_s = match case {
            LocalCase::Less => v_sigma,
            LocalCase::Greater => threshold,
            LocalCase::Equal => v_of_s_at(candidate, target.p, threshold + 1, CAP_P),
        };
        let used_exact_s_fallback =
            case == LocalCase::Equal && !cache_before && candidate.s_cache.is_some();
        let unit = match case {
            LocalCase::Greater => greater_unit(candidate, target.p, target.e),
            LocalCase::Less | LocalCase::Equal => unit_of_s_at(candidate, target.p, v_s),
        };

        analysis.push(LocalAnalysis {
            target: target.p,
            exponent: target.e,
            v_sigma,
            threshold,
            case,
            v_s,
            unit,
            used_exact_s_fallback,
        });
    }

    analysis
}

/// Applies the unified local square condition to every target factor.
pub fn f56(candidate: &mut Candidate) -> Option<Rejection> {
    if candidate.f[..candidate.omega as usize]
        .iter()
        .any(|factor| factor.p > u64::from(u32::MAX))
    {
        // The order/LTE implementation is still a u32-era optimization.
        // Widened candidates defer to later exact handling until a future
        // local-order/LTE widening pass.
        return None;
    }
    for local in analyze(candidate) {
        if local.v_s % 2 == 1 {
            return Some(Rejection::LocalFactorOddVal);
        }
        if legendre(
            local.unit,
            u32::try_from(local.target).expect("local prime does not fit legacy unit type"),
        ) == -1
        {
            return Some(Rejection::LocalFactorBadUnit);
        }
    }
    None
}

fn greater_unit(candidate: &Candidate, target: u64, exponent: u32) -> u32 {
    let Some(divisor) = target.checked_pow(exponent) else {
        return 1;
    };
    let reduced = candidate.m / divisor;
    let residue =
        u32::try_from(exact::cube_mod(reduced, target)).expect("supported local residue fits u32");
    if residue == 0 {
        0
    } else {
        u32::try_from(target - u64::from(residue)).expect("local prime does not fit unit type")
    }
}

fn s_mod(candidate: &Candidate, modulus: u128) -> u128 {
    exact::s_mod(candidate, modulus)
}

fn prime_power(prime: u64, exponent: u32) -> Option<u128> {
    let mut result = 1u128;
    for _ in 0..exponent {
        result = result.checked_mul(u128::from(prime))?;
    }
    Some(result)
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

fn exact_unit(candidate: &mut Candidate, p: u64, v: u32) -> u32 {
    u32::try_from(exact_s_cached(candidate).unit_mod(p, v)).expect("supported local unit fits u32")
}

#[cfg(test)]
mod tests {
    use super::{LocalCase, analyze, f56};
    use crate::{Candidate, build_spf};

    #[test]
    fn all_three_local_cases_are_reachable() {
        let spf = build_spf(2_215);
        let less = analyze(&mut Candidate::new(10u64, &spf));
        let equal = analyze(&mut Candidate::new(965u64, &spf));
        let greater = analyze(&mut Candidate::new(2_215u64, &spf));
        assert!(less.iter().any(|local| local.case == LocalCase::Less));
        assert!(equal.iter().any(|local| local.case == LocalCase::Equal));
        assert!(greater.iter().any(|local| local.case == LocalCase::Greater));
        let _ = f56(&mut Candidate::new(10u64, &spf));
    }
}
