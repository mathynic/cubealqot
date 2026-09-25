//! F4b: refinement of zeros at odd primes not dividing `m`.

use crate::{
    Candidate, exact,
    numth::{legendre, valuation},
};

use super::Rejection;
use super::f4_modsq::F4Context;

/// Maximum foreign-zero valuation tier before exact-S fallback.
pub const CAP_Q: u32 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F4bAnalysis {
    pub index: usize,
    pub q: u32,
    pub v: u32,
    pub unit: u32,
    pub used_exact_s_fallback: bool,
}

/// Computes the foreign-zero valuation using modular tiers and exact-S
/// fallback when the configured cap cannot resolve it.
pub fn v_of_s_at(candidate: &mut Candidate, q: u32, t_start: u32, t_max: u32) -> u32 {
    assert!(
        q > 3 && q % 2 == 1,
        "foreign modulus must be an odd prime above three"
    );

    if t_start <= t_max {
        for tier in t_start..=t_max {
            let Some(modulus) = prime_power(q, tier) else {
                break;
            };
            let residue = s_mod(candidate, modulus);
            if residue != 0 {
                return valuation(residue, u128::from(q));
            }
        }
    }

    exact_s_cached(candidate).valuation(u64::from(q))
}

/// Extracts `(S mod q^(v+1)) / q^v mod q`.
pub fn unit_of_s_at(candidate: &mut Candidate, q: u32, v: u32) -> u32 {
    let Some(modulus) = prime_power(q, v.saturating_add(1)) else {
        return exact_unit(candidate, q, v);
    };
    let residue = s_mod(candidate, modulus);
    if residue == 0 {
        1
    } else {
        (residue / u128::from(q).pow(v)) as u32 % q
    }
}

/// Analyzes every zero recorded by F4, without applying earlier filters.
pub fn analyze(context: &F4Context, candidate: &mut Candidate) -> Vec<F4bAnalysis> {
    let foreign_zeros = candidate.foreign_zeros.clone();
    let mut analyses = Vec::with_capacity(foreign_zeros.len());

    for index in foreign_zeros {
        assert!(
            index < context.sieve_primes.len(),
            "foreign-zero index is outside F4 context"
        );
        let q = context.sieve_primes[index];
        assert!(
            !candidate.f[..candidate.omega as usize]
                .iter()
                .any(|factor| factor.p == u64::from(q)),
            "foreign-zero modulus must not divide candidate"
        );
        let cache_before = candidate.s_cache.is_some();
        let v = v_of_s_at(candidate, q, 2, CAP_Q);
        let used_exact_s_fallback = !cache_before && candidate.s_cache.is_some();
        let unit = unit_of_s_at(candidate, q, v);
        analyses.push(F4bAnalysis {
            index,
            q,
            v,
            unit,
            used_exact_s_fallback,
        });
    }

    analyses
}

/// Applies the foreign-zero refinement. All recorded zeros are analyzed so a
/// validation trace cannot hide later entries behind an early rejection.
pub fn f4b(context: &F4Context, candidate: &mut Candidate) -> Option<Rejection> {
    let mut first_rejection = None;
    for analysis in analyze(context, candidate) {
        let rejection = if analysis.v % 2 == 1 {
            Some(Rejection::ModZeroOddVal)
        } else if legendre(analysis.unit, analysis.q) == -1 {
            Some(Rejection::ModZeroBadUnit)
        } else {
            None
        };
        if first_rejection.is_none() {
            first_rejection = rejection;
        }
    }
    first_rejection
}

fn s_mod(candidate: &Candidate, modulus: u128) -> u128 {
    exact::s_mod(candidate, modulus)
}

fn prime_power(prime: u32, exponent: u32) -> Option<u128> {
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

fn exact_unit(candidate: &mut Candidate, q: u32, v: u32) -> u32 {
    exact_s_cached(candidate).unit_mod(u64::from(q), v) as u32
}
