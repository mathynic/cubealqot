//! Complete 3-adic square filter for `S = sigma(m^3) - m^3`.

use crate::{Candidate, exact, numth::valuation, tables::SigmaTable};

use super::Rejection;

/// Maximum 3-adic tier used before the exact-S fallback.
pub const CAP3: u32 = 12;

/// Small context for the first, modulus-3 table lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct F3Context {
    pub sigma3: SigmaTable,
}

impl F3Context {
    pub fn new(max_e: u32) -> Self {
        Self {
            sigma3: SigmaTable::build(3, max_e.max(63)),
        }
    }
}

impl Default for F3Context {
    fn default() -> Self {
        Self::new(63)
    }
}

/// Values inspected by the F3 predicate.  The trace keeps the unit visible
/// so positive even valuations cannot be accidentally tested as raw `S % 3`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F3Analysis {
    pub s_mod3: u8,
    pub v_sigma: u32,
    pub v3_s: u32,
    pub unit3: u8,
    pub entered_zero_branch: bool,
    pub used_exact_s_fallback: bool,
}

/// Computes `V = v3(sigma(m^3))` from the factorization of `m`.
pub fn v3_sigma(candidate: &Candidate) -> u32 {
    candidate.f[..candidate.omega as usize]
        .iter()
        .filter(|factor| factor.p != 3 && factor.p % 3 == 2 && factor.e % 2 == 1)
        .map(|factor| valuation(u128::from(factor.p) + 1, 3))
        .sum()
}

/// Resolves `v3(S)` from the first vanishing modulus-3 tier onward.
pub fn v_of_s_at(candidate: &mut Candidate, q: u128, t_start: u32, t_max: u32) -> u32 {
    assert_eq!(q, 3, "F3 currently supports the 3-adic valuation only");

    if t_start <= t_max {
        for t in t_start..=t_max {
            let modulus = 3u128.pow(t);
            let s_mod = exact::s_mod(candidate, modulus);
            if s_mod != 0 {
                return valuation(s_mod, 3);
            }
        }
    }

    exact_s_cached(candidate).valuation(3)
}

/// Extracts `(S mod 3^(v+1)) / 3^v mod 3`.
pub fn unit3_of_s(candidate: &mut Candidate, v: u32) -> u8 {
    let Some(exponent) = v.checked_add(1) else {
        return exact_unit3(candidate, v);
    };
    if exponent >= 81 {
        return exact_unit3(candidate, v);
    }

    let modulus = 3u128.pow(exponent);
    let s_mod = exact::s_mod(candidate, modulus);
    if s_mod == 0 {
        // `m=1` is outside the search range. Its zero aliquot sum is treated
        // as a harmless pass so the helper remains total.
        return 1;
    }
    ((s_mod / 3u128.pow(v)) % 3) as u8
}

/// Returns the complete F3 trace using the default modulus-3 computation.
pub fn analyze(candidate: &mut Candidate) -> F3Analysis {
    analyze_with_context(&F3Context::default(), candidate)
}

/// Returns the complete F3 trace using a caller-provided modulus-3 table.
pub fn analyze_with_context(context: &F3Context, candidate: &mut Candidate) -> F3Analysis {
    let sig3 = candidate.f[..candidate.omega as usize]
        .iter()
        .map(|factor| context.sigma3.sigma(factor.p, factor.e))
        .fold(1u32, |product, term| product * term % 3);
    let s_mod3 = ((sig3 + 3 - exact::m3_mod(candidate, 3) as u32) % 3) as u8;
    let v_sigma = v3_sigma(candidate);

    if s_mod3 != 0 {
        return F3Analysis {
            s_mod3,
            v_sigma,
            v3_s: 0,
            unit3: s_mod3,
            entered_zero_branch: false,
            used_exact_s_fallback: false,
        };
    }

    let cache_before = candidate.s_cache.is_some();
    let v3_s = v_of_s_at(candidate, 3, 2, CAP3);
    let used_exact_s_fallback = !cache_before && candidate.s_cache.is_some();
    let unit3 = unit3_of_s(candidate, v3_s);

    F3Analysis {
        s_mod3,
        v_sigma,
        v3_s,
        unit3,
        entered_zero_branch: true,
        used_exact_s_fallback,
    }
}

/// Applies the complete 3-local square condition.
pub fn f3(candidate: &mut Candidate) -> Option<Rejection> {
    f3_with_context(&F3Context::default(), candidate)
}

/// Applies F3 using a reusable modulus-3 table context.
pub fn f3_with_context(context: &F3Context, candidate: &mut Candidate) -> Option<Rejection> {
    // The rejection test does not need the diagnostic v3(sigma) value.
    let sig3 = candidate.f[..candidate.omega as usize]
        .iter()
        .map(|factor| context.sigma3.sigma(factor.p, factor.e))
        .fold(1u32, |product, term| product * term % 3);
    // m^3 == m modulo 3 for every integer m.
    let s_mod3 = (sig3 + 3 - (candidate.m % 3) as u32) % 3;
    match s_mod3 {
        2 => Some(Rejection::Adic3Nonsquare),
        1 => None,
        0 => {
            let v = v_of_s_at(candidate, 3, 2, CAP3);
            if v % 2 == 1 {
                return Some(Rejection::Adic3OddVal);
            }
            (unit3_of_s(candidate, v) != 1).then_some(Rejection::Adic3BadUnit)
        }
        _ => unreachable!(),
    }
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

fn exact_unit3(candidate: &mut Candidate, v: u32) -> u8 {
    let s = exact_s_cached(candidate);
    s.unit_mod(3, v) as u8
}
