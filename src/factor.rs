//! Factorization data structures and the flat-SPF factor walk.

/// Maximum number of distinct prime factors for a positive `u64` input.
pub const MAX_OMEGA: usize = 15;

pub type Root = u64;
pub type Prime = u64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Factor {
    pub p: Prime,
    pub e: u32,
}

/// A factorized search candidate and its worker-local scratch state.
#[derive(Debug)]
pub struct Candidate {
    pub m: Root,
    pub f: [Factor; MAX_OMEGA],
    pub omega: u8,
    pub a2: u8,
    pub s_mod_sieve: Vec<u32>,
    pub foreign_zeros: Vec<usize>,
    pub cross_val: [u32; MAX_OMEGA],
    pub s_cache: Option<u128>,
    /// Representation-neutral cache reserved for widened exact fallbacks.
    pub exact_s_cache: Option<crate::exact::ExactNat>,
}

impl Candidate {
    /// Factorizes `m` using `spf` and initializes all later-stage scratch.
    pub fn new(m: impl Into<Root>, spf: &[u16]) -> Self {
        let m = m.into();
        let mut factors = [Factor::default(); MAX_OMEGA];
        let omega = factor_into(m, spf, &mut factors);
        Self::from_factors(m, factors, omega)
    }

    /// Initializes a candidate from a factorization produced by either the
    /// flat or segmented factorizer.
    pub fn from_factors(m: impl Into<Root>, factors: [Factor; MAX_OMEGA], omega: u8) -> Self {
        let m = m.into();
        assert!(m > 0, "candidate input must be positive");
        assert!((omega as usize) <= MAX_OMEGA, "invalid factor count");
        let a2 = if omega > 0 && factors[0].p == 2 {
            factors[0].e as u8
        } else {
            0
        };

        Self {
            m,
            f: factors,
            omega,
            a2,
            s_mod_sieve: Vec::new(),
            foreign_zeros: Vec::new(),
            cross_val: [0; MAX_OMEGA],
            s_cache: None,
            exact_s_cache: None,
        }
    }

    /// Returns `m^3` in the exact arithmetic type used by the baseline.
    pub fn m3(&self) -> u128 {
        u128::from(self.m)
            .checked_pow(3)
            .expect("exact u128 arithmetic does not cover this root yet")
    }
}

/// Factorizes `m` into ascending `(prime, exponent)` pairs using a flat SPF.
///
/// The SPF table must contain an entry for every value through `m`. Prime
/// residuals are represented by zero SPF entries, as produced by
/// [`crate::spf::build_spf`]. The output array is cleared first so callers can
/// safely reuse it between candidates.
pub fn factor_into(m: impl Into<Root>, spf: &[u16], out: &mut [Factor; MAX_OMEGA]) -> u8 {
    let m = m.into();
    assert!(m > 0, "factorization input must be positive");
    let m_index = usize::try_from(m).expect("factorization input does not fit usize");
    assert!(
        m_index < spf.len(),
        "SPF table does not cover factorization input"
    );

    *out = [Factor::default(); MAX_OMEGA];

    let mut x = m;
    let mut count = 0usize;
    while x > 1 {
        let x_index = usize::try_from(x).expect("factorization input does not fit usize");
        let spf_factor = spf[x_index] as Prime;
        if spf_factor == 0 {
            assert!(count < MAX_OMEGA, "factorization exceeds MAX_OMEGA");
            out[count] = Factor { p: x, e: 1 };
            count += 1;
            break;
        }

        let p = spf_factor;
        assert!(p >= 2 && x % p == 0, "invalid SPF table entry");
        let mut exponent = 0;
        while x % p == 0 {
            x /= p;
            exponent += 1;
        }

        assert!(count < MAX_OMEGA, "factorization exceeds MAX_OMEGA");
        out[count] = Factor { p, e: exponent };
        count += 1;
    }

    count as u8
}

#[cfg(test)]
mod tests {
    use super::{Factor, MAX_OMEGA, factor_into};
    use crate::spf::build_spf;

    #[test]
    fn one_has_no_factors() {
        let spf = build_spf(1);
        let mut factors = [Factor::default(); MAX_OMEGA];
        assert_eq!(factor_into(1u64, &spf, &mut factors), 0);
        assert_eq!(factors, [Factor::default(); MAX_OMEGA]);
    }

    #[test]
    fn factors_are_emitted_in_ascending_order() {
        let spf = build_spf(72);
        let mut factors = [Factor::default(); MAX_OMEGA];
        let omega = factor_into(72u64, &spf, &mut factors);
        assert_eq!(omega, 2);
        assert_eq!(factors[0], Factor { p: 2, e: 3 });
        assert_eq!(factors[1], Factor { p: 3, e: 2 });
    }
}
