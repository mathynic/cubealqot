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

    /// Reuses worker storage after factorization has replaced `self.f`,
    /// including its inactive slots. Keep capacities but discard all data
    /// and exact caches belonging to the previous root.
    #[inline]
    pub(crate) fn reset_after_factorization(&mut self, m: Root, omega: u8) {
        assert!(m > 0, "candidate input must be positive");
        assert!((omega as usize) <= MAX_OMEGA, "invalid factor count");
        self.m = m;
        self.omega = omega;
        self.a2 = if omega > 0 && self.f[0].p == 2 {
            self.f[0].e as u8
        } else {
            0
        };
        self.s_mod_sieve.clear();
        self.foreign_zeros.clear();
        self.cross_val.fill(0);
        self.s_cache = None;
        self.exact_s_cache = None;
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
    fn reused_candidate_resets_every_scratch_field_and_keeps_vector_capacity() {
        let spf = build_spf(72);
        let mut candidate = super::Candidate::new(72u64, &spf);
        for m in [45u64, 18, 7, 64, 3] {
            candidate.s_mod_sieve = vec![97; 23];
            candidate.foreign_zeros = vec![0, 2, 4];
            candidate.cross_val.fill(u32::MAX);
            candidate.s_cache = Some(123);
            candidate.exact_s_cache = Some(crate::exact::ExactNat::from_biguint(
                num_bigint::BigUint::from(1u8) << 200usize,
            ));
            let sieve_capacity = candidate.s_mod_sieve.capacity();
            let zero_capacity = candidate.foreign_zeros.capacity();
            let sieve_pointer = candidate.s_mod_sieve.as_ptr();
            let zero_pointer = candidate.foreign_zeros.as_ptr();
            let omega = factor_into(m, &spf, &mut candidate.f);
            candidate.reset_after_factorization(m, omega);
            let fresh = super::Candidate::new(m, &spf);
            assert_eq!(candidate.m, fresh.m);
            assert_eq!(candidate.f, fresh.f);
            assert_eq!(candidate.omega, fresh.omega);
            assert_eq!(candidate.a2, fresh.a2);
            assert_eq!(candidate.cross_val, fresh.cross_val);
            assert_eq!(candidate.s_cache, fresh.s_cache);
            assert_eq!(candidate.exact_s_cache, fresh.exact_s_cache);
            assert_eq!(candidate.s_mod_sieve, fresh.s_mod_sieve);
            assert_eq!(candidate.foreign_zeros, fresh.foreign_zeros);
            assert_eq!(candidate.s_mod_sieve.capacity(), sieve_capacity);
            assert_eq!(candidate.foreign_zeros.capacity(), zero_capacity);
            assert_eq!(candidate.s_mod_sieve.as_ptr(), sieve_pointer);
            assert_eq!(candidate.foreign_zeros.as_ptr(), zero_pointer);
        }
    }

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
