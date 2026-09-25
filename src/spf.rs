//! Flat and segmented smallest-prime-factor sieves.

use crate::factor::{Factor, MAX_OMEGA};

/// Largest endpoint for which the flat SPF representation is the default.
pub const FLAT_SPF_LIMIT: u64 = 100_000_000;

/// Default segmented width, chosen to keep the packed factor bag cache-sized.
pub const SEGMENT_WIDTH: u64 = 1 << 18;

/// Largest base-prime bound currently prepared for segmented factorization.
/// This supports controlled roots through approximately `2e6^2`.
pub const MAX_BASE_PRIME_LIMIT: u32 = 2_000_000;

/// Builds a flat SPF table for `0..=limit`.
///
/// Prime entries remain zero. Every composite entry contains its smallest
/// prime factor. The `u16` representation is sufficient for the `u32` search
/// domain because a composite `u32` has a prime factor at most `sqrt(u32)`.
pub fn build_spf(limit: u32) -> Vec<u16> {
    let len = (limit as usize)
        .checked_add(1)
        .expect("SPF limit does not fit in the platform address space");
    let mut spf = vec![0u16; len];

    for p in 2..=limit {
        if spf[p as usize] != 0 {
            continue;
        }

        // Avoid overflowing p*p and avoid visiting multiples when p is above
        // the square root; those entries are either prime or already marked.
        if p <= limit / p {
            let first = p * p;
            for multiple in (first..=limit).step_by(p as usize) {
                let slot = &mut spf[multiple as usize];
                if *slot == 0 {
                    *slot = p as u16;
                }
            }
        }
    }

    spf
}

/// Short alias for [`build_spf`].
pub fn build(limit: u32) -> Vec<u16> {
    build_spf(limit)
}

/// Factor data for one inclusive segment `[start, end]`.
///
/// `rem` holds the residual after all base-prime divisions. `packed` is a
/// fixed-width flat bag of `(prime << 6) | exponent` entries; six exponent
/// bits represent the complete `u64`-domain exponent range `0..=63`.
#[derive(Clone, Debug)]
pub struct SegmentedSpf {
    start: u64,
    end: u64,
    rem: Vec<u64>,
    counts: Vec<u8>,
    packed: Vec<u64>,
}

impl SegmentedSpf {
    /// Builds a segmented factorization table for the inclusive range.
    pub fn new(start: impl Into<u64>, end: impl Into<u64>) -> Self {
        Self::try_new(start, end).unwrap_or_else(|error| panic!("{error}"))
    }

    /// Fallible constructor that rejects ranges requiring unavailable base
    /// primes before allocating the segment or starting the search.
    pub fn try_new(start: impl Into<u64>, end: impl Into<u64>) -> Result<Self, String> {
        let start = start.into();
        let end = end.into();
        if start < 2 {
            return Err("segmented range must start at least at two".to_owned());
        }
        if end < start {
            return Err("segmented range end must not precede start".to_owned());
        }
        let root = crate::exact::isqrt(u128::from(end));
        if root > u128::from(MAX_BASE_PRIME_LIMIT) {
            return Err(format!(
                "requested range requires base-prime coverage through {root}, but configured coverage ends at {}",
                MAX_BASE_PRIME_LIMIT
            ));
        }
        let root = u32::try_from(root).expect("base-prime horizon fits u32");

        let len = usize::try_from(u64::from(end) - u64::from(start) + 1)
            .expect("segmented range does not fit in usize");
        let mut rem = (0..len)
            .map(|index| start + u64::try_from(index).expect("segment index fits in u64"))
            .collect::<Vec<_>>();
        let mut counts = vec![0u8; len];
        let mut packed = vec![0u64; len * MAX_OMEGA];

        for prime in primes_up_to(root) {
            let first = u64::from(start).div_ceil(u64::from(prime)) * u64::from(prime);
            let mut multiple = first;
            while multiple <= u64::from(end) {
                let index = usize::try_from(multiple - u64::from(start))
                    .expect("segment offset fits in usize");
                let mut exponent = 0u32;
                while rem[index] % u64::from(prime) == 0 {
                    rem[index] /= u64::from(prime);
                    exponent += 1;
                }
                if exponent != 0 {
                    let count = counts[index] as usize;
                    assert!(count < MAX_OMEGA, "factorization exceeds MAX_OMEGA");
                    assert!(exponent <= 63, "factor exponent exceeds packed width");
                    packed[index * MAX_OMEGA + count] =
                        (u64::from(prime) << 6) | u64::from(exponent);
                    counts[index] += 1;
                }
                multiple += u64::from(prime);
            }
        }

        Ok(Self {
            start,
            end,
            rem,
            counts,
            packed,
        })
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    pub fn len(&self) -> usize {
        self.rem.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rem.is_empty()
    }

    /// Copies the ascending factorization of `m` into `out`.
    pub fn factor_into(&self, m: impl Into<u64>, out: &mut [Factor; MAX_OMEGA]) -> u8 {
        let m = m.into();
        assert!(m >= self.start && m <= self.end, "value is outside segment");
        *out = [Factor::default(); MAX_OMEGA];

        let index = usize::try_from(m - self.start).expect("segment offset fits in usize");
        let mut count = self.counts[index] as usize;
        for slot in 0..count {
            let encoded = self.packed[index * MAX_OMEGA + slot];
            out[slot] = Factor {
                p: encoded >> 6,
                e: u32::try_from(encoded & 0x3f).expect("packed exponent fits u32"),
            };
        }
        if self.rem[index] > 1 {
            assert!(count < MAX_OMEGA, "factorization exceeds MAX_OMEGA");
            out[count] = Factor {
                p: self.rem[index],
                e: 1,
            };
            count += 1;
        }
        count as u8
    }
}

fn primes_up_to(limit: u32) -> Vec<u32> {
    let len = usize::try_from(limit)
        .expect("prime limit fits in usize")
        .saturating_add(1);
    let mut composite = vec![false; len];
    let mut primes = Vec::new();
    for candidate in 2..=limit {
        let index = candidate as usize;
        if composite[index] {
            continue;
        }
        primes.push(candidate);
        if candidate <= limit / candidate {
            let first = candidate * candidate;
            for multiple in (first..=limit).step_by(candidate as usize) {
                composite[multiple as usize] = true;
            }
        }
    }
    primes
}

#[cfg(test)]
mod tests {
    use super::build_spf;

    #[test]
    fn primes_are_zero_and_composites_are_marked() {
        let spf = build_spf(12);

        assert_eq!(spf[2], 0);
        assert_eq!(spf[3], 0);
        assert_eq!(spf[4], 2);
        assert_eq!(spf[6], 2);
        assert_eq!(spf[9], 3);
        assert_eq!(spf[12], 2);
    }
}
