//! Flat and segmented smallest-prime-factor sieves.

use crate::factor::{Factor, MAX_OMEGA};

/// Largest endpoint for which the flat SPF representation is the default.
pub const FLAT_SPF_LIMIT: u64 = 100_000_000;

/// Default segmented width, chosen to keep the packed factor bag cache-sized.
pub const SEGMENT_WIDTH: u64 = 1 << 18;

/// Largest base-prime bound currently prepared for segmented factorization.
/// This supports controlled roots through approximately `3e6^2`.
pub const MAX_BASE_PRIME_LIMIT: u32 = 3_000_000;

/// Checks the full run endpoint before segment allocation or worker startup.
pub(crate) fn base_prime_limit(end: u64) -> Result<u32, String> {
    let root = crate::exact::isqrt(u128::from(end));
    if root > u128::from(MAX_BASE_PRIME_LIMIT) {
        return Err(format!(
            "requested range requires base-prime coverage through {root}, but configured coverage ends at {}",
            MAX_BASE_PRIME_LIMIT
        ));
    }
    Ok(u32::try_from(root).expect("base-prime horizon fits u32"))
}

/// Complete, immutable base primes prepared once for a run's endpoint.
/// Keep the coverage bound separately: it need not itself be prime.
#[derive(Debug)]
pub(crate) struct BasePrimes {
    limit: u32,
    primes: Vec<u32>,
}

impl BasePrimes {
    pub(crate) fn for_end(end: u64) -> Result<Self, String> {
        let limit = base_prime_limit(end)?;
        Ok(Self {
            limit,
            primes: primes_up_to(limit),
        })
    }
}

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
        validate_segment_bounds(start, end)?;
        let base_primes = BasePrimes::for_end(end)?;
        Self::try_new_with_base_primes(start, end, &base_primes)
    }

    /// Reuses the run's complete prime table, rejecting insufficient coverage
    /// before allocating segment buffers.
    pub(crate) fn try_new_with_base_primes(
        start: u64,
        end: u64,
        base_primes: &BasePrimes,
    ) -> Result<Self, String> {
        validate_segment_bounds(start, end)?;
        let root = base_prime_limit(end)?;
        if root > base_primes.limit {
            return Err(format!(
                "segment requires base-prime coverage through {root}, but supplied coverage ends at {}",
                base_primes.limit
            ));
        }

        let len = usize::try_from(u64::from(end) - u64::from(start) + 1)
            .expect("segmented range does not fit in usize");
        let mut rem = (0..len)
            .map(|index| start + u64::try_from(index).expect("segment index fits in u64"))
            .collect::<Vec<_>>();
        let mut counts = vec![0u8; len];
        let mut packed = vec![0u64; len * MAX_OMEGA];

        for &prime in &base_primes.primes {
            if prime > root {
                break;
            }
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

fn validate_segment_bounds(start: u64, end: u64) -> Result<(), String> {
    if start < 2 {
        return Err("segmented range must start at least at two".to_owned());
    }
    if end < start {
        return Err("segmented range end must not precede start".to_owned());
    }
    Ok(())
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
    use super::{BasePrimes, MAX_BASE_PRIME_LIMIT, SegmentedSpf, base_prime_limit, build_spf};
    use crate::{Factor, MAX_OMEGA, factor::factor_into};

    #[test]
    fn shared_base_primes_match_flat_factorizations_across_segments() {
        let spf = build_spf(65_535);
        let base_primes = BasePrimes::for_end(65_535).unwrap();
        for (start, end) in [(2, 1025), (31_000, 32_023), (64_512, 65_535)] {
            let segment = SegmentedSpf::try_new_with_base_primes(start, end, &base_primes).unwrap();
            for m in start..=end {
                let mut actual = [Factor::default(); MAX_OMEGA];
                let mut expected = actual;
                assert_eq!(
                    segment.factor_into(m, &mut actual),
                    factor_into(m, &spf, &mut expected),
                    "m={m}"
                );
                assert_eq!(actual, expected, "m={m}");
            }
        }
    }

    #[test]
    fn shared_coverage_uses_the_sieved_bound_and_rejects_a_missing_prime() {
        let base_primes = BasePrimes::for_end(100).unwrap();
        assert_eq!(base_primes.limit, 10);
        assert_eq!(base_primes.primes.last(), Some(&7));
        // sqrt(120) is still 10, and no prime from 8 through 10 is missing.
        SegmentedSpf::try_new_with_base_primes(100, 120, &base_primes).unwrap();
        let error = SegmentedSpf::try_new_with_base_primes(2, 121, &base_primes).unwrap_err();
        assert!(error.contains("coverage through 11"), "{error}");
        assert!(error.contains("coverage ends at 10"), "{error}");
    }

    #[test]
    fn shared_wide_table_covers_prime_squares_and_the_campaign_endpoint() {
        let base_primes = BasePrimes::for_end(5_000_000_000_000).unwrap();
        for (m, expected) in [
            (2_000_003u64.pow(2), vec![Factor { p: 2_000_003, e: 2 }]),
            (
                5_000_000_000_000,
                vec![Factor { p: 2, e: 12 }, Factor { p: 5, e: 13 }],
            ),
        ] {
            let segment = SegmentedSpf::try_new_with_base_primes(m, m, &base_primes).unwrap();
            let mut actual = [Factor::default(); MAX_OMEGA];
            let count = segment.factor_into(m, &mut actual);
            assert_eq!(&actual[..count as usize], expected);
        }
    }

    #[test]
    fn base_prime_coverage_accepts_the_last_supported_endpoint() {
        let first_unsupported = (u64::from(MAX_BASE_PRIME_LIMIT) + 1).pow(2);
        assert_eq!(
            base_prime_limit(first_unsupported - 1).unwrap(),
            MAX_BASE_PRIME_LIMIT
        );
        assert!(base_prime_limit(first_unsupported).is_err());
    }

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
