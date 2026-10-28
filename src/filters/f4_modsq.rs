//! F4: cheap odd-prime modular square sieve.

use crate::{
    Candidate,
    tables::{SigmaTable, SqSet},
};

use super::Rejection;

/// Precomputed data for one configured F4 sieve.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct F4Context {
    pub sieve_primes: Vec<u32>,
    pub sigma_tables: Vec<SigmaTable>,
    pub sq_sets: Vec<SqSet>,
}

impl F4Context {
    /// Builds matching sigma and square-residue tables for each sieve prime.
    pub fn new(sieve_primes: &[u32], max_e: u32) -> Self {
        let max_e = max_e.max(63);
        for &q in sieve_primes {
            assert!(
                q > 3 && q % 2 == 1,
                "F4 moduli must be odd primes above three"
            );
        }

        Self {
            sieve_primes: sieve_primes.to_vec(),
            sigma_tables: sieve_primes
                .iter()
                .map(|&q| SigmaTable::build(q, max_e))
                .collect(),
            sq_sets: sieve_primes.iter().map(|&q| SqSet::build(q)).collect(),
        }
    }
}

/// Applies the cheap F4 sieve.
///
/// Every configured residue is recorded. A zero residue at a prime dividing
/// `m` is retained for later local-factor handling; a zero at a foreign prime
/// is recorded in `foreign_zeros` and is not rejected by cheap F4. Only a
/// nonzero nonsquare residue rejects here.
pub fn f4(context: &F4Context, candidate: &mut Candidate, residues: &[u32]) -> Option<Rejection> {
    f4_impl(context, candidate, residues, false)
}

/// Predicate path for discarded candidates. Compute input residues only for
/// visited primes. Scratch may be partial on rejection; callers needing
/// complete diagnostics must use f4 instead.
pub(crate) fn f4_short(context: &F4Context, candidate: &mut Candidate) -> Option<Rejection> {
    f4_impl(context, candidate, &[], true)
}

fn f4_impl(
    context: &F4Context,
    candidate: &mut Candidate,
    residues: &[u32],
    early_exit: bool,
) -> Option<Rejection> {
    assert_eq!(
        context.sieve_primes.len(),
        context.sigma_tables.len(),
        "F4 sigma table count must match sieve-prime count"
    );
    assert_eq!(
        context.sieve_primes.len(),
        context.sq_sets.len(),
        "F4 square-set count must match sieve-prime count"
    );
    if !early_exit {
        assert_eq!(
            context.sieve_primes.len(),
            residues.len(),
            "F4 residue count must match sieve-prime count"
        );
    }

    candidate.s_mod_sieve.clear();
    candidate.s_mod_sieve.resize(context.sieve_primes.len(), 0);
    candidate.foreign_zeros.clear();
    let mut rejected = false;

    for (index, &q) in context.sieve_primes.iter().enumerate() {
        let residue = if early_exit {
            (candidate.m % u64::from(q)) as u32
        } else {
            residues[index]
        };
        assert!(residue < q, "F4 residue is outside its modulus");

        let mut sigma_product = 1u64;
        for factor in &candidate.f[..candidate.omega as usize] {
            sigma_product = sigma_product
                * u64::from(context.sigma_tables[index].sigma(factor.p, factor.e))
                % u64::from(q);
        }
        let cube = ((u128::from(residue) * u128::from(residue) * u128::from(residue))
            % u128::from(q)) as u32;
        let s_mod = ((sigma_product + u64::from(q) - u64::from(cube)) % u64::from(q)) as u32;
        candidate.s_mod_sieve[index] = s_mod;

        if s_mod == 0 {
            let q_divides_m = candidate.f[..candidate.omega as usize]
                .iter()
                .any(|factor| factor.p == u64::from(q));
            if !q_divides_m {
                candidate.foreign_zeros.push(index);
            }
        } else if !context.sq_sets[index].contains(s_mod) {
            if early_exit {
                return Some(Rejection::ModNonsquare);
            }
            rejected = true;
        }
    }

    rejected.then_some(Rejection::ModNonsquare)
}

#[cfg(test)]
mod tests {
    use super::{F4Context, f4, f4_short};
    use crate::{Candidate, Factor, MAX_OMEGA, build_spf, tables::init_residues};

    #[test]
    fn per_prime_input_residues_preserve_results_and_required_scratch() {
        let primes = [
            5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
            97,
        ];
        let reverse = primes.iter().copied().rev().collect::<Vec<_>>();
        let spf = build_spf(5000);
        let mut rows = (2u64..=5000)
            .map(|m| Candidate::new(m, &spf))
            .collect::<Vec<_>>();
        for (m, factors) in [
            (5_000_000_000_000u64, vec![(2, 12), (5, 13)]),
            (1u64 << 63, vec![(2, 63)]),
            (
                18_446_744_073_709_551_557,
                vec![(18_446_744_073_709_551_557, 1)],
            ),
            (
                3 * 2_305_843_041_732_208_837,
                vec![(3, 1), (2_305_843_041_732_208_837, 1)],
            ),
        ] {
            let mut slots = [Factor::default(); MAX_OMEGA];
            for (slot, &(p, e)) in slots.iter_mut().zip(&factors) {
                *slot = Factor { p, e };
            }
            rows.push(Candidate::from_factors(m, slots, factors.len() as u8));
        }
        for sieve_primes in [&[][..], &primes[..1], &primes[..], reverse.as_slice()] {
            let context = F4Context::new(sieve_primes, 63);
            let mut saw_partial = false;
            for row in &rows {
                let mut full = Candidate::from_factors(row.m, row.f, row.omega);
                let mut lazy = Candidate::from_factors(row.m, row.f, row.omega);
                // Reused scratch must not retain data from an earlier candidate.
                lazy.s_mod_sieve = vec![u32::MAX; sieve_primes.len() + 2];
                lazy.foreign_zeros = vec![usize::MAX];
                let residues = init_residues(sieve_primes, row.m);
                let expected = f4(&context, &mut full, &residues);
                assert_eq!(f4_short(&context, &mut lazy), expected, "m={}", row.m);
                let visited = full
                    .s_mod_sieve
                    .iter()
                    .enumerate()
                    .position(|(i, &residue)| residue != 0 && !context.sq_sets[i].contains(residue))
                    .map_or(sieve_primes.len(), |i| i + 1);
                assert_eq!(lazy.s_mod_sieve.len(), sieve_primes.len());
                assert_eq!(
                    &lazy.s_mod_sieve[..visited],
                    &full.s_mod_sieve[..visited],
                    "m={}",
                    row.m
                );
                assert!(
                    lazy.s_mod_sieve[visited..]
                        .iter()
                        .all(|&residue| residue == 0)
                );
                assert_eq!(
                    lazy.foreign_zeros,
                    full.foreign_zeros
                        .iter()
                        .copied()
                        .filter(|&i| i < visited)
                        .collect::<Vec<_>>()
                );
                saw_partial |= full.s_mod_sieve != lazy.s_mod_sieve;
                if expected.is_none() {
                    // F4b and later stages need every residue and foreign zero.
                    assert_eq!(lazy.s_mod_sieve, full.s_mod_sieve);
                    assert_eq!(lazy.foreign_zeros, full.foreign_zeros);
                }
            }
            if sieve_primes.len() > 1 {
                assert!(saw_partial, "early rejection must skip later residues");
            }
        }
    }
}
