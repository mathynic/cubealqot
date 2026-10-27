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

/// Predicate path for discarded candidates. Scratch may be partial on
/// rejection; callers needing complete diagnostics must use f4 instead.
pub(crate) fn f4_short(
    context: &F4Context,
    candidate: &mut Candidate,
    residues: &[u32],
) -> Option<Rejection> {
    f4_impl(context, candidate, residues, true)
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
    assert_eq!(
        context.sieve_primes.len(),
        residues.len(),
        "F4 residue count must match sieve-prime count"
    );

    candidate.s_mod_sieve.clear();
    candidate.s_mod_sieve.resize(context.sieve_primes.len(), 0);
    candidate.foreign_zeros.clear();
    let mut rejected = false;

    for (index, &q) in context.sieve_primes.iter().enumerate() {
        let residue = residues[index];
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
