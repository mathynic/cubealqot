//! F7: cheap special-family tests and tags.

use serde::{Deserialize, Serialize};

use crate::{Candidate, tables::SigmaTable};

use super::Rejection;

/// Primes congruent to 3 modulo 4 used by the sum-of-two-squares test.
pub const DEFAULT_SPECIAL_PRIMES: [u32; 10] = [3, 7, 11, 19, 23, 31, 43, 47, 59, 67];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FamilyTag {
    #[serde(rename = "sq")]
    Sq,
    #[serde(rename = "2sq")]
    TwoSq,
    #[serde(rename = "pq_handoff")]
    PqHandoff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpecialCheck {
    pub prime: u32,
    pub sigma_mod_prime: u32,
    pub sigma_mod_prime_squared: u32,
    pub rejects: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct F7Context {
    pub special_primes: Vec<u32>,
    pub sigma_tables: Vec<SigmaTable>,
}

impl F7Context {
    pub fn new(special_primes: &[u32], max_e: u32) -> Self {
        let max_e = max_e.max(63);
        for &prime in special_primes {
            assert!(
                prime >= 3 && prime % 4 == 3,
                "F7 primes must be congruent to three modulo four"
            );
        }
        Self {
            special_primes: special_primes.to_vec(),
            sigma_tables: special_primes
                .iter()
                .map(|&prime| SigmaTable::build(prime * prime, max_e))
                .collect(),
        }
    }
}

impl Default for F7Context {
    fn default() -> Self {
        Self::new(&DEFAULT_SPECIAL_PRIMES, 31)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct F7Analysis {
    pub family: Option<FamilyTag>,
    pub checks: Vec<SpecialCheck>,
}

/// Returns the exact structural family tag, when one applies.
pub fn family_tag(candidate: &Candidate) -> Option<FamilyTag> {
    let factors = &candidate.f[..candidate.omega as usize];
    if factors.iter().all(|factor| factor.e % 2 == 0) {
        return Some(FamilyTag::Sq);
    }
    if candidate.a2 == 1
        && factors
            .iter()
            .filter(|factor| factor.p != 2)
            .all(|factor| factor.e % 2 == 0)
    {
        return Some(FamilyTag::TwoSq);
    }
    if factors.len() == 2
        && factors
            .iter()
            .all(|factor| factor.p % 2 == 1 && factor.e == 1)
    {
        return Some(FamilyTag::PqHandoff);
    }
    None
}

/// Analyzes all configured square-family checks without short-circuiting.
pub fn analyze(context: &F7Context, candidate: &Candidate) -> F7Analysis {
    let family = family_tag(candidate);
    let checks = if family == Some(FamilyTag::Sq) {
        context
            .special_primes
            .iter()
            .zip(&context.sigma_tables)
            .map(|(&prime, table)| {
                let sigma_mod_prime_squared = sigma_mod(candidate, table);
                let sigma_mod_prime = sigma_mod_prime_squared % prime;
                SpecialCheck {
                    prime,
                    sigma_mod_prime,
                    sigma_mod_prime_squared,
                    rejects: sigma_mod_prime == 0 && sigma_mod_prime_squared != 0,
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    F7Analysis { family, checks }
}

/// Applies the cheap F7 rejection. Tags never reject; they annotate families
/// for later consumers.
pub fn f7(context: &F7Context, candidate: &Candidate) -> Option<Rejection> {
    analyze(context, candidate)
        .checks
        .iter()
        .any(|check| check.rejects)
        .then_some(Rejection::SpecialSumTwoSquares)
}

fn sigma_mod(candidate: &Candidate, table: &SigmaTable) -> u32 {
    candidate.f[..candidate.omega as usize]
        .iter()
        .fold(1u64, |product, factor| {
            product * u64::from(table.sigma(factor.p, factor.e)) % u64::from(table.modulus)
        }) as u32
}

#[cfg(test)]
mod tests {
    use super::{F7Context, FamilyTag, analyze, f7};
    use crate::{Candidate, build_spf};

    #[test]
    fn special_families_are_tagged() {
        let spf = build_spf(36);
        assert_eq!(
            analyze(&F7Context::default(), &Candidate::new(36u64, &spf)).family,
            Some(FamilyTag::Sq)
        );
        assert_eq!(
            analyze(&F7Context::default(), &Candidate::new(18u64, &spf)).family,
            Some(FamilyTag::TwoSq)
        );
        assert_eq!(
            analyze(&F7Context::default(), &Candidate::new(15u64, &spf)).family,
            Some(FamilyTag::PqHandoff)
        );
    }

    #[test]
    fn sum_of_two_squares_check_has_witness() {
        let spf = build_spf(121);
        let context = F7Context::default();
        assert!(f7(&context, &Candidate::new(121u64, &spf)).is_some());
    }
}
