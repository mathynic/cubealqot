//! F1: structural prime-power rejection.

use crate::Candidate;

use super::Rejection;

/// Applies F1 to one candidate.
///
/// A candidate with one distinct prime factor is a prime power and is
/// rejected by the structural condition in the reviewed plan.
pub fn f1(candidate: &Candidate) -> Option<Rejection> {
    (candidate.omega == 1).then_some(Rejection::PrimePower)
}
