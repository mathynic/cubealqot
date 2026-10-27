//! Search filters currently implemented for the staged pipeline.

use serde::{Deserialize, Serialize};

pub mod f1_structural;
pub mod f2_adic2;
pub mod f3_adic3;
pub mod f4_modsq;
pub mod f4b_foreign;
pub mod f56_local;
pub mod f7_special;

use crate::family::{CanonicalInt, ExclusionWitness, TheoremMap};
use crate::{Candidate, exact};

pub const CANONICAL_STAGES: [Stage; 8] = Stage::ALL;
/// The opt-in order when an admitted family map is configured.
pub const FAMILY_STAGES: [Stage; 9] = [
    Stage::F1,
    Stage::F2,
    Stage::F7c,
    Stage::F3,
    Stage::F4,
    Stage::F4b,
    Stage::F56,
    Stage::F7,
    Stage::F8,
];

pub use f1_structural::f1;
pub use f2_adic2::f2;
pub use f3_adic3::{F3Context, f3};
pub use f4_modsq::{F4Context, f4};
pub use f4b_foreign::f4b;
pub use f7_special::{F7Context, FamilyTag, f7};
pub use f56_local::f56;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Stage {
    F1,
    F2,
    /// Stable family-filter identifier. Its runtime placement is after F2.
    F7c,
    F3,
    F4,
    F4b,
    F56,
    F7,
    F8,
}

impl Stage {
    pub const ALL: [Self; 8] = [
        Self::F1,
        Self::F2,
        Self::F3,
        Self::F4,
        Self::F4b,
        Self::F56,
        Self::F7,
        Self::F8,
    ];

    pub const fn index(self) -> usize {
        match self {
            Self::F1 => 0,
            Self::F2 => 1,
            Self::F3 => 2,
            Self::F4 => 3,
            Self::F4b => 4,
            Self::F56 => 5,
            Self::F7 => 6,
            Self::F8 => 7,
            Self::F7c => 8,
        }
    }

    /// Index in the actual execution order. The legacy `index` remains the
    /// stable no-map statistics slot for the original eight stages.
    pub const fn execution_index(self) -> usize {
        match self {
            Self::F1 => 0,
            Self::F2 => 1,
            Self::F7c => 2,
            Self::F3 => 3,
            Self::F4 => 4,
            Self::F4b => 5,
            Self::F56 => 6,
            Self::F7 => 7,
            Self::F8 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    PrimePower,
    Adic2OddVal,
    Adic2BadUnit,
    Adic3Nonsquare,
    Adic3OddVal,
    Adic3BadUnit,
    ModNonsquare,
    ModZeroOddVal,
    ModZeroBadUnit,
    LocalFactorOddVal,
    LocalFactorBadUnit,
    SpecialSumTwoSquares,
    CertifiedFamilyExcluded,
    ExactNonsquare,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalContext {
    pub f3: F3Context,
    pub f4: F4Context,
    pub f7: F7Context,
}

impl CanonicalContext {
    pub fn new(sieve_primes: &[u32], max_e: u32) -> Self {
        let max_e = max_e.max(63);
        Self {
            f3: F3Context::new(max_e),
            f4: F4Context::new(sieve_primes, max_e),
            f7: F7Context::new(&f7_special::DEFAULT_SPECIAL_PRIMES, max_e),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineTrace {
    pub evaluated: Vec<Stage>,
    pub outcome: Outcome,
    pub family_witness: Option<ExclusionWitness>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UngatedPredicates {
    pub evaluated: [Stage; 7],
    pub f1: Option<Rejection>,
    pub f2: Option<Rejection>,
    pub f3: Option<Rejection>,
    pub f4: Option<Rejection>,
    pub f4b: Option<Rejection>,
    pub f56: Option<Rejection>,
    pub f7: Option<Rejection>,
    pub family: Option<ExclusionWitness>,
    pub exact: Outcome,
}

/// Exact result type for the widened ungated validation path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WideOutcome {
    ExactNonsquare,
    Solution { y: exact::ExactNat },
}

/// Ungated F1--F7 results plus a tiered exact F8 result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WideUngatedPredicates {
    pub evaluated: [Stage; 7],
    pub f1: Option<Rejection>,
    pub f2: Option<Rejection>,
    pub f3: Option<Rejection>,
    pub f4: Option<Rejection>,
    pub f4b: Option<Rejection>,
    pub f56: Option<Rejection>,
    pub f7: Option<Rejection>,
    pub family: Option<ExclusionWitness>,
    pub exact: WideOutcome,
}

/// Evaluates every predicate for a factored u64-domain candidate. Unlike the
/// legacy API, its exact result can retain a BigUint square root.
pub fn evaluate_ungated_wide(
    context: &CanonicalContext,
    candidate: &mut Candidate,
    residues: &[u32],
) -> WideUngatedPredicates {
    evaluate_ungated_wide_with_family_map(context, candidate, residues, None)
}

/// Evaluates every predicate plus the optional family lookup. The family
/// lookup reads only the candidate's established factorization.
pub fn evaluate_ungated_wide_with_family_map(
    context: &CanonicalContext,
    candidate: &mut Candidate,
    residues: &[u32],
    family_map: Option<&TheoremMap>,
) -> WideUngatedPredicates {
    let f1 = f1(candidate);
    let f2 = f2_adic2::f2(candidate);
    let f3 = f3_adic3::f3_with_context(&context.f3, candidate);
    let f4 = f4(&context.f4, candidate, residues);
    let f4b = f4b_foreign::f4b(&context.f4, candidate);
    let f56 = f56_local::f56(candidate);
    let f7 = f7_special::f7(&context.f7, candidate);
    let family = family_map.and_then(|map| lookup_family_map(map, candidate));
    let sum = exact::exact_s_exact(candidate);
    let exact = if exact::is_square_exact(&sum) {
        WideOutcome::Solution {
            y: exact::isqrt_exact(&sum),
        }
    } else {
        WideOutcome::ExactNonsquare
    };

    WideUngatedPredicates {
        evaluated: [
            Stage::F1,
            Stage::F2,
            Stage::F3,
            Stage::F4,
            Stage::F4b,
            Stage::F56,
            Stage::F7,
        ],
        f1,
        f2,
        f3,
        f4,
        f4b,
        f56,
        f7,
        family,
        exact,
    }
}

impl UngatedPredicates {
    pub fn evaluated_all(&self) -> bool {
        self.evaluated == Stage::ALL[..7]
    }

    pub fn first_rejection(&self) -> Option<(Stage, Rejection)> {
        [
            (Stage::F1, self.f1),
            (Stage::F2, self.f2),
            (
                Stage::F7c,
                self.family
                    .as_ref()
                    .map(|_| Rejection::CertifiedFamilyExcluded),
            ),
            (Stage::F3, self.f3),
            (Stage::F4, self.f4),
            (Stage::F4b, self.f4b),
            (Stage::F56, self.f56),
            (Stage::F7, self.f7),
        ]
        .into_iter()
        .find_map(|(stage, rejection)| rejection.map(|rejection| (stage, rejection)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    Rejected { stage: Stage, rejection: Rejection },
    Solution { y: u128 },
    WideSolution { y: exact::ExactNat },
}

/// Evaluates every implemented predicate, even if an earlier predicate rejects.
pub fn evaluate_ungated(
    context: &CanonicalContext,
    candidate: &mut Candidate,
    residues: &[u32],
) -> UngatedPredicates {
    evaluate_ungated_with_family_map(context, candidate, residues, None)
}

/// Evaluates every legacy-width predicate plus the optional family lookup.
pub fn evaluate_ungated_with_family_map(
    context: &CanonicalContext,
    candidate: &mut Candidate,
    residues: &[u32],
    family_map: Option<&TheoremMap>,
) -> UngatedPredicates {
    let f1 = f1(candidate);
    let f2 = f2(candidate);
    let f3 = f3_adic3::f3_with_context(&context.f3, candidate);
    let f4 = f4(&context.f4, candidate, residues);
    let f4b = f4b_foreign::f4b(&context.f4, candidate);
    let f56 = f56(candidate);
    let f7 = f7_special::f7(&context.f7, candidate);
    let family = family_map.and_then(|map| lookup_family_map(map, candidate));
    let sum = exact::aliquot_sum(candidate);
    let exact = if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    };

    UngatedPredicates {
        evaluated: [
            Stage::F1,
            Stage::F2,
            Stage::F3,
            Stage::F4,
            Stage::F4b,
            Stage::F56,
            Stage::F7,
        ],
        f1,
        f2,
        f3,
        f4,
        f4b,
        f56,
        f7,
        family,
        exact,
    }
}

/// Applies an admitted theorem map to the native factorization contract.
/// No primality proof or certificate replay runs on this candidate path.
pub fn lookup_family_map(map: &TheoremMap, candidate: &Candidate) -> Option<ExclusionWitness> {
    // Established factors divide the native root exactly. If no eligible
    // cofactor is admitted, no arbitrary-precision lookup can exclude it.
    if !candidate.f[..candidate.omega as usize]
        .iter()
        .any(|factor| factor.e == 1 && map.contains_native_cofactor(candidate.m / factor.p))
    {
        return None;
    }
    let m = CanonicalInt::from_decimal(&candidate.m.to_string())
        .expect("native candidate root must have canonical decimal form");
    for factor in candidate.f[..candidate.omega as usize]
        .iter()
        .filter(|factor| factor.e == 1)
    {
        let q = CanonicalInt::from_decimal(&factor.p.to_string())
            .expect("native factor prime must have canonical decimal form");
        let n_bigint = m.as_bigint() / q.as_bigint();
        let n = CanonicalInt::from_decimal(&n_bigint.to_string())
            .expect("native exact factor division must remain canonical");
        if n.as_bigint() <= &num_bigint::BigInt::from(1u8) {
            continue;
        }
        if let crate::family::LookupDecision::Excluded(witness) = map.lookup(&m, &n, &q) {
            return Some(witness);
        }
    }
    None
}

/// Runs the implemented filters in their canonical order and records every
/// stage reached, including the exact fallback stage.
pub fn run_canonical(
    context: &CanonicalContext,
    candidate: &mut Candidate,
    residues: &[u32],
) -> PipelineTrace {
    run_canonical_with_family_map(context, candidate, residues, None)
}

/// Runs the canonical pipeline with an optional admitted family map. A
/// configured map is evaluated immediately after F2; no-map execution keeps
/// the original eight-stage trace exactly.
pub fn run_canonical_with_family_map(
    context: &CanonicalContext,
    candidate: &mut Candidate,
    residues: &[u32],
    family_map: Option<&TheoremMap>,
) -> PipelineTrace {
    let mut evaluated = Vec::with_capacity(if family_map.is_some() {
        FAMILY_STAGES.len()
    } else {
        Stage::ALL.len()
    });

    evaluated.push(Stage::F1);
    if let Some(rejection) = f1(candidate) {
        return PipelineTrace {
            evaluated,
            outcome: Outcome::Rejected {
                stage: Stage::F1,
                rejection,
            },
            family_witness: None,
        };
    }

    evaluated.push(Stage::F2);
    if let Some(rejection) = f2(candidate) {
        return PipelineTrace {
            evaluated,
            outcome: Outcome::rejected_f2(rejection),
            family_witness: None,
        };
    }

    let family_witness = if let Some(map) = family_map {
        evaluated.push(Stage::F7c);
        if let Some(witness) = lookup_family_map(map, candidate) {
            return PipelineTrace {
                evaluated,
                outcome: Outcome::Rejected {
                    stage: Stage::F7c,
                    rejection: Rejection::CertifiedFamilyExcluded,
                },
                family_witness: Some(witness),
            };
        }
        None
    } else {
        None
    };

    evaluated.push(Stage::F3);
    if let Some(rejection) = f3_adic3::f3_with_context(&context.f3, candidate) {
        return PipelineTrace {
            evaluated,
            outcome: Outcome::Rejected {
                stage: Stage::F3,
                rejection,
            },
            family_witness,
        };
    }

    evaluated.push(Stage::F4);
    if let Some(rejection) = f4(&context.f4, candidate, residues) {
        return PipelineTrace {
            evaluated,
            outcome: Outcome::Rejected {
                stage: Stage::F4,
                rejection,
            },
            family_witness,
        };
    }

    evaluated.push(Stage::F4b);
    if let Some(rejection) = f4b_foreign::f4b(&context.f4, candidate) {
        return PipelineTrace {
            evaluated,
            outcome: Outcome::rejected_f4b(rejection),
            family_witness,
        };
    }

    evaluated.push(Stage::F56);
    if let Some(rejection) = f56(candidate) {
        return PipelineTrace {
            evaluated,
            outcome: Outcome::Rejected {
                stage: Stage::F56,
                rejection,
            },
            family_witness,
        };
    }

    evaluated.push(Stage::F7);
    if let Some(rejection) = f7_special::f7(&context.f7, candidate) {
        return PipelineTrace {
            evaluated,
            outcome: Outcome::Rejected {
                stage: Stage::F7,
                rejection,
            },
            family_witness,
        };
    }

    evaluated.push(Stage::F8);
    let outcome = exact_outcome(exact::exact_s_exact(candidate));
    PipelineTrace {
        evaluated,
        outcome,
        family_witness,
    }
}

fn exact_outcome(sum: exact::ExactNat) -> Outcome {
    if !exact::is_square_exact(&sum) {
        return Outcome::exact_nonsquare();
    }

    match exact::isqrt_exact(&sum) {
        exact::ExactNat::Small(y) => Outcome::solution(y),
        y => Outcome::WideSolution { y },
    }
}

impl Outcome {
    pub const fn rejected_f1() -> Self {
        Self::Rejected {
            stage: Stage::F1,
            rejection: Rejection::PrimePower,
        }
    }

    pub const fn exact_nonsquare() -> Self {
        Self::Rejected {
            stage: Stage::F8,
            rejection: Rejection::ExactNonsquare,
        }
    }

    pub const fn rejected_f4() -> Self {
        Self::Rejected {
            stage: Stage::F4,
            rejection: Rejection::ModNonsquare,
        }
    }

    pub const fn rejected_f2(rejection: Rejection) -> Self {
        Self::Rejected {
            stage: Stage::F2,
            rejection,
        }
    }

    pub const fn rejected_f4b(rejection: Rejection) -> Self {
        Self::Rejected {
            stage: Stage::F4b,
            rejection,
        }
    }

    pub const fn solution(y: u128) -> Self {
        Self::Solution { y }
    }
}

/// Runs the currently enabled pipeline: F1, followed by the exact baseline.
///
/// Later filters are intentionally absent at this milestone. Keeping the
/// exact fallback here makes the normal first-rejection behavior explicit and
/// gives the F1 validation a complete reference outcome.
pub fn run(candidate: &mut Candidate) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F2, then the exact fallback.
pub fn run_with_f2(candidate: &mut Candidate) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f2(candidate) {
        return Outcome::rejected_f2(rejection);
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F3, then the exact fallback.
pub fn run_with_f3(candidate: &mut Candidate) -> Outcome {
    run_with_f3_context(&F3Context::default(), candidate)
}

/// Runs the enabled normal pipeline through F3 with a reusable context.
pub fn run_with_f3_context(context: &F3Context, candidate: &mut Candidate) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f2(candidate) {
        return Outcome::rejected_f2(rejection);
    }
    if let Some(rejection) = f3_adic3::f3_with_context(context, candidate) {
        return Outcome::Rejected {
            stage: Stage::F3,
            rejection,
        };
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F2, F3, and F4, then the exact
/// fallback.  `run_with_f4` remains available as the earlier F1-to-F4 entry
/// point for callers validating F4 in isolation.
pub fn run_with_f2_f4(context: &F4Context, candidate: &mut Candidate, residues: &[u32]) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f2(candidate) {
        return Outcome::rejected_f2(rejection);
    }
    if let Some(rejection) = f3(candidate) {
        return Outcome::Rejected {
            stage: Stage::F3,
            rejection,
        };
    }
    if let Some(rejection) = f4(context, candidate, residues) {
        return Outcome::Rejected {
            stage: Stage::F4,
            rejection,
        };
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F3 and F4 with reusable contexts.
pub fn run_with_f3_f4(
    f3_context: &F3Context,
    f4_context: &F4Context,
    candidate: &mut Candidate,
    residues: &[u32],
) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f2(candidate) {
        return Outcome::rejected_f2(rejection);
    }
    if let Some(rejection) = f3_adic3::f3_with_context(f3_context, candidate) {
        return Outcome::Rejected {
            stage: Stage::F3,
            rejection,
        };
    }
    if let Some(rejection) = f4(f4_context, candidate, residues) {
        return Outcome::Rejected {
            stage: Stage::F4,
            rejection,
        };
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F4b, then the exact fallback.
pub fn run_with_f3_f4_f4b(
    f3_context: &F3Context,
    f4_context: &F4Context,
    candidate: &mut Candidate,
    residues: &[u32],
) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f2(candidate) {
        return Outcome::rejected_f2(rejection);
    }
    if let Some(rejection) = f3_adic3::f3_with_context(f3_context, candidate) {
        return Outcome::Rejected {
            stage: Stage::F3,
            rejection,
        };
    }
    if let Some(rejection) = f4(f4_context, candidate, residues) {
        return Outcome::Rejected {
            stage: Stage::F4,
            rejection,
        };
    }
    if let Some(rejection) = f4b_foreign::f4b(f4_context, candidate) {
        return Outcome::rejected_f4b(rejection);
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F5/F6, then the exact fallback.
pub fn run_with_f56(candidate: &mut Candidate) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f2(candidate) {
        return Outcome::rejected_f2(rejection);
    }
    if let Some(rejection) = f3(candidate) {
        return Outcome::Rejected {
            stage: Stage::F3,
            rejection,
        };
    }
    if let Some(rejection) = f56(candidate) {
        return Outcome::Rejected {
            stage: Stage::F56,
            rejection,
        };
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F4 and F5/F6, then the exact
/// fallback, using reusable residue/table contexts.
pub fn run_with_f3_f4_f56(
    f3_context: &F3Context,
    f4_context: &F4Context,
    candidate: &mut Candidate,
    residues: &[u32],
) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f2(candidate) {
        return Outcome::rejected_f2(rejection);
    }
    if let Some(rejection) = f3_adic3::f3_with_context(f3_context, candidate) {
        return Outcome::Rejected {
            stage: Stage::F3,
            rejection,
        };
    }
    if let Some(rejection) = f4(f4_context, candidate, residues) {
        return Outcome::Rejected {
            stage: Stage::F4,
            rejection,
        };
    }
    if let Some(rejection) = f4b_foreign::f4b(f4_context, candidate) {
        return Outcome::rejected_f4b(rejection);
    }
    if let Some(rejection) = f56(candidate) {
        return Outcome::Rejected {
            stage: Stage::F56,
            rejection,
        };
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F7, then the exact fallback.
pub fn run_with_f3_f4_f56_f7(
    f3_context: &F3Context,
    f4_context: &F4Context,
    f7_context: &F7Context,
    candidate: &mut Candidate,
    residues: &[u32],
) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f2(candidate) {
        return Outcome::rejected_f2(rejection);
    }
    if let Some(rejection) = f3_adic3::f3_with_context(f3_context, candidate) {
        return Outcome::Rejected {
            stage: Stage::F3,
            rejection,
        };
    }
    if let Some(rejection) = f4(f4_context, candidate, residues) {
        return Outcome::Rejected {
            stage: Stage::F4,
            rejection,
        };
    }
    if let Some(rejection) = f4b_foreign::f4b(f4_context, candidate) {
        return Outcome::rejected_f4b(rejection);
    }
    if let Some(rejection) = f56(candidate) {
        return Outcome::Rejected {
            stage: Stage::F56,
            rejection,
        };
    }
    if let Some(rejection) = f7_special::f7(f7_context, candidate) {
        return Outcome::Rejected {
            stage: Stage::F7,
            rejection,
        };
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

/// Runs the enabled normal pipeline through F4, then the exact fallback.
pub fn run_with_f4(context: &F4Context, candidate: &mut Candidate, residues: &[u32]) -> Outcome {
    if let Some(rejection) = f1(candidate) {
        return Outcome::Rejected {
            stage: Stage::F1,
            rejection,
        };
    }
    if let Some(rejection) = f4(context, candidate, residues) {
        return Outcome::Rejected {
            stage: Stage::F4,
            rejection,
        };
    }

    let sum = exact::aliquot_sum(candidate);
    if exact::is_square(sum) {
        Outcome::solution(exact::isqrt(sum))
    } else {
        Outcome::exact_nonsquare()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CanonicalContext, Outcome, Rejection, Stage, TheoremMap, f1, lookup_family_map, run,
        run_canonical_with_family_map,
    };
    use crate::{Candidate, build_spf};

    /// Reference adapter from before the native negative pre-check.
    fn lookup_without_native_index(
        map: &TheoremMap,
        candidate: &Candidate,
    ) -> Option<crate::family::ExclusionWitness> {
        use crate::family::{CanonicalInt, LookupDecision};
        let m = CanonicalInt::from_decimal(&candidate.m.to_string()).unwrap();
        for factor in candidate.f[..candidate.omega as usize]
            .iter()
            .filter(|f| f.e == 1)
        {
            let q = CanonicalInt::from_decimal(&factor.p.to_string()).unwrap();
            let n =
                CanonicalInt::from_decimal(&(m.as_bigint() / q.as_bigint()).to_string()).unwrap();
            if n.as_bigint() <= &num_bigint::BigInt::from(1u8) {
                continue;
            }
            if let LookupDecision::Excluded(witness) = map.lookup(&m, &n, &q) {
                return Some(witness);
            }
        }
        None
    }

    #[test]
    fn native_family_precheck_matches_original_adapter_and_witnesses() {
        let spf = build_spf(10_000);
        let maps = [
            TheoremMap::new(),
            TheoremMap::test_only_single("3", &["2"]),
            TheoremMap::test_only_single("5", &["3", "11"]),
            TheoremMap::test_only_single("9", &["2"]),
            TheoremMap::test_only_single("18446744073709551618", &["2"]),
        ];
        for map in &maps {
            for m in 2u64..=10_000 {
                let candidate = Candidate::new(m, &spf);
                assert_eq!(
                    lookup_family_map(map, &candidate),
                    lookup_without_native_index(map, &candidate),
                    "m={m}"
                );
            }
            for p in [4_294_967_311u64, 2_305_843_041_732_208_837] {
                let mut factors = [crate::Factor::default(); crate::MAX_OMEGA];
                factors[0] = crate::Factor { p: 3, e: 1 };
                factors[1] = crate::Factor { p, e: 1 };
                let candidate = Candidate::from_factors(3 * p, factors, 2);
                assert_eq!(
                    lookup_family_map(map, &candidate),
                    lookup_without_native_index(map, &candidate)
                );
            }
        }
    }

    #[test]
    fn prime_power_is_rejected_at_f1() {
        let spf = build_spf(7);
        let candidate = Candidate::new(7u64, &spf);
        assert_eq!(f1(&candidate), Some(Rejection::PrimePower));
    }

    #[test]
    fn composite_reaches_exact_fallback() {
        let spf = build_spf(6);
        let mut candidate = Candidate::new(6u64, &spf);
        assert_eq!(
            run(&mut candidate),
            Outcome::Rejected {
                stage: Stage::F8,
                rejection: Rejection::ExactNonsquare,
            }
        );
    }

    #[test]
    fn family_stage_runs_after_f2_and_preserves_listed_membership() {
        let map = TheoremMap::test_only_single("5", &["11"]);
        let spf = crate::build_spf(15);
        let context = CanonicalContext::new(&[5, 7, 11, 13], 31);
        let mut candidate = Candidate::new(15u64, &spf);
        let residues = crate::tables::init_residues(&context.f4.sieve_primes, 15u64);
        let trace = run_canonical_with_family_map(&context, &mut candidate, &residues, Some(&map));
        assert_eq!(trace.evaluated, vec![Stage::F1, Stage::F2, Stage::F7c]);
        assert_eq!(
            trace.outcome,
            Outcome::Rejected {
                stage: Stage::F7c,
                rejection: Rejection::CertifiedFamilyExcluded,
            }
        );
        let witness = trace.family_witness.expect("family witness");
        assert_eq!(witness.m().to_string(), "15");
        assert_eq!(witness.n().to_string(), "5");
        assert_eq!(witness.q().to_string(), "3");

        let listed_map = TheoremMap::test_only_single("5", &["3"]);
        let mut listed_candidate = Candidate::new(15u64, &spf);
        let listed = run_canonical_with_family_map(
            &context,
            &mut listed_candidate,
            &residues,
            Some(&listed_map),
        );
        assert!(!listed.evaluated.contains(&Stage::F7c) || listed.family_witness.is_none());
        assert!(!matches!(
            listed.outcome,
            Outcome::Rejected {
                stage: Stage::F7c,
                ..
            }
        ));
    }

    #[test]
    fn runtime_family_adapter_observes_exponent_one_rules_and_q_two() {
        let map = TheoremMap::test_only_single("9", &["3"]);
        let spf = crate::build_spf(30);
        let candidate = Candidate::new(18u64, &spf);
        // m=18=9*2: q=2 is below N and has exponent one, so an absent q is
        // an exclusion. This exercises the runtime adapter independently of
        // the short-circuit filters.
        let witness = lookup_family_map(&map, &candidate).expect("q=2 exclusion");
        assert_eq!(witness.m().to_string(), "18");
        assert_eq!(witness.n().to_string(), "9");
        assert_eq!(witness.q().to_string(), "2");

        let listed_map = TheoremMap::test_only_single("9", &["2"]);
        assert!(lookup_family_map(&listed_map, &candidate).is_none());

        let repeated = Candidate::new(12u64, &spf);
        let repeated_map = TheoremMap::test_only_single("6", &["2"]);
        // q=2 occurs with exponent two in 12 and must not be considered.
        assert!(lookup_family_map(&repeated_map, &repeated).is_none());
    }
}
