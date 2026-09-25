//! Exact, non-completeness-claiming filtering of backend integral points.
//!
//! This module checks every supplied point.  It does not decide whether the
//! backend enumerated all points and therefore can never produce a family
//! completeness claim.

use std::collections::BTreeSet;

use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive, Zero};

use super::certificate::UntrustedIntegralPoint;
use super::integer_io::CanonicalInt;
use super::primality::{CompositeWitness, NotPrimeReason, PrimeStatus, classify_u64};
use super::problem::Problem;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFamilySolution {
    q: CanonicalInt,
    y: CanonicalInt,
}

impl VerifiedFamilySolution {
    pub fn q(&self) -> &CanonicalInt {
        &self.q
    }

    pub fn y(&self) -> &CanonicalInt {
        &self.y
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PointRejectionReason {
    OffCurve,
    MissingXDivisibility,
    MissingYDivisibility,
    QOutOfRange,
    QSharesFactorWithN,
    CompositeQ { witness: CompositeWitness },
    NotPrimeQ { reason: NotPrimeReason },
    ExactEquationMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PointDecision {
    Accepted { solution: VerifiedFamilySolution },
    Discarded { reason: PointRejectionReason },
    PrimeProofInconclusive { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckedPoint {
    pub point: UntrustedIntegralPoint,
    pub decision: PointDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PointFilterStatus {
    /// Every supplied point was checked; this says nothing about completeness.
    Filtered,
    /// At least one potentially relevant point lacked a prime proof.
    Inconclusive { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointFilterResult {
    status: PointFilterStatus,
    accepted: Vec<VerifiedFamilySolution>,
    decisions: Vec<CheckedPoint>,
}

impl PointFilterResult {
    pub fn status(&self) -> &PointFilterStatus {
        &self.status
    }

    /// Accepted points are deduplicated by q only after all input points have
    /// been checked and recorded in `decisions`.
    pub fn accepted(&self) -> &[VerifiedFamilySolution] {
        &self.accepted
    }

    pub fn decisions(&self) -> &[CheckedPoint] {
        &self.decisions
    }

    pub fn claims_completeness(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PointPrimeStatus {
    ProvenPrime,
    ProvenComposite { witness: CompositeWitness },
    NotPrime { reason: NotPrimeReason },
    Inconclusive(String),
}

pub trait PointPrimeOracle {
    fn classify(&self, q: &CanonicalInt) -> PointPrimeStatus;
}

/// The production point oracle currently has a proved u64 domain.  A larger
/// q is explicitly inconclusive until a separately verified certificate path
/// is wired into this boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeterministicPointPrimeOracle;

impl PointPrimeOracle for DeterministicPointPrimeOracle {
    fn classify(&self, q: &CanonicalInt) -> PointPrimeStatus {
        let Some(q) = q.as_bigint().to_u64() else {
            return PointPrimeStatus::Inconclusive(
                "q is outside the deterministic u64 prime-proof domain".to_owned(),
            );
        };
        match classify_u64(q) {
            PrimeStatus::ProvenPrime(_) => PointPrimeStatus::ProvenPrime,
            PrimeStatus::ProvenComposite(witness) => PointPrimeStatus::ProvenComposite { witness },
            PrimeStatus::NotPrime(reason) => PointPrimeStatus::NotPrime { reason },
            PrimeStatus::Inconclusive(reason) => PointPrimeStatus::Inconclusive(reason),
        }
    }
}

pub fn filter_integral_points(
    problem: &Problem,
    points: &[UntrustedIntegralPoint],
) -> PointFilterResult {
    let oracle = DeterministicPointPrimeOracle;
    filter_integral_points_with_prime_oracle(problem, points, &oracle)
}

pub fn filter_integral_points_with_prime_oracle(
    problem: &Problem,
    points: &[UntrustedIntegralPoint],
    oracle: &dyn PointPrimeOracle,
) -> PointFilterResult {
    let decisions = points
        .iter()
        .cloned()
        .map(|point| CheckedPoint {
            decision: check_point(problem, &point, oracle),
            point,
        })
        .collect::<Vec<_>>();

    let mut seen_q = BTreeSet::new();
    let mut accepted = Vec::new();
    let mut inconclusive_reason = None;
    for checked in &decisions {
        match &checked.decision {
            PointDecision::Accepted { solution } => {
                if seen_q.insert(solution.q.clone()) {
                    accepted.push(solution.clone());
                }
            }
            PointDecision::PrimeProofInconclusive { reason } => {
                if inconclusive_reason.is_none() {
                    inconclusive_reason = Some(reason.clone());
                }
            }
            PointDecision::Discarded { .. } => {}
        }
    }

    let status = match inconclusive_reason {
        Some(reason) => PointFilterStatus::Inconclusive { reason },
        None => PointFilterStatus::Filtered,
    };
    PointFilterResult {
        status,
        accepted,
        decisions,
    }
}

fn check_point(
    problem: &Problem,
    point: &UntrustedIntegralPoint,
    oracle: &dyn PointPrimeOracle,
) -> PointDecision {
    let x = point.x.as_bigint();
    let y = point.y.as_bigint();

    // This is deliberately the first mathematical check.  No family
    // interpretation is assigned to a point that is not on the original
    // model returned by the backend.
    if y * y != problem.curve_rhs(&point.x).as_bigint().clone() {
        return PointDecision::Discarded {
            reason: PointRejectionReason::OffCurve,
        };
    }

    let d = problem.d().as_bigint();
    if x % d != BigInt::zero() {
        return PointDecision::Discarded {
            reason: PointRejectionReason::MissingXDivisibility,
        };
    }
    if y % d != BigInt::zero() {
        return PointDecision::Discarded {
            reason: PointRejectionReason::MissingYDivisibility,
        };
    }

    let q = x / d;
    if q < BigInt::from(2u8) {
        return PointDecision::Discarded {
            reason: PointRejectionReason::QOutOfRange,
        };
    }

    let n = problem.n().as_bigint();
    if gcd(q.clone(), n.clone()) != BigInt::from(1u8) {
        return PointDecision::Discarded {
            reason: PointRejectionReason::QSharesFactorWithN,
        };
    }

    let q = canonical_bigint(q);
    let prime_status = oracle.classify(&q);
    match prime_status {
        PointPrimeStatus::ProvenPrime => {}
        PointPrimeStatus::ProvenComposite { witness } => {
            return PointDecision::Discarded {
                reason: PointRejectionReason::CompositeQ { witness },
            };
        }
        PointPrimeStatus::NotPrime { reason } => {
            return PointDecision::Discarded {
                reason: PointRejectionReason::NotPrimeQ { reason },
            };
        }
        PointPrimeStatus::Inconclusive(reason) => {
            return PointDecision::PrimeProofInconclusive { reason };
        }
    }

    let family_y = canonical_bigint(y / d);
    if !exact_family_equation(problem, &q, &family_y) {
        return PointDecision::Discarded {
            reason: PointRejectionReason::ExactEquationMismatch,
        };
    }
    let normalized_y = if family_y.as_bigint().is_negative() {
        canonical_bigint(-family_y.into_bigint())
    } else {
        family_y
    };
    PointDecision::Accepted {
        solution: VerifiedFamilySolution { q, y: normalized_y },
    }
}

fn exact_family_equation(problem: &Problem, q: &CanonicalInt, y: &CanonicalInt) -> bool {
    y.as_bigint() * y.as_bigint() == problem.rhs(q).as_bigint().clone()
}

fn canonical_bigint(value: BigInt) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("BigInt formatting is canonical")
}

fn gcd(mut left: BigInt, mut right: BigInt) -> BigInt {
    left = left.abs();
    right = right.abs();
    while !right.is_zero() {
        let remainder = left % &right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::family::problem;

    fn integer(value: &str) -> CanonicalInt {
        CanonicalInt::from_decimal(value).unwrap()
    }

    fn synthetic_problem(n: &str, a: &str, d: &str) -> Problem {
        problem::test_problem(n, a, d)
    }

    fn point(x: &str, y: &str) -> UntrustedIntegralPoint {
        UntrustedIntegralPoint {
            x: integer(x),
            y: integer(y),
        }
    }

    struct ForcedPrimeStatus(PointPrimeStatus);

    impl PointPrimeOracle for ForcedPrimeStatus {
        fn classify(&self, _q: &CanonicalInt) -> PointPrimeStatus {
            self.0.clone()
        }
    }

    #[test]
    fn acceptance_normalizes_y_and_deduplicates_only_after_all_checks() {
        let problem = synthetic_problem("3", "15", "2");
        let result = filter_integral_points(
            &problem,
            &[point("4", "22"), point("4", "-22"), point("4", "22")],
        );

        assert_eq!(result.status(), &PointFilterStatus::Filtered);
        assert_eq!(result.accepted().len(), 1);
        assert_eq!(result.accepted()[0].q(), &integer("2"));
        assert_eq!(result.accepted()[0].y(), &integer("11"));
        assert_eq!(result.decisions().len(), 3);
        assert!(
            result
                .decisions()
                .iter()
                .all(|checked| matches!(checked.decision, PointDecision::Accepted { .. }))
        );
        assert!(!result.claims_completeness());
    }

    #[test]
    fn prime_uncertainty_is_not_a_rejection_or_empty_result() {
        let problem = synthetic_problem("3", "15", "2");
        let oracle = ForcedPrimeStatus(PointPrimeStatus::Inconclusive(
            "forced test uncertainty".into(),
        ));
        let result =
            filter_integral_points_with_prime_oracle(&problem, &[point("4", "22")], &oracle);

        assert!(matches!(
            result.status(),
            PointFilterStatus::Inconclusive { reason } if reason == "forced test uncertainty"
        ));
        assert!(matches!(
            result.decisions()[0].decision,
            PointDecision::PrimeProofInconclusive { .. }
        ));
        assert!(result.accepted().is_empty());
    }

    #[test]
    fn composite_and_shared_factor_decisions_are_distinct() {
        let composite_problem = synthetic_problem("3", "5", "1");
        let result = filter_integral_points(&composite_problem, &[point("4", "13")]);
        assert!(matches!(
            result.decisions()[0].decision,
            PointDecision::Discarded {
                reason: PointRejectionReason::CompositeQ {
                    witness: CompositeWitness::SmallFactor { factor: 2 }
                }
            }
        ));

        let problem = synthetic_problem("3", "15", "2");
        let composite = ForcedPrimeStatus(PointPrimeStatus::ProvenComposite {
            witness: CompositeWitness::SmallFactor { factor: 2 },
        });
        let result =
            filter_integral_points_with_prime_oracle(&problem, &[point("4", "22")], &composite);
        assert!(matches!(
            result.decisions()[0].decision,
            PointDecision::Discarded {
                reason: PointRejectionReason::CompositeQ { .. }
            }
        ));

        let shared_problem = synthetic_problem("2", "15", "2");
        let result = filter_integral_points(&shared_problem, &[point("4", "22")]);
        assert!(matches!(
            result.decisions()[0].decision,
            PointDecision::Discarded {
                reason: PointRejectionReason::QSharesFactorWithN
            }
        ));
    }

    #[test]
    fn exact_equation_mismatch_is_a_rejection_predicate() {
        let problem = synthetic_problem("3", "15", "2");
        assert!(!exact_family_equation(
            &problem,
            &integer("2"),
            &integer("10")
        ));
        assert!(exact_family_equation(
            &problem,
            &integer("2"),
            &integer("11")
        ));
    }

    #[test]
    fn negative_and_zero_q_are_out_of_range() {
        let negative_problem = synthetic_problem("9", "1093", "364");
        let negative = filter_integral_points(&negative_problem, &[point("-364", "9828")]);
        assert!(matches!(
            negative.decisions()[0].decision,
            PointDecision::Discarded {
                reason: PointRejectionReason::QOutOfRange
            }
        ));

        let zero_problem = synthetic_problem("3", "9", "2");
        let zero = filter_integral_points(&zero_problem, &[point("0", "6")]);
        assert!(matches!(
            zero.decisions()[0].decision,
            PointDecision::Discarded {
                reason: PointRejectionReason::QOutOfRange
            }
        ));
    }
}
