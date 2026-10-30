//! Accounting for the canonical short-circuit pipeline.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::filters::{Outcome, PipelineTrace, Rejection, Stage};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct FamilyStageStats {
    pub reached: u64,
    pub rejected: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PipelineStats {
    pub tested: u64,
    pub reached_stages: [u64; 8],
    pub rejected_stages: [u64; 8],
    pub solutions: u64,
    pub rejection_reasons: BTreeMap<Rejection, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<FamilyStageStats>,
}

impl PipelineStats {
    pub fn record(&mut self, trace: &PipelineTrace) {
        self.record_parts(&trace.evaluated, &trace.outcome);
    }

    fn record_parts(&mut self, evaluated: &[Stage], outcome: &Outcome) {
        self.tested += 1;
        for &stage in evaluated {
            if stage == Stage::F7c {
                self.family
                    .get_or_insert_with(FamilyStageStats::default)
                    .reached += 1;
            } else {
                self.reached_stages[stage.index()] += 1;
            }
        }

        match outcome {
            Outcome::Rejected { stage, rejection } => {
                if *stage == Stage::F7c {
                    self.family
                        .get_or_insert_with(FamilyStageStats::default)
                        .rejected += 1;
                } else {
                    self.rejected_stages[stage.index()] += 1;
                }
                *self.rejection_reasons.entry(*rejection).or_default() += 1;
            }
            Outcome::Solution { .. } | Outcome::WideSolution { .. } => self.solutions += 1,
        }
    }

    pub fn merge(&mut self, other: &Self) {
        self.tested += other.tested;
        for (left, right) in self.reached_stages.iter_mut().zip(other.reached_stages) {
            *left += right;
        }
        for (left, right) in self.rejected_stages.iter_mut().zip(other.rejected_stages) {
            *left += right;
        }
        self.solutions += other.solutions;
        match (&mut self.family, other.family.as_ref()) {
            (Some(left), Some(right)) => {
                left.reached += right.reached;
                left.rejected += right.rejected;
            }
            (None, Some(right)) => self.family = Some(right.clone()),
            _ => {}
        }
        for (&reason, &count) in &other.rejection_reasons {
            *self.rejection_reasons.entry(reason).or_default() += count;
        }
    }

    pub fn reached(&self, stage: Stage) -> u64 {
        if stage == Stage::F7c {
            self.family.as_ref().map_or(0, |family| family.reached)
        } else {
            self.reached_stages[stage.index()]
        }
    }

    pub fn rejected_at(&self, stage: Stage) -> u64 {
        if stage == Stage::F7c {
            self.family.as_ref().map_or(0, |family| family.rejected)
        } else {
            self.rejected_stages[stage.index()]
        }
    }

    /// Checks the conservation laws for a short-circuit trace collection.
    pub fn check_invariants(&self) -> Result<(), String> {
        if self.family.is_some() {
            self.check_invariants_for(&crate::filters::FAMILY_STAGES)
        } else {
            self.check_invariants_for(&Stage::ALL)
        }
    }

    /// Checks conservation for an explicitly enabled stage order.
    pub fn check_invariants_for(&self, stages: &[Stage]) -> Result<(), String> {
        if stages.is_empty() || self.reached(stages[0]) != self.tested {
            return Err("F1 reach count must equal tested count".to_owned());
        }

        for pair in stages.windows(2) {
            let current = self.reached(pair[0]);
            let next = self.reached(pair[1]);
            if next > current {
                return Err(format!(
                    "reach count increased from {:?} ({current}) to {:?} ({next})",
                    pair[0], pair[1]
                ));
            }
            if current - next != self.rejected_at(pair[0]) {
                return Err(format!(
                    "stage {:?} does not balance: reached={current}, next={next}, rejected={}",
                    pair[0],
                    self.rejected_at(pair[0])
                ));
            }
        }

        let exact_rejections = self
            .rejection_reasons
            .get(&Rejection::ExactNonsquare)
            .copied()
            .unwrap_or(0);
        if self.reached(Stage::F8) != exact_rejections + self.solutions {
            return Err(format!(
                "F8 does not balance: reached={}, exact nonsquares={exact_rejections}, solutions={}",
                self.reached(Stage::F8),
                self.solutions
            ));
        }

        let reason_total: u64 = self.rejection_reasons.values().sum();
        let stage_total: u64 = self.rejected_stages.iter().sum::<u64>()
            + self.family.as_ref().map_or(0, |family| family.rejected);
        if reason_total != stage_total {
            return Err(format!(
                "rejection reason total {reason_total} differs from stage total {stage_total}"
            ));
        }

        Ok(())
    }
}

const REJECTION_REASONS: [Rejection; 14] = [
    Rejection::PrimePower,
    Rejection::Adic2OddVal,
    Rejection::Adic2BadUnit,
    Rejection::Adic3Nonsquare,
    Rejection::Adic3OddVal,
    Rejection::Adic3BadUnit,
    Rejection::ModNonsquare,
    Rejection::ModZeroOddVal,
    Rejection::ModZeroBadUnit,
    Rejection::LocalFactorOddVal,
    Rejection::LocalFactorBadUnit,
    Rejection::SpecialSumTwoSquares,
    Rejection::CertifiedFamilyExcluded,
    Rejection::ExactNonsquare,
];

// Exhaustive matching keeps these private counters independent of enum
// discriminants and requires an update when a rejection reason is added.
const fn reason_index(reason: Rejection) -> usize {
    match reason {
        Rejection::PrimePower => 0,
        Rejection::Adic2OddVal => 1,
        Rejection::Adic2BadUnit => 2,
        Rejection::Adic3Nonsquare => 3,
        Rejection::Adic3OddVal => 4,
        Rejection::Adic3BadUnit => 5,
        Rejection::ModNonsquare => 6,
        Rejection::ModZeroOddVal => 7,
        Rejection::ModZeroBadUnit => 8,
        Rejection::LocalFactorOddVal => 9,
        Rejection::LocalFactorBadUnit => 10,
        Rejection::SpecialSumTwoSquares => 11,
        Rejection::CertifiedFamilyExcluded => 12,
        Rejection::ExactNonsquare => 13,
    }
}

/// Worker-only accounting for canonical prefixes. Record just the stopping
/// outcome, then recover reach counts once per chunk. Arbitrary public
/// PipelineTrace values must continue through PipelineStats::record.
#[derive(Clone, Debug)]
pub(crate) struct CanonicalStats {
    tested: u64,
    stopped: [u64; crate::filters::FAMILY_STAGES.len()],
    reasons: [u64; REJECTION_REASONS.len()],
    solutions: u64,
    family_enabled: bool,
}

impl CanonicalStats {
    pub(crate) fn new(family_enabled: bool) -> Self {
        Self {
            tested: 0,
            stopped: [0; crate::filters::FAMILY_STAGES.len()],
            reasons: [0; REJECTION_REASONS.len()],
            solutions: 0,
            family_enabled,
        }
    }

    pub(crate) fn record(&mut self, outcome: &Outcome) {
        self.tested += 1;
        match outcome {
            Outcome::Rejected { stage, rejection } => {
                self.stopped[stage.index()] += 1;
                self.reasons[reason_index(*rejection)] += 1;
            }
            Outcome::Solution { .. } | Outcome::WideSolution { .. } => self.solutions += 1,
        }
    }

    pub(crate) fn finish(self) -> PipelineStats {
        let mut stats = PipelineStats {
            tested: self.tested,
            solutions: self.solutions,
            ..Default::default()
        };
        stats
            .rejected_stages
            .copy_from_slice(&self.stopped[..Stage::ALL.len()]);
        let stages = if self.family_enabled {
            &crate::filters::FAMILY_STAGES[..]
        } else {
            &Stage::ALL[..]
        };
        let mut remaining = self.tested;
        for &stage in stages {
            let stopped = self.stopped[stage.index()];
            if stage == Stage::F7c {
                // Preserve None when every candidate stopped before F7c.
                if remaining > 0 {
                    stats.family = Some(FamilyStageStats {
                        reached: remaining,
                        rejected: stopped,
                    });
                }
            } else {
                stats.reached_stages[stage.index()] = remaining;
            }
            remaining -= stopped;
        }
        debug_assert_eq!(remaining, self.solutions);
        for reason in REJECTION_REASONS {
            let count = self.reasons[reason_index(reason)];
            if count != 0 {
                stats.rejection_reasons.insert(reason, count);
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::{FAMILY_STAGES, Outcome};

    fn outcomes(family_enabled: bool) -> Vec<Outcome> {
        let mut outcomes = REJECTION_REASONS
            .iter()
            .filter_map(|&rejection| {
                let stage = match rejection {
                    Rejection::PrimePower => Stage::F1,
                    Rejection::Adic2OddVal | Rejection::Adic2BadUnit => Stage::F2,
                    Rejection::Adic3Nonsquare
                    | Rejection::Adic3OddVal
                    | Rejection::Adic3BadUnit => Stage::F3,
                    Rejection::ModNonsquare => Stage::F4,
                    Rejection::ModZeroOddVal | Rejection::ModZeroBadUnit => Stage::F4b,
                    Rejection::LocalFactorOddVal | Rejection::LocalFactorBadUnit => Stage::F56,
                    Rejection::SpecialSumTwoSquares => Stage::F7,
                    Rejection::CertifiedFamilyExcluded if !family_enabled => return None,
                    Rejection::CertifiedFamilyExcluded => Stage::F7c,
                    Rejection::ExactNonsquare => Stage::F8,
                };
                Some(Outcome::Rejected { stage, rejection })
            })
            .collect::<Vec<_>>();
        outcomes.push(Outcome::solution(1));
        outcomes.push(Outcome::WideSolution {
            y: crate::exact::ExactNat::from_biguint(num_bigint::BigUint::from(1u8) << 130usize),
        });
        outcomes
    }

    fn trace(outcome: &Outcome, family_enabled: bool) -> PipelineTrace {
        let order = if family_enabled {
            &FAMILY_STAGES[..]
        } else {
            &Stage::ALL[..]
        };
        let reached = match outcome {
            Outcome::Rejected { stage, .. } => order.iter().position(|s| s == stage).unwrap() + 1,
            _ => order.len(),
        };
        PipelineTrace {
            evaluated: order[..reached].to_vec(),
            outcome: outcome.clone(),
            family_witness: None,
        }
    }

    #[test]
    fn canonical_arrays_match_public_statistics_for_all_reasons_and_prefixes() {
        let indices = REJECTION_REASONS
            .map(reason_index)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(indices, (0..REJECTION_REASONS.len()).collect());
        for enabled in [false, true] {
            assert_eq!(
                CanonicalStats::new(enabled).finish(),
                PipelineStats::default()
            );
            for mode in 0..3 {
                let mut canonical = CanonicalStats::new(enabled);
                let mut public = PipelineStats::default();
                for (index, outcome) in outcomes(enabled).iter().enumerate() {
                    if (mode == 1
                        && !matches!(
                            outcome,
                            Outcome::Rejected {
                                stage: Stage::F1,
                                ..
                            }
                        ))
                        || (mode == 2 && matches!(outcome, Outcome::Rejected { .. }))
                    {
                        continue;
                    }
                    for _ in 0..=index % 3 {
                        canonical.record(outcome);
                        public.record(&trace(outcome, enabled));
                        assert_eq!(canonical.clone().finish(), public);
                    }
                }
                public.check_invariants().unwrap();
                assert_eq!(
                    serde_json::to_vec(&canonical.finish()).unwrap(),
                    serde_json::to_vec(&public).unwrap()
                );
            }
        }
    }

    #[test]
    fn finished_worker_chunks_merge_like_public_statistics() {
        for enabled in [false, true] {
            let rows = outcomes(enabled);
            let mut expected = PipelineStats::default();
            for outcome in &rows {
                expected.record(&trace(outcome, enabled));
            }
            for chunk_size in [1, 3, 7] {
                let mut actual = PipelineStats::default();
                for chunk in rows.chunks(chunk_size) {
                    let mut canonical = CanonicalStats::new(enabled);
                    for outcome in chunk {
                        canonical.record(outcome);
                    }
                    actual.merge(&canonical.finish());
                }
                assert_eq!(actual, expected);
                actual.check_invariants().unwrap();
            }
        }
    }
}
