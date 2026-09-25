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
        self.tested += 1;
        for &stage in &trace.evaluated {
            if stage == Stage::F7c {
                self.family
                    .get_or_insert_with(FamilyStageStats::default)
                    .reached += 1;
            } else {
                self.reached_stages[stage.index()] += 1;
            }
        }

        match &trace.outcome {
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
