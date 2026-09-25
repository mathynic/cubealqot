//! Differential validation against the independent Python oracle.

use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
    process::{Child, Command, Stdio},
    time::Instant,
};

use serde::Deserialize;

use crate::{Candidate, build_spf, cross, exact, filters};

#[derive(Debug, Deserialize)]
struct OracleRecord {
    m: u32,
    sigma_m3: u128,
    s: u128,
    is_square: bool,
    method: String,
}

/// Counts produced by a successful Rust/Python baseline comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub direct_checked: u64,
    pub multiplicative_checked: u64,
}

/// Counts produced by the ungated F1 and normal F1-to-exact checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F1ValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub ungated_prime_power_rejections: u64,
    pub pipeline_prime_power_rejections: u64,
}

/// Counts produced by the ungated F2 and normal F1-to-F2-to-exact checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F2ValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub ungated_rejections: u64,
    pub pipeline_rejections: u64,
    pub equal_valuation_cases: u64,
    pub exact_s_fallbacks: u64,
}

/// Counts produced by the ungated F3 and normal F1-to-F3 checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F3ValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub ungated_rejections: u64,
    pub pipeline_rejections: u64,
    pub positive_even_valuation_cases: u64,
}

/// Compares the Rust baseline with the Python oracle for `2..=max`.
pub fn validate_range(max: u32) -> Result<ValidationSummary, String> {
    if max < 2 {
        return Err("validation maximum must be at least 2".to_owned());
    }

    let spf = build_spf(max);
    let mut oracle = spawn_oracle(max)?;
    let stdout = oracle
        .stdout
        .take()
        .ok_or_else(|| "Python oracle stdout was not captured".to_owned())?;
    let mut lines = BufReader::new(stdout).lines();
    let comparison = compare_records(&mut lines, max, &spf);

    if comparison.is_err() {
        let _ = oracle.kill();
        let _ = oracle.wait();
        return comparison;
    }

    let status = oracle
        .wait()
        .map_err(|error| format!("could not wait for Python oracle: {error}"))?;
    if !status.success() {
        return Err(format!(
            "Python oracle exited unsuccessfully: {}",
            read_child_stderr(&mut oracle)
        ));
    }

    comparison
}

/// Validates F1 independently of stage order and checks the F1-to-exact
/// pipeline against the exact baseline.
pub fn validate_f1_range(max: u32) -> Result<F1ValidationSummary, String> {
    if max < 2 {
        return Err("F1 validation maximum must be at least 2".to_owned());
    }

    let spf = build_spf(max);
    let mut ungated_prime_power_rejections = 0;
    let mut pipeline_prime_power_rejections = 0;

    for m in 2..=max {
        // Ungated check: evaluate F1 directly, regardless of what any future
        // earlier filter might do.
        let candidate = Candidate::new(m, &spf);
        let ungated = filters::f1(&candidate);
        if ungated.is_some() {
            ungated_prime_power_rejections += 1;
            if exact::aliquot_sum_is_square(&candidate) {
                return Err(format!("ungated F1 rejected a square at m={m}"));
            }
        }

        // Normal pipeline check: F1 is first, then the exact fallback.
        let mut pipeline_candidate = Candidate::new(m, &spf);
        let expected = if ungated.is_some() {
            filters::Outcome::rejected_f1()
        } else {
            let sum = exact::aliquot_sum(&pipeline_candidate);
            if exact::is_square(sum) {
                filters::Outcome::solution(exact::isqrt(sum))
            } else {
                filters::Outcome::exact_nonsquare()
            }
        };
        let actual = filters::run(&mut pipeline_candidate);
        if actual != expected {
            return Err(format!("F1 pipeline mismatch at m={m}"));
        }
        if matches!(
            actual,
            filters::Outcome::Rejected {
                stage: filters::Stage::F1,
                ..
            }
        ) {
            pipeline_prime_power_rejections += 1;
        }
    }

    Ok(F1ValidationSummary {
        max,
        checked: u64::from(max - 1),
        ungated_prime_power_rejections,
        pipeline_prime_power_rejections,
    })
}

/// Validates F2 independently of stage order and checks the F1-to-F2-to-exact
/// pipeline against the exact baseline.
pub fn validate_f2_range(max: u32) -> Result<F2ValidationSummary, String> {
    if max < 2 {
        return Err("F2 validation maximum must be at least 2".to_owned());
    }

    let spf = build_spf(max);
    let mut ungated_rejections = 0;
    let mut pipeline_rejections = 0;
    let mut equal_valuation_cases = 0;
    let mut exact_s_fallbacks = 0;

    for m in 2..=max {
        // Ungated check: F2 must be mathematically sound even when F1 would
        // have rejected the same candidate first in normal pipeline mode.
        let mut ungated_candidate = Candidate::new(m, &spf);
        let analysis = filters::f2_adic2::analyze(&mut ungated_candidate);
        if analysis.equal_valuation {
            equal_valuation_cases += 1;
        }
        if analysis.used_exact_s_fallback {
            exact_s_fallbacks += 1;
        }
        if let Some(rejection) = filters::f2(&mut ungated_candidate) {
            ungated_rejections += 1;
            if exact::aliquot_sum_is_square(&ungated_candidate) {
                return Err(format!(
                    "ungated F2 rejected a square at m={m}: {rejection:?}"
                ));
            }
        }

        let mut pipeline_candidate = Candidate::new(m, &spf);
        let actual = filters::run_with_f2(&mut pipeline_candidate);
        let expected = if pipeline_candidate.omega == 1 {
            filters::Outcome::rejected_f1()
        } else {
            let mut expected_f2_candidate = Candidate::new(m, &spf);
            match filters::f2(&mut expected_f2_candidate) {
                Some(rejection) => filters::Outcome::rejected_f2(rejection),
                None => {
                    let sum = exact::aliquot_sum(&expected_f2_candidate);
                    if exact::is_square(sum) {
                        filters::Outcome::solution(exact::isqrt(sum))
                    } else {
                        filters::Outcome::exact_nonsquare()
                    }
                }
            }
        };
        if actual != expected {
            return Err(format!("F2 pipeline mismatch at m={m}"));
        }
        if matches!(
            actual,
            filters::Outcome::Rejected {
                stage: filters::Stage::F2,
                ..
            }
        ) {
            pipeline_rejections += 1;
        }
    }

    Ok(F2ValidationSummary {
        max,
        checked: u64::from(max - 1),
        ungated_rejections,
        pipeline_rejections,
        equal_valuation_cases,
        exact_s_fallbacks,
    })
}

/// Validates F3 independently of stage order and checks the F1-to-F2-to-F3
/// pipeline against the exact baseline.
pub fn validate_f3_range(max: u32) -> Result<F3ValidationSummary, String> {
    if max < 2 {
        return Err("F3 validation maximum must be at least 2".to_owned());
    }

    let spf = build_spf(max);
    let context = filters::F3Context::default();
    let mut ungated_rejections = 0;
    let mut pipeline_rejections = 0;
    let mut positive_even_valuation_cases = 0;

    for m in 2..=max {
        // Ungated check: F3 must remain sound even when F1 or F2 would have
        // rejected the same candidate in normal stage order.
        let mut ungated_candidate = Candidate::new(m, &spf);
        let analysis = filters::f3_adic3::analyze_with_context(&context, &mut ungated_candidate);
        if analysis.entered_zero_branch && analysis.v3_s > 0 && analysis.v3_s % 2 == 0 {
            positive_even_valuation_cases += 1;
        }
        if let Some(rejection) =
            filters::f3_adic3::f3_with_context(&context, &mut ungated_candidate)
        {
            ungated_rejections += 1;
            if exact::aliquot_sum_is_square(&ungated_candidate) {
                return Err(format!(
                    "ungated F3 rejected a square at m={m}: {rejection:?}"
                ));
            }
        }

        let mut pipeline_candidate = Candidate::new(m, &spf);
        let actual = filters::run_with_f3_context(&context, &mut pipeline_candidate);
        let expected = if pipeline_candidate.omega == 1 {
            filters::Outcome::rejected_f1()
        } else {
            let mut expected_candidate = Candidate::new(m, &spf);
            match filters::f2(&mut expected_candidate) {
                Some(rejection) => filters::Outcome::rejected_f2(rejection),
                None => match filters::f3_adic3::f3_with_context(&context, &mut expected_candidate)
                {
                    Some(rejection) => filters::Outcome::Rejected {
                        stage: filters::Stage::F3,
                        rejection,
                    },
                    None => {
                        let sum = exact::aliquot_sum(&expected_candidate);
                        if exact::is_square(sum) {
                            filters::Outcome::solution(exact::isqrt(sum))
                        } else {
                            filters::Outcome::exact_nonsquare()
                        }
                    }
                },
            }
        };
        if actual != expected {
            return Err(format!("F3 pipeline mismatch at m={m}"));
        }
        if matches!(
            actual,
            filters::Outcome::Rejected {
                stage: filters::Stage::F3,
                ..
            }
        ) {
            pipeline_rejections += 1;
        }
    }

    if positive_even_valuation_cases == 0 {
        return Err("F3 validation did not exercise a positive even v3 unit".to_owned());
    }

    Ok(F3ValidationSummary {
        max,
        checked: u64::from(max - 1),
        ungated_rejections,
        pipeline_rejections,
        positive_even_valuation_cases,
    })
}

/// Counts produced by the exhaustive cross-hit/LTE comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub pairs: u64,
    pub hits: u64,
}

/// Counts produced by the ungated F5/F6 local-decision comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F56ValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub local_decisions: u64,
    pub less_cases: u64,
    pub equal_cases: u64,
    pub greater_cases: u64,
    pub ungated_rejections: u64,
    pub pipeline_rejections: u64,
}

/// F4b soundness results and rejection-per-foreign-zero-check benchmark.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct F4bValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub foreign_zero_checks: u64,
    pub ungated_rejections: u64,
    pub pipeline_rejections: u64,
    pub rejection_per_cycle: f64,
    pub elapsed_nanos: u128,
}

/// Counts produced by the ungated F7 rejection and family-tag validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct F7ValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub sq_tags: u64,
    pub two_sq_tags: u64,
    pub pq_handoff_tags: u64,
    pub ungated_rejections: u64,
    pub pipeline_rejections: u64,
}

/// Counts and accounting data for the canonical short-circuit pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PipelineValidationSummary {
    pub max: u32,
    pub checked: u64,
    pub ungated_predicate_rejections: u64,
    pub short_circuit_rejections: u64,
    pub exact_fallbacks: u64,
    pub stats: crate::stats::PipelineStats,
}

/// Compares the canonical short-circuit trace with all independently
/// evaluated predicates and checks every rejection against exact `S`.
pub fn validate_pipeline_range(max: u32) -> Result<PipelineValidationSummary, String> {
    if max < 2 {
        return Err("pipeline validation maximum must be at least 2".to_owned());
    }

    const SIEVE_PRIMES: [u32; 23] = [
        5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    ];
    let spf = build_spf(max);
    let context = filters::CanonicalContext::new(&SIEVE_PRIMES, 20);
    let mut stats = crate::stats::PipelineStats::default();
    let mut ungated_predicate_rejections = 0u64;
    let mut short_circuit_rejections = 0u64;
    let mut exact_fallbacks = 0u64;

    for m in 2..=max {
        let residues = crate::tables::init_residues(&SIEVE_PRIMES, m);
        let mut ungated_candidate = Candidate::new(m, &spf);
        let ungated = filters::evaluate_ungated(&context, &mut ungated_candidate, &residues);
        if !ungated.evaluated_all() {
            return Err(format!("ungated predicate set skipped a stage at m={m}"));
        }

        for (stage, rejection) in [
            (filters::Stage::F1, ungated.f1),
            (filters::Stage::F2, ungated.f2),
            (filters::Stage::F3, ungated.f3),
            (filters::Stage::F4, ungated.f4),
            (filters::Stage::F4b, ungated.f4b),
            (filters::Stage::F56, ungated.f56),
            (filters::Stage::F7, ungated.f7),
        ] {
            if rejection.is_some() {
                ungated_predicate_rejections += 1;
                if matches!(&ungated.exact, filters::Outcome::Solution { .. }) {
                    return Err(format!(
                        "ungated {:?} rejected an exact square at m={m}",
                        stage
                    ));
                }
            }
        }

        let mut traced_candidate = Candidate::new(m, &spf);
        let trace = filters::run_canonical(&context, &mut traced_candidate, &residues);
        let expected = ungated.first_rejection().map_or_else(
            || ungated.exact.clone(),
            |(stage, rejection)| filters::Outcome::Rejected { stage, rejection },
        );
        if trace.outcome != expected {
            return Err(format!(
                "canonical trace mismatch at m={m}: actual={:?}, expected={expected:?}",
                trace.outcome
            ));
        }
        let expected_evaluated = match ungated.first_rejection() {
            Some((stage, _)) => filters::Stage::ALL[..=stage.index()].to_vec(),
            None => filters::Stage::ALL.to_vec(),
        };
        if trace.evaluated != expected_evaluated {
            return Err(format!(
                "canonical stage trace mismatch at m={m}: actual={:?}, expected={expected_evaluated:?}",
                trace.evaluated
            ));
        }
        if matches!(&trace.outcome, filters::Outcome::Rejected { .. }) {
            short_circuit_rejections += 1;
        }
        if trace.evaluated.contains(&filters::Stage::F8) {
            exact_fallbacks += 1;
        }
        stats.record(&trace);
    }

    stats.check_invariants()?;

    Ok(PipelineValidationSummary {
        max,
        checked: u64::from(max - 1),
        ungated_predicate_rejections,
        short_circuit_rejections,
        exact_fallbacks,
        stats,
    })
}

/// Compares every LTE cross-hit and aggregate valuation with direct exact
/// division of `T_j = sigma(p_j^(3e_j))`.
pub fn validate_cross_range(max: u32) -> Result<CrossValidationSummary, String> {
    if max < 2 {
        return Err("cross validation maximum must be at least 2".to_owned());
    }

    let spf = build_spf(max);
    let mut pairs = 0u64;
    let mut hits = 0u64;

    for m in 2..=max {
        let mut candidate = Candidate::new(m, &spf);
        let actual = cross::cross_hits(&mut candidate);
        let factors = candidate.f[..candidate.omega as usize].to_vec();
        let mut expected_totals = [0u32; crate::MAX_OMEGA];

        for (target_index, target) in factors
            .iter()
            .enumerate()
            .filter(|(_, factor)| factor.p >= 5)
        {
            for source in factors.iter().filter(|factor| factor.p != target.p) {
                pairs += 1;
                let term = exact_cross_term(source.p, source.e);
                let expected = if term % u128::from(target.p) == 0 {
                    hits += 1;
                    let value = exact_valuation(term, u128::from(target.p));
                    expected_totals[target_index] += value;
                    Some(value)
                } else {
                    None
                };
                let found = actual
                    .iter()
                    .find(|hit| hit.target == target.p && hit.source == source.p);
                match (expected, found) {
                    (None, None) => {}
                    (Some(value), Some(hit)) if hit.val == value => {}
                    (expected, found) => {
                        return Err(format!(
                            "cross mismatch at m={m}, target={}, source={}: expected={expected:?}, found={found:?}",
                            target.p, source.p
                        ));
                    }
                }
            }
        }

        for (index, expected) in expected_totals.iter().enumerate() {
            if candidate.cross_val[index] != *expected {
                return Err(format!(
                    "cross aggregate mismatch at m={m}, factor index={index}: expected={expected}, got={}",
                    candidate.cross_val[index]
                ));
            }
        }
    }

    if hits == 0 {
        return Err("cross validation found no hits".to_owned());
    }

    Ok(CrossValidationSummary {
        max,
        checked: u64::from(max - 1),
        pairs,
        hits,
    })
}

/// Compares every local F5/F6 valuation and unit with exact `S` arithmetic,
/// while also checking the normal F1-to-F3-to-F56 first-rejection ordering.
pub fn validate_f56_range(max: u32) -> Result<F56ValidationSummary, String> {
    if max < 2 {
        return Err("F5/F6 validation maximum must be at least 2".to_owned());
    }

    let spf = build_spf(max);
    let mut local_decisions = 0u64;
    let mut less_cases = 0u64;
    let mut equal_cases = 0u64;
    let mut greater_cases = 0u64;
    let mut ungated_rejections = 0u64;
    let mut pipeline_rejections = 0u64;

    for m in 2..=max {
        let mut ungated_candidate = Candidate::new(m, &spf);
        let sigma = exact::exact_sigma(&ungated_candidate);
        let s = exact::aliquot_sum(&ungated_candidate);
        let locals = filters::f56_local::analyze(&mut ungated_candidate);

        for local in &locals {
            local_decisions += 1;
            let exact_v_sigma = exact_valuation(sigma, u128::from(local.target));
            let exact_v_s = exact_valuation(s, u128::from(local.target));
            let exact_unit = exact_local_unit(s, local.target, exact_v_s);
            if local.v_sigma != exact_v_sigma || local.v_s != exact_v_s || local.unit != exact_unit
            {
                return Err(format!(
                    "local mismatch at m={m}, p={}: Rust (V={}, v={}, unit={}), exact (V={exact_v_sigma}, v={exact_v_s}, unit={exact_unit})",
                    local.target, local.v_sigma, local.v_s, local.unit
                ));
            }
            match local.case {
                filters::f56_local::LocalCase::Less => less_cases += 1,
                filters::f56_local::LocalCase::Equal => equal_cases += 1,
                filters::f56_local::LocalCase::Greater => greater_cases += 1,
            }
        }

        if filters::f56_local::f56(&mut ungated_candidate).is_some() {
            ungated_rejections += 1;
            if exact::is_square(s) {
                return Err(format!("ungated F5/F6 rejected a square at m={m}"));
            }
        }

        let mut pipeline_candidate = Candidate::new(m, &spf);
        let actual = filters::run_with_f56(&mut pipeline_candidate);
        let mut expected_candidate = Candidate::new(m, &spf);
        let expected = if let Some(rejection) = filters::f1(&expected_candidate) {
            filters::Outcome::Rejected {
                stage: filters::Stage::F1,
                rejection,
            }
        } else if let Some(rejection) = filters::f2(&mut expected_candidate) {
            filters::Outcome::rejected_f2(rejection)
        } else if let Some(rejection) = filters::f3(&mut expected_candidate) {
            filters::Outcome::Rejected {
                stage: filters::Stage::F3,
                rejection,
            }
        } else if let Some(rejection) = filters::f56(&mut expected_candidate) {
            filters::Outcome::Rejected {
                stage: filters::Stage::F56,
                rejection,
            }
        } else {
            let expected_s = exact::aliquot_sum(&expected_candidate);
            if exact::is_square(expected_s) {
                filters::Outcome::solution(exact::isqrt(expected_s))
            } else {
                filters::Outcome::exact_nonsquare()
            }
        };
        if actual != expected {
            return Err(format!("F5/F6 pipeline mismatch at m={m}"));
        }
        if matches!(
            actual,
            filters::Outcome::Rejected {
                stage: filters::Stage::F56,
                ..
            }
        ) {
            pipeline_rejections += 1;
        }
    }

    if equal_cases == 0 || greater_cases == 0 || less_cases == 0 {
        return Err(format!(
            "F5/F6 validation missed a branch: less={less_cases}, equal={equal_cases}, greater={greater_cases}"
        ));
    }

    Ok(F56ValidationSummary {
        max,
        checked: u64::from(max - 1),
        local_decisions,
        less_cases,
        equal_cases,
        greater_cases,
        ungated_rejections,
        pipeline_rejections,
    })
}

/// Validates F4b ungated over every F4 foreign zero and benchmarks its
/// rejection yield per checked foreign-zero entry.
pub fn validate_f4b_range(max: u32) -> Result<F4bValidationSummary, String> {
    if max < 2 {
        return Err("F4b validation maximum must be at least 2".to_owned());
    }

    const SIEVE_PRIMES: [u32; 23] = [
        5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    ];
    let spf = build_spf(max);
    let context = filters::F4Context::new(&SIEVE_PRIMES, 20);
    let f3_context = filters::F3Context::default();
    let mut foreign_zero_checks = 0u64;
    let mut ungated_rejections = 0u64;
    let mut pipeline_rejections = 0u64;
    let mut elapsed_nanos = 0u128;

    for m in 2..=max {
        let residues = crate::tables::init_residues(&SIEVE_PRIMES, m);
        let mut ungated_candidate = Candidate::new(m, &spf);
        let _ = filters::f4(&context, &mut ungated_candidate, &residues);
        foreign_zero_checks += ungated_candidate.foreign_zeros.len() as u64;

        let analyses = filters::f4b_foreign::analyze(&context, &mut ungated_candidate);
        let s = exact::aliquot_sum(&ungated_candidate);
        for analysis in analyses {
            let exact_v = exact_valuation(s, u128::from(analysis.q));
            let mut exact_unit = s;
            for _ in 0..exact_v {
                exact_unit /= u128::from(analysis.q);
            }
            let expected_unit = (exact_unit % u128::from(analysis.q)) as u32;
            if analysis.v != exact_v || analysis.unit != expected_unit {
                return Err(format!(
                    "F4b local mismatch at m={m}, q={}: Rust (v={}, unit={}), exact (v={exact_v}, unit={expected_unit})",
                    analysis.q, analysis.v, analysis.unit
                ));
            }
        }

        let start = Instant::now();
        let rejection = filters::f4b_foreign::f4b(&context, &mut ungated_candidate);
        elapsed_nanos += start.elapsed().as_nanos();
        if rejection.is_some() {
            ungated_rejections += 1;
            if exact::is_square(s) {
                return Err(format!("ungated F4b rejected a square at m={m}"));
            }
        }

        let mut pipeline_candidate = Candidate::new(m, &spf);
        let actual =
            filters::run_with_f3_f4_f4b(&f3_context, &context, &mut pipeline_candidate, &residues);
        if matches!(
            actual,
            filters::Outcome::Rejected {
                stage: filters::Stage::F4b,
                ..
            }
        ) {
            pipeline_rejections += 1;
        }
    }

    if foreign_zero_checks == 0 {
        return Err("F4b validation found no foreign-zero checks".to_owned());
    }

    Ok(F4bValidationSummary {
        max,
        checked: u64::from(max - 1),
        foreign_zero_checks,
        ungated_rejections,
        pipeline_rejections,
        rejection_per_cycle: ungated_rejections as f64 / foreign_zero_checks as f64,
        elapsed_nanos,
    })
}

/// Validates F7's exact family tags and checks every cheap sigma rejection
/// against exact sigma/S arithmetic and the complete normal pipeline.
pub fn validate_f7_range(max: u32) -> Result<F7ValidationSummary, String> {
    if max < 2 {
        return Err("F7 validation maximum must be at least 2".to_owned());
    }

    const SIEVE_PRIMES: [u32; 23] = [
        5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    ];
    let spf = build_spf(max);
    let f3_context = filters::F3Context::default();
    let f4_context = filters::F4Context::new(&SIEVE_PRIMES, 20);
    let f7_context = filters::F7Context::default();
    let mut sq_tags = 0u64;
    let mut two_sq_tags = 0u64;
    let mut pq_handoff_tags = 0u64;
    let mut ungated_rejections = 0u64;
    let mut pipeline_rejections = 0u64;

    for m in 2..=max {
        let candidate = Candidate::new(m, &spf);
        let factors = &candidate.f[..candidate.omega as usize];
        let expected_family = if factors.iter().all(|factor| factor.e % 2 == 0) {
            Some(filters::FamilyTag::Sq)
        } else if candidate.a2 == 1
            && factors
                .iter()
                .filter(|factor| factor.p != 2)
                .all(|factor| factor.e % 2 == 0)
        {
            Some(filters::FamilyTag::TwoSq)
        } else if factors.len() == 2
            && factors
                .iter()
                .all(|factor| factor.p % 2 == 1 && factor.e == 1)
        {
            Some(filters::FamilyTag::PqHandoff)
        } else {
            None
        };
        let analysis = filters::f7_special::analyze(&f7_context, &candidate);
        if analysis.family != expected_family {
            return Err(format!("F7 family tag mismatch at m={m}"));
        }
        match analysis.family {
            Some(filters::FamilyTag::Sq) => sq_tags += 1,
            Some(filters::FamilyTag::TwoSq) => two_sq_tags += 1,
            Some(filters::FamilyTag::PqHandoff) => pq_handoff_tags += 1,
            None => {}
        }

        if filters::f7_special::f7(&f7_context, &candidate).is_some() {
            ungated_rejections += 1;
            if !matches!(analysis.family, Some(filters::FamilyTag::Sq)) {
                return Err(format!("F7 rejected a non-square family at m={m}"));
            }
            let sigma = exact::exact_sigma(&candidate);
            for check in analysis.checks.iter().filter(|check| check.rejects) {
                if exact_valuation(sigma, u128::from(check.prime)) != 1 {
                    return Err(format!("F7 valuation mismatch at m={m}, r={}", check.prime));
                }
            }
            if exact::aliquot_sum_is_square(&candidate) {
                return Err(format!("ungated F7 rejected a square at m={m}"));
            }
        }

        let residues = crate::tables::init_residues(&SIEVE_PRIMES, m);
        let mut pipeline_candidate = Candidate::new(m, &spf);
        let actual = filters::run_with_f3_f4_f56_f7(
            &f3_context,
            &f4_context,
            &f7_context,
            &mut pipeline_candidate,
            &residues,
        );
        if matches!(
            actual,
            filters::Outcome::Rejected {
                stage: filters::Stage::F7,
                ..
            }
        ) {
            pipeline_rejections += 1;
        }
    }

    if sq_tags == 0 || two_sq_tags == 0 || pq_handoff_tags == 0 {
        return Err(format!(
            "F7 validation missed a family tag: sq={sq_tags}, 2sq={two_sq_tags}, pq={pq_handoff_tags}"
        ));
    }

    Ok(F7ValidationSummary {
        max,
        checked: u64::from(max - 1),
        sq_tags,
        two_sq_tags,
        pq_handoff_tags,
        ungated_rejections,
        pipeline_rejections,
    })
}

fn exact_cross_term(source: u64, exponent: u32) -> u128 {
    let mut power = 1u128;
    let mut sum = 0u128;
    for index in 0..=3 * exponent {
        sum = sum
            .checked_add(power)
            .expect("exact cross term does not fit in u128");
        if index < 3 * exponent {
            power = power
                .checked_mul(u128::from(source))
                .expect("exact cross term does not fit in u128");
        }
    }
    sum
}

fn exact_valuation(mut value: u128, prime: u128) -> u32 {
    let mut valuation = 0;
    while value % prime == 0 {
        value /= prime;
        valuation += 1;
    }
    valuation
}

fn exact_local_unit(mut value: u128, prime: u64, valuation: u32) -> u32 {
    for _ in 0..valuation {
        value /= u128::from(prime);
    }
    (value % u128::from(prime)) as u32
}

fn compare_records(
    lines: &mut impl Iterator<Item = std::io::Result<String>>,
    max: u32,
    spf: &[u16],
) -> Result<ValidationSummary, String> {
    let mut checked = 0u64;
    let mut direct_checked = 0u64;
    let mut multiplicative_checked = 0u64;

    for expected_m in 2..=max {
        let line = lines
            .next()
            .ok_or_else(|| format!("Python oracle stopped before m={expected_m}"))?
            .map_err(|error| format!("could not read Python oracle output: {error}"))?;
        let oracle: OracleRecord = serde_json::from_str(&line)
            .map_err(|error| format!("invalid Python oracle record for m={expected_m}: {error}"))?;

        if oracle.m != expected_m {
            return Err(format!(
                "Python oracle record out of order: expected m={expected_m}, got m={}",
                oracle.m
            ));
        }

        let candidate = Candidate::new(expected_m, spf);
        let sigma = exact::exact_sigma(&candidate);
        let s = exact::aliquot_sum(&candidate);
        let is_square = exact::is_square(s);

        if sigma != oracle.sigma_m3 || s != oracle.s || is_square != oracle.is_square {
            return Err(format!(
                "Rust/Python mismatch for m={expected_m}: Rust (sigma={sigma}, s={s}, is_square={is_square}), Python (sigma={}, s={}, is_square={})",
                oracle.sigma_m3, oracle.s, oracle.is_square
            ));
        }

        match oracle.method.as_str() {
            "direct" => direct_checked += 1,
            "multiplicative" => multiplicative_checked += 1,
            method => return Err(format!("unknown Python oracle method: {method}")),
        }
        checked += 1;
    }

    if let Some(extra) = lines.next() {
        let extra =
            extra.map_err(|error| format!("could not read extra oracle output: {error}"))?;
        if !extra.trim().is_empty() {
            return Err("Python oracle emitted more records than requested".to_owned());
        }
    }

    Ok(ValidationSummary {
        max,
        checked,
        direct_checked,
        multiplicative_checked,
    })
}

fn spawn_oracle(max: u32) -> Result<Child, String> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("oracle.py");
    if !script.is_file() {
        return Err(format!(
            "Python oracle script is missing: {}",
            script.display()
        ));
    }

    let command_args = |python: &str| {
        let mut command = Command::new(python);
        command
            .arg(&script)
            .arg("--max")
            .arg(max.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    };

    match command_args("python").spawn() {
        Ok(child) => Ok(child),
        Err(first_error) if first_error.kind() == std::io::ErrorKind::NotFound => {
            command_args("python3").spawn().map_err(|second_error| {
                format!("could not start Python oracle: {first_error}; {second_error}")
            })
        }
        Err(error) => Err(format!("could not start Python oracle: {error}")),
    }
}

fn read_child_stderr(child: &mut Child) -> String {
    let Some(mut stderr) = child.stderr.take() else {
        return "stderr unavailable".to_owned();
    };
    let mut output = String::new();
    let _ = stderr.read_to_string(&mut output);
    output.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        validate_f1_range, validate_f2_range, validate_f3_range, validate_f4b_range,
        validate_f7_range, validate_f56_range, validate_pipeline_range, validate_range,
    };

    #[test]
    fn rejects_an_empty_validation_range() {
        assert!(validate_range(1).is_err());
    }

    #[test]
    fn rejects_an_empty_f1_validation_range() {
        assert!(validate_f1_range(1).is_err());
    }

    #[test]
    fn rejects_an_empty_f2_validation_range() {
        assert!(validate_f2_range(1).is_err());
    }

    #[test]
    fn rejects_an_empty_f3_validation_range() {
        assert!(validate_f3_range(1).is_err());
    }

    #[test]
    fn rejects_an_empty_f56_validation_range() {
        assert!(validate_f56_range(1).is_err());
    }

    #[test]
    fn rejects_an_empty_f4b_validation_range() {
        assert!(validate_f4b_range(1).is_err());
    }

    #[test]
    fn rejects_an_empty_f7_validation_range() {
        assert!(validate_f7_range(1).is_err());
    }

    #[test]
    fn rejects_an_empty_pipeline_validation_range() {
        assert!(validate_pipeline_range(1).is_err());
    }
}
