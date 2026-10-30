//! Deterministic survivor JSONL and resumable run state.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    Candidate, build_spf, cross,
    family::{ExclusionWitness, LoadedTheoremMap, TheoremMap},
    filters::{self, CanonicalContext, FamilyTag, Outcome, PipelineTrace, Rejection, Stage},
    numth::legendre,
    spf::{BasePrimes, FLAT_SPF_LIMIT, SEGMENT_WIDTH, SegmentedSpf},
    stats::{CanonicalStats, PipelineStats},
};

/// Version of the persistence contract that records theorem-map premises.
pub const RUN_METADATA_SCHEMA_VERSION: u32 = 3;
/// Legacy checkpoints omit theorem-map premises and are represented as v1.
pub const LEGACY_CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const RHS_VERSION: u32 = crate::family::admission::FAMILY_RHS_VERSION;
pub const STAGE_SCHEMA_VERSION: u32 = 1;

const SIEVE_PRIMES: [u32; 23] = [
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossRecord {
    pub t: u64,
    pub s: u64,
    pub e: u32,
    pub v: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalRecord {
    #[serde(rename = "V")]
    pub valuation_sigma: u32,
    #[serde(rename = "v")]
    pub valuation_s: u32,
    pub unit: u32,
    pub lr: i32,
}

/// Stable JSONL representation of one analyzed candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SurvivorRecord {
    pub m: u64,
    pub factors: Vec<[u64; 2]>,
    pub omega: u8,
    pub a2: u8,
    pub stage: Stage,
    pub rejection: Option<Rejection>,
    pub v2_s: u32,
    pub unit2: u8,
    pub v3_s: u32,
    pub unit3: u8,
    pub s_mod: BTreeMap<u32, u32>,
    pub foreign_zeros: Vec<usize>,
    pub cross: Vec<CrossRecord>,
    pub local: BTreeMap<u64, LocalRecord>,
    pub family: Option<FamilyTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_witness: Option<ExclusionWitness>,
    #[serde(rename = "S")]
    pub s: Option<u128>,
    pub y: Option<u128>,
    #[serde(default, rename = "S_big", skip_serializing_if = "Option::is_none")]
    pub s_big: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y_big: Option<String>,
}

impl SurvivorRecord {
    /// Builds a record after the canonical trace. The ungated analyses fill
    /// late-stage fields even when the normal trace stopped early.
    pub fn from_trace(
        context: &CanonicalContext,
        candidate: &mut Candidate,
        residues: &[u32],
        trace: &PipelineTrace,
    ) -> Self {
        let _ = filters::evaluate_ungated_wide(context, candidate, residues);
        let f2 = filters::f2_adic2::analyze(candidate);
        let f3 = filters::f3_adic3::analyze_with_context(&context.f3, candidate);
        let hits = cross::cross_hits(candidate);
        let locals = filters::f56_local::analyze(candidate);
        let family = filters::f7_special::family_tag(candidate);

        let (stage, rejection, y, y_big) = match &trace.outcome {
            Outcome::Rejected { stage, rejection } => (*stage, Some(*rejection), None, None),
            Outcome::Solution { y } => (Stage::F8, None, Some(*y), None),
            Outcome::WideSolution { y } => (
                Stage::F8,
                None,
                y.as_u128(),
                y.as_u128().is_none().then(|| y.to_biguint().to_string()),
            ),
        };
        let (s, s_big) = if trace.evaluated.contains(&Stage::F8) {
            match candidate
                .exact_s_cache
                .clone()
                .unwrap_or_else(|| crate::exact::exact_s_exact(candidate))
            {
                crate::exact::ExactNat::Small(value) => (Some(value), None),
                crate::exact::ExactNat::Big(value) => (None, Some(value.to_string())),
            }
        } else {
            (None, None)
        };

        let factors = candidate.f[..candidate.omega as usize]
            .iter()
            .map(|factor| [factor.p, u64::from(factor.e)])
            .collect();
        let s_mod = context
            .f4
            .sieve_primes
            .iter()
            .copied()
            .zip(candidate.s_mod_sieve.iter().copied())
            .collect();
        let mut cross: Vec<CrossRecord> = hits
            .into_iter()
            .map(|hit| CrossRecord {
                t: hit.target,
                s: hit.source,
                e: hit.e_source,
                v: hit.val,
            })
            .collect();
        cross.sort_by_key(|hit| (hit.t, hit.s));
        let local = locals
            .into_iter()
            .map(|local| {
                (
                    local.target,
                    LocalRecord {
                        valuation_sigma: local.v_sigma,
                        valuation_s: local.v_s,
                        unit: local.unit,
                        lr: legendre(
                            local.unit,
                            u32::try_from(local.target)
                                .expect("local prime does not fit legacy unit type"),
                        ),
                    },
                )
            })
            .collect();

        Self {
            m: candidate.m,
            factors,
            omega: candidate.omega,
            a2: candidate.a2,
            stage,
            rejection,
            v2_s: f2.v2_s,
            unit2: f2.unit8,
            v3_s: f3.v3_s,
            unit3: f3.unit3,
            s_mod,
            foreign_zeros: candidate.foreign_zeros.clone(),
            cross,
            local,
            family,
            family_witness: trace.family_witness.clone(),
            s,
            y,
            s_big,
            y_big,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RunOutput {
    pub records: Vec<SurvivorRecord>,
    pub stats: PipelineStats,
    /// Present for map-enabled runs so callers can report backend trust.
    pub run_metadata: Option<RunMetadata>,
}

/// Legacy checkpoint quantum and maximum diagnostic streaming batch.
pub const STREAM_BATCH_SIZE: u32 = 1 << 16;

/// Maximum compute batch when only sparse F8 survivor records are retained.
pub const MAX_COMPUTE_BATCH_SIZE: u32 = 1 << 20;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StreamOutput {
    pub records_written: u64,
    pub stats: PipelineStats,
    pub interrupted: bool,
    /// Present for map-enabled runs so callers can report backend trust.
    pub run_metadata: Option<RunMetadata>,
}

/// Immutable mathematical premises bound to a persisted run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunPremises {
    pub schema_version: u32,
    pub theorem_map_digest: Option<String>,
    pub theorem_snapshot_id: Option<String>,
    pub theorem_store_id: Option<String>,
    pub theorem_policy_id: Option<String>,
    pub selected_admission_ids: Vec<String>,
    pub admitted_proof_policy: String,
    pub rhs_version: u32,
    pub stage_schema_version: u32,
    pub enabled_stages: Vec<Stage>,
}

impl RunPremises {
    pub fn legacy_no_map() -> Self {
        Self {
            schema_version: LEGACY_CHECKPOINT_SCHEMA_VERSION,
            theorem_map_digest: None,
            theorem_snapshot_id: None,
            theorem_store_id: None,
            theorem_policy_id: None,
            selected_admission_ids: Vec::new(),
            admitted_proof_policy: "no-theorem-map".to_owned(),
            rhs_version: RHS_VERSION,
            stage_schema_version: STAGE_SCHEMA_VERSION,
            enabled_stages: Stage::ALL.to_vec(),
        }
    }

    pub fn for_family_map(family_map: &TheoremMap) -> Result<Self, String> {
        Ok(Self {
            schema_version: RUN_METADATA_SCHEMA_VERSION,
            theorem_map_digest: Some(family_map.snapshot_digest()?),
            theorem_snapshot_id: None,
            theorem_store_id: None,
            theorem_policy_id: None,
            selected_admission_ids: Vec::new(),
            admitted_proof_policy: family_map.admitted_proof_policy().to_owned(),
            rhs_version: RHS_VERSION,
            stage_schema_version: STAGE_SCHEMA_VERSION,
            enabled_stages: filters::FAMILY_STAGES.to_vec(),
        })
    }

    pub fn for_loaded_family_map(loaded: &LoadedTheoremMap) -> Result<Self, String> {
        let mut premises = Self::for_family_map(loaded.map())?;
        premises.theorem_snapshot_id = Some(loaded.snapshot_id().to_owned());
        premises.theorem_store_id = Some(loaded.store_id().to_owned());
        premises.theorem_policy_id = Some(loaded.policy_id().to_owned());
        premises.selected_admission_ids = loaded.admission_ids().to_vec();
        Ok(premises)
    }

    pub fn uses_theorem_map(&self) -> bool {
        self.theorem_map_digest.is_some()
    }
}

/// Run metadata is intentionally separate from the mathematical output
/// records. It makes backend trust explicit for completed bounded streams.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunMetadata {
    pub schema_version: u32,
    pub config_hash: String,
    pub premises: RunPremises,
    pub backend_trusted: bool,
}

impl RunMetadata {
    pub fn from(config_hash: String, premises: RunPremises) -> Self {
        let backend_trusted = premises.admitted_proof_policy == "trusted-backend"
            || premises.admitted_proof_policy == "mixed-local-and-trusted-backend";
        Self {
            schema_version: RUN_METADATA_SCHEMA_VERSION,
            config_hash,
            premises,
            backend_trusted,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamProgress {
    pub completed_through: u64,
    pub tested: u64,
    pub records_written: u64,
}

/// Controls how often a checkpointed stream durably records progress.
///
/// Candidate intervals are measured from the last durable checkpoint. An
/// elapsed-time interval is an additional trigger; when either trigger fires,
/// the current batch is flushed and the checkpoint is atomically replaced.
/// The default used by the legacy checkpointed APIs is one checkpoint per
/// streaming batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointSchedule {
    pub every_candidates: Option<u64>,
    pub every_seconds: Option<Duration>,
}

impl CheckpointSchedule {
    pub fn new(
        every_candidates: Option<u64>,
        every_seconds: Option<Duration>,
    ) -> Result<Self, String> {
        if every_candidates == Some(0) {
            return Err("checkpoint candidate interval must be positive".to_owned());
        }
        if every_seconds.is_some_and(|interval| interval.is_zero()) {
            return Err("checkpoint time interval must be positive".to_owned());
        }
        Ok(Self {
            every_candidates,
            every_seconds,
        })
    }

    pub const fn every_batch() -> Self {
        Self {
            every_candidates: Some(STREAM_BATCH_SIZE as u64),
            every_seconds: None,
        }
    }

    pub const fn disabled() -> Self {
        Self {
            every_candidates: None,
            every_seconds: None,
        }
    }
}

/// One factorization setup shared across all workers and streaming batches.
enum FactorizationTables {
    Flat(Vec<u16>),
    Segmented(BasePrimes),
}

impl FactorizationTables {
    fn for_end(end: u64) -> Result<Self, String> {
        if end <= FLAT_SPF_LIMIT {
            Ok(Self::Flat(build_spf(
                u32::try_from(end).expect("flat limit fits u32"),
            )))
        } else {
            Ok(Self::Segmented(BasePrimes::for_end(end)?))
        }
    }
}

/// Collects a range using contiguous worker chunks and canonical merge order.
pub fn collect_range(
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
) -> Result<RunOutput, String> {
    validate_range(start, end, threads)?;
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    collect_range_with_setup(
        start,
        end,
        threads,
        dump_beyond,
        &factorization,
        &context,
        None,
    )
}

/// Collects a range with an explicitly supplied immutable theorem map.
pub fn collect_range_with_family_map(
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    family_map: &TheoremMap,
) -> Result<RunOutput, String> {
    validate_range(start, end, threads)?;
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let mut output = collect_range_with_setup(
        start,
        end,
        threads,
        dump_beyond,
        &factorization,
        &context,
        Some(family_map),
    )?;
    let premises = RunPremises::for_family_map(family_map)?;
    output.run_metadata = Some(RunMetadata::from(
        config_hash_with_premises("collect", &premises),
        premises,
    ));
    Ok(output)
}

/// Collect a range using a theorem map loaded from one immutable store
/// snapshot.  The mathematical lookup is the same as
/// `collect_range_with_family_map`, but the run metadata retains the
/// snapshot/store/admission selection identity that was verified at load
/// time.  No backend is consulted by this function.
pub fn collect_range_with_loaded_family_map(
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    loaded: &LoadedTheoremMap,
) -> Result<RunOutput, String> {
    validate_range(start, end, threads)?;
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let mut output = collect_range_with_setup(
        start,
        end,
        threads,
        dump_beyond,
        &factorization,
        &context,
        Some(loaded.map()),
    )?;
    let premises = RunPremises::for_loaded_family_map(loaded)?;
    output.run_metadata = Some(RunMetadata::from(
        config_hash_with_premises("collect", &premises),
        premises,
    ));
    Ok(output)
}

fn collect_range_with_setup(
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    factorization: &FactorizationTables,
    context: &CanonicalContext,
    family_map: Option<&TheoremMap>,
) -> Result<RunOutput, String> {
    validate_range(start, end, threads)?;
    let count =
        usize::try_from(u128::from(end) - u128::from(start) + 1).expect("range length fits usize");
    let worker_count = threads.min(count);
    let chunk_size = count.div_ceil(worker_count);
    let mut chunks = Vec::new();
    for worker in 0..worker_count {
        let offset = worker * chunk_size;
        if offset >= count {
            break;
        }
        let chunk_start = start + u64::try_from(offset).expect("chunk offset fits u64");
        let chunk_end = end.min(
            chunk_start
                .checked_add(u64::try_from(chunk_size - 1).expect("chunk size fits u64"))
                .expect("chunk end fits u64"),
        );
        chunks.push((chunk_start, chunk_end));
    }

    let outputs = std::thread::scope(|scope| {
        let handles = chunks
            .into_iter()
            .map(|(chunk_start, chunk_end)| {
                let worker_context = context.clone();
                scope.spawn(move || {
                    collect_chunk(
                        chunk_start,
                        chunk_end,
                        factorization,
                        &worker_context,
                        dump_beyond,
                        family_map,
                    )
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("pipeline worker panicked"))
            .collect::<Vec<_>>()
    });

    let mut output = RunOutput::default();
    for worker_output in outputs {
        output.stats.merge(&worker_output.stats);
        output.records.extend(worker_output.records);
    }
    output.records.sort_by_key(|record| record.m);
    if family_map.is_some() {
        output.stats.check_invariants_for(&filters::FAMILY_STAGES)?;
    } else {
        output.stats.check_invariants()?;
    }
    Ok(output)
}

pub fn write_jsonl_range(
    path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
) -> Result<RunOutput, String> {
    let output = collect_range(start, end, threads, dump_beyond)?;
    write_records(path, &output.records, false)?;
    Ok(output)
}

/// Writes a range using the opt-in family stage.
pub fn write_jsonl_range_with_family_map(
    path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    family_map: &TheoremMap,
) -> Result<RunOutput, String> {
    let output = collect_range_with_family_map(start, end, threads, dump_beyond, family_map)?;
    write_records(path, &output.records, false)?;
    Ok(output)
}

/// Streams a range to JSONL in bounded batches without checkpointing.
pub fn stream_jsonl_range(
    path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
) -> Result<StreamOutput, String> {
    stream_jsonl_range_with_progress(path, start, end, threads, dump_beyond, |_| {})
}

/// Streaming JSONL writer with a callback after each flushed batch.
pub fn stream_jsonl_range_with_progress(
    path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    progress: impl FnMut(StreamProgress),
) -> Result<StreamOutput, String> {
    stream_jsonl_range_with_progress_and_cancel(
        path,
        start,
        end,
        threads,
        dump_beyond,
        progress,
        || false,
    )
}

/// Streaming JSONL writer with progress reporting and cooperative
/// cancellation. Cancellation is honored only between complete batches.
pub fn stream_jsonl_range_with_progress_and_cancel(
    path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    validate_range(start, end, threads)?;
    let mut progress = progress;
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let mut writer = JsonlWriter::new(path, false)?;
    stream_batches(
        &mut writer,
        &factorization,
        &context,
        start,
        end,
        start,
        end,
        threads,
        dump_beyond,
        PipelineStats::default(),
        Vec::new(),
        CheckpointSchedule::disabled(),
        None,
        None,
        None,
        None,
        &mut progress,
        &should_stop,
    )
}

/// Streams a range with an explicitly supplied immutable theorem map.
pub fn stream_jsonl_range_with_family_map(
    path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    family_map: &TheoremMap,
) -> Result<StreamOutput, String> {
    stream_jsonl_range_with_family_map_and_cancel(
        path,
        start,
        end,
        threads,
        dump_beyond,
        family_map,
        || false,
    )
}

/// Map-enabled streaming with cooperative cancellation.
pub fn stream_jsonl_range_with_family_map_and_cancel(
    path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    family_map: &TheoremMap,
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    validate_range(start, end, threads)?;
    let premises = RunPremises::for_family_map(family_map)?;
    let run_hash = config_hash_with_premises("stream", &premises);
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let mut writer = JsonlWriter::new(path, false)?;
    stream_batches(
        &mut writer,
        &factorization,
        &context,
        start,
        end,
        start,
        end,
        threads,
        dump_beyond,
        PipelineStats::default(),
        Vec::new(),
        CheckpointSchedule::disabled(),
        None,
        Some(run_hash),
        Some(family_map),
        Some(premises),
        &mut |_| {},
        &should_stop,
    )
}

/// Streaming search bound to a previously loaded immutable store snapshot.
/// The loader has already verified every admission; this function only holds
/// the resulting map and premises for the lifetime of the run.
pub fn stream_jsonl_range_with_loaded_family_map_and_cancel(
    path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    loaded: &LoadedTheoremMap,
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    validate_range(start, end, threads)?;
    let premises = RunPremises::for_loaded_family_map(loaded)?;
    let run_hash = config_hash_with_premises("stream", &premises);
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let mut writer = JsonlWriter::new(path, false)?;
    stream_batches(
        &mut writer,
        &factorization,
        &context,
        start,
        end,
        start,
        end,
        threads,
        dump_beyond,
        PipelineStats::default(),
        Vec::new(),
        CheckpointSchedule::disabled(),
        None,
        Some(run_hash),
        Some(loaded.map()),
        Some(premises),
        &mut |_| {},
        &should_stop,
    )
}

/// Starts a checkpointed streaming JSONL run using the default one-batch
/// checkpoint schedule.
pub fn stream_jsonl_range_checkpointed(
    output_path: &Path,
    checkpoint_path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    progress: impl FnMut(StreamProgress),
) -> Result<StreamOutput, String> {
    stream_jsonl_range_checkpointed_with_progress_and_cancel(
        output_path,
        checkpoint_path,
        start,
        end,
        threads,
        dump_beyond,
        config,
        progress,
        || false,
    )
}

pub fn stream_jsonl_range_checkpointed_with_progress_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    stream_jsonl_range_checkpointed_with_schedule_and_cancel(
        output_path,
        checkpoint_path,
        start,
        end,
        threads,
        dump_beyond,
        config,
        CheckpointSchedule::every_batch(),
        progress,
        should_stop,
    )
}

/// Starts a checkpointed stream using an explicit periodic schedule.
pub fn stream_jsonl_range_checkpointed_with_schedule_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    schedule: CheckpointSchedule,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    validate_range(start, end, threads)?;
    let mut progress = progress;
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let mut writer = JsonlWriter::new(output_path, false)?;
    let initial_checkpoint = Checkpoint::new_for_range(
        start,
        end,
        start,
        PipelineStats::default(),
        config_hash(config),
        Vec::new(),
    );
    write_checkpoint(checkpoint_path, &initial_checkpoint)?;
    stream_batches(
        &mut writer,
        &factorization,
        &context,
        start,
        end,
        start,
        end,
        threads,
        dump_beyond,
        PipelineStats::default(),
        Vec::new(),
        schedule,
        Some(checkpoint_path),
        Some(config_hash(config)),
        None,
        None,
        &mut progress,
        &should_stop,
    )
}

/// Starts a checkpointed stream bound to one immutable admitted theorem map.
/// The map is held by reference for the entire run; its canonical digest and
/// proof policy are persisted in every schema-2 checkpoint.
pub fn stream_jsonl_range_checkpointed_with_family_map_and_schedule_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    schedule: CheckpointSchedule,
    family_map: &TheoremMap,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    validate_range(start, end, threads)?;
    let mut progress = progress;
    let premises = RunPremises::for_family_map(family_map)?;
    let run_hash = config_hash_with_premises(config, &premises);
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let mut writer = JsonlWriter::new(output_path, false)?;
    let initial_checkpoint = Checkpoint::new_for_run(
        start,
        end,
        start,
        PipelineStats::default(),
        config,
        premises.clone(),
        Vec::new(),
    );
    write_checkpoint(checkpoint_path, &initial_checkpoint)?;
    stream_batches(
        &mut writer,
        &factorization,
        &context,
        start,
        end,
        start,
        end,
        threads,
        dump_beyond,
        PipelineStats::default(),
        Vec::new(),
        schedule,
        Some(checkpoint_path),
        Some(run_hash),
        Some(family_map),
        Some(premises),
        &mut progress,
        &should_stop,
    )
}

pub fn stream_jsonl_range_checkpointed_with_family_map_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    family_map: &TheoremMap,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    stream_jsonl_range_checkpointed_with_family_map_and_schedule_and_cancel(
        output_path,
        checkpoint_path,
        start,
        end,
        threads,
        dump_beyond,
        config,
        CheckpointSchedule::every_batch(),
        family_map,
        progress,
        should_stop,
    )
}

/// Starts a checkpointed stream bound to one loaded immutable store snapshot.
pub fn stream_jsonl_range_checkpointed_with_loaded_family_map_and_schedule_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    start: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    schedule: CheckpointSchedule,
    loaded: &LoadedTheoremMap,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    validate_range(start, end, threads)?;
    let mut progress = progress;
    let premises = RunPremises::for_loaded_family_map(loaded)?;
    let run_hash = config_hash_with_premises(config, &premises);
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let mut writer = JsonlWriter::new(output_path, false)?;
    let initial_checkpoint = Checkpoint::new_for_run(
        start,
        end,
        start,
        PipelineStats::default(),
        config,
        premises.clone(),
        Vec::new(),
    );
    write_checkpoint(checkpoint_path, &initial_checkpoint)?;
    stream_batches(
        &mut writer,
        &factorization,
        &context,
        start,
        end,
        start,
        end,
        threads,
        dump_beyond,
        PipelineStats::default(),
        Vec::new(),
        schedule,
        Some(checkpoint_path),
        Some(run_hash),
        Some(loaded.map()),
        Some(premises),
        &mut progress,
        &should_stop,
    )
}

pub fn read_jsonl(path: &Path) -> Result<Vec<SurvivorRecord>, String> {
    let file = File::open(path).map_err(|error| format!("could not open JSONL: {error}"))?;
    let mut records = Vec::new();
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|error| format!("could not read JSONL line: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        records.push(serde_json::from_str(&line).map_err(|error| {
            format!("invalid JSONL record at line {}: {error}", line_number + 1)
        })?);
    }
    Ok(records)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardMetadata {
    pub start_m: u64,
    pub end_m: u64,
    pub path: String,
    pub bytes: u64,
}

impl ShardMetadata {
    pub fn from_file(start_m: u64, end_m: u64, path: &Path) -> Result<Self, String> {
        let bytes = fs::metadata(path)
            .map_err(|error| format!("could not stat output shard: {error}"))?
            .len();
        Ok(Self {
            start_m,
            end_m,
            path: path.to_string_lossy().into_owned(),
            bytes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Checkpoint {
    #[serde(default = "legacy_checkpoint_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub range_start: u64,
    #[serde(default)]
    pub range_end: u64,
    pub next_m: u64,
    #[serde(default)]
    pub complete: bool,
    pub stats: PipelineStats,
    pub config_hash: String,
    pub completed_output_shards: Vec<ShardMetadata>,
    #[serde(default)]
    pub output_bytes: u64,
    /// None is the explicit legacy no-map format. Map-enabled checkpoints
    /// must carry the complete premises identity.
    #[serde(default)]
    pub premises: Option<RunPremises>,
}

fn legacy_checkpoint_schema_version() -> u32 {
    LEGACY_CHECKPOINT_SCHEMA_VERSION
}

impl Checkpoint {
    pub fn new(
        next_m: u64,
        stats: PipelineStats,
        config_hash: String,
        completed_output_shards: Vec<ShardMetadata>,
    ) -> Self {
        let output_bytes = completed_output_shards
            .iter()
            .map(|shard| shard.bytes)
            .sum();
        Self {
            schema_version: LEGACY_CHECKPOINT_SCHEMA_VERSION,
            range_start: 0,
            range_end: 0,
            next_m,
            complete: false,
            stats,
            config_hash,
            completed_output_shards,
            output_bytes,
            premises: None,
        }
    }

    pub fn new_for_range(
        range_start: u64,
        range_end: u64,
        next_m: u64,
        stats: PipelineStats,
        config_hash: String,
        completed_output_shards: Vec<ShardMetadata>,
    ) -> Self {
        let mut checkpoint = Self::new(next_m, stats, config_hash, completed_output_shards);
        checkpoint.range_start = range_start;
        checkpoint.range_end = range_end;
        if next_m > range_end {
            checkpoint.next_m = range_end;
            checkpoint.complete = true;
        }
        checkpoint
    }

    pub fn new_for_run(
        range_start: u64,
        range_end: u64,
        next_m: u64,
        stats: PipelineStats,
        config: &str,
        premises: RunPremises,
        completed_output_shards: Vec<ShardMetadata>,
    ) -> Self {
        let run_hash = config_hash_with_premises(config, &premises);
        let mut checkpoint = Self::new_for_range(
            range_start,
            range_end,
            next_m,
            stats,
            run_hash,
            completed_output_shards,
        );
        checkpoint.schema_version = RUN_METADATA_SCHEMA_VERSION;
        checkpoint.premises = Some(premises);
        checkpoint
    }

    fn verify_config(&self, config: &str) -> Result<(), String> {
        if self.config_hash != config_hash(config) {
            return Err("checkpoint config hash does not match requested config".to_owned());
        }
        Ok(())
    }

    fn verify_run(
        &self,
        config: &str,
        expected_premises: &RunPremises,
        family_map: Option<&TheoremMap>,
    ) -> Result<(), String> {
        if self.schema_version == LEGACY_CHECKPOINT_SCHEMA_VERSION {
            if expected_premises.uses_theorem_map() {
                return Err(
                    "legacy checkpoint has no theorem snapshot; map-enabled resume is rejected"
                        .to_owned(),
                );
            }
            if self.premises.is_some() {
                return Err("legacy checkpoint has malformed premises metadata".to_owned());
            }
            return self.verify_config(config);
        }
        if self.schema_version != RUN_METADATA_SCHEMA_VERSION {
            return Err(format!(
                "unsupported map-aware checkpoint schema version {}",
                self.schema_version
            ));
        }
        let Some(actual) = self.premises.as_ref() else {
            return Err("map-aware checkpoint is missing premises metadata".to_owned());
        };
        if actual != expected_premises {
            return Err("checkpoint mathematical premises do not match requested run".to_owned());
        }
        if self.config_hash != config_hash_with_premises(config, expected_premises) {
            return Err("checkpoint config hash does not match requested run".to_owned());
        }
        if expected_premises.uses_theorem_map() {
            let Some(family_map) = family_map else {
                return Err("map-enabled resume requires the admitted theorem snapshot".to_owned());
            };
            let actual_digest = family_map.snapshot_digest()?;
            if expected_premises.theorem_map_digest.as_deref() != Some(actual_digest.as_str()) {
                return Err("theorem snapshot digest does not match checkpoint".to_owned());
            }
            if expected_premises.admitted_proof_policy != family_map.admitted_proof_policy() {
                return Err("admitted theorem proof policy does not match checkpoint".to_owned());
            }
        }
        Ok(())
    }
}

pub fn write_checkpoint(path: &Path, checkpoint: &Checkpoint) -> Result<(), String> {
    let temp_path = checkpoint_temp_path(path);
    let file = File::create(&temp_path)
        .map_err(|error| format!("could not create checkpoint temporary file: {error}"))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, checkpoint)
        .map_err(|error| format!("could not serialize checkpoint: {error}"))?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("could not finish checkpoint: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("could not flush checkpoint: {error}"))?;
    writer
        .into_inner()
        .map_err(|error| format!("could not finalize checkpoint: {error}"))?
        .sync_all()
        .map_err(|error| format!("could not sync checkpoint: {error}"))?;
    atomic_replace(&temp_path, path)
        .map_err(|error| format!("could not replace checkpoint atomically: {error}"))
}

fn checkpoint_temp_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".tmp");
    value.into()
}

#[cfg(not(windows))]
fn atomic_replace(temp_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp_path, path)
}

#[cfg(windows)]
unsafe extern "system" {
    fn MoveFileExW(existing_file_name: *const u16, new_file_name: *const u16, flags: u32) -> i32;
}

#[cfg(windows)]
fn atomic_replace(temp_path: &Path, path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::time::Duration;

    let source = temp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    for attempt in 0u32..8 {
        let result = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                0x0000_0001 | 0x0000_0008,
            )
        };
        if result != 0 {
            return Ok(());
        }

        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::PermissionDenied || attempt == 7 {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(25 * u64::from(attempt + 1)));
    }

    unreachable!("atomic replacement loop must return")
}

pub fn read_checkpoint(path: &Path) -> Result<Checkpoint, String> {
    let contents =
        fs::read_to_string(path).map_err(|error| format!("could not read checkpoint: {error}"))?;
    let mut checkpoint: Checkpoint =
        serde_json::from_str(&contents).map_err(|error| format!("invalid checkpoint: {error}"))?;
    if checkpoint.output_bytes == 0 {
        checkpoint.output_bytes = checkpoint
            .completed_output_shards
            .iter()
            .map(|shard| shard.bytes)
            .sum();
    }
    Ok(checkpoint)
}

/// Resumes the range at the checkpoint's `next_m` and appends new JSONL lines.
pub fn resume_jsonl_range(
    output_path: &Path,
    checkpoint_path: &Path,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
) -> Result<RunOutput, String> {
    let checkpoint = read_checkpoint(checkpoint_path)?;
    if checkpoint.schema_version != LEGACY_CHECKPOINT_SCHEMA_VERSION
        || checkpoint.premises.is_some()
    {
        return Err(
            "map-aware checkpoint requires the admitted theorem snapshot resume API".to_owned(),
        );
    }
    checkpoint.verify_config(config)?;
    if checkpoint.complete || checkpoint.next_m > end {
        return Ok(RunOutput {
            records: Vec::new(),
            stats: checkpoint.stats,
            run_metadata: checkpoint
                .premises
                .clone()
                .map(|premises| RunMetadata::from(checkpoint.config_hash.clone(), premises)),
        });
    }

    let previous_bytes = fs::metadata(output_path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let output = collect_range(checkpoint.next_m, end, threads, dump_beyond)?;
    write_records(output_path, &output.records, true)?;

    let mut cumulative = checkpoint.stats.clone();
    cumulative.merge(&output.stats);
    cumulative.check_invariants()?;
    let mut shards = checkpoint.completed_output_shards.clone();
    let total_bytes = fs::metadata(output_path)
        .map_err(|error| format!("could not stat resumed JSONL: {error}"))?
        .len();
    shards.push(ShardMetadata {
        start_m: checkpoint.next_m,
        end_m: end,
        path: output_path.to_string_lossy().into_owned(),
        bytes: total_bytes.saturating_sub(previous_bytes),
    });
    let mut updated = Checkpoint::new(end, cumulative.clone(), config_hash(config), shards);
    updated.complete = true;
    write_checkpoint(checkpoint_path, &updated)?;

    Ok(RunOutput {
        records: output.records,
        stats: cumulative,
        run_metadata: checkpoint
            .premises
            .map(|premises| RunMetadata::from(checkpoint.config_hash.clone(), premises)),
    })
}

/// Resumes a checkpointed streaming run. Any output beyond the last
/// checkpointed byte is discarded before new records are appended.
pub fn resume_stream_jsonl_range(
    output_path: &Path,
    checkpoint_path: &Path,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    progress: impl FnMut(StreamProgress),
) -> Result<StreamOutput, String> {
    resume_stream_jsonl_range_with_progress_and_cancel(
        output_path,
        checkpoint_path,
        end,
        threads,
        dump_beyond,
        config,
        progress,
        || false,
    )
}

pub fn resume_stream_jsonl_range_with_progress_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    resume_stream_jsonl_range_with_schedule_and_cancel(
        output_path,
        checkpoint_path,
        end,
        threads,
        dump_beyond,
        config,
        CheckpointSchedule::every_batch(),
        progress,
        should_stop,
    )
}

/// Resumes a checkpointed stream using an explicit periodic schedule.
pub fn resume_stream_jsonl_range_with_schedule_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    schedule: CheckpointSchedule,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    resume_stream_jsonl_range_with_run_and_schedule_and_cancel(
        output_path,
        checkpoint_path,
        end,
        threads,
        dump_beyond,
        config,
        schedule,
        None,
        None,
        progress,
        should_stop,
    )
}

/// Resumes a checkpointed stream while revalidating its immutable theorem
/// snapshot and all historical family exclusion witnesses.
pub fn resume_stream_jsonl_range_with_family_map_and_schedule_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    schedule: CheckpointSchedule,
    family_map: Option<&TheoremMap>,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    let premises = if let Some(family_map) = family_map {
        Some(RunPremises::for_family_map(family_map)?)
    } else {
        None
    };
    resume_stream_jsonl_range_with_run_and_schedule_and_cancel(
        output_path,
        checkpoint_path,
        end,
        threads,
        dump_beyond,
        config,
        schedule,
        family_map,
        premises,
        progress,
        should_stop,
    )
}

pub fn resume_stream_jsonl_range_with_family_map_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    family_map: Option<&TheoremMap>,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    resume_stream_jsonl_range_with_family_map_and_schedule_and_cancel(
        output_path,
        checkpoint_path,
        end,
        threads,
        dump_beyond,
        config,
        CheckpointSchedule::every_batch(),
        family_map,
        progress,
        should_stop,
    )
}

/// Resumes a checkpointed stream after loading the exact same immutable store
/// snapshot.  The snapshot is checked before any output truncation.
pub fn resume_stream_jsonl_range_with_loaded_family_map_and_schedule_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    schedule: CheckpointSchedule,
    loaded: &LoadedTheoremMap,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    let premises = RunPremises::for_loaded_family_map(loaded)?;
    resume_stream_jsonl_range_with_run_and_schedule_and_cancel(
        output_path,
        checkpoint_path,
        end,
        threads,
        dump_beyond,
        config,
        schedule,
        Some(loaded.map()),
        Some(premises),
        progress,
        should_stop,
    )
}

fn resume_stream_jsonl_range_with_run_and_schedule_and_cancel(
    output_path: &Path,
    checkpoint_path: &Path,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    config: &str,
    schedule: CheckpointSchedule,
    family_map: Option<&TheoremMap>,
    expected_premises: Option<RunPremises>,
    progress: impl FnMut(StreamProgress),
    should_stop: impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    let checkpoint = read_checkpoint(checkpoint_path)?;
    if let Some(expected_premises) = expected_premises.as_ref() {
        checkpoint.verify_run(config, expected_premises, family_map)?;
    } else if checkpoint.schema_version != LEGACY_CHECKPOINT_SCHEMA_VERSION
        || checkpoint.premises.is_some()
    {
        return Err("map-aware checkpoint requires its theorem snapshot".to_owned());
    } else {
        checkpoint.verify_config(config)?;
    }
    validate_range(checkpoint.next_m.min(end), end, threads)?;

    let expected_bytes = checkpoint.output_bytes;
    if checkpoint.schema_version == RUN_METADATA_SCHEMA_VERSION {
        validate_persisted_family_records(output_path, expected_bytes, family_map)?;
    } else if checkpoint.schema_version != LEGACY_CHECKPOINT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported checkpoint schema version {}",
            checkpoint.schema_version
        ));
    }
    let output = OpenOptions::new()
        .write(true)
        .open(output_path)
        .map_err(|error| format!("could not open JSONL for resume: {error}"))?;
    let actual_bytes = output
        .metadata()
        .map_err(|error| format!("could not stat JSONL for resume: {error}"))?
        .len();
    if actual_bytes < expected_bytes {
        return Err(format!(
            "JSONL is shorter than checkpoint ({} < {} bytes)",
            actual_bytes, expected_bytes
        ));
    }
    output
        .set_len(expected_bytes)
        .map_err(|error| format!("could not truncate JSONL to checkpoint: {error}"))?;
    drop(output);

    if checkpoint.complete || checkpoint.next_m > end {
        return Ok(StreamOutput {
            records_written: 0,
            stats: checkpoint.stats,
            interrupted: false,
            run_metadata: checkpoint
                .premises
                .map(|premises| RunMetadata::from(checkpoint.config_hash.clone(), premises)),
        });
    }

    let mut progress = progress;
    let factorization = FactorizationTables::for_end(end)?;
    let context = CanonicalContext::new(&SIEVE_PRIMES, 31);
    let range_start = if checkpoint.range_start == 0 {
        checkpoint.next_m
    } else {
        checkpoint.range_start
    };
    let range_end = if checkpoint.range_end == 0 {
        end
    } else {
        checkpoint.range_end
    };
    let mut writer = JsonlWriter::new(output_path, true)?;
    stream_batches(
        &mut writer,
        &factorization,
        &context,
        range_start,
        range_end,
        checkpoint.next_m,
        end,
        threads,
        dump_beyond,
        checkpoint.stats,
        checkpoint.completed_output_shards,
        schedule,
        Some(checkpoint_path),
        Some(checkpoint.config_hash),
        family_map,
        checkpoint.premises,
        &mut progress,
        &should_stop,
    )
}

struct JsonlWriter<'a> {
    path: &'a Path,
    writer: BufWriter<File>,
}

impl<'a> JsonlWriter<'a> {
    fn new(path: &'a Path, append: bool) -> Result<Self, String> {
        let file = if append {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|error| format!("could not append JSONL: {error}"))?
        } else {
            File::create(path).map_err(|error| format!("could not create JSONL: {error}"))?
        };
        Ok(Self {
            path,
            writer: BufWriter::new(file),
        })
    }

    fn write_records(&mut self, records: &[SurvivorRecord]) -> Result<(), String> {
        for record in records {
            serde_json::to_writer(&mut self.writer, record)
                .map_err(|error| format!("could not serialize JSONL record: {error}"))?;
            self.writer
                .write_all(b"\n")
                .map_err(|error| format!("could not write JSONL separator: {error}"))?;
        }
        Ok(())
    }

    fn flush_and_len(&mut self) -> Result<u64, String> {
        self.writer
            .flush()
            .map_err(|error| format!("could not flush JSONL: {error}"))?;
        self.writer
            .get_ref()
            .sync_data()
            .map_err(|error| format!("could not sync JSONL: {error}"))?;
        fs::metadata(self.path)
            .map(|metadata| metadata.len())
            .map_err(|error| format!("could not stat JSONL: {error}"))
    }
}

struct CheckpointScheduler {
    schedule: CheckpointSchedule,
    candidates_since_checkpoint: u64,
    checkpoint_started: Instant,
}

impl CheckpointScheduler {
    fn new(schedule: CheckpointSchedule) -> Self {
        Self {
            schedule,
            candidates_since_checkpoint: 0,
            checkpoint_started: Instant::now(),
        }
    }

    fn batch_len(&self, remaining: u64, dump_beyond: Stage) -> u64 {
        // Keep diagnostic memory and elapsed-checkpoint polling at their
        // existing bounds. Explicit candidate intervals still clip any batch.
        let batch_limit = if dump_beyond == Stage::F8 && self.schedule.every_seconds.is_none() {
            u64::from(MAX_COMPUTE_BATCH_SIZE)
        } else {
            u64::from(STREAM_BATCH_SIZE)
        };
        let candidate_limit = self
            .schedule
            .every_candidates
            .map(|interval| {
                interval
                    .saturating_sub(self.candidates_since_checkpoint)
                    .max(1)
            })
            .unwrap_or(batch_limit);
        remaining.min(batch_limit).min(candidate_limit)
    }

    fn advance(&mut self, candidates: u64, final_batch: bool) -> bool {
        self.candidates_since_checkpoint =
            self.candidates_since_checkpoint.saturating_add(candidates);
        let candidate_due = self
            .schedule
            .every_candidates
            .is_some_and(|interval| self.candidates_since_checkpoint >= interval);
        let time_due = self
            .schedule
            .every_seconds
            .is_some_and(|interval| self.checkpoint_started.elapsed() >= interval);
        final_batch || candidate_due || time_due
    }

    fn checkpointed(&mut self) {
        self.candidates_since_checkpoint = 0;
        self.checkpoint_started = Instant::now();
    }
}

fn stream_batches<'a>(
    writer: &mut JsonlWriter<'a>,
    factorization: &FactorizationTables,
    context: &CanonicalContext,
    range_start: u64,
    range_end: u64,
    mut next_m: u64,
    end: u64,
    threads: usize,
    dump_beyond: Stage,
    mut cumulative: PipelineStats,
    mut shards: Vec<ShardMetadata>,
    schedule: CheckpointSchedule,
    checkpoint_path: Option<&Path>,
    checkpoint_hash: Option<String>,
    family_map: Option<&TheoremMap>,
    run_premises: Option<RunPremises>,
    progress: &mut impl FnMut(StreamProgress),
    should_stop: &impl Fn() -> bool,
) -> Result<StreamOutput, String> {
    let mut records_written = 0u64;
    let mut scheduler = CheckpointScheduler::new(schedule);
    loop {
        if should_stop() {
            return Ok(StreamOutput {
                records_written,
                stats: cumulative,
                interrupted: true,
                run_metadata: run_premises.clone().map(|premises| {
                    RunMetadata::from(checkpoint_hash.clone().unwrap_or_default(), premises)
                }),
            });
        }
        let batch_len = scheduler.batch_len(end - next_m + 1, dump_beyond);
        let batch_end = end.min(next_m.saturating_add(batch_len.saturating_sub(1)));
        let before_bytes = fs::metadata(writer.path)
            .map_err(|error| format!("could not stat JSONL before batch: {error}"))?
            .len();
        let batch = collect_range_with_setup(
            next_m,
            batch_end,
            threads,
            dump_beyond,
            factorization,
            context,
            family_map,
        )?;
        writer.write_records(&batch.records)?;
        let after_bytes = writer.flush_and_len()?;

        cumulative.merge(&batch.stats);
        if family_map.is_some() {
            cumulative.check_invariants_for(&filters::FAMILY_STAGES)?;
        } else {
            cumulative.check_invariants()?;
        }
        let batch_records = u64::try_from(batch.records.len()).expect("record count fits in u64");
        records_written += batch_records;
        shards.push(ShardMetadata {
            start_m: next_m,
            end_m: batch_end,
            path: writer.path.to_string_lossy().into_owned(),
            bytes: after_bytes.saturating_sub(before_bytes),
        });

        let completed_through = batch_end;
        let complete = batch_end == end;
        let following = if complete {
            end
        } else {
            batch_end.checked_add(1).expect("next root fits in u64")
        };
        let candidates = batch_end - next_m + 1;
        let checkpoint_due = scheduler.advance(candidates, batch_end == end);
        if let (Some(checkpoint_path), Some(checkpoint_hash)) =
            (checkpoint_path, checkpoint_hash.as_ref())
        {
            if checkpoint_due {
                let mut checkpoint = Checkpoint::new_for_range(
                    range_start,
                    range_end,
                    following,
                    cumulative.clone(),
                    checkpoint_hash.clone(),
                    shards.clone(),
                );
                if let Some(premises) = run_premises.clone() {
                    checkpoint.schema_version = RUN_METADATA_SCHEMA_VERSION;
                    checkpoint.premises = Some(premises);
                }
                checkpoint.complete = complete;
                write_checkpoint(checkpoint_path, &checkpoint)?;
                scheduler.checkpointed();
            }
        }
        progress(StreamProgress {
            completed_through,
            tested: cumulative.tested,
            records_written,
        });

        if complete {
            return Ok(StreamOutput {
                records_written,
                stats: cumulative,
                interrupted: false,
                run_metadata: run_premises.map(|premises| {
                    RunMetadata::from(checkpoint_hash.unwrap_or_default(), premises)
                }),
            });
        }
        next_m = following;
    }
}

/// Deterministic, process-independent FNV-1a configuration digest.
pub fn config_hash(config: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in config.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// Hash ordinary run options together with the complete mathematical
/// premises. A map path is deliberately not used as an identity component.
pub fn config_hash_with_premises(config: &str, premises: &RunPremises) -> String {
    let encoded = serde_json::to_string(premises).expect("RunPremises is serializable");
    config_hash(&format!("{config}\nrun-premises:{encoded}"))
}

fn validate_persisted_family_records(
    output_path: &Path,
    expected_bytes: u64,
    family_map: Option<&TheoremMap>,
) -> Result<(), String> {
    let bytes = fs::read(output_path)
        .map_err(|error| format!("could not read persisted JSONL for validation: {error}"))?;
    let expected = usize::try_from(expected_bytes)
        .map_err(|_| "persisted JSONL length does not fit this process".to_owned())?;
    if bytes.len() < expected {
        return Err("persisted JSONL is shorter than its checkpoint".to_owned());
    }
    let Some(family_map) = family_map else {
        if bytes[..expected]
            .windows(b"certified_family_excluded".len())
            .any(|window| window == b"certified_family_excluded")
        {
            return Err(
                "historical family exclusions require the admitted theorem snapshot".to_owned(),
            );
        }
        return Ok(());
    };
    for (line_number, line) in bytes[..expected].split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let record: SurvivorRecord = serde_json::from_slice(line).map_err(|error| {
            format!(
                "invalid persisted JSONL record at line {}: {error}",
                line_number + 1
            )
        })?;
        let family_rejection = record.rejection == Some(Rejection::CertifiedFamilyExcluded);
        match (&record.family_witness, family_rejection) {
            (Some(witness), true) => match family_map.lookup(witness.m(), witness.n(), witness.q())
            {
                crate::family::LookupDecision::Excluded(expected) if expected == *witness => {}
                _ => {
                    return Err(
                        "persisted family exclusion witness is not admitted by the snapshot"
                            .to_owned(),
                    );
                }
            },
            (Some(_), false) => {
                return Err(
                    "persisted family witness is attached to a non-family rejection".to_owned(),
                );
            }
            (None, true) => {
                return Err("persisted family exclusion is missing its witness".to_owned());
            }
            (None, false) => {}
        }
    }
    Ok(())
}

fn collect_chunk(
    start: u64,
    end: u64,
    factorization: &FactorizationTables,
    context: &CanonicalContext,
    dump_beyond: Stage,
    family_map: Option<&TheoremMap>,
) -> RunOutput {
    let mut output = RunOutput::default();
    let mut canonical_stats = CanonicalStats::new(family_map.is_some());
    let mut candidate =
        Candidate::from_factors(start, [crate::Factor::default(); crate::MAX_OMEGA], 0);
    match factorization {
        FactorizationTables::Flat(spf) => {
            for m in start..=end {
                let omega = crate::factor::factor_into(m, spf, &mut candidate.f);
                candidate.reset_after_factorization(m, omega);
                process_candidate(
                    &mut output,
                    context,
                    &mut candidate,
                    dump_beyond,
                    family_map,
                    &mut canonical_stats,
                );
            }
        }
        FactorizationTables::Segmented(base_primes) => {
            let mut segment_start = start;
            loop {
                let segment_end =
                    end.min(segment_start.saturating_add(SEGMENT_WIDTH.saturating_sub(1)));
                let segment =
                    SegmentedSpf::try_new_with_base_primes(segment_start, segment_end, base_primes)
                        .expect("run base primes cover every segment");
                for m in segment_start..=segment_end {
                    let omega = segment.factor_into(m, &mut candidate.f);
                    candidate.reset_after_factorization(m, omega);
                    process_candidate(
                        &mut output,
                        context,
                        &mut candidate,
                        dump_beyond,
                        family_map,
                        &mut canonical_stats,
                    );
                }
                if segment_end == end {
                    break;
                }
                segment_start = segment_end + 1;
            }
        }
    }
    output.stats = canonical_stats.finish();
    output
}

fn process_candidate(
    output: &mut RunOutput,
    context: &CanonicalContext,
    candidate: &mut Candidate,
    dump_beyond: Stage,
    family_map: Option<&TheoremMap>,
    canonical_stats: &mut CanonicalStats,
) {
    let trace = filters::run_canonical_with_lazy_residues(context, candidate, family_map);
    canonical_stats.record(&trace.outcome);
    let dump = match &trace.outcome {
        Outcome::Rejected { stage, .. } => stage.execution_index() >= dump_beyond.execution_index(),
        Outcome::Solution { .. } | Outcome::WideSolution { .. } => true,
    };
    if dump {
        // Early rejections still need complete residues for ungated record
        // diagnostics. Ordinary discarded candidates need no such vector.
        // Materialize the canonical prefix only for a retained record.
        let trace = trace.into_pipeline_trace();
        let residues = crate::tables::init_residues(&context.f4.sieve_primes, candidate.m);
        output.records.push(SurvivorRecord::from_trace(
            context, candidate, &residues, &trace,
        ));
    }
}

fn write_records(path: &Path, records: &[SurvivorRecord], append: bool) -> Result<(), String> {
    let file = if append {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("could not append JSONL: {error}"))?
    } else {
        File::create(path).map_err(|error| format!("could not create JSONL: {error}"))?
    };
    let mut writer = BufWriter::new(file);
    for record in records {
        serde_json::to_writer(&mut writer, record)
            .map_err(|error| format!("could not serialize JSONL record: {error}"))?;
        writer
            .write_all(b"\n")
            .map_err(|error| format!("could not write JSONL separator: {error}"))?;
    }
    writer
        .flush()
        .map_err(|error| format!("could not flush JSONL: {error}"))
}

/// Partitions an inclusive root interval without using `end + 1` as a
/// sentinel.
pub fn partition_range(start: u64, end: u64, threads: usize) -> Result<Vec<(u64, u64)>, String> {
    validate_range_options(start, end, threads)?;
    let count = u128::from(end) - u128::from(start) + 1;
    let count_usize = usize::try_from(count).map_err(|_| {
        "requested interval is too large for the current process address space".to_owned()
    })?;
    let worker_count = threads.min(count_usize);
    let chunk_size = count_usize.div_ceil(worker_count);
    let mut ranges = Vec::with_capacity(worker_count);
    for worker in 0..worker_count {
        let offset = u128::from(u64::try_from(worker).expect("worker index fits u64"))
            * u128::from(u64::try_from(chunk_size).expect("chunk size fits u64"));
        if offset >= count {
            break;
        }
        let chunk_start =
            u64::try_from(u128::from(start) + offset).expect("partition start fits in u64");
        let chunk_end_offset =
            offset + u128::from(u64::try_from(chunk_size - 1).expect("chunk size fits u64"));
        let chunk_end = u64::try_from(u128::from(start) + chunk_end_offset.min(count - 1))
            .expect("partition end fits in u64");
        ranges.push((chunk_start, chunk_end));
    }
    Ok(ranges)
}

fn validate_range(start: u64, end: u64, threads: usize) -> Result<(), String> {
    validate_range_options(start, end, threads)?;
    crate::spf::base_prime_limit(end)?;
    Ok(())
}

fn validate_range_options(start: u64, end: u64, threads: usize) -> Result<(), String> {
    if start < 2 {
        return Err("run start must be at least 2".to_owned());
    }
    if end < start {
        return Err("run end must not precede start".to_owned());
    }
    if threads == 0 {
        return Err("thread count must be positive".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CheckpointSchedule, CheckpointScheduler, MAX_COMPUTE_BATCH_SIZE, STREAM_BATCH_SIZE,
    };
    use crate::filters::Stage;
    use std::time::Duration;

    #[test]
    fn reused_worker_candidates_match_fresh_complete_diagnostics_and_statistics() {
        let ranges = [
            (2u64, 2048u64),
            (4_294_967_288, 4_294_967_304),
            (3_480_818_220_231, 3_480_818_220_247),
        ];
        let base = crate::spf::BasePrimes::for_end(ranges[2].1).unwrap();
        let tables = super::FactorizationTables::Segmented(base);
        let super::FactorizationTables::Segmented(base) = &tables else {
            unreachable!()
        };
        let context = crate::filters::CanonicalContext::new(&super::SIEVE_PRIMES, 63);
        let map = crate::family::TheoremMap::test_only_single("5", &["11"]);
        for family_map in [None, Some(&map)] {
            for (start, end) in ranges {
                let segment =
                    crate::spf::SegmentedSpf::try_new_with_base_primes(start, end, base).unwrap();
                let mut expected_stats = crate::stats::PipelineStats::default();
                let mut expected_records = Vec::new();
                for m in start..=end {
                    let mut factors = [crate::Factor::default(); crate::MAX_OMEGA];
                    let omega = segment.factor_into(m, &mut factors);
                    let mut candidate = crate::Candidate::from_factors(m, factors, omega);
                    let residues = crate::tables::init_residues(&context.f4.sieve_primes, m);
                    let trace = crate::filters::run_canonical_with_family_map(
                        &context,
                        &mut candidate,
                        &residues,
                        family_map,
                    );
                    expected_stats.record(&trace);
                    expected_records.push(super::SurvivorRecord::from_trace(
                        &context,
                        &mut candidate,
                        &residues,
                        &trace,
                    ));
                }
                let flat = (end <= 2048)
                    .then(|| super::FactorizationTables::Flat(crate::build_spf(end as u32)));
                for factorization in std::iter::once(&tables).chain(flat.as_ref()) {
                    for dump in [Stage::F1, Stage::F8] {
                        let actual = super::collect_chunk(
                            start,
                            end,
                            factorization,
                            &context,
                            dump,
                            family_map,
                        );
                        let expected = expected_records
                            .iter()
                            .filter(|record| dump == Stage::F1 || record.stage == Stage::F8)
                            .cloned()
                            .collect::<Vec<_>>();
                        assert_eq!(
                            actual.stats, expected_stats,
                            "range={start}..={end}, dump={dump:?}"
                        );
                        assert_eq!(
                            actual.records, expected,
                            "range={start}..={end}, dump={dump:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn large_compute_batches_land_exactly_on_candidate_checkpoints() {
        let max = u64::from(MAX_COMPUTE_BATCH_SIZE);
        let mut scheduler =
            CheckpointScheduler::new(CheckpointSchedule::new(Some(max + 17), None).unwrap());
        assert_eq!(scheduler.batch_len(3 * max, Stage::F8), max);
        assert!(!scheduler.advance(max, false));
        assert_eq!(scheduler.batch_len(2 * max, Stage::F8), 17);
        assert!(scheduler.advance(17, false));
        scheduler.checkpointed();
        assert_eq!(scheduler.batch_len(2 * max, Stage::F8), max);
        assert_eq!(scheduler.batch_len(9, Stage::F8), 9);
    }

    #[test]
    fn diagnostic_default_and_elapsed_schedules_keep_legacy_batch_bounds() {
        let max = u64::from(MAX_COMPUTE_BATCH_SIZE);
        let small = u64::from(STREAM_BATCH_SIZE);
        let scheduler = CheckpointScheduler::new(CheckpointSchedule::disabled());
        assert_eq!(scheduler.batch_len(2 * max, Stage::F8), max);
        for stage in crate::filters::FAMILY_STAGES {
            if stage != Stage::F8 {
                assert_eq!(scheduler.batch_len(2 * max, stage), small);
            }
        }
        let default = CheckpointScheduler::new(CheckpointSchedule::every_batch());
        assert_eq!(default.batch_len(2 * max, Stage::F8), small);
        let elapsed = CheckpointScheduler::new(
            CheckpointSchedule::new(Some(2 * max), Some(Duration::from_secs(1))).unwrap(),
        );
        assert_eq!(elapsed.batch_len(2 * max, Stage::F8), small);
    }
}
