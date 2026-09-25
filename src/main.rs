use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use cubealqot::family::{LoadedTheoremMap, StoreReader, StoreSnapshot, TheoremMap};
use cubealqot::{filters::Stage, survivors};

#[derive(Debug, Parser)]
#[command(name = "cubealqot")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the canonical pipeline and write deterministic survivor JSONL.
    Run {
        /// Inclusive first candidate.
        #[arg(long, default_value_t = 2)]
        start: u64,
        /// Inclusive last candidate.
        #[arg(long)]
        end: u64,
        /// Number of contiguous worker chunks.
        #[arg(long, default_value_t = 1)]
        threads: usize,
        /// JSONL output path.
        #[arg(long)]
        output: PathBuf,
        /// Optional checkpoint to write, or resume checkpoint when --resume is set.
        #[arg(long)]
        checkpoint: Option<PathBuf>,
        /// Checkpoint after this many candidates (defaults to one stream batch).
        #[arg(long, value_name = "CANDIDATES")]
        checkpoint_every: Option<u64>,
        /// Checkpoint after this many elapsed seconds, in addition to --checkpoint-every.
        #[arg(long, value_name = "SECONDS")]
        checkpoint_every_seconds: Option<u64>,
        /// Resume from CHECKPOINT. With no value, use --checkpoint.
        #[arg(
            long,
            value_name = "CHECKPOINT",
            num_args = 0..=1,
            default_missing_value = "__checkpoint_flag__"
        )]
        resume: Option<String>,
        /// Dump candidates rejected at this stage or later. F8 is the default.
        #[arg(long, default_value = "F8")]
        dump_beyond: String,
        /// Immutable proof store containing the selected theorem snapshot.
        #[arg(long)]
        family_store: Option<PathBuf>,
        /// Immutable theorem snapshot exported from the selected proof store.
        #[arg(long)]
        family_snapshot: Option<PathBuf>,
    },
    /// Measure ungated stage costs for a sequential baseline.
    Profile {
        /// Inclusive first candidate.
        #[arg(long, default_value_t = 2)]
        start: u64,
        /// Inclusive last candidate.
        #[arg(long)]
        end: u64,
        /// Must be 1; the profiler measures one worker for comparable evidence.
        #[arg(long, default_value_t = 1)]
        threads: usize,
        /// Optional JSON report path.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Compare the Rust exact baseline with the independent Python oracle.
    Validate {
        /// Inclusive maximum m to validate.
        #[arg(long)]
        max: u32,
    },
}

fn main() {
    match Cli::parse().command {
        Some(Command::Run {
            start,
            end,
            threads,
            output,
            checkpoint,
            checkpoint_every,
            checkpoint_every_seconds,
            resume: resume_arg,
            dump_beyond,
            family_store,
            family_snapshot,
        }) => {
            let Some(dump_stage) = parse_stage(&dump_beyond) else {
                eprintln!("invalid --dump-beyond stage: {dump_beyond}");
                std::process::exit(1);
            };
            let (resume, resume_path) = match resume_arg {
                None => (false, None),
                Some(value) if value == "__checkpoint_flag__" => (true, None),
                Some(value) => (true, Some(PathBuf::from(value))),
            };
            let checkpoint = match (checkpoint, resume_path) {
                (Some(checkpoint), Some(resume_path)) if checkpoint != resume_path => {
                    eprintln!("--resume CHECKPOINT and --checkpoint must name the same file");
                    std::process::exit(1);
                }
                (Some(_), Some(resume_path)) => Some(resume_path),
                (None, Some(resume_path)) => Some(resume_path),
                (checkpoint, None) => checkpoint,
            };
            let schedule_requested =
                checkpoint_every.is_some() || checkpoint_every_seconds.is_some();
            if checkpoint.is_none() && schedule_requested {
                eprintln!("--checkpoint-every requires --checkpoint or --resume");
                std::process::exit(1);
            }
            let schedule = if checkpoint.is_some() {
                match survivors::CheckpointSchedule::new(
                    checkpoint_every,
                    checkpoint_every_seconds.map(Duration::from_secs),
                ) {
                    Ok(schedule) if schedule_requested => schedule,
                    Ok(_) => survivors::CheckpointSchedule::every_batch(),
                    Err(error) => {
                        eprintln!("invalid checkpoint schedule: {error}");
                        std::process::exit(1);
                    }
                }
            } else {
                survivors::CheckpointSchedule::disabled()
            };
            let loaded_family_map = match (family_store, family_snapshot) {
                (None, None) => None,
                (Some(_), None) | (None, Some(_)) => {
                    eprintln!("--family-store and --family-snapshot must be supplied together");
                    std::process::exit(1);
                }
                (Some(store), Some(snapshot)) => match load_family_snapshot(&store, &snapshot) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        eprintln!("could not load theorem snapshot: {error}");
                        std::process::exit(1);
                    }
                },
            };
            let interrupted = Arc::new(AtomicBool::new(false));
            let signal = Arc::clone(&interrupted);
            if let Err(error) = ctrlc::set_handler(move || {
                signal.store(true, Ordering::SeqCst);
            }) {
                eprintln!("could not install Ctrl-C handler: {error}");
                std::process::exit(1);
            }
            if let Some(loaded) = loaded_family_map.as_ref() {
                run_loaded_family_map(
                    &output,
                    checkpoint.as_deref(),
                    start,
                    end,
                    threads,
                    dump_stage,
                    resume,
                    &dump_beyond,
                    loaded,
                    &interrupted,
                    schedule,
                );
                return;
            }
            let Some(checkpoint_path) = checkpoint else {
                if resume {
                    eprintln!("--resume requires --checkpoint CHECKPOINT");
                    std::process::exit(1);
                }
                let result = survivors::stream_jsonl_range_with_progress_and_cancel(
                    &output,
                    start,
                    end,
                    threads,
                    dump_stage,
                    throttled_progress_reporter(),
                    || interrupted.load(Ordering::SeqCst),
                );
                match result {
                    Ok(run) => {
                        if run.interrupted {
                            eprintln!("interrupted; durable output contains completed batches");
                            std::process::exit(130);
                        }
                        println!(
                            "wrote {} JSONL records; tested {} candidates",
                            run.records_written, run.stats.tested
                        );
                    }
                    Err(error) => {
                        eprintln!("run failed: {error}");
                        std::process::exit(1);
                    }
                }
                return;
            };

            let config =
                format!("start={start};end={end};threads={threads};dump_beyond={dump_beyond}");
            if resume {
                match survivors::resume_stream_jsonl_range_with_schedule_and_cancel(
                    &output,
                    &checkpoint_path,
                    end,
                    threads,
                    dump_stage,
                    &config,
                    schedule,
                    throttled_progress_reporter(),
                    || interrupted.load(Ordering::SeqCst),
                ) {
                    Ok(run) => {
                        if run.interrupted {
                            eprintln!("interrupted; durable output contains completed batches");
                            std::process::exit(130);
                        }
                        println!(
                            "resumed JSONL output; records added {}, tested {} cumulative candidates",
                            run.records_written, run.stats.tested
                        );
                    }
                    Err(error) => {
                        eprintln!("resume failed: {error}");
                        std::process::exit(1);
                    }
                }
            } else {
                match survivors::stream_jsonl_range_checkpointed_with_schedule_and_cancel(
                    &output,
                    &checkpoint_path,
                    start,
                    end,
                    threads,
                    dump_stage,
                    &config,
                    schedule,
                    throttled_progress_reporter(),
                    || interrupted.load(Ordering::SeqCst),
                ) {
                    Ok(run) => {
                        if run.interrupted {
                            eprintln!("interrupted; durable output contains completed batches");
                            std::process::exit(130);
                        }
                        println!(
                            "wrote {} JSONL records and checkpoint; tested {} candidates",
                            run.records_written, run.stats.tested
                        );
                    }
                    Err(error) => {
                        eprintln!("run failed: {error}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Some(Command::Profile {
            start,
            end,
            threads,
            output,
        }) => match cubealqot::profile::profile_range(start, end, threads) {
            Ok(report) => {
                let json =
                    serde_json::to_string_pretty(&report).expect("profile report should serialize");
                if let Some(path) = output {
                    if let Err(error) = fs::write(&path, format!("{json}\n")) {
                        eprintln!("could not write profile report: {error}");
                        std::process::exit(1);
                    }
                    println!("wrote profile report to {}", path.display());
                } else {
                    println!("{json}");
                }
            }
            Err(error) => {
                eprintln!("profile failed: {error}");
                std::process::exit(1);
            }
        },
        Some(Command::Validate { max }) => {
            let baseline = cubealqot::validate::validate_range(max);
            let f1 = cubealqot::validate::validate_f1_range(max);
            let f2 = cubealqot::validate::validate_f2_range(max);
            let f3 = cubealqot::validate::validate_f3_range(max);
            let cross = cubealqot::validate::validate_cross_range(max);
            let f56 = cubealqot::validate::validate_f56_range(max);
            let f4b = cubealqot::validate::validate_f4b_range(max);
            let f7 = cubealqot::validate::validate_f7_range(max);
            let pipeline = cubealqot::validate::validate_pipeline_range(max);
            match (baseline, f1, f2, f3, cross, f56, f4b, f7, pipeline) {
                (
                    Ok(summary),
                    Ok(f1_summary),
                    Ok(f2_summary),
                    Ok(f3_summary),
                    Ok(cross_summary),
                    Ok(f56_summary),
                    Ok(f4b_summary),
                    Ok(f7_summary),
                    Ok(pipeline_summary),
                ) => println!(
                    "validated m=2..={} ({} candidates; {} direct, {} multiplicative; F1 rejected {}; F2 rejected {}; F3 rejected {}; {} positive-even-v3; {} cross pairs, {} hits; F5/F6 rejected {}; branches <{} ={} >{}; F4b ungated rejected {} / {} foreign-zero checks ({:.4} per cycle), pipeline-first {}; F7 rejected {}; tags sq={} 2sq={} pq={}; pipeline short-circuit rejected {}, ungated predicate hits {}, exact fallbacks {})",
                    summary.max,
                    summary.checked,
                    summary.direct_checked,
                    summary.multiplicative_checked,
                    f1_summary.pipeline_prime_power_rejections,
                    f2_summary.pipeline_rejections,
                    f3_summary.pipeline_rejections,
                    f3_summary.positive_even_valuation_cases,
                    cross_summary.pairs,
                    cross_summary.hits,
                    f56_summary.pipeline_rejections,
                    f56_summary.less_cases,
                    f56_summary.equal_cases,
                    f56_summary.greater_cases,
                    f4b_summary.ungated_rejections,
                    f4b_summary.foreign_zero_checks,
                    f4b_summary.rejection_per_cycle,
                    f4b_summary.pipeline_rejections,
                    f7_summary.ungated_rejections,
                    f7_summary.sq_tags,
                    f7_summary.two_sq_tags,
                    f7_summary.pq_handoff_tags,
                    pipeline_summary.short_circuit_rejections,
                    pipeline_summary.ungated_predicate_rejections,
                    pipeline_summary.exact_fallbacks
                ),
                (Err(error), _, _, _, _, _, _, _, _)
                | (_, Err(error), _, _, _, _, _, _, _)
                | (_, _, Err(error), _, _, _, _, _, _)
                | (_, _, _, Err(error), _, _, _, _, _)
                | (_, _, _, _, Err(error), _, _, _, _)
                | (_, _, _, _, _, Err(error), _, _, _)
                | (_, _, _, _, _, _, Err(error), _, _)
                | (_, _, _, _, _, _, _, Err(error), _)
                | (_, _, _, _, _, _, _, _, Err(error)) => {
                    eprintln!("validation failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        None => println!("cubealqot scaffold"),
    }
}

fn load_family_snapshot(
    store_path: &PathBuf,
    snapshot_path: &PathBuf,
) -> Result<LoadedTheoremMap, String> {
    let reader = StoreReader::open(store_path).map_err(|error| error.to_string())?;
    let bytes = fs::read(snapshot_path)
        .map_err(|error| format!("could not read theorem snapshot: {error}"))?;
    let snapshot: StoreSnapshot = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid theorem snapshot: {error}"))?;
    TheoremMap::from_store_snapshot(&reader, &snapshot)
}

fn run_loaded_family_map(
    output: &Path,
    checkpoint_path: Option<&Path>,
    start: u64,
    end: u64,
    threads: usize,
    dump_stage: Stage,
    resume: bool,
    dump_beyond: &str,
    loaded: &LoadedTheoremMap,
    interrupted: &Arc<AtomicBool>,
    schedule: survivors::CheckpointSchedule,
) {
    if checkpoint_path.is_none() {
        if resume {
            eprintln!("--resume requires --checkpoint CHECKPOINT");
            std::process::exit(1);
        }
        let result = survivors::stream_jsonl_range_with_loaded_family_map_and_cancel(
            output,
            start,
            end,
            threads,
            dump_stage,
            loaded,
            || interrupted.load(Ordering::SeqCst),
        );
        match result {
            Ok(run) if run.interrupted => {
                eprintln!("interrupted; durable output contains completed batches");
                std::process::exit(130);
            }
            Ok(run) => println!(
                "wrote {} JSONL records; tested {} candidates; loaded theorem snapshot {}",
                run.records_written,
                run.stats.tested,
                loaded.snapshot_id()
            ),
            Err(error) => {
                eprintln!("run failed: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    let checkpoint = checkpoint_path.expect("checked above");
    let config = format!("start={start};end={end};threads={threads};dump_beyond={dump_beyond}");
    let result = if resume {
        survivors::resume_stream_jsonl_range_with_loaded_family_map_and_schedule_and_cancel(
            output,
            checkpoint,
            end,
            threads,
            dump_stage,
            &config,
            schedule,
            loaded,
            throttled_progress_reporter(),
            || interrupted.load(Ordering::SeqCst),
        )
    } else {
        survivors::stream_jsonl_range_checkpointed_with_loaded_family_map_and_schedule_and_cancel(
            output,
            checkpoint,
            start,
            end,
            threads,
            dump_stage,
            &config,
            schedule,
            loaded,
            throttled_progress_reporter(),
            || interrupted.load(Ordering::SeqCst),
        )
    };
    match result {
        Ok(run) if run.interrupted => {
            eprintln!("interrupted; durable output contains completed batches");
            std::process::exit(130);
        }
        Ok(run) if resume => println!(
            "resumed JSONL output; records added {}, tested {} cumulative candidates; loaded theorem snapshot {}",
            run.records_written,
            run.stats.tested,
            loaded.snapshot_id()
        ),
        Ok(run) => println!(
            "wrote {} JSONL records and checkpoint; tested {} candidates; loaded theorem snapshot {}",
            run.records_written,
            run.stats.tested,
            loaded.snapshot_id()
        ),
        Err(error) => {
            eprintln!("{} failed: {error}", if resume { "resume" } else { "run" });
            std::process::exit(1);
        }
    }
}

fn parse_stage(value: &str) -> Option<Stage> {
    match value {
        "F1" => Some(Stage::F1),
        "F2" => Some(Stage::F2),
        "F7c" => Some(Stage::F7c),
        "F3" => Some(Stage::F3),
        "F4" => Some(Stage::F4),
        "F4b" => Some(Stage::F4b),
        "F56" => Some(Stage::F56),
        "F7" => Some(Stage::F7),
        "F8" => Some(Stage::F8),
        _ => None,
    }
}

const CLI_PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

fn progress_is_due(last_reported: &mut Option<Instant>, now: Instant) -> bool {
    let due = last_reported
        .map(|last| now.duration_since(last) >= CLI_PROGRESS_INTERVAL)
        .unwrap_or(true);
    if due {
        *last_reported = Some(now);
    }
    due
}

fn throttled_progress_reporter() -> impl FnMut(survivors::StreamProgress) {
    let mut last_reported = None;
    move |progress| {
        if progress_is_due(&mut last_reported, Instant::now()) {
            eprintln!(
                "processed through m={} ({} candidates; {} JSONL records)",
                progress.completed_through, progress.tested, progress.records_written
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_progress_is_immediate_then_throttled_for_five_seconds() {
        let first = Instant::now();
        let mut last_reported = None;

        assert!(progress_is_due(&mut last_reported, first));
        assert!(!progress_is_due(
            &mut last_reported,
            first + Duration::from_secs(4)
        ));
        assert!(progress_is_due(
            &mut last_reported,
            first + Duration::from_secs(5)
        ));
    }
}
