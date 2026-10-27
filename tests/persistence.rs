use std::{
    cell::Cell,
    fs,
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use cubealqot::filters::Stage;
use cubealqot::survivors::{
    Checkpoint, CheckpointSchedule, MAX_COMPUTE_BATCH_SIZE, STREAM_BATCH_SIZE, ShardMetadata,
    config_hash, read_checkpoint, read_jsonl, resume_jsonl_range, resume_stream_jsonl_range,
    resume_stream_jsonl_range_with_progress_and_cancel,
    resume_stream_jsonl_range_with_schedule_and_cancel, stream_jsonl_range,
    stream_jsonl_range_checkpointed, stream_jsonl_range_checkpointed_with_progress_and_cancel,
    stream_jsonl_range_checkpointed_with_schedule_and_cancel, write_checkpoint, write_jsonl_range,
};

fn temp_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cubealqot-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

#[test]
fn unsupported_endpoint_is_rejected_before_output_or_checkpoint_changes() {
    let output_path = temp_path("unsupported-output");
    let checkpoint_path = temp_path("unsupported-checkpoint");
    fs::write(&output_path, b"existing output").unwrap();
    fs::write(&checkpoint_path, b"existing checkpoint").unwrap();
    let end = (u64::from(cubealqot::MAX_BASE_PRIME_LIMIT) + 1).pow(2);

    let error = stream_jsonl_range_checkpointed(
        &output_path,
        &checkpoint_path,
        4_000_000_000_001,
        end,
        4,
        Stage::F8,
        "unsupported range",
        |_| panic!("unsupported run must not start processing"),
    )
    .expect_err("full endpoint must be checked before starting batches");
    assert!(error.contains("base-prime coverage"), "{error}");
    assert_eq!(fs::read(&output_path).unwrap(), b"existing output");
    assert_eq!(fs::read(&checkpoint_path).unwrap(), b"existing checkpoint");

    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn one_and_four_thread_jsonl_are_byte_identical() {
    let one_path = temp_path("one");
    let four_path = temp_path("four");

    write_jsonl_range(&one_path, 2, 300, 1, Stage::F1).expect("one-thread output should write");
    write_jsonl_range(&four_path, 2, 300, 4, Stage::F1).expect("four-thread output should write");

    assert_eq!(fs::read(&one_path).unwrap(), fs::read(&four_path).unwrap());
    let records = read_jsonl(&one_path).expect("JSONL should parse");
    assert_eq!(records.len(), 299);
    assert!(records.windows(2).all(|pair| pair[0].m < pair[1].m));

    let _ = fs::remove_file(one_path);
    let _ = fs::remove_file(four_path);
}

#[test]
fn checkpoint_resume_matches_one_shot_output() {
    let full_path = temp_path("full");
    let resumed_path = temp_path("resumed");
    let checkpoint_path = temp_path("checkpoint");
    let checkpoint_copy_path = temp_path("checkpoint-copy");
    let checkpoint_temp_path = PathBuf::from(format!("{}.tmp", checkpoint_path.display()));
    let config = "range=2..=300;threads=4;dump_beyond=F1";

    let full =
        write_jsonl_range(&full_path, 2, 300, 1, Stage::F1).expect("full output should write");
    let partial = write_jsonl_range(&resumed_path, 2, 100, 1, Stage::F1)
        .expect("partial output should write");
    let checkpoint = Checkpoint::new(
        101,
        partial.stats,
        config_hash(config),
        vec![ShardMetadata::from_file(2, 100, &resumed_path).expect("shard should stat")],
    );
    write_checkpoint(&checkpoint_path, &checkpoint).expect("checkpoint should write");
    assert!(!checkpoint_temp_path.exists());
    write_checkpoint(&checkpoint_copy_path, &checkpoint).expect("checkpoint copy should write");
    assert_eq!(
        fs::read(&checkpoint_path).unwrap(),
        fs::read(&checkpoint_copy_path).unwrap()
    );

    let resumed = resume_jsonl_range(&resumed_path, &checkpoint_path, 300, 4, Stage::F1, config)
        .expect("resume should succeed");
    assert_eq!(
        fs::read(&full_path).unwrap(),
        fs::read(&resumed_path).unwrap()
    );
    assert_eq!(resumed.stats, full.stats);

    let saved = read_checkpoint(&checkpoint_path).expect("saved checkpoint should parse");
    assert_eq!(saved.next_m, 300);
    assert!(saved.complete);
    assert_eq!(saved.stats, full.stats);
    assert_eq!(saved.completed_output_shards.len(), 2);

    let error = resume_jsonl_range(
        &resumed_path,
        &checkpoint_path,
        300,
        1,
        Stage::F1,
        "different-config",
    )
    .expect_err("config changes must invalidate resume");
    assert!(error.contains("config hash"));

    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(resumed_path);
    let _ = fs::remove_file(checkpoint_path);
    let _ = fs::remove_file(checkpoint_copy_path);
}

#[test]
fn streaming_low_dump_flushes_bounded_batches_and_completes_records() {
    let path = temp_path("streaming");
    let end = 2u64 + u64::from(STREAM_BATCH_SIZE) + 10 - 1;
    let saw_intermediate_flush = Cell::new(false);

    let output = cubealqot::survivors::stream_jsonl_range_with_progress(
        &path,
        2,
        end,
        2,
        Stage::F1,
        |progress| {
            if progress.completed_through < end {
                assert!(fs::metadata(&path).unwrap().len() > 0);
                saw_intermediate_flush.set(true);
            }
        },
    )
    .expect("streaming run should succeed");

    assert!(saw_intermediate_flush.get());
    assert_eq!(output.records_written, end - 1);
    assert_eq!(read_jsonl(&path).unwrap().len(), (end - 1) as usize);

    let _ = fs::remove_file(path);
}

#[test]
fn checkpoint_schema_describes_each_flushed_batch() {
    let path = temp_path("checkpoint-schema");
    let checkpoint_path = temp_path("checkpoint-schema-state");
    let end = 2u64 + u64::from(STREAM_BATCH_SIZE) + 10 - 1;
    let config = format!("start=2;end={end};threads=2;dump_beyond=F8");
    let saw_intermediate_checkpoint = Cell::new(false);

    stream_jsonl_range_checkpointed(
        &path,
        &checkpoint_path,
        2,
        end,
        2,
        Stage::F8,
        &config,
        |progress| {
            let checkpoint = read_checkpoint(&checkpoint_path).expect("checkpoint should parse");
            assert_eq!(checkpoint.range_start, 2);
            assert_eq!(checkpoint.range_end, end);
            assert_eq!(
                checkpoint.next_m,
                if checkpoint.complete {
                    progress.completed_through
                } else {
                    progress.completed_through + 1
                }
            );
            assert_eq!(checkpoint.stats.tested, progress.tested);
            assert_eq!(checkpoint.output_bytes, fs::metadata(&path).unwrap().len());
            assert_eq!(
                checkpoint.completed_output_shards.last().unwrap().end_m,
                progress.completed_through
            );
            if progress.completed_through < end {
                saw_intermediate_checkpoint.set(true);
            }
        },
    )
    .expect("checkpointed stream should succeed");

    assert!(saw_intermediate_checkpoint.get());
    let checkpoint = read_checkpoint(&checkpoint_path).expect("final checkpoint should parse");
    assert_eq!(checkpoint.next_m, end);
    assert!(checkpoint.complete);

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn interrupted_flat_run_resumes_without_gaps_or_duplicates() {
    let full_path = temp_path("interrupt-flat-full");
    let resumed_path = temp_path("interrupt-flat-resumed");
    let checkpoint_path = temp_path("interrupt-flat-checkpoint");
    let end = 2u64 + u64::from(STREAM_BATCH_SIZE) + 10 - 1;
    let config = format!("start=2;end={end};threads=2;dump_beyond=F8");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_progress = Arc::clone(&stop);

    stream_jsonl_range(&full_path, 2, end, 1, Stage::F8).expect("full run should write");
    let interrupted = stream_jsonl_range_checkpointed_with_progress_and_cancel(
        &resumed_path,
        &checkpoint_path,
        2,
        end,
        2,
        Stage::F8,
        &config,
        move |progress| {
            if progress.completed_through < end {
                stop_for_progress.store(true, Ordering::SeqCst);
            }
        },
        || stop.load(Ordering::SeqCst),
    )
    .expect("interrupted run should return cleanly");

    assert!(interrupted.interrupted);
    let checkpoint = read_checkpoint(&checkpoint_path).expect("checkpoint should parse");
    assert!(checkpoint.next_m > 2);
    assert!(checkpoint.next_m <= end);

    resume_stream_jsonl_range_with_progress_and_cancel(
        &resumed_path,
        &checkpoint_path,
        end,
        4,
        Stage::F8,
        &config,
        |_| {},
        || false,
    )
    .expect("resume should finish");

    assert_eq!(
        fs::read(&full_path).unwrap(),
        fs::read(&resumed_path).unwrap()
    );
    let records = read_jsonl(&resumed_path).unwrap();
    assert!(records.windows(2).all(|pair| pair[0].m < pair[1].m));

    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(resumed_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn wide_prime_square_boundary_resumes_with_shared_coverage_and_new_worker_count() {
    let start = 2_000_003u64.pow(2) - 100;
    let end = start + u64::from(STREAM_BATCH_SIZE) + 99;
    let full_path = temp_path("wide-shared-full");
    let resumed_path = temp_path("wide-shared-resumed");
    let checkpoint_path = temp_path("wide-shared-checkpoint");
    let config = format!("wide-shared-{start}-{end}");
    let stop = Cell::new(false);
    let full = stream_jsonl_range(&full_path, start, end, 1, Stage::F8).unwrap();
    let partial = stream_jsonl_range_checkpointed_with_progress_and_cancel(
        &resumed_path,
        &checkpoint_path,
        start,
        end,
        4,
        Stage::F8,
        &config,
        |_| stop.set(true),
        || stop.get(),
    )
    .unwrap();
    assert!(partial.interrupted);
    assert_eq!(
        read_checkpoint(&checkpoint_path).unwrap().next_m,
        start + u64::from(STREAM_BATCH_SIZE)
    );
    let resumed = resume_stream_jsonl_range_with_progress_and_cancel(
        &resumed_path,
        &checkpoint_path,
        end,
        2,
        Stage::F8,
        &config,
        |_| {},
        || false,
    )
    .unwrap();
    assert_eq!(resumed.stats, full.stats);
    assert_eq!(
        fs::read(&resumed_path).unwrap(),
        fs::read(&full_path).unwrap()
    );
    assert!(read_checkpoint(&checkpoint_path).unwrap().complete);
    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(resumed_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn interrupted_segment_transition_resumes_without_gaps_or_duplicates() {
    let start = cubealqot::FLAT_SPF_LIMIT - 100;
    let end = start + u64::from(STREAM_BATCH_SIZE) + 10 - 1;
    let full_path = temp_path("interrupt-transition-full");
    let resumed_path = temp_path("interrupt-transition-resumed");
    let checkpoint_path = temp_path("interrupt-transition-checkpoint");
    let config = format!("start={start};end={end};threads=2;dump_beyond=F8");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_progress = Arc::clone(&stop);

    stream_jsonl_range(&full_path, start, end, 1, Stage::F8)
        .expect("full transition run should write");
    let interrupted = stream_jsonl_range_checkpointed_with_progress_and_cancel(
        &resumed_path,
        &checkpoint_path,
        start,
        end,
        2,
        Stage::F8,
        &config,
        move |progress| {
            if progress.completed_through < end {
                stop_for_progress.store(true, Ordering::SeqCst);
            }
        },
        || stop.load(Ordering::SeqCst),
    )
    .expect("transition interruption should return cleanly");

    assert!(interrupted.interrupted);
    resume_stream_jsonl_range_with_progress_and_cancel(
        &resumed_path,
        &checkpoint_path,
        end,
        4,
        Stage::F8,
        &config,
        |_| {},
        || false,
    )
    .expect("transition resume should finish");

    assert_eq!(
        fs::read(&full_path).unwrap(),
        fs::read(&resumed_path).unwrap()
    );

    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(resumed_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn streaming_one_and_four_thread_outputs_are_byte_identical() {
    let one_path = temp_path("stream-one");
    let four_path = temp_path("stream-four");
    let legacy_path = temp_path("stream-legacy");

    stream_jsonl_range(&one_path, 2, 300, 1, Stage::F1).expect("one-thread stream should write");
    stream_jsonl_range(&four_path, 2, 300, 4, Stage::F1).expect("four-thread stream should write");
    write_jsonl_range(&legacy_path, 2, 300, 1, Stage::F1)
        .expect("legacy one-shot output should write");

    assert_eq!(fs::read(&one_path).unwrap(), fs::read(&four_path).unwrap());
    assert_eq!(
        fs::read(&one_path).unwrap(),
        fs::read(&legacy_path).unwrap()
    );

    let _ = fs::remove_file(one_path);
    let _ = fs::remove_file(four_path);
    let _ = fs::remove_file(legacy_path);
}

#[test]
fn streaming_uses_segmented_factorization_above_flat_threshold() {
    let path = temp_path("stream-segmented");

    let output = stream_jsonl_range(&path, 100_000_000, 100_000_020, 2, Stage::F1)
        .expect("segmented streaming range should write");

    assert_eq!(output.stats.tested, 21);
    assert_eq!(output.records_written, 21);
    assert_eq!(read_jsonl(&path).unwrap().len(), 21);

    let _ = fs::remove_file(path);
}

#[test]
fn streaming_checkpoint_resume_matches_one_shot_output() {
    let full_path = temp_path("stream-full");
    let resumed_path = temp_path("stream-resumed");
    let checkpoint_path = temp_path("stream-checkpoint");
    let config = "start=2;end=300;threads=4;dump_beyond=F1";

    stream_jsonl_range(&full_path, 2, 300, 1, Stage::F1).expect("full stream should write");
    let partial = stream_jsonl_range(&resumed_path, 2, 100, 1, Stage::F1)
        .expect("partial stream should write");
    let checkpoint = Checkpoint::new_for_range(
        2,
        300,
        101,
        partial.stats,
        config_hash(config),
        vec![ShardMetadata::from_file(2, 100, &resumed_path).expect("shard should stat")],
    );
    write_checkpoint(&checkpoint_path, &checkpoint).expect("partial stream should checkpoint");
    let mut tail = fs::OpenOptions::new()
        .append(true)
        .open(&resumed_path)
        .unwrap();
    tail.write_all(b"uncheckpointed-tail").unwrap();
    drop(tail);
    resume_stream_jsonl_range(
        &resumed_path,
        &checkpoint_path,
        300,
        4,
        Stage::F1,
        config,
        |_| {},
    )
    .expect("stream resume should succeed");

    assert_eq!(
        fs::read(&full_path).unwrap(),
        fs::read(&resumed_path).unwrap()
    );
    let checkpoint = read_checkpoint(&checkpoint_path).expect("checkpoint should parse");
    assert_eq!(checkpoint.range_start, 2);
    assert_eq!(checkpoint.range_end, 300);
    assert_eq!(checkpoint.next_m, 300);
    assert!(checkpoint.complete);
    assert_eq!(
        checkpoint.output_bytes,
        fs::metadata(&full_path).unwrap().len()
    );

    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(resumed_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn periodic_candidate_schedule_checkpoints_at_exact_boundaries() {
    let full_path = temp_path("periodic-full");
    let scheduled_path = temp_path("periodic-scheduled");
    let checkpoint_path = temp_path("periodic-checkpoint");
    let end = 20;
    let config = format!("start=2;end={end};threads=1;dump_beyond=F1");
    let schedule = CheckpointSchedule::new(Some(3), None).expect("schedule should be valid");
    let mut checkpoint_next = Vec::new();

    stream_jsonl_range(&full_path, 2, end, 1, Stage::F1).expect("full run should write");
    stream_jsonl_range_checkpointed_with_schedule_and_cancel(
        &scheduled_path,
        &checkpoint_path,
        2,
        end,
        1,
        Stage::F1,
        &config,
        schedule,
        |progress| {
            let checkpoint = read_checkpoint(&checkpoint_path).expect("checkpoint should parse");
            if checkpoint.next_m
                == if checkpoint.complete {
                    progress.completed_through
                } else {
                    progress.completed_through + 1
                }
            {
                assert_eq!(
                    checkpoint.output_bytes,
                    fs::metadata(&scheduled_path).unwrap().len()
                );
                checkpoint_next.push(checkpoint.next_m);
            }
        },
        || false,
    )
    .expect("scheduled run should write");

    assert_eq!(
        checkpoint_next,
        vec![5, 8, 11, 14, 17, 20, 20],
        "checkpoints must land on candidate-count boundaries plus the final record"
    );
    assert_eq!(
        fs::read(&full_path).unwrap(),
        fs::read(&scheduled_path).unwrap()
    );

    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(scheduled_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn repeated_periodic_resume_cycles_match_uninterrupted_output() {
    let full_path = temp_path("periodic-cycles-full");
    let resumed_path = temp_path("periodic-cycles-resumed");
    let checkpoint_path = temp_path("periodic-cycles-checkpoint");
    let end = 2u64 + u64::from(STREAM_BATCH_SIZE) + 23;
    let config = format!("start=2;end={end};threads=2;dump_beyond=F8");
    let schedule = CheckpointSchedule::new(Some(17_000), None).expect("schedule should be valid");

    stream_jsonl_range(&full_path, 2, end, 1, Stage::F8).expect("full run should write");

    // Rebuild a partial run and stop once per invocation. Each stop occurs
    // after a flushed, checkpointed interval; the next invocation must append
    // exactly the next interval.
    let _ = fs::remove_file(&resumed_path);
    let _ = fs::remove_file(&checkpoint_path);
    let mut cycles = 0;
    loop {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_progress = Arc::clone(&stop);
        let run = if cycles == 0 {
            stream_jsonl_range_checkpointed_with_schedule_and_cancel(
                &resumed_path,
                &checkpoint_path,
                2,
                end,
                2,
                Stage::F8,
                &config,
                schedule,
                move |_| stop_for_progress.store(true, Ordering::SeqCst),
                || stop.load(Ordering::SeqCst),
            )
        } else {
            resume_stream_jsonl_range_with_schedule_and_cancel(
                &resumed_path,
                &checkpoint_path,
                end,
                2,
                Stage::F8,
                &config,
                schedule,
                move |_| stop_for_progress.store(true, Ordering::SeqCst),
                || stop.load(Ordering::SeqCst),
            )
        };
        let run = run.expect("scheduled run should return cleanly");
        cycles += 1;
        if !run.interrupted {
            break;
        }
        assert!(
            cycles < 20,
            "periodic resume should finish in bounded cycles"
        );
    }

    assert!(cycles > 1);
    assert_eq!(
        fs::read(&full_path).unwrap(),
        fs::read(&resumed_path).unwrap()
    );

    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(resumed_path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn elapsed_schedule_is_supported_and_zero_intervals_are_rejected() {
    assert!(CheckpointSchedule::new(Some(0), None).is_err());
    assert!(CheckpointSchedule::new(None, Some(Duration::ZERO)).is_err());

    let path = temp_path("elapsed-schedule");
    let checkpoint_path = temp_path("elapsed-checkpoint");
    let end = 2u64 + u64::from(STREAM_BATCH_SIZE) + 1;
    let schedule = CheckpointSchedule::new(None, Some(Duration::from_nanos(1)))
        .expect("positive elapsed schedule should be valid");
    let config = format!("start=2;end={end};threads=1;dump_beyond=F8");
    let mut checkpoints = 0;
    stream_jsonl_range_checkpointed_with_schedule_and_cancel(
        &path,
        &checkpoint_path,
        2,
        end,
        1,
        Stage::F8,
        &config,
        schedule,
        |progress| {
            let checkpoint = read_checkpoint(&checkpoint_path).expect("checkpoint should parse");
            if checkpoint.next_m
                == if checkpoint.complete {
                    progress.completed_through
                } else {
                    progress.completed_through + 1
                }
            {
                checkpoints += 1;
            }
        },
        || false,
    )
    .expect("elapsed schedule should run");
    assert!(
        checkpoints >= 2,
        "elapsed schedule should checkpoint before final batch"
    );

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(checkpoint_path);
}

#[test]
fn large_batches_resume_small_shards_and_discard_uncheckpointed_survivors() {
    // This retained regression reaches F8 and produces a real survivor record.
    let start = 3_480_818_220_239u64;
    let max = u64::from(MAX_COMPUTE_BATCH_SIZE);
    let end = start + max + 16;
    let config = "large-compute-resume";
    let full_path = temp_path("large-full");
    let full = stream_jsonl_range(&full_path, start, end, 1, Stage::F8).unwrap();
    assert!(full.records_written > 0);

    for old_small_shards in [true, false] {
        let output_path = temp_path("large-resumed");
        let checkpoint_path = temp_path("large-state");
        let stop = Cell::new(false);
        let schedule = if old_small_shards {
            CheckpointSchedule::every_batch()
        } else {
            CheckpointSchedule::new(Some(max + 17), None).unwrap()
        };
        let partial = stream_jsonl_range_checkpointed_with_schedule_and_cancel(
            &output_path,
            &checkpoint_path,
            start,
            end,
            4,
            Stage::F8,
            config,
            schedule,
            |_| stop.set(true),
            || stop.get(),
        )
        .unwrap();
        assert!(partial.interrupted);
        assert!(partial.records_written > 0);
        let saved = read_checkpoint(&checkpoint_path).unwrap();
        if old_small_shards {
            assert_eq!(saved.next_m, start + u64::from(STREAM_BATCH_SIZE));
            assert_eq!(saved.completed_output_shards.len(), 1);
        } else {
            assert_eq!(partial.stats.tested, max);
            assert_eq!(saved.next_m, start);
            assert_eq!(saved.stats.tested, 0);
            assert_eq!(saved.output_bytes, 0);
            assert!(fs::metadata(&output_path).unwrap().len() > 0);
        }
        let resumed = resume_stream_jsonl_range_with_schedule_and_cancel(
            &output_path,
            &checkpoint_path,
            end,
            2,
            Stage::F8,
            config,
            CheckpointSchedule::new(Some(max + 17), None).unwrap(),
            |_| {},
            || false,
        )
        .unwrap();
        assert_eq!(resumed.stats, full.stats);
        assert_eq!(
            fs::read(&output_path).unwrap(),
            fs::read(&full_path).unwrap()
        );
        let saved = read_checkpoint(&checkpoint_path).unwrap();
        assert!(saved.complete);
        let mut next = start;
        let mut bytes = 0;
        for shard in saved.completed_output_shards {
            assert_eq!(shard.start_m, next);
            next = shard.end_m + 1;
            bytes += shard.bytes;
        }
        assert_eq!(next, end + 1);
        assert_eq!(bytes, fs::metadata(&output_path).unwrap().len());
        let _ = fs::remove_file(output_path);
        let _ = fs::remove_file(checkpoint_path);
    }
    let _ = fs::remove_file(full_path);
}

#[test]
fn larger_than_legacy_candidate_intervals_checkpoint_exactly() {
    let output_path = temp_path("larger-interval");
    let checkpoint_path = temp_path("larger-interval-state");
    let interval = u64::from(STREAM_BATCH_SIZE) + 17;
    let end = 2 + 2 * interval + 6;
    let mut checkpoints = Vec::new();
    stream_jsonl_range_checkpointed_with_schedule_and_cancel(
        &output_path,
        &checkpoint_path,
        2,
        end,
        4,
        Stage::F8,
        "larger-interval",
        CheckpointSchedule::new(Some(interval), None).unwrap(),
        |progress| {
            let saved = read_checkpoint(&checkpoint_path).unwrap();
            assert_eq!(saved.stats.tested, progress.tested);
            checkpoints.push(progress.tested);
        },
        || false,
    )
    .unwrap();
    assert_eq!(checkpoints, vec![interval, 2 * interval, 2 * interval + 7]);
    let _ = fs::remove_file(output_path);
    let _ = fs::remove_file(checkpoint_path);
}
