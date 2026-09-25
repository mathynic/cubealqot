use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use cubealqot::{filters::Stage, survivors};

fn temp_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cubealqot-turn25-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

#[test]
fn crossing_u32_boundary_is_deterministic_across_periodic_resumes() {
    let start = u64::from(u32::MAX) - 96;
    let end = u64::from(u32::MAX) + 96;
    let full_path = temp_path("full");
    let four_thread_path = temp_path("four-thread");
    let resumed_path = temp_path("resumed");
    let checkpoint_path = temp_path("checkpoint");
    let config = format!("start={start};end={end};threads=2;dump_beyond=F1");
    let schedule = survivors::CheckpointSchedule::new(Some(37), None)
        .expect("candidate checkpoint interval should be valid");

    let full = survivors::stream_jsonl_range(&full_path, start, end, 1, Stage::F1)
        .expect("uninterrupted crossing run should succeed");
    assert_eq!(full.stats.tested, end - start + 1);
    survivors::stream_jsonl_range(&four_thread_path, start, end, 4, Stage::F1)
        .expect("uninterrupted multi-thread crossing run should succeed");
    assert_eq!(
        fs::read(&full_path).expect("one-thread output should be readable"),
        fs::read(&four_thread_path).expect("multi-thread output should be readable")
    );

    let mut cycles = 0;
    loop {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_progress = Arc::clone(&stop);
        let run = if cycles == 0 {
            survivors::stream_jsonl_range_checkpointed_with_schedule_and_cancel(
                &resumed_path,
                &checkpoint_path,
                start,
                end,
                2,
                Stage::F1,
                &config,
                schedule,
                move |progress| {
                    if progress.completed_through < end {
                        stop_for_progress.store(true, Ordering::SeqCst);
                    }
                },
                || stop.load(Ordering::SeqCst),
            )
        } else {
            survivors::resume_stream_jsonl_range_with_schedule_and_cancel(
                &resumed_path,
                &checkpoint_path,
                end,
                4,
                Stage::F1,
                &config,
                schedule,
                move |progress| {
                    if progress.completed_through < end {
                        stop_for_progress.store(true, Ordering::SeqCst);
                    }
                },
                || stop.load(Ordering::SeqCst),
            )
        }
        .expect("each interrupted/resumed cycle should succeed");

        cycles += 1;
        if !run.interrupted {
            break;
        }
        assert!(
            cycles < 20,
            "periodic resume should finish in bounded cycles"
        );
    }

    let checkpoint = survivors::read_checkpoint(&checkpoint_path)
        .expect("final crossing checkpoint should be readable");
    assert!(checkpoint.complete);
    assert_eq!(checkpoint.range_start, start);
    assert_eq!(checkpoint.range_end, end);
    assert_eq!(checkpoint.stats.tested, end - start + 1);

    let full_bytes = fs::read(&full_path).expect("full output should be readable");
    let resumed_bytes = fs::read(&resumed_path).expect("resumed output should be readable");
    assert_eq!(full_bytes, resumed_bytes);

    let records = survivors::read_jsonl(&resumed_path).expect("crossing JSONL should parse");
    assert_eq!(records.len(), (end - start + 1) as usize);
    assert_eq!(
        records.first().expect("records should be non-empty").m,
        start
    );
    assert_eq!(records.last().expect("records should be non-empty").m, end);
    assert!(records.windows(2).all(|pair| pair[0].m + 1 == pair[1].m));
    assert!(records.iter().any(|record| record.m == u64::from(u32::MAX)));
    assert!(records.iter().any(|record| record.m > u64::from(u32::MAX)));
    assert!(
        records
            .iter()
            .flat_map(|record| record.factors.iter())
            .any(|factor| factor[0] > u64::from(u32::MAX))
    );
    for record in &records {
        let reconstructed = record
            .factors
            .iter()
            .map(|&[prime, exponent]| u128::from(prime).pow(exponent as u32))
            .product::<u128>();
        assert_eq!(reconstructed, u128::from(record.m), "m={}", record.m);
    }

    let _ = fs::remove_file(full_path);
    let _ = fs::remove_file(four_thread_path);
    let _ = fs::remove_file(resumed_path);
    let _ = fs::remove_file(checkpoint_path);
}
