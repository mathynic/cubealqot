use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use cubealqot::{
    family::{StoreReader, TheoremMap},
    filters::Stage,
    survivors::{
        self, CheckpointSchedule,
        resume_stream_jsonl_range_with_loaded_family_map_and_schedule_and_cancel,
        stream_jsonl_range_checkpointed_with_loaded_family_map_and_schedule_and_cancel,
    },
};
use serde_json::Value;

fn temp_dir(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("cubealqot-pp07-{label}-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn run(binary: &Path, args: &[&str]) -> std::process::Output {
    Command::new(binary).args(args).output().unwrap()
}

fn factors(root: &Path) -> PathBuf {
    let path = root.join("factors.json");
    fs::write(
        &path,
        br#"[{"prime":"2","exponent":1,"certificate":{"kind":"u64","n":"2"}},{"prime":"7","exponent":1,"certificate":{"kind":"u64","n":"7"}}]"#,
    )
    .unwrap();
    path
}

#[test]
fn native_run_loads_one_snapshot_offline_and_rejects_corruption_before_output() {
    let root = temp_dir("cli");
    let factor_path = factors(&root);
    let store = root.join("store");
    let artifact = root.join("certificate.json");
    let snapshot = root.join("snapshot.json");
    let mapped = root.join("mapped.jsonl");
    let plain = root.join("plain.jsonl");
    let corrupt_output = root.join("corrupt.jsonl");
    let family_binary = PathBuf::from(env!("CARGO_BIN_EXE_cubealqot-family"));
    let native_binary = PathBuf::from(env!("CARGO_BIN_EXE_cubealqot"));
    let factor = factor_path.to_string_lossy().into_owned();
    let store_arg = store.to_string_lossy().into_owned();
    let artifact_arg = artifact.to_string_lossy().into_owned();
    let snapshot_arg = snapshot.to_string_lossy().into_owned();

    let proved = run(
        &family_binary,
        &[
            "prove",
            "--n",
            "14",
            "--factors",
            &factor,
            "--output",
            &artifact_arg,
            "--store",
            &store_arg,
        ],
    );
    assert!(
        proved.status.success(),
        "{}",
        String::from_utf8_lossy(&proved.stdout)
    );
    let exported = run(
        &family_binary,
        &[
            "export-map",
            "--store",
            &store_arg,
            "--admissions",
            "all",
            "--output",
            &snapshot_arg,
        ],
    );
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stdout)
    );

    let mapped_arg = mapped.to_string_lossy().into_owned();
    let mapped_run = run(
        &native_binary,
        &[
            "run",
            "--start",
            "2",
            "--end",
            "100",
            "--threads",
            "1",
            "--output",
            &mapped_arg,
            "--family-store",
            &store_arg,
            "--family-snapshot",
            &snapshot_arg,
        ],
    );
    assert!(
        mapped_run.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&mapped_run.stderr)
    );
    assert!(String::from_utf8_lossy(&mapped_run.stdout).contains("loaded theorem snapshot"));

    let plain_arg = plain.to_string_lossy().into_owned();
    let plain_run = run(
        &native_binary,
        &[
            "run",
            "--start",
            "2",
            "--end",
            "100",
            "--threads",
            "1",
            "--output",
            &plain_arg,
        ],
    );
    assert!(
        plain_run.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&plain_run.stderr)
    );
    assert_eq!(fs::read(mapped).unwrap(), fs::read(plain).unwrap());

    let mut corrupted: Value = serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    corrupted["policy_id"] = Value::String("forged-policy".to_owned());
    let corrupt_snapshot = root.join("corrupt-snapshot.json");
    fs::write(&corrupt_snapshot, serde_json::to_vec(&corrupted).unwrap()).unwrap();
    let corrupt_snapshot_arg = corrupt_snapshot.to_string_lossy().into_owned();
    let corrupt_output_arg = corrupt_output.to_string_lossy().into_owned();
    let rejected = run(
        &native_binary,
        &[
            "run",
            "--start",
            "2",
            "--end",
            "100",
            "--output",
            &corrupt_output_arg,
            "--family-store",
            &store_arg,
            "--family-snapshot",
            &corrupt_snapshot_arg,
        ],
    );
    assert!(!rejected.status.success());
    assert!(
        !corrupt_output.exists(),
        "corrupt premises must fail before output creation"
    );
    let certificate_digest = corrupted["admissions"][0]["certificate"]["object_digest"]
        .as_str()
        .unwrap();
    fs::remove_file(store.join("objects").join(certificate_digest)).unwrap();
    let missing_output = root.join("missing.jsonl");
    let missing_output_arg = missing_output.to_string_lossy().into_owned();
    let missing = run(
        &native_binary,
        &[
            "run",
            "--start",
            "2",
            "--end",
            "100",
            "--output",
            &missing_output_arg,
            "--family-store",
            &store_arg,
            "--family-snapshot",
            &snapshot_arg,
        ],
    );
    assert!(!missing.status.success());
    assert!(
        !missing_output.exists(),
        "missing admissions must fail before output creation"
    );
}

#[test]
fn loaded_snapshot_resume_keeps_selection_identity_and_results() {
    let root = temp_dir("resume");
    let factor_path = factors(&root);
    let store = root.join("store");
    let artifact = root.join("certificate.json");
    let snapshot = root.join("snapshot.json");
    let family_binary = PathBuf::from(env!("CARGO_BIN_EXE_cubealqot-family"));
    let factor = factor_path.to_string_lossy().into_owned();
    let store_arg = store.to_string_lossy().into_owned();
    let artifact_arg = artifact.to_string_lossy().into_owned();
    let snapshot_arg = snapshot.to_string_lossy().into_owned();
    assert!(
        run(
            &family_binary,
            &[
                "prove",
                "--n",
                "14",
                "--factors",
                &factor,
                "--output",
                &artifact_arg,
                "--store",
                &store_arg,
            ],
        )
        .status
        .success()
    );
    assert!(
        run(
            &family_binary,
            &[
                "export-map",
                "--store",
                &store_arg,
                "--admissions",
                "all",
                "--output",
                &snapshot_arg,
            ],
        )
        .status
        .success()
    );

    let reader = StoreReader::open(&store).unwrap();
    let snapshot: cubealqot::family::StoreSnapshot =
        serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    let loaded = TheoremMap::from_store_snapshot(&reader, &snapshot).unwrap();
    let full = root.join("full.jsonl");
    let resumed = root.join("resumed.jsonl");
    let checkpoint = root.join("resume.checkpoint.json");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_progress = stop.clone();
    let config = "pp-07;start=2;end=100;threads=1;dump=F8";
    let partial = stream_jsonl_range_checkpointed_with_loaded_family_map_and_schedule_and_cancel(
        &resumed,
        &checkpoint,
        2,
        100,
        1,
        Stage::F8,
        config,
        CheckpointSchedule::new(Some(16), None).unwrap(),
        &loaded,
        move |progress| {
            if progress.completed_through < 100 {
                stop_for_progress.store(true, Ordering::SeqCst);
            }
        },
        || stop.load(Ordering::SeqCst),
    )
    .unwrap();
    assert!(partial.interrupted);
    let checkpoint_value = survivors::read_checkpoint(&checkpoint).unwrap();
    let premises = checkpoint_value.premises.unwrap();
    assert_eq!(
        premises.theorem_snapshot_id.as_deref(),
        Some(snapshot.snapshot_id.as_str())
    );
    assert_eq!(
        premises.theorem_store_id.as_deref(),
        Some(snapshot.store_id.as_str())
    );
    assert_eq!(
        premises.theorem_policy_id.as_deref(),
        Some(snapshot.policy_id.as_str())
    );
    assert_eq!(
        premises.selected_admission_ids.len(),
        snapshot.admissions.len()
    );

    let legacy_map_checkpoint = root.join("legacy-map.checkpoint.json");
    let mut legacy_value: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    legacy_value["schema_version"] = Value::from(2u64);
    fs::write(
        &legacy_map_checkpoint,
        serde_json::to_vec(&legacy_value).unwrap(),
    )
    .unwrap();
    let legacy_error = survivors::resume_stream_jsonl_range_with_schedule_and_cancel(
        &resumed,
        &legacy_map_checkpoint,
        100,
        1,
        Stage::F8,
        config,
        CheckpointSchedule::new(Some(16), None).unwrap(),
        |_| {},
        || false,
    )
    .expect_err("obsolete map-aware schema must not resume through the no-map API");
    assert!(legacy_error.contains("theorem snapshot"));

    resume_stream_jsonl_range_with_loaded_family_map_and_schedule_and_cancel(
        &resumed,
        &checkpoint,
        100,
        4,
        Stage::F8,
        config,
        CheckpointSchedule::new(Some(16), None).unwrap(),
        &loaded,
        |_| {},
        || false,
    )
    .unwrap();
    let plain = survivors::stream_jsonl_range_with_loaded_family_map_and_cancel(
        &full,
        2,
        100,
        1,
        Stage::F8,
        &loaded,
        || false,
    )
    .unwrap();
    assert_eq!(
        plain.records_written,
        fs::read_to_string(&full).unwrap().lines().count() as u64
    );
    assert_eq!(fs::read(full).unwrap(), fs::read(resumed).unwrap());
}
