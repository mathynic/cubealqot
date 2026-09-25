//! PP-08 regressions: benchmark/campaign orchestration reuses committed
//! admissions and does not make backend replay part of search.

use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use cubealqot::{
    family::{StoreReader, StoreSnapshot, TheoremMap},
    filters::Stage,
    survivors,
};
use serde_json::Value;

fn temp_dir(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("cubealqot-pp08-{label}-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn run(binary: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(binary).args(args).output().unwrap()
}

#[test]
fn benchmark_json_preserves_wide_u128_diagnostics() {
    let value = serde_json::json!({
        "S": u128::MAX,
        "Y": u128::MAX - 1,
    });
    let encoded = serde_json::to_string(&value).unwrap();
    assert!(encoded.contains(&u128::MAX.to_string()));
    assert!(encoded.contains(&(u128::MAX - 1).to_string()));
}

#[cfg(windows)]
#[test]
fn legacy_receipt_resumes_against_migrated_admission_without_backend_replay() {
    let root = temp_dir("legacy-receipt");
    let store = root.join("store");
    let campaign = root.join("campaign");
    let report = root.join("inspection.json");
    fs::create_dir_all(&campaign).unwrap();

    let binary = PathBuf::from(env!("CARGO_BIN_EXE_cubealqot-family"));
    let library = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("out/m7-proof-library");
    let inspect = Command::new(&binary)
        .args([
            "store",
            "inspect-legacy",
            "--source",
            library.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        inspect.status.success(),
        "inspect stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspection: Value = serde_json::from_slice(&inspect.stdout).unwrap();
    let digest = inspection["report_digest"].as_str().unwrap();
    let imported = Command::new(&binary)
        .args([
            "store",
            "import-legacy",
            "--store",
            store.to_str().unwrap(),
            "--report",
            report.to_str().unwrap(),
            "--report-digest",
            digest,
            "--policy",
            "recorded-local-campaign-v1",
        ])
        .output()
        .unwrap();
    assert!(
        imported.status.success(),
        "import stdout={} stderr={}",
        String::from_utf8_lossy(&imported.stdout),
        String::from_utf8_lossy(&imported.stderr)
    );

    let certificates = campaign.join("certificates");
    let receipts = campaign.join("receipts");
    fs::create_dir_all(&certificates).unwrap();
    fs::create_dir_all(&receipts).unwrap();
    let artifact_name = "N21-limit7200-20260919T032320Z-c6fa164b19df4093aa8f1f2e0442c0c9.json";
    fs::copy(
        library.join("certificates").join(artifact_name),
        certificates.join(artifact_name),
    )
    .unwrap();
    fs::copy(library.join("receipts/N21.json"), receipts.join("N21.json")).unwrap();

    let candidates = root.join("recommended-jobs.json");
    fs::write(
        &candidates,
        br#"{"jobs":[{"priority":1,"N":"21","factors":[[3,1],[7,1]]}]}"#,
    )
    .unwrap();
    let source_script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/m7/run-candidate-campaign.ps1");
    let mut script = fs::read_to_string(source_script).unwrap();
    let ps_quote = |path: &std::path::Path| path.to_string_lossy().replace('\'', "''");
    script = script.replace(
        "$crate = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))",
        &format!(
            "$crate = '{}'",
            ps_quote(PathBuf::from(env!("CARGO_MANIFEST_DIR")).as_path())
        ),
    );
    script = script.replace(
        "$candidateFile = Join-Path $crate 'out/m7-candidate-analysis/recommended-jobs.json'",
        &format!("$candidateFile = '{}'", ps_quote(&candidates)),
    );
    script = script.replace(
        "$binary = Join-Path $crate 'target/release/cubealqot-family.exe'",
        &format!("$binary = '{}'", ps_quote(&binary)),
    );
    let script_path = root.join("run-candidate-campaign.ps1");
    fs::write(&script_path, script).unwrap();

    let resumed = Command::new("pwsh")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            script_path.to_str().unwrap(),
            "-OnlyN",
            "21",
            "-TimeoutSeconds",
            "1",
            "-OutputDirectory",
            campaign.to_str().unwrap(),
            "-ProofStore",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&resumed.stdout);
    let stderr = String::from_utf8_lossy(&resumed.stderr);
    assert!(
        resumed.status.success(),
        "resume stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("skipping committed admission"), "{stdout}");
    assert!(stdout.contains("no backend replay"), "{stdout}");
    let receipt: Value =
        serde_json::from_slice(&fs::read(receipts.join("N21.json")).unwrap()).unwrap();
    assert!(receipt.get("admission_id").is_none());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn loaded_snapshot_collection_is_offline_and_matches_direct_map() {
    let root = temp_dir("loaded");
    let factors = root.join("factors.json");
    let store = root.join("store");
    let artifact = root.join("certificate.json");
    let snapshot = root.join("snapshot.json");
    fs::write(
        &factors,
        br#"[{"prime":"2","exponent":1,"certificate":{"kind":"u64","n":"2"}},{"prime":"7","exponent":1,"certificate":{"kind":"u64","n":"7"}}]"#,
    ).unwrap();
    let family = PathBuf::from(env!("CARGO_BIN_EXE_cubealqot-family"));
    let store_s = store.to_string_lossy().into_owned();
    let factors_s = factors.to_string_lossy().into_owned();
    let artifact_s = artifact.to_string_lossy().into_owned();
    let snapshot_s = snapshot.to_string_lossy().into_owned();
    assert!(
        run(
            &family,
            &[
                "prove",
                "--n",
                "14",
                "--factors",
                &factors_s,
                "--output",
                &artifact_s,
                "--store",
                &store_s
            ]
        )
        .status
        .success()
    );
    assert!(
        run(
            &family,
            &[
                "export-map",
                "--store",
                &store_s,
                "--admissions",
                "all",
                "--output",
                &snapshot_s
            ]
        )
        .status
        .success()
    );

    let reader = StoreReader::open(&store).unwrap();
    let snapshot: StoreSnapshot = serde_json::from_slice(&fs::read(&snapshot).unwrap()).unwrap();
    let loaded = TheoremMap::from_store_snapshot(&reader, &snapshot).unwrap();
    assert!(!loaded.map().uses_backend_trust());
    let offline =
        survivors::collect_range_with_loaded_family_map(2, 100, 2, Stage::F8, &loaded).unwrap();
    let direct =
        survivors::collect_range_with_family_map(2, 100, 2, Stage::F8, loaded.map()).unwrap();
    assert_eq!(offline.records, direct.records);
    let premises = offline.run_metadata.unwrap().premises;
    assert_eq!(
        premises.theorem_snapshot_id.as_deref(),
        Some(snapshot.snapshot_id.as_str())
    );
    assert_eq!(premises.selected_admission_ids, loaded.admission_ids());
}

#[test]
fn orchestration_sources_require_frozen_snapshot_and_committed_admission() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let prepare =
        fs::read_to_string(root.join("scripts/m7/prepare-placement-benchmark.py")).unwrap();
    let benchmark = fs::read_to_string(root.join("scripts/m7/placement-benchmark.rs")).unwrap();
    let wrapper =
        fs::read_to_string(root.join("scripts/m7/benchmark-family-placement.ps1")).unwrap();
    let campaign = fs::read_to_string(root.join("scripts/m7/run-candidate-campaign.ps1")).unwrap();
    assert!(prepare.contains("--store"));
    assert!(prepare.contains("--snapshot"));
    assert!(prepare.contains("theorem-snapshot.json"));
    assert!(benchmark.contains("StoreReader::open"));
    assert!(benchmark.contains("from_store_snapshot"));
    assert!(!benchmark.contains("admit_trusted_backend_certificate"));
    assert!(wrapper.contains("-ProofStore"));
    assert!(wrapper.contains("-Snapshot"));
    assert!(campaign.contains("committed"));
    assert!(campaign.contains("admission_id"));
}
