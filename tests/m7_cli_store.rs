use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cubealqot-family"))
}

fn temp_dir(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("cubealqot-pp06-{label}-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn run(args: &[&str]) -> (i32, Value, String) {
    let output = Command::new(binary()).args(args).output().unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout was not JSON: {error}; stdout={:?}; stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (
        output.status.code().unwrap_or(-1),
        value,
        String::from_utf8_lossy(&output.stderr).into(),
    )
}

fn source_library() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("out/m7-proof-library")
        .leak()
}

fn write_factors(root: &Path) -> PathBuf {
    let path = root.join("factors.json");
    fs::write(
        &path,
        br#"[{"prime":"2","exponent":1,"certificate":{"kind":"u64","n":"2"}},{"prime":"7","exponent":1,"certificate":{"kind":"u64","n":"7"}}]"#,
    )
    .unwrap();
    path
}

#[test]
fn import_list_check_and_export_are_reusable_without_sage() {
    let root = temp_dir("store");
    let report = root.join("inspection.json");
    let store = root.join("proof-store");
    let snapshot = root.join("snapshot.json");

    let (code, inspection, _) = run(&[
        "store",
        "inspect-legacy",
        "--source",
        source_library().to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{inspection:?}");
    assert_eq!(inspection["status"], "INSPECTED");
    let digest = inspection["report_digest"].as_str().unwrap();
    assert!(report.is_file());

    let (code, imported, _) = run(&[
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
    ]);
    assert_eq!(code, 0, "{imported:?}");
    assert_eq!(imported["status"], "IMPORTED");
    assert_eq!(imported["admitted_count"], 7);
    assert_eq!(imported["backend_invoked"], false);

    let (code, listed, stderr) = run(&["store", "list", "--store", store.to_str().unwrap()]);
    assert_eq!(code, 0, "{listed:?}; stderr={stderr}");
    assert_eq!(listed["status"], "LISTED");
    assert_eq!(listed["entries"].as_array().unwrap().len(), 7);
    assert!(
        listed["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["proof_kind"] == "TrustedIntegralPoints"
                && entry["provenance"] == "MigratedRecordedLocalCampaign")
    );

    let (code, checked, _) = run(&["store", "check", "--store", store.to_str().unwrap()]);
    assert_eq!(code, 0, "{checked:?}");
    assert_eq!(checked["status"], "CHECKED");
    assert_eq!(checked["backend_invoked"], false);

    let (code, exported, _) = run(&[
        "export-map",
        "--store",
        store.to_str().unwrap(),
        "--admissions",
        "all",
        "--output",
        snapshot.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{exported:?}");
    assert_eq!(exported["status"], "EXPORTED");
    assert_eq!(exported["completeness"], "trusted-backend");
    let snapshot_json: Value = serde_json::from_slice(&fs::read(snapshot).unwrap()).unwrap();
    assert_eq!(snapshot_json["admissions"].as_array().unwrap().len(), 7);
    assert!(
        snapshot_json["admissions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| {
                entry["allowed_q"].is_array() && !entry["evidence"].as_array().unwrap().is_empty()
            })
    );
}

#[test]
fn requested_missing_admission_is_not_silently_dropped() {
    let root = temp_dir("missing");
    let report = root.join("inspection.json");
    let store = root.join("proof-store");
    let (_, inspection, _) = run(&[
        "store",
        "inspect-legacy",
        "--source",
        source_library().to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
    ]);
    let digest = inspection["report_digest"].as_str().unwrap();
    let (import_code, _, _) = run(&[
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
    ]);
    assert_eq!(import_code, 0);
    let output = root.join("snapshot.json");
    let (code, value, _) = run(&[
        "export-map",
        "--store",
        store.to_str().unwrap(),
        "--admissions",
        "missing-admission",
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(code, 3);
    assert_eq!(value["status"], "INVALID_INPUT");
}

#[test]
fn local_prove_admit_and_loaded_verify_use_the_selected_store() {
    let root = temp_dir("local-admit");
    let factors = write_factors(&root);
    let artifact = root.join("artifact.json");
    let store = root.join("store");
    let factors = factors.to_string_lossy().to_string();
    let artifact_string = artifact.to_string_lossy().to_string();
    let store_string = store.to_string_lossy().to_string();

    let (code, proved, _) = run(&[
        "prove",
        "--n",
        "14",
        "--factors",
        &factors,
        "--output",
        &artifact_string,
        "--store",
        &store_string,
    ]);
    assert_eq!(code, 0, "{proved:?}");
    let admission_id = proved["admission_id"].as_str().unwrap();

    let reused_artifact = root.join("reused-artifact.json");
    let reused_artifact_string = reused_artifact.to_string_lossy().to_string();
    let (code, reused, _) = run(&[
        "prove",
        "--n",
        "14",
        "--factors",
        &factors,
        "--backend",
        "none",
        "--output",
        &reused_artifact_string,
        "--store",
        &store_string,
    ]);
    assert_eq!(code, 0, "{reused:?}");
    assert_eq!(reused["admission_id"], admission_id);
    assert_eq!(reused["store_root"], store_string);

    let (code, verified, _) = run(&["verify", &artifact_string, "--store", &store_string]);
    assert_eq!(code, 0, "{verified:?}");
    assert_eq!(verified["verification"], "loaded-admission");
    assert_eq!(verified["backend_invoked"], false);
    assert_eq!(verified["admission_id"], admission_id);

    let (code, admitted, _) = run(&[
        "admit",
        &artifact_string,
        "--store",
        &store_string,
        "--backend",
        "none",
    ]);
    assert_eq!(code, 0, "{admitted:?}");
    assert_eq!(admitted["backend_invoked"], false);

    let (code, refreshed, _) = run(&[
        "refresh",
        admission_id,
        "--store",
        &store_string,
        "--backend",
        "none",
    ]);
    assert_eq!(code, 2, "{refreshed:?}");
    assert_eq!(refreshed["status"], "INCONCLUSIVE");
}
