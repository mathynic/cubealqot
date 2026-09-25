//! PQ-03 real qualified-backend replay, publication and offline reload.
//!
//! This test is explicitly run after PQ-02 with `--ignored`; it uses the
//! isolated qualified helper and a disposable store, never the campaign
//! store. The default Rust suite does not launch Sage.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cubealqot::family::admission::{SageTranscriptEvidence, build_trusted_family_certificate};
use cubealqot::family::pocklington::UntrustedPrimeCertificate;
use cubealqot::family::problem::{self, ProblemBuildResult, validate_problem};
use cubealqot::family::sage::{
    SageAdapter, SageAdapterConfig, SageAdapterResult, SageBackendPolicy,
};
use cubealqot::family::{
    AdmissionLoad, AdmissionProvenance, CanonicalInt, CompletenessTrust, StoreReader,
    TrustedBackendAdmissionVerification, admit_trusted_backend_certificate_with_evidence,
    persist_trusted_backend_admission,
};
use sha2::{Digest, Sha256};

const QUALIFIED_HELPER_SHA256: &str =
    "88196FD1F3A90B1BBAD9A6A5A6A0C46CE8D8B0FA1D99FDFF31727C3923F56C9A";

fn integer(value: &str) -> CanonicalInt {
    CanonicalInt::from_decimal(value).expect("fixture integer is canonical")
}

fn n11_input() -> problem::UntrustedProblem {
    problem::UntrustedProblem {
        n: integer("11"),
        factors: vec![problem::UntrustedCofactorFactor {
            prime: integer("11"),
            exponent: 1,
            certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("11") }),
        }],
    }
}

fn n11_problem() -> cubealqot::family::problem::Problem {
    match validate_problem(&n11_input()) {
        ProblemBuildResult::Certified(problem) => problem,
        other => panic!("expected certified N=11 problem, got {other:?}"),
    }
}

fn temporary_root(label: &str) -> PathBuf {
    if let Some(base) = std::env::var_os("CUBEALQOT_PQ03_RETAIN_ROOT") {
        let root = PathBuf::from(base).join(label);
        let _ = fs::remove_dir_all(&root);
        return root;
    }
    let root = std::env::temp_dir().join(format!("cubealqot-pq03-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    root
}

fn cleanup_root(root: &Path) {
    if std::env::var_os("CUBEALQOT_PQ03_RETAIN_ROOT").is_none() {
        let _ = fs::remove_dir_all(root);
    }
}

fn qualified_helper(root: &Path) -> PathBuf {
    let helper = root.join("out/m7-pari-qualification/pq01-work/helper/sage_integral_points.py");
    assert!(
        helper.is_file(),
        "PQ-01 qualified helper is missing: {helper:?}"
    );
    let digest = Sha256::digest(fs::read(&helper).expect("read qualified helper"));
    let digest_hex = digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    assert_eq!(digest_hex, QUALIFIED_HELPER_SHA256);
    helper
}

fn qualified_adapter(root: &Path, evidence_dir: PathBuf, helper: PathBuf) -> SageAdapter {
    let script_sha256 = QUALIFIED_HELPER_SHA256.to_ascii_lowercase();
    let policy = SageBackendPolicy {
        distribution: "Ubuntu-26.04".to_owned(),
        environment: "cubealqot-m7".to_owned(),
        conda_executable: "conda".to_owned(),
        sage_version: "10.8".to_owned(),
        python_version: "3.14.7".to_owned(),
        script_sha256,
    };
    SageAdapter::new(SageAdapterConfig {
        launcher: root.join("scripts/m7/invoke-sage.ps1"),
        helper,
        powershell_executable: "powershell.exe".to_owned(),
        distribution: policy.distribution.clone(),
        conda_executable: policy.conda_executable.clone(),
        environment: policy.environment.clone(),
        timeout: Duration::from_secs(180),
        evidence_dir,
        policy,
        extra_launcher_args: Vec::new(),
    })
}

#[test]
#[ignore = "PQ-03 real Sage qualification; run explicitly after PQ-02"]
fn qualified_backend_replays_publishes_and_reloads_offline() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let helper = qualified_helper(&root);
    let evidence_root = temporary_root("evidence");
    let adapter = qualified_adapter(&root, evidence_root.clone(), helper.clone());
    let input = n11_input();
    let problem = n11_problem();

    let (completion, initial_evidence) = match adapter.enumerate(&problem) {
        SageAdapterResult::Complete {
            completion,
            evidence,
        } => (completion, evidence),
        other => panic!("qualified initial backend run was not complete: {other:?}"),
    };
    assert!(completion.response().complete);
    assert!(completion.response().proof.integral_points_complete);
    assert!(
        completion.points().is_empty(),
        "N=11 must have an empty point set"
    );

    let certificate = build_trusted_family_certificate(
        &input,
        &problem,
        &completion,
        SageTranscriptEvidence::from(&initial_evidence),
    )
    .expect("qualified backend certificate should build");
    let replay = match admit_trusted_backend_certificate_with_evidence(&certificate, &adapter) {
        TrustedBackendAdmissionVerification::Verified(value) => value,
        other => panic!("qualified backend replay was not verified: {other:?}"),
    };
    assert_eq!(
        replay.verified().solutions(),
        certificate.solutions.as_slice()
    );
    assert_ne!(
        replay.replay_evidence().job_id,
        initial_evidence.job_id,
        "initial and replay jobs need distinct transcript identities"
    );

    let store_root = temporary_root("store");
    let published =
        persist_trusted_backend_admission(&store_root, &certificate, &initial_evidence, &replay)
            .expect("verified replay should publish");
    let reader = StoreReader::open(&store_root).expect("open disposable PQ-03 store");
    let AdmissionLoad::Loaded(loaded) = reader
        .load_admission(published.admission_id())
        .expect("offline persisted admission should load")
    else {
        panic!("published admission was not loadable")
    };
    assert_eq!(
        loaded.status(),
        &cubealqot::family::FamilyCertificateStatus::CertifiedEmpty
    );
    assert_eq!(
        loaded.proof_kind(),
        &cubealqot::family::CertificateProofKind::TrustedIntegralPoints
    );
    assert_eq!(
        loaded.committed().record().provenance,
        AdmissionProvenance::FreshBackendReplay
    );
    assert_eq!(
        loaded.committed().record().policy.completeness,
        CompletenessTrust::HistoricalBackend
    );
    let backend = loaded
        .committed()
        .record()
        .backend
        .as_ref()
        .expect("backend identity must be persisted");
    assert_eq!(
        backend.policy.helper_sha256,
        QUALIFIED_HELPER_SHA256.to_ascii_lowercase()
    );
    assert_eq!(
        backend.point_set_sha256,
        certificate_point_hash(&certificate)
    );
    assert_eq!(loaded.solutions().len(), 0);

    // A certificate admitted under the qualified helper cannot be replayed
    // through a different helper identity, even if the mathematical content
    // is otherwise unchanged.
    let mut changed_config = qualified_adapter(&root, temporary_root("changed-evidence"), helper)
        .config()
        .clone();
    changed_config.policy.script_sha256 = "old-unqualified-helper".to_owned();
    let changed_adapter = SageAdapter::new(changed_config);
    assert!(matches!(
        admit_trusted_backend_certificate_with_evidence(&certificate, &changed_adapter),
        TrustedBackendAdmissionVerification::Rejected { .. }
    ));

    cleanup_root(&store_root);
    cleanup_root(&evidence_root);
}

fn certificate_point_hash(certificate: &cubealqot::family::UntrustedFamilyCertificate) -> String {
    let cubealqot::family::UntrustedCompletenessProof::TrustedIntegralPoints { backend } =
        &certificate.proof
    else {
        panic!("expected trusted backend certificate")
    };
    backend.point_list_sha256.clone()
}

#[test]
#[ignore = "PQ-03 historical proof-store audit; run explicitly"]
fn historical_admissions_load_offline_without_backend_execution() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("out/m7-proof-store");
    assert!(
        root.join("store.json").is_file(),
        "historical proof store is missing"
    );
    let reader = StoreReader::open(&root).expect("historical proof store should open offline");
    let mut ids = Vec::new();
    for entry in fs::read_dir(root.join("admissions")).expect("read admission directory") {
        let path = entry.expect("read admission entry").path();
        if let Some(name) = path.file_name().and_then(|value| value.to_str())
            && let Some(id) = name.strip_suffix(".commit.json")
        {
            ids.push(id.to_owned());
        }
    }
    ids.sort();
    assert!(
        !ids.is_empty(),
        "historical proof store contains no admissions"
    );
    for id in ids {
        assert!(
            matches!(reader.load_admission(&id), Ok(AdmissionLoad::Loaded(_))),
            "historical admission {id} did not load offline"
        );
    }
}
