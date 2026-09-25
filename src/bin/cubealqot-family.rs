//! M7-14 offline family CLI.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use cubealqot::family::load_mw_point_file;
use cubealqot::family::problem::{self, UntrustedProblem, validate_problem};
use cubealqot::family::{
    AdmissionLoad, BoundedDiscoveryResult, CertificateVerification, DEFAULT_STORE_ROOT,
    FamilyCertificateStatus, PublishedAdmission, RECORDED_LOCAL_CAMPAIGN_POLICY_ID, SageAdapter,
    SageAdapterConfig, SageAdapterResult, SageRunEvidence, SageTranscriptEvidence, StoreReader,
    StoreSnapshot, StoreSnapshotAdmission, TheoremMap, TrustedBackendAdmissionVerification,
    UntrustedCompletenessProof, UntrustedFamilyCertificate, admission_id_for_certificate,
    build_local_family_certificate, build_trusted_family_certificate, canonical_json_bytes,
    commit_legacy_proof_library, discover_bounded, inspect_legacy_proof_library,
    parse_family_certificate, parse_legacy_migration_report, persist_local_admission,
    persist_trusted_backend_admission, persist_trusted_backend_refresh, search_local_certificate,
    serialize_legacy_migration_report, verify_family_certificate,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CLI_ARTIFACT_SCHEMA_VERSION: u32 = 1;
const INCONCLUSIVE_EXIT: i32 = 2;
const INVALID_EXIT: i32 = 3;
const OPERATIONAL_EXIT: i32 = 4;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BackendKind {
    None,
    Sage,
}

#[derive(Debug, Parser)]
#[command(
    name = "cubealqot-family",
    about = "Independent fixed-cofactor family proof and discovery CLI",
    after_help = "Completeness is either self-contained (local proof), backend-trusted (approved Sage replay), or bounded-only (finite discovery). Store list/check/export and loaded-admission verification are offline; Sage runs only for explicit admit/refresh or selected prove/verify replay."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check local proof support and the selected backend environment.
    Doctor {
        #[arg(long, value_enum, default_value_t = BackendKind::None)]
        backend: BackendKind,
    },
    /// Discover solutions only in the inclusive finite interval [2, q-max].
    Bounded {
        #[arg(long)]
        n: String,
        #[arg(long)]
        factors: PathBuf,
        #[arg(long)]
        q_max: u64,
    },
    /// Try the local proof, then the selected approved backend.
    Prove {
        #[arg(long)]
        n: String,
        #[arg(long)]
        factors: PathBuf,
        #[arg(long, value_enum, default_value_t = BackendKind::None)]
        backend: BackendKind,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 60)]
        timeout_seconds: u64,
        #[arg(long)]
        store: Option<PathBuf>,
        /// Exact original-model discovery points to pass as untrusted backend hints.
        #[arg(long = "mw-points")]
        mw_points: Option<PathBuf>,
    },
    /// Verify a local artifact offline or replay a trusted Sage artifact.
    Verify {
        certificate: PathBuf,
        #[arg(long, value_enum, default_value_t = BackendKind::None)]
        backend: BackendKind,
        #[arg(long, default_value_t = 60)]
        timeout_seconds: u64,
        #[arg(long)]
        store: Option<PathBuf>,
    },
    /// Export only self-contained verified certificates into a map snapshot.
    ExportMap {
        #[arg(long)]
        certificates: Option<PathBuf>,
        #[arg(long)]
        store: Option<PathBuf>,
        #[arg(long)]
        admissions: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Import, inspect and reuse immutable admissions in a proof store.
    Store {
        #[command(subcommand)]
        command: StoreCommand,
    },
    /// Admit an external certificate into a selected store.
    Admit {
        certificate: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long, value_enum, default_value_t = BackendKind::None)]
        backend: BackendKind,
        #[arg(long, default_value_t = 60)]
        timeout_seconds: u64,
    },
    /// Explicitly refresh one persisted backend admission.
    Refresh {
        admission_id: String,
        #[arg(long)]
        store: PathBuf,
        #[arg(long, value_enum, default_value_t = BackendKind::None)]
        backend: BackendKind,
        #[arg(long, default_value_t = 60)]
        timeout_seconds: u64,
    },
}

#[derive(Debug, Subcommand)]
enum StoreCommand {
    /// Inspect retained campaigns without writing theorem admissions.
    InspectLegacy {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        report: PathBuf,
    },
    /// Commit a previously inspected report under the historical policy.
    ImportLegacy {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        report_digest: String,
        #[arg(long)]
        policy: String,
    },
    /// List committed admissions using offline loading only.
    List {
        #[arg(long)]
        store: PathBuf,
    },
    /// Check every committed admission using offline loading only.
    Check {
        #[arg(long)]
        store: PathBuf,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CliArtifact {
    schema_version: u32,
    job_id: String,
    input_sha256: String,
    environment_sha256: String,
    certificate: UntrustedFamilyCertificate,
}

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return;
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"status":"INVALID_INPUT","completeness":"none","reason":"invalid command-line arguments"})
            );
            eprintln!("{error}");
            process::exit(INVALID_EXIT);
        }
    };
    let code = match run(cli.command) {
        Ok(Outcome::Success(value)) => {
            println!("{value}");
            0
        }
        Ok(Outcome::Inconclusive(value)) => {
            println!("{value}");
            INCONCLUSIVE_EXIT
        }
        Ok(Outcome::Invalid(value)) => {
            println!("{value}");
            INVALID_EXIT
        }
        Ok(Outcome::Operational(value)) => {
            println!("{value}");
            OPERATIONAL_EXIT
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"status":"OPERATIONAL_ERROR","completeness":"none","reason":error})
            );
            OPERATIONAL_EXIT
        }
    };
    process::exit(code);
}

enum Outcome {
    Success(serde_json::Value),
    Inconclusive(serde_json::Value),
    Invalid(serde_json::Value),
    Operational(serde_json::Value),
}

fn run(command: Command) -> Result<Outcome, String> {
    match command {
        Command::Doctor { backend } => doctor(backend),
        Command::Bounded { n, factors, q_max } => bounded(&n, &factors, q_max),
        Command::Prove {
            n,
            factors,
            backend,
            output,
            timeout_seconds,
            store,
            mw_points,
        } => prove(
            &n,
            &factors,
            backend,
            &output,
            timeout_seconds,
            store.as_deref(),
            mw_points.as_deref(),
        ),
        Command::Verify {
            certificate,
            backend,
            timeout_seconds,
            store,
        } => verify(&certificate, backend, timeout_seconds, store.as_deref()),
        Command::ExportMap {
            certificates,
            store,
            admissions,
            output,
        } => export_map(
            certificates.as_deref(),
            store.as_deref(),
            admissions.as_deref(),
            &output,
        ),
        Command::Store { command } => store_command(command),
        Command::Admit {
            certificate,
            store,
            backend,
            timeout_seconds,
        } => admit(&certificate, &store, backend, timeout_seconds),
        Command::Refresh {
            admission_id,
            store,
            backend,
            timeout_seconds,
        } => refresh(&admission_id, &store, backend, timeout_seconds),
    }
}

fn doctor(backend: BackendKind) -> Result<Outcome, String> {
    let (backend_status, reason) = match backend {
        BackendKind::None => ("UNSELECTED", "no backend selected".to_owned()),
        BackendKind::Sage => match SageAdapterConfig::m7_default(std::env::temp_dir()) {
            Ok(config) if config.launcher.is_file() && config.helper.is_file() => (
                "CONFIGURED",
                "pinned Sage adapter files are present".to_owned(),
            ),
            Ok(_) => (
                "UNAVAILABLE",
                "pinned Sage adapter files are missing".to_owned(),
            ),
            Err(error) => (
                "UNAVAILABLE",
                format!("could not inspect Sage policy: {error}"),
            ),
        },
    };
    Ok(Outcome::Success(serde_json::json!({
        "command": "doctor",
        "status": "READY",
        "completeness": "none",
        "local_prover": "AVAILABLE",
        "backend": backend_status,
        "backend_reason": reason,
    })))
}

fn bounded(n: &str, factors_path: &Path, q_max: u64) -> Result<Outcome, String> {
    let input = match load_problem(n, factors_path) {
        Ok(input) => input,
        Err(reason) => return Ok(Outcome::Invalid(invalid(reason))),
    };
    let problem = match validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        problem::ProblemBuildResult::Rejected { reason } => {
            return Ok(Outcome::Invalid(invalid(reason)));
        }
        problem::ProblemBuildResult::Inconclusive { reason } => {
            return Ok(Outcome::Inconclusive(inconclusive(reason, "bounded-only")));
        }
    };
    match discover_bounded(&problem, q_max) {
        BoundedDiscoveryResult::Bounded(discovery) => Ok(Outcome::Success(serde_json::json!({
            "command": "bounded",
            "status": "BOUNDED",
            "completeness": "bounded-only",
            "global_completeness": false,
            "n": discovery.n(),
            "q_min": "2",
            "q_max": discovery.q_max().to_string(),
            "last_examined_q": discovery.last_examined_q().map(|q| q.to_string()),
            "candidates": discovery.candidates(),
            "tested_prime_count": discovery.tested_prime_count(),
            "excluded_dividing_n_count": discovery.excluded_dividing_n_count(),
        }))),
        BoundedDiscoveryResult::Inconclusive { partial, reason } => {
            Ok(Outcome::Inconclusive(serde_json::json!({
                "command": "bounded",
                "status": "INCONCLUSIVE",
                "completeness": "bounded-only",
                "global_completeness": false,
                "n": partial.n(),
                "q_min": "2",
                "q_max": partial.q_max().to_string(),
                "last_examined_q": partial.last_examined_q().map(|q| q.to_string()),
                "candidates": partial.candidates(),
                "reason": reason,
            })))
        }
    }
}

fn prove(
    n: &str,
    factors_path: &Path,
    backend: BackendKind,
    output: &Path,
    timeout_seconds: u64,
    store: Option<&Path>,
    mw_points_path: Option<&Path>,
) -> Result<Outcome, String> {
    if output.exists() {
        return Ok(Outcome::Invalid(invalid(
            "proof artifact already exists and is immutable",
        )));
    }
    let input = match load_problem(n, factors_path) {
        Ok(input) => input,
        Err(reason) => return Ok(Outcome::Invalid(invalid(reason))),
    };
    let problem = match validate_problem(&input) {
        problem::ProblemBuildResult::Certified(problem) => problem,
        problem::ProblemBuildResult::Rejected { reason } => {
            return Ok(Outcome::Invalid(invalid(reason)));
        }
        problem::ProblemBuildResult::Inconclusive { reason } => {
            return Ok(Outcome::Inconclusive(inconclusive(reason, "none")));
        }
    };

    // Load and validate an explicit hint before any local/store shortcut.  A
    // source path is only an input transport; the backend and later replay
    // receive the frozen in-memory points, never the mutable path.
    let discovery_points = match mw_points_path {
        Some(path) => match load_mw_point_file(path, &problem) {
            Ok(file) => Some(file.points().to_vec()),
            Err(error) => return Ok(Outcome::Invalid(invalid(error.to_string()))),
        },
        None => None,
    };

    let store_root = store.map(PathBuf::from).unwrap_or_else(proof_store_root);
    if store_root.join("store.json").is_file() {
        let reader = match StoreReader::open(&store_root) {
            Ok(reader) => reader,
            Err(error) => return Ok(Outcome::Operational(store_failed(error))),
        };
        if let Some(loaded) = reader
            .load_admission_for_problem(&input)
            .map_err(|error| error.to_string())?
        {
            let environment =
                if loaded.proof_kind() == &cubealqot::family::CertificateProofKind::Local {
                    "local-proof-v1"
                } else {
                    "sage-replay"
                };
            let publication = PublishedAdmission::already_committed(
                store_root.clone(),
                loaded.committed().admission_id().to_owned(),
            );
            return write_certified_artifact(
                loaded.certificate().clone(),
                input,
                environment,
                output,
                Some(&publication),
            );
        }
    }

    match search_local_certificate(&input, &problem, &(2..=16).collect::<Vec<_>>()) {
        cubealqot::family::LocalSearchResult::Found(local) => {
            let certificate = match build_local_family_certificate(&input, &problem, local) {
                Ok(certificate) => certificate,
                Err(reason) => {
                    return Ok(Outcome::Inconclusive(inconclusive(
                        reason,
                        "self-contained",
                    )));
                }
            };
            let publication = match persist_local_admission(&store_root, &certificate) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(Outcome::Operational(persistence_failed(
                        error,
                        "self-contained",
                    )));
                }
            };
            return write_certified_artifact(
                certificate,
                input,
                "local-proof-v1",
                output,
                Some(&publication),
            );
        }
        cubealqot::family::LocalSearchResult::Rejected { reason } => {
            return Ok(Outcome::Invalid(invalid(reason)));
        }
        cubealqot::family::LocalSearchResult::Inconclusive { .. } => {}
    }

    if !matches!(backend, BackendKind::Sage) {
        return Ok(Outcome::Inconclusive(inconclusive(
            "local proof did not cover this family and no backend was selected",
            "none",
        )));
    }
    let mut config = match if discovery_points.is_some() {
        SageAdapterConfig::m7_mw04_default(job_evidence_dir(output))
    } else {
        SageAdapterConfig::m7_default(job_evidence_dir(output))
    } {
        Ok(config) => config,
        Err(error) => {
            return Ok(Outcome::Inconclusive(inconclusive(
                error.to_string(),
                "backend-trusted",
            )));
        }
    };
    config.timeout = Duration::from_secs(timeout_seconds);
    let adapter = SageAdapter::new(config);
    let (completion, evidence) =
        match adapter.enumerate_with_discovery_points(&problem, discovery_points.as_deref()) {
            SageAdapterResult::Complete {
                completion,
                evidence,
            } => (completion, evidence),
            SageAdapterResult::Inconclusive { reason, .. } => {
                return Ok(Outcome::Inconclusive(inconclusive(
                    reason,
                    "backend-trusted",
                )));
            }
        };
    let certificate = match build_trusted_family_certificate(
        &input,
        &problem,
        &completion,
        SageTranscriptEvidence::from(&evidence),
    ) {
        Ok(certificate) => certificate,
        Err(reason) => {
            return Ok(Outcome::Inconclusive(inconclusive(
                reason,
                "backend-trusted",
            )));
        }
    };
    match cubealqot::family::admit_trusted_backend_certificate_with_evidence(&certificate, &adapter)
    {
        TrustedBackendAdmissionVerification::Verified(admission) => {
            let publication = match persist_trusted_backend_admission(
                &store_root,
                &certificate,
                &evidence,
                &admission,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(Outcome::Operational(persistence_failed(
                        error,
                        "backend-trusted",
                    )));
                }
            };
            write_certified_artifact(
                certificate,
                input,
                "sage-replay",
                output,
                Some(&publication),
            )
        }
        TrustedBackendAdmissionVerification::Rejected { reason } => {
            Ok(Outcome::Invalid(invalid(reason)))
        }
        TrustedBackendAdmissionVerification::Inconclusive { reason } => Ok(Outcome::Inconclusive(
            inconclusive(reason, "backend-trusted"),
        )),
    }
}

fn verify(
    path: &Path,
    backend: BackendKind,
    timeout_seconds: u64,
    store: Option<&Path>,
) -> Result<Outcome, String> {
    let (certificate, artifact) = match read_certificate_file(path) {
        Ok(value) => value,
        Err(reason) => return Ok(Outcome::Invalid(invalid(reason))),
    };
    let admission_id =
        admission_id_for_certificate(&certificate).map_err(|error| error.to_string())?;
    if let Some(store) = store {
        let reader = match StoreReader::open(store) {
            Ok(reader) => reader,
            Err(error) => return Ok(Outcome::Operational(store_failed(error))),
        };
        match reader.load_admission(&admission_id) {
            Ok(AdmissionLoad::Loaded(loaded)) => {
                return Ok(Outcome::Success(verified_json(
                    family_status(loaded.status()),
                    completeness_name(loaded.proof_kind()),
                    artifact.as_ref().map(|value| value.job_id.as_str()),
                    "loaded-admission",
                    false,
                    Some(loaded.committed().admission_id()),
                )));
            }
            Ok(AdmissionLoad::NotAdmitted) => {}
            Err(error) => return Ok(Outcome::Operational(store_failed(error))),
        }
    }
    match verify_family_certificate(&certificate) {
        CertificateVerification::Verified(value) => Ok(Outcome::Success(verified_json(
            value.status(),
            "self-contained",
            artifact.as_ref().map(|value| value.job_id.as_str()),
            "content-inspection",
            false,
            None,
        ))),
        CertificateVerification::Rejected { reason } => Ok(Outcome::Invalid(invalid(reason))),
        CertificateVerification::Inconclusive { reason } => {
            if !matches!(
                certificate.proof,
                cubealqot::family::UntrustedCompletenessProof::TrustedIntegralPoints { .. }
            ) || matches!(backend, BackendKind::None)
            {
                return Ok(Outcome::Inconclusive(inconclusive(
                    reason,
                    "backend-trusted",
                )));
            }
            let _problem = match validate_problem(&certificate.problem) {
                problem::ProblemBuildResult::Certified(problem) => problem,
                problem::ProblemBuildResult::Rejected { reason } => {
                    return Ok(Outcome::Invalid(invalid(reason)));
                }
                problem::ProblemBuildResult::Inconclusive { reason } => {
                    return Ok(Outcome::Inconclusive(inconclusive(
                        reason,
                        "backend-trusted",
                    )));
                }
            };
            let uses_mw04_helper = matches!(
                &certificate.proof,
                UntrustedCompletenessProof::TrustedIntegralPoints { backend }
                    if backend.request.discovery_points.is_some()
            );
            let mut config = match if uses_mw04_helper {
                SageAdapterConfig::m7_mw04_default(job_evidence_dir(path))
            } else {
                SageAdapterConfig::m7_default(job_evidence_dir(path))
            } {
                Ok(config) => config,
                Err(error) => {
                    return Ok(Outcome::Inconclusive(inconclusive(
                        error.to_string(),
                        "backend-trusted",
                    )));
                }
            };
            config.timeout = Duration::from_secs(timeout_seconds);
            let adapter = SageAdapter::new(config);
            match cubealqot::family::admit_trusted_backend_certificate(&certificate, &adapter) {
                CertificateVerification::Verified(value) => Ok(Outcome::Success(verified_json(
                    value.status(),
                    "backend-trusted",
                    artifact.as_ref().map(|value| value.job_id.as_str()),
                    "backend-replay",
                    true,
                    None,
                ))),
                CertificateVerification::Rejected { reason } => {
                    Ok(Outcome::Invalid(invalid(reason)))
                }
                CertificateVerification::Inconclusive { reason } => Ok(Outcome::Inconclusive(
                    inconclusive(reason, "backend-trusted"),
                )),
            }
        }
    }
}

fn export_map(
    certificates: Option<&Path>,
    store: Option<&Path>,
    admissions: Option<&str>,
    output: &Path,
) -> Result<Outcome, String> {
    match (certificates, store) {
        (Some(_), Some(_)) | (None, None) => Ok(Outcome::Invalid(invalid(
            "exactly one of --certificates or --store is required",
        ))),
        (None, Some(store)) => export_store_map(store, admissions.unwrap_or("all"), output),
        (Some(directory), None) => export_legacy_map(directory, output),
    }
}

fn export_legacy_map(directory: &Path, output: &Path) -> Result<Outcome, String> {
    if output.exists() {
        return Ok(Outcome::Invalid(invalid(
            "map snapshot already exists and is immutable",
        )));
    }
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => return Ok(Outcome::Invalid(invalid(error.to_string()))),
    };
    let mut theorem_map = TheoremMap::new();
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        let bytes = fs::read(entry.path()).map_err(|error| error.to_string())?;
        let artifact: CliArtifact = match serde_json::from_slice(&bytes) {
            Ok(artifact) => artifact,
            Err(error) => {
                return Ok(Outcome::Invalid(invalid(format!(
                    "invalid artifact: {error}"
                ))));
            }
        };
        if let Err(reason) = validate_artifact_identity(&artifact) {
            return Ok(Outcome::Invalid(invalid(reason)));
        }
        let verified = match verify_family_certificate(&artifact.certificate) {
            CertificateVerification::Verified(value) => value,
            CertificateVerification::Inconclusive { reason } => {
                return Ok(Outcome::Inconclusive(inconclusive(
                    reason,
                    "backend-trusted",
                )));
            }
            CertificateVerification::Rejected { reason } => {
                return Ok(Outcome::Invalid(invalid(reason)));
            }
        };
        if let Err(error) = theorem_map.insert_verified(&artifact.certificate, &verified) {
            return Ok(Outcome::Invalid(invalid(format!(
                "theorem-map import failed: {error:?}"
            ))));
        }
    }
    let snapshot = theorem_map.snapshot();
    let bytes = serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?;
    write_new(output, &bytes).map_err(|error| error.to_string())?;
    Ok(Outcome::Success(serde_json::json!({
        "command": "export-map",
        "status": "EXPORTED",
        "completeness": "self-contained",
        "entries": snapshot.entries().len(),
        "output": output,
    })))
}

fn store_command(command: StoreCommand) -> Result<Outcome, String> {
    match command {
        StoreCommand::InspectLegacy { source, report } => inspect_legacy(&source, &report),
        StoreCommand::ImportLegacy {
            store,
            report,
            report_digest,
            policy,
        } => import_legacy(&store, &report, &report_digest, &policy),
        StoreCommand::List { store } => list_store(&store),
        StoreCommand::Check { store } => check_store(&store),
    }
}

fn inspect_legacy(source: &Path, report: &Path) -> Result<Outcome, String> {
    let inspection = match inspect_legacy_proof_library(source) {
        Ok(value) => value,
        Err(error) => return Ok(Outcome::Operational(store_failed(error))),
    };
    let bytes =
        serialize_legacy_migration_report(&inspection.report).map_err(|error| error.to_string())?;
    if let Err(error) = write_immutable_or_same(report, &bytes) {
        return Ok(Outcome::Invalid(invalid(error.to_string())));
    }
    let incomplete_count = inspection
        .report
        .entries
        .iter()
        .filter(|entry| {
            entry.disposition == cubealqot::family::ImportDisposition::IncompleteEvidence
        })
        .count();
    Ok(Outcome::Success(serde_json::json!({
        "command": "store inspect-legacy",
        "status": "INSPECTED",
        "completeness": "historical-import-review",
        "backend_invoked": false,
        "report": report,
        "report_digest": inspection.report_digest(),
        "admitted_count": inspection.admitted_count(),
        "incomplete_count": incomplete_count,
        "entry_count": inspection.report.entries.len(),
    })))
}

fn import_legacy(
    store: &Path,
    report: &Path,
    report_digest: &str,
    policy: &str,
) -> Result<Outcome, String> {
    if policy != RECORDED_LOCAL_CAMPAIGN_POLICY_ID {
        return Ok(Outcome::Invalid(invalid(
            "unsupported legacy import policy",
        )));
    }
    let bytes = match fs::read(report) {
        Ok(bytes) => bytes,
        Err(error) => return Ok(Outcome::Invalid(invalid(error.to_string()))),
    };
    let inspection = match parse_legacy_migration_report(&bytes, report_digest) {
        Ok(value) => value,
        Err(error) => return Ok(Outcome::Invalid(invalid(error.to_string()))),
    };
    let date = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs()
        .to_string();
    let committed = match commit_legacy_proof_library(store, &inspection, &date) {
        Ok(value) => value,
        Err(error) => return Ok(Outcome::Operational(store_failed(error))),
    };
    let admitted_count = committed
        .entries
        .iter()
        .filter(|entry| entry.disposition == cubealqot::family::ImportDisposition::Admitted)
        .count();
    let incomplete_count = committed
        .entries
        .iter()
        .filter(|entry| {
            entry.disposition == cubealqot::family::ImportDisposition::IncompleteEvidence
        })
        .count();
    let value = serde_json::json!({
        "command": "store import-legacy",
        "status": if incomplete_count > 0 && admitted_count == 0 { "INCONCLUSIVE" } else { "IMPORTED" },
        "completeness": if admitted_count == 0 { "historical-import-review" } else { "backend-trusted" },
        "backend_invoked": false,
        "store": store,
        "report_digest": committed.inspection_digest,
        "admitted_count": admitted_count,
        "incomplete_count": incomplete_count,
        "entries": committed.entries,
    });
    if incomplete_count > 0 && admitted_count == 0 {
        Ok(Outcome::Inconclusive(value))
    } else {
        Ok(Outcome::Success(value))
    }
}

fn list_store(store: &Path) -> Result<Outcome, String> {
    let reader = match StoreReader::open(store) {
        Ok(reader) => reader,
        Err(error) => return Ok(Outcome::Operational(store_failed(error))),
    };
    let mut entries = Vec::new();
    for admission_id in admission_ids(store)? {
        let loaded = match reader.load_admission(&admission_id) {
            Ok(AdmissionLoad::Loaded(value)) => value,
            Ok(AdmissionLoad::NotAdmitted) => {
                return Ok(Outcome::Operational(invalid(
                    "commit disappeared during store listing",
                )));
            }
            Err(error) => return Ok(Outcome::Operational(store_failed(error))),
        };
        let record = loaded.committed().record();
        entries.push(serde_json::json!({
            "admission_id": admission_id,
            "n": loaded.n(),
            "status": status_name(family_status(loaded.status())),
            "proof_kind": loaded.proof_kind(),
            "provenance": record.provenance,
            "completeness": record.policy.completeness,
            "solution_count": loaded.solutions().len(),
            "evidence_count": record.evidence.len(),
            "certificate_digest": record.certificate.canonical_sha256,
        }));
    }
    Ok(Outcome::Success(serde_json::json!({
        "command": "store list",
        "status": "LISTED",
        "completeness": "offline-store",
        "backend_invoked": false,
        "store_id": reader.manifest().store_id,
        "entries": entries,
    })))
}

fn check_store(store: &Path) -> Result<Outcome, String> {
    let reader = match StoreReader::open(store) {
        Ok(reader) => reader,
        Err(error) => return Ok(Outcome::Operational(store_failed(error))),
    };
    let mut checked = 0usize;
    for admission_id in admission_ids(store)? {
        match reader.load_admission(&admission_id) {
            Ok(AdmissionLoad::Loaded(_)) => checked += 1,
            Ok(AdmissionLoad::NotAdmitted) => {
                return Ok(Outcome::Operational(invalid(
                    "commit disappeared during store check",
                )));
            }
            Err(cubealqot::family::PersistenceError::IncompleteEvidence { reason, .. }) => {
                return Ok(Outcome::Inconclusive(inconclusive(reason, "offline-store")));
            }
            Err(error) => return Ok(Outcome::Operational(store_failed(error))),
        }
    }
    Ok(Outcome::Success(serde_json::json!({
        "command": "store check",
        "status": "CHECKED",
        "completeness": "offline-store",
        "backend_invoked": false,
        "admission_count": checked,
    })))
}

fn export_store_map(store: &Path, selection: &str, output: &Path) -> Result<Outcome, String> {
    if output.exists() {
        return Ok(Outcome::Invalid(invalid(
            "map snapshot already exists and is immutable",
        )));
    }
    let reader = match StoreReader::open(store) {
        Ok(reader) => reader,
        Err(error) => return Ok(Outcome::Operational(store_failed(error))),
    };
    let available = admission_ids(store)?;
    let selected = if selection == "all" {
        available.clone()
    } else {
        let requested = selection
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        for id in &requested {
            if !available.iter().any(|candidate| candidate == id) {
                return Ok(Outcome::Invalid(invalid(format!(
                    "requested admission is not available: {id}"
                ))));
            }
        }
        requested
    };
    if selected.is_empty() {
        return Ok(Outcome::Invalid(invalid("admission selection is empty")));
    }
    let mut theorem_map = TheoremMap::new();
    let mut admissions = Vec::new();
    for admission_id in &selected {
        let loaded = match reader.load_admission(admission_id) {
            Ok(AdmissionLoad::Loaded(value)) => value,
            Ok(AdmissionLoad::NotAdmitted) => {
                return Ok(Outcome::Invalid(invalid(format!(
                    "requested admission is not committed: {admission_id}"
                ))));
            }
            Err(error) => return Ok(Outcome::Operational(store_failed(error))),
        };
        if let Err(error) = theorem_map.insert_persisted(&loaded) {
            return Ok(Outcome::Invalid(invalid(format!(
                "theorem-map import failed: {error:?}"
            ))));
        }
        let record = loaded.committed().record();
        admissions.push(StoreSnapshotAdmission {
            admission_id: admission_id.clone(),
            theorem: record.theorem.clone(),
            allowed_q: loaded
                .solutions()
                .iter()
                .map(|solution| solution.q.clone())
                .collect(),
            proof_kind: record.proof_kind.clone(),
            provenance: record.provenance.clone(),
            completeness: record.policy.completeness.clone(),
            certificate: record.certificate.clone(),
            evidence: record.evidence.clone(),
            backend: record.backend.clone(),
            source: record.source.clone(),
        });
    }
    let mut snapshot = StoreSnapshot {
        schema_version: cubealqot::family::STORE_SNAPSHOT_SCHEMA_VERSION,
        snapshot_id: String::new(),
        store_id: reader.manifest().store_id.clone(),
        policy_id: reader.manifest().policy.policy_id.clone(),
        rhs_version: reader.manifest().policy.rhs_version,
        admissions,
    };
    let identity_value = serde_json::to_value(&snapshot).map_err(|error| error.to_string())?;
    let identity_bytes =
        canonical_json_bytes(&identity_value).map_err(|error| error.to_string())?;
    snapshot.snapshot_id = format!("m7-snapshot-{}", sha256_hex(&identity_bytes));
    let snapshot_value = serde_json::to_value(&snapshot).map_err(|error| error.to_string())?;
    let bytes = canonical_json_bytes(&snapshot_value).map_err(|error| error.to_string())?;
    write_immutable_or_same(output, &bytes).map_err(|error| error.to_string())?;
    Ok(Outcome::Success(serde_json::json!({
        "command": "export-map",
        "status": "EXPORTED",
        "completeness": theorem_map.admitted_proof_policy(),
        "backend_invoked": false,
        "snapshot_id": snapshot.snapshot_id,
        "store_id": snapshot.store_id,
        "admissions": selected,
        "output": output,
    })))
}

fn admit(
    path: &Path,
    store: &Path,
    backend: BackendKind,
    timeout_seconds: u64,
) -> Result<Outcome, String> {
    let (certificate, _) = match read_certificate_file(path) {
        Ok(value) => value,
        Err(reason) => return Ok(Outcome::Invalid(invalid(reason))),
    };
    match &certificate.proof {
        UntrustedCompletenessProof::Local { .. } => {
            match persist_local_admission(store, &certificate) {
                Ok(publication) => Ok(Outcome::Success(serde_json::json!({
                    "command": "admit",
                    "status": status_name(family_status(&certificate.status)),
                    "completeness": "self-contained",
                    "verification": "content-inspection",
                    "backend_invoked": false,
                    "admission_id": publication.admission_id(),
                    "store_root": publication.store_root(),
                }))),
                Err(error) => Ok(Outcome::Invalid(invalid(error.to_string()))),
            }
        }
        UntrustedCompletenessProof::TrustedIntegralPoints { backend: proof } => {
            if !matches!(backend, BackendKind::Sage) {
                return Ok(Outcome::Inconclusive(inconclusive(
                    "trusted backend admission requires --backend sage",
                    "backend-trusted",
                )));
            }
            let initial = match retained_transcript(path, &proof.evidence) {
                Ok(value) => value,
                Err(reason) => {
                    return Ok(Outcome::Inconclusive(inconclusive(
                        reason,
                        "backend-trusted",
                    )));
                }
            };
            let mut config = match if proof.request.discovery_points.is_some() {
                SageAdapterConfig::m7_mw04_default(job_evidence_dir(path))
            } else {
                SageAdapterConfig::m7_default(job_evidence_dir(path))
            } {
                Ok(config) => config,
                Err(error) => {
                    return Ok(Outcome::Inconclusive(inconclusive(
                        error.to_string(),
                        "backend-trusted",
                    )));
                }
            };
            config.timeout = Duration::from_secs(timeout_seconds);
            let adapter = SageAdapter::new(config);
            match cubealqot::family::admit_trusted_backend_certificate_with_evidence(
                &certificate,
                &adapter,
            ) {
                TrustedBackendAdmissionVerification::Verified(admission) => {
                    match persist_trusted_backend_admission(
                        store,
                        &certificate,
                        &initial,
                        &admission,
                    ) {
                        Ok(publication) => Ok(Outcome::Success(serde_json::json!({
                            "command": "admit",
                            "status": status_name(family_status(&certificate.status)),
                            "completeness": "backend-trusted",
                            "verification": "backend-replay",
                            "backend_invoked": true,
                            "admission_id": publication.admission_id(),
                            "store_root": publication.store_root(),
                        }))),
                        Err(error) => Ok(Outcome::Operational(persistence_failed(
                            error,
                            "backend-trusted",
                        ))),
                    }
                }
                TrustedBackendAdmissionVerification::Rejected { reason } => {
                    Ok(Outcome::Invalid(invalid(reason)))
                }
                TrustedBackendAdmissionVerification::Inconclusive { reason } => Ok(
                    Outcome::Inconclusive(inconclusive(reason, "backend-trusted")),
                ),
            }
        }
    }
}

fn refresh(
    admission_id: &str,
    store: &Path,
    backend: BackendKind,
    timeout_seconds: u64,
) -> Result<Outcome, String> {
    if !matches!(backend, BackendKind::Sage) {
        return Ok(Outcome::Inconclusive(inconclusive(
            "trusted backend refresh requires --backend sage",
            "backend-trusted",
        )));
    }
    let reader = match StoreReader::open(store) {
        Ok(reader) => reader,
        Err(error) => return Ok(Outcome::Operational(store_failed(error))),
    };
    let loaded = match reader.load_admission(admission_id) {
        Ok(AdmissionLoad::Loaded(value)) => value,
        Ok(AdmissionLoad::NotAdmitted) => {
            return Ok(Outcome::Invalid(invalid("admission is not committed")));
        }
        Err(error) => return Ok(Outcome::Operational(store_failed(error))),
    };
    let record = loaded.committed().record();
    let Some(backend_binding) = record.backend.as_ref() else {
        return Ok(Outcome::Invalid(invalid(
            "admission is not a trusted backend theorem",
        )));
    };
    let initial = evidence_from_store(store, &backend_binding.initial)?;
    let mut config = match if matches!(
        &loaded.certificate().proof,
        UntrustedCompletenessProof::TrustedIntegralPoints { backend }
            if backend.request.discovery_points.is_some()
    ) {
        SageAdapterConfig::m7_mw04_default(store.join("refresh-evidence"))
    } else {
        SageAdapterConfig::m7_default(store.join("refresh-evidence"))
    } {
        Ok(config) => config,
        Err(error) => {
            return Ok(Outcome::Inconclusive(inconclusive(
                error.to_string(),
                "backend-trusted",
            )));
        }
    };
    config.timeout = Duration::from_secs(timeout_seconds);
    let adapter = SageAdapter::new(config);
    match cubealqot::family::admit_trusted_backend_certificate_with_evidence(
        loaded.certificate(),
        &adapter,
    ) {
        TrustedBackendAdmissionVerification::Verified(admission) => {
            match persist_trusted_backend_refresh(store, loaded.certificate(), &initial, &admission)
            {
                Ok(publication) => Ok(Outcome::Success(serde_json::json!({
                    "command": "refresh",
                    "status": "REFRESHED",
                    "completeness": "backend-trusted",
                    "verification": "backend-replay",
                    "backend_invoked": true,
                    "previous_admission_id": admission_id,
                    "admission_id": publication.admission_id(),
                    "store_root": publication.store_root(),
                }))),
                Err(error) => Ok(Outcome::Operational(persistence_failed(
                    error,
                    "backend-trusted",
                ))),
            }
        }
        TrustedBackendAdmissionVerification::Rejected { reason } => {
            Ok(Outcome::Invalid(invalid(reason)))
        }
        TrustedBackendAdmissionVerification::Inconclusive { reason } => Ok(Outcome::Inconclusive(
            inconclusive(reason, "backend-trusted"),
        )),
    }
}

fn read_certificate_file(
    path: &Path,
) -> Result<(UntrustedFamilyCertificate, Option<CliArtifact>), String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    match serde_json::from_slice::<CliArtifact>(&bytes) {
        Ok(artifact) => {
            if artifact.schema_version != CLI_ARTIFACT_SCHEMA_VERSION {
                return Err("unsupported CLI artifact schema version".to_owned());
            }
            validate_artifact_identity(&artifact)?;
            Ok((artifact.certificate.clone(), Some(artifact)))
        }
        Err(_) => parse_family_certificate(&bytes)
            .map(|certificate| (certificate, None))
            .map_err(|error| error.to_string()),
    }
}

fn retained_transcript(
    certificate_path: &Path,
    evidence: &SageTranscriptEvidence,
) -> Result<SageRunEvidence, String> {
    let directory = job_evidence_dir(certificate_path).join(&evidence.job_id);
    let value = SageRunEvidence {
        job_id: evidence.job_id.clone(),
        request_path: directory.join("request.json"),
        stdout_path: directory.join("response.json"),
        stderr_path: directory.join("backend.log"),
        request_sha256: evidence.request_sha256.clone(),
        stdout_sha256: evidence.response_sha256.clone(),
        stderr_sha256: evidence.stderr_sha256.clone(),
        exit_code: evidence.exit_code,
        timed_out: evidence.timed_out,
    };
    for path in [&value.request_path, &value.stdout_path, &value.stderr_path] {
        if !path.is_file() {
            return Err(format!(
                "retained backend transcript is missing: {}",
                path.display()
            ));
        }
    }
    Ok(value)
}

fn evidence_from_store(
    store: &Path,
    transcript: &cubealqot::family::TranscriptReference,
) -> Result<SageRunEvidence, String> {
    let object = |digest: &str| store.join("objects").join(digest);
    let value = SageRunEvidence {
        job_id: transcript.job_id.clone(),
        request_path: object(&transcript.request_sha256),
        stdout_path: object(&transcript.response_sha256),
        stderr_path: object(&transcript.stderr_sha256),
        request_sha256: transcript.request_sha256.clone(),
        stdout_sha256: transcript.response_sha256.clone(),
        stderr_sha256: transcript.stderr_sha256.clone(),
        exit_code: transcript.exit_code,
        timed_out: transcript.timed_out,
    };
    for path in [&value.request_path, &value.stdout_path, &value.stderr_path] {
        if !path.is_file() {
            return Err(format!(
                "stored backend transcript object is missing: {}",
                path.display()
            ));
        }
    }
    Ok(value)
}

fn admission_ids(store: &Path) -> Result<Vec<String>, String> {
    let directory = store.join("admissions");
    let entries = fs::read_dir(directory).map_err(|error| error.to_string())?;
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".commit.json") {
            ids.push(name.trim_end_matches(".commit.json").to_owned());
        }
    }
    ids.sort();
    Ok(ids)
}

fn write_immutable_or_same(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if path.exists() {
        return if fs::read(path)? == bytes {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "immutable output already exists with different content",
            ))
        };
    }
    write_new(path, bytes)
}

fn load_problem(n: &str, path: &Path) -> Result<UntrustedProblem, String> {
    let n = cubealqot::family::CanonicalInt::from_decimal(n)
        .map_err(|_| "N is not a canonical decimal integer".to_owned())?;
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let factors = serde_json::from_slice(&bytes)
        .map_err(|error| format!("factors file must be a JSON factor array: {error}"))?;
    Ok(UntrustedProblem { n, factors })
}

fn write_certified_artifact(
    certificate: UntrustedFamilyCertificate,
    input: UntrustedProblem,
    environment: &str,
    output: &Path,
    publication: Option<&cubealqot::family::PublishedAdmission>,
) -> Result<Outcome, String> {
    let environment_sha256 = sha256_hex(environment.as_bytes());
    let input_bytes = serde_json::to_vec(&input).map_err(|error| error.to_string())?;
    let input_sha256 = sha256_hex(&input_bytes);
    let job_id = format!(
        "m7-job-{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos(),
        format!("{}-{}", &input_sha256[..16], &environment_sha256[..16])
    );
    let artifact = CliArtifact {
        schema_version: CLI_ARTIFACT_SCHEMA_VERSION,
        job_id: job_id.clone(),
        input_sha256,
        environment_sha256,
        certificate,
    };
    let bytes = serde_json::to_vec(&artifact).map_err(|error| error.to_string())?;
    write_new(output, &bytes).map_err(|error| error.to_string())?;
    let status = match artifact.certificate.status {
        FamilyCertificateStatus::CertifiedEmpty => "CERTIFIED_EMPTY",
        FamilyCertificateStatus::CertifiedSolutions => "CERTIFIED_SOLUTIONS",
        FamilyCertificateStatus::Inconclusive => "INCONCLUSIVE",
    };
    Ok(Outcome::Success(serde_json::json!({
        "command": "prove",
        "status": status,
        "completeness": if environment == "local-proof-v1" {
            "self-contained"
        } else {
            "backend-trusted"
        },
        "job_id": job_id,
        "output": output,
        "admission_id": publication.map(|value| value.admission_id()),
        "store_root": publication.map(|value| value.store_root()),
    })))
}

fn persistence_failed(
    error: cubealqot::family::PersistenceError,
    completeness: &str,
) -> serde_json::Value {
    serde_json::json!({
        "command": "prove",
        "status": "PERSISTENCE_FAILED",
        "completeness": completeness,
        "proof_verified": true,
        "reason": error.to_string(),
    })
}

fn proof_store_root() -> PathBuf {
    std::env::var_os("CUBEALQOT_M7_PROOF_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STORE_ROOT))
}

fn validate_artifact_identity(artifact: &CliArtifact) -> Result<(), String> {
    let input_bytes =
        serde_json::to_vec(&artifact.certificate.problem).map_err(|error| error.to_string())?;
    if sha256_hex(&input_bytes) != artifact.input_sha256 {
        return Err("CLI artifact input digest does not match its problem".to_owned());
    }
    if artifact.job_id.is_empty()
        || artifact.environment_sha256.len() != 64
        || !artifact
            .environment_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("CLI artifact job/environment identity is malformed".to_owned());
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn job_evidence_dir(path: &Path) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("m7-adapter-evidence")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn status_name(status: cubealqot::family::FamilyStatus) -> &'static str {
    match status {
        cubealqot::family::FamilyStatus::CertifiedEmpty => "CERTIFIED_EMPTY",
        cubealqot::family::FamilyStatus::CertifiedSolutions => "CERTIFIED_SOLUTIONS",
        cubealqot::family::FamilyStatus::Inconclusive => "INCONCLUSIVE",
    }
}

fn verified_json(
    status: cubealqot::family::FamilyStatus,
    completeness: &'static str,
    job_id: Option<&str>,
    verification: &'static str,
    backend_invoked: bool,
    admission_id: Option<&str>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "command": "verify",
        "status": status_name(status),
        "completeness": completeness,
        "verification": verification,
        "backend_invoked": backend_invoked,
    });
    if let Some(job_id) = job_id {
        value["job_id"] = serde_json::Value::String(job_id.to_owned());
    }
    if let Some(admission_id) = admission_id {
        value["admission_id"] = serde_json::Value::String(admission_id.to_owned());
    }
    value
}

fn family_status(status: &FamilyCertificateStatus) -> cubealqot::family::FamilyStatus {
    match status {
        FamilyCertificateStatus::CertifiedEmpty => cubealqot::family::FamilyStatus::CertifiedEmpty,
        FamilyCertificateStatus::CertifiedSolutions => {
            cubealqot::family::FamilyStatus::CertifiedSolutions
        }
        FamilyCertificateStatus::Inconclusive => cubealqot::family::FamilyStatus::Inconclusive,
    }
}

fn completeness_name(kind: &cubealqot::family::CertificateProofKind) -> &'static str {
    match kind {
        cubealqot::family::CertificateProofKind::Local => "self-contained",
        cubealqot::family::CertificateProofKind::TrustedIntegralPoints => "backend-trusted",
    }
}

fn store_failed(error: cubealqot::family::PersistenceError) -> serde_json::Value {
    serde_json::json!({
        "command": "store",
        "status": "STORE_ERROR",
        "completeness": "none",
        "backend_invoked": false,
        "reason": error.to_string(),
    })
}

fn invalid(reason: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "status": "INVALID_INPUT",
        "completeness": "none",
        "reason": reason.into()
    })
}

fn inconclusive(reason: impl Into<String>, completeness: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "INCONCLUSIVE",
        "completeness": completeness,
        "reason": reason.into()
    })
}
