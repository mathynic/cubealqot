//! PP-05 historical proof-library migration.
//!
//! Migration is deliberately split into two capabilities.  Inspection reads
//! and checks the retained campaign library without writing a theorem store;
//! commit accepts only an unchanged, digest-bound inspection and publishes
//! immutable historical admissions.  Neither phase starts Sage.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::admission::{
    CertificateProofKind, CertificateVerification, FamilyCertificateStatus,
    UntrustedCompletenessProof, UntrustedFamilyCertificate, serialize_family_certificate,
    verify_persisted_complete_certificate,
};
use super::integer_io::CanonicalInt;
use super::persistence::{
    ADMISSION_SCHEMA_VERSION, AdmissionPolicy, AdmissionProvenance, AdmissionRecord,
    BackendEvidenceBinding, BackendPolicyIdentity, CompletenessTrust, ContentReference,
    ImportDisposition, PersistenceError, PointSetComparison, PublishResult,
    RECORDED_LOCAL_CAMPAIGN_POLICY_ID, SourceReference, StoreManifest, StoreObject, StoreWriter,
    TheoremBinding, TranscriptReference, canonical_json_bytes, canonical_json_identity,
    canonical_solution_set_sha256, json_content_reference, raw_content_reference,
};
use super::point_filter::{PointFilterStatus, filter_integral_points};
use super::sage::{
    SageBackendPolicy, SageRequest, SageResponse, parse_sage_response, validate_sage_response,
};

pub const LEGACY_MIGRATION_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegacyFileIdentity {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegacyTranscriptIdentity {
    pub directory: String,
    pub request: String,
    pub response: String,
    pub log: String,
    pub job_id: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub log_sha256: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegacyMigrationEntry {
    pub source_artifact: String,
    pub n: Option<CanonicalInt>,
    pub disposition: ImportDisposition,
    pub reason: String,
    pub source_artifact_sha256: Option<String>,
    pub source_artifact_canonical_sha256: Option<String>,
    pub receipt: Option<String>,
    pub receipt_sha256: Option<String>,
    pub campaign_run_id: Option<String>,
    pub campaign_job_id: Option<String>,
    pub initial_transcript: Option<LegacyTranscriptIdentity>,
    pub replay_transcript: Option<LegacyTranscriptIdentity>,
    pub run_manifest: Option<String>,
    pub certificate_solution_set_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegacyMigrationReport {
    pub schema_version: u32,
    pub migration_policy: String,
    pub source_root: String,
    pub source_manifest_sha256: String,
    pub files: Vec<LegacyFileIdentity>,
    pub entries: Vec<LegacyMigrationEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMigrationInspection {
    pub report: LegacyMigrationReport,
    digest: String,
}

impl LegacyMigrationInspection {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn report_digest(&self) -> &str {
        self.digest()
    }

    pub fn admitted_count(&self) -> usize {
        self.report
            .entries
            .iter()
            .filter(|entry| entry.disposition == ImportDisposition::Admitted)
            .count()
    }
}

pub fn serialize_legacy_migration_report(
    report: &LegacyMigrationReport,
) -> Result<Vec<u8>, PersistenceError> {
    canonical_json_bytes(&serde_json::to_value(report).map_err(|error| {
        PersistenceError::Serialization {
            reason: error.to_string(),
        }
    })?)
}

pub fn parse_legacy_migration_report(
    bytes: &[u8],
    expected_digest: &str,
) -> Result<LegacyMigrationInspection, PersistenceError> {
    let report: LegacyMigrationReport =
        serde_json::from_slice(bytes).map_err(|error| PersistenceError::Serialization {
            reason: error.to_string(),
        })?;
    let actual_digest = canonical_json_sha256_local(&report)?;
    if actual_digest != expected_digest {
        return Err(PersistenceError::IntegrityFailure {
            reason: "legacy migration report digest does not match supplied identity".to_owned(),
        });
    }
    Ok(LegacyMigrationInspection {
        report,
        digest: actual_digest,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegacyMigrationCommitEntry {
    pub n: Option<CanonicalInt>,
    pub disposition: ImportDisposition,
    pub reason: String,
    pub source_artifact_sha256: Option<String>,
    pub admission_id: Option<String>,
    pub destination_record_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LegacyMigrationCommitReport {
    pub schema_version: u32,
    pub migration_policy: String,
    pub migration_date: String,
    pub inspection_digest: String,
    pub source_manifest_sha256: String,
    pub entries: Vec<LegacyMigrationCommitEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LegacyArtifact {
    schema_version: u32,
    job_id: String,
    input_sha256: String,
    environment_sha256: String,
    certificate: UntrustedFamilyCertificate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LegacyReceipt {
    n: CanonicalInt,
    status: String,
    artifact_name: String,
    sha256: String,
    run_id: String,
}

/// Inspect the owner's retained M7 proof library.  This function is read-only
/// and never invokes Sage or writes into the proof store.
pub fn inspect_legacy_proof_library(
    source_root: &Path,
) -> Result<LegacyMigrationInspection, PersistenceError> {
    let source_root = fs::canonicalize(source_root)
        .map_err(|error| io_error("canonicalize legacy proof library", error))?;
    let files = file_manifest(&source_root)?;
    let source_manifest_sha256 = canonical_json_sha256_local(&files)?;
    let certificate_dir = source_root.join("certificates");
    let mut paths = if certificate_dir.is_dir() {
        fs::read_dir(&certificate_dir)
            .map_err(|error| io_error("read legacy certificate directory", error))?
            .filter_map(|result| result.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.is_file()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with('N') && name.ends_with(".json"))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    paths.sort();

    let entries = paths
        .iter()
        .map(|path| inspect_artifact(&source_root, path))
        .collect::<Result<Vec<_>, _>>()?;
    let report = LegacyMigrationReport {
        schema_version: LEGACY_MIGRATION_SCHEMA_VERSION,
        migration_policy: RECORDED_LOCAL_CAMPAIGN_POLICY_ID.to_owned(),
        source_root: source_root.to_string_lossy().into_owned(),
        source_manifest_sha256,
        files,
        entries,
    };
    let digest = canonical_json_sha256_local(&report)?;
    Ok(LegacyMigrationInspection { report, digest })
}

/// Commit an unchanged inspection report to the managed proof store.  The
/// `migration_date` is supplied by the explicit caller and is stored as
/// provenance metadata; it does not alter the theorem.
pub fn commit_legacy_proof_library(
    store_root: &Path,
    inspection: &LegacyMigrationInspection,
    migration_date: &str,
) -> Result<LegacyMigrationCommitReport, PersistenceError> {
    if inspection.report.schema_version != LEGACY_MIGRATION_SCHEMA_VERSION
        || inspection.report.migration_policy != RECORDED_LOCAL_CAMPAIGN_POLICY_ID
    {
        return Err(PersistenceError::UnsupportedSchema {
            kind: "legacy migration report",
            version: inspection.report.schema_version,
        });
    }
    let actual_digest = canonical_json_sha256_local(&inspection.report)?;
    if actual_digest != inspection.digest {
        return Err(PersistenceError::IntegrityFailure {
            reason: "legacy migration report was changed after inspection".to_owned(),
        });
    }
    if migration_date.trim().is_empty() {
        return Err(PersistenceError::InvalidRecord {
            reason: "migration date must be nonempty".to_owned(),
        });
    }

    let source_root = PathBuf::from(&inspection.report.source_root);
    let current_files = file_manifest(&source_root)?;
    let current_manifest = canonical_json_sha256_local(&current_files)?;
    if current_manifest != inspection.report.source_manifest_sha256
        || current_files != inspection.report.files
    {
        return Err(PersistenceError::IntegrityFailure {
            reason: "legacy proof library changed after inspection".to_owned(),
        });
    }

    let mut writer = StoreWriter::create(
        store_root,
        StoreManifest::new(
            "cubealqot-m7-proof-store-v1".to_owned(),
            crate::family::persistence::StorePolicy {
                policy_id: crate::family::persistence::PERSISTED_ADMISSION_POLICY_ID.to_owned(),
                verifier_version: 1,
                certificate_schema_version: 1,
                rhs_version: 1,
                accepted_trust: CompletenessTrust::HistoricalBackend,
                revoked_policy_ids: Vec::new(),
            },
        ),
    )?;
    let report_bytes = serialize_legacy_migration_report(&inspection.report)?;
    let report_reference = json_content_reference(&report_bytes, "application/json")?;
    let report_object = StoreObject::new(report_reference.clone(), report_bytes);

    let mut outcomes = Vec::with_capacity(inspection.report.entries.len());
    for entry in &inspection.report.entries {
        if entry.disposition != ImportDisposition::Admitted {
            outcomes.push(LegacyMigrationCommitEntry {
                n: entry.n.clone(),
                disposition: entry.disposition.clone(),
                reason: entry.reason.clone(),
                source_artifact_sha256: entry.source_artifact_sha256.clone(),
                admission_id: None,
                destination_record_sha256: None,
            });
            continue;
        }
        let (record, mut objects) = build_migrated_record(
            &source_root,
            entry,
            &inspection.report,
            &inspection.digest,
            migration_date,
            &report_reference,
        )?;
        objects.push(report_object.clone());
        let proposed_record_sha256 =
            canonical_json_identity(&serde_json::to_vec(&record).map_err(|error| {
                PersistenceError::Serialization {
                    reason: error.to_string(),
                }
            })?)?
            .raw_sha256;
        let admission_id = record.admission_id.clone();
        let publication = writer.publish_trusted_backend(&record, &objects)?;
        let (destination_record_sha256, reason) = match publication {
            PublishResult::Committed { .. } => (
                proposed_record_sha256,
                "published immutable historical admission".to_owned(),
            ),
            PublishResult::AlreadyCommitted { .. } => {
                let existing = writer
                    .reader()
                    .read_committed_record(&admission_id)?
                    .ok_or_else(|| PersistenceError::IntegrityFailure {
                        reason: "idempotent migration reported an absent committed record"
                            .to_owned(),
                    })?;
                let existing_bytes = serde_json::to_vec(&existing).map_err(|error| {
                    PersistenceError::Serialization {
                        reason: error.to_string(),
                    }
                })?;
                (
                    canonical_json_identity(&existing_bytes)?.raw_sha256,
                    "already committed immutable historical admission".to_owned(),
                )
            }
        };
        outcomes.push(LegacyMigrationCommitEntry {
            n: entry.n.clone(),
            disposition: ImportDisposition::Admitted,
            reason,
            source_artifact_sha256: entry.source_artifact_sha256.clone(),
            admission_id: Some(admission_id),
            destination_record_sha256: Some(destination_record_sha256),
        });
    }
    drop(writer);
    Ok(LegacyMigrationCommitReport {
        schema_version: LEGACY_MIGRATION_SCHEMA_VERSION,
        migration_policy: RECORDED_LOCAL_CAMPAIGN_POLICY_ID.to_owned(),
        migration_date: migration_date.to_owned(),
        inspection_digest: inspection.digest.clone(),
        source_manifest_sha256: inspection.report.source_manifest_sha256.clone(),
        entries: outcomes,
    })
}

/// Compatibility aliases matching the terminology used by the PP-05 plan.
pub fn inspect_legacy_campaigns(
    source_root: &Path,
) -> Result<LegacyMigrationInspection, PersistenceError> {
    inspect_legacy_proof_library(source_root)
}

pub fn commit_legacy_campaigns(
    store_root: &Path,
    inspection: &LegacyMigrationInspection,
    migration_date: &str,
) -> Result<LegacyMigrationCommitReport, PersistenceError> {
    commit_legacy_proof_library(store_root, inspection, migration_date)
}

fn inspect_artifact(
    source_root: &Path,
    path: &Path,
) -> Result<LegacyMigrationEntry, PersistenceError> {
    let source_artifact = relative_path(source_root, path)?;
    let bytes =
        fs::read(path).map_err(|error| io_error("read legacy certificate artifact", error))?;
    let raw_sha256 = sha256_hex(&bytes);
    let canonical_sha256 = match canonical_json_identity(&bytes) {
        Ok(identity) => identity.canonical_sha256,
        Err(error) => {
            return Ok(incomplete_entry(
                source_artifact,
                None,
                ImportDisposition::Rejected,
                format!("malformed certificate artifact: {error}"),
                Some(raw_sha256),
                None,
            ));
        }
    };
    let artifact: LegacyArtifact = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(incomplete_entry(
                source_artifact,
                None,
                ImportDisposition::Rejected,
                format!("malformed certificate artifact: {error}"),
                Some(raw_sha256),
                Some(canonical_sha256),
            ));
        }
    };
    let n = Some(artifact.certificate.problem.n.clone());
    if artifact.schema_version != 1 {
        return Ok(incomplete_entry(
            source_artifact,
            n,
            ImportDisposition::Rejected,
            format!(
                "unsupported legacy artifact schema {}",
                artifact.schema_version
            ),
            Some(raw_sha256),
            Some(canonical_sha256),
        ));
    }
    let receipt_path = source_root
        .join("receipts")
        .join(format!("N{}.json", artifact.certificate.problem.n));
    let receipt_bytes = match fs::read(&receipt_path) {
        Ok(value) => value,
        Err(_) => {
            return Ok(incomplete_entry(
                source_artifact,
                n,
                ImportDisposition::IncompleteEvidence,
                "missing receipt for certificate artifact".to_owned(),
                Some(raw_sha256),
                Some(canonical_sha256),
            ));
        }
    };
    let receipt: LegacyReceipt = match serde_json::from_slice(&receipt_bytes) {
        Ok(value) => value,
        Err(error) => {
            return Ok(incomplete_entry(
                source_artifact,
                n,
                ImportDisposition::Rejected,
                format!("malformed receipt: {error}"),
                Some(raw_sha256),
                Some(canonical_sha256),
            ));
        }
    };
    let artifact_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if receipt.n != artifact.certificate.problem.n
        || receipt.artifact_name != artifact_name
        || !receipt.sha256.eq_ignore_ascii_case(&raw_sha256)
        || receipt.status != legacy_status_name(&artifact.certificate.status)
    {
        return Ok(incomplete_entry(
            source_artifact,
            n,
            ImportDisposition::Rejected,
            "receipt does not identify this exact artifact".to_owned(),
            Some(raw_sha256),
            Some(canonical_sha256),
        ));
    }
    let event = match successful_campaign_event(source_root, artifact_name, &artifact) {
        Ok(value) => value,
        Err(reason) => {
            return Ok(incomplete_entry(
                source_artifact,
                n,
                ImportDisposition::IncompleteEvidence,
                reason,
                Some(raw_sha256),
                Some(canonical_sha256),
            ));
        }
    };
    if receipt.run_id != event.run_id || receipt.status != event.status {
        return Ok(incomplete_entry(
            source_artifact,
            n,
            ImportDisposition::Rejected,
            "receipt and successful campaign result disagree".to_owned(),
            Some(raw_sha256),
            Some(canonical_sha256),
        ));
    }
    let verified = match verify_persisted_complete_certificate(&artifact.certificate) {
        CertificateVerification::Verified(value) => value,
        CertificateVerification::Rejected { reason } => {
            return Ok(incomplete_entry(
                source_artifact,
                n,
                ImportDisposition::Rejected,
                format!("offline certificate verification rejected: {reason}"),
                Some(raw_sha256),
                Some(canonical_sha256),
            ));
        }
        CertificateVerification::Inconclusive { reason } => {
            return Ok(incomplete_entry(
                source_artifact,
                n,
                ImportDisposition::IncompleteEvidence,
                format!("offline certificate verification is inconclusive: {reason}"),
                Some(raw_sha256),
                Some(canonical_sha256),
            ));
        }
    };
    if artifact.certificate.proof_kind != CertificateProofKind::TrustedIntegralPoints {
        return Ok(incomplete_entry(
            source_artifact,
            n,
            ImportDisposition::Rejected,
            "historical migration requires the retained backend proof kind".to_owned(),
            Some(raw_sha256),
            Some(canonical_sha256),
        ));
    }
    let initial = match validate_retained_transcript(
        source_root,
        &artifact.certificate,
        verified.problem(),
        None,
    ) {
        Ok(value) => value,
        Err(reason) => {
            return Ok(incomplete_entry(
                source_artifact,
                n,
                ImportDisposition::IncompleteEvidence,
                format!("initial transcript linkage failed: {reason}"),
                Some(raw_sha256),
                Some(canonical_sha256),
            ));
        }
    };
    let replay = match find_replay_transcript(
        source_root,
        &artifact.certificate,
        verified.problem(),
        &initial,
    ) {
        Ok(value) => value,
        Err(reason) => {
            return Ok(incomplete_entry(
                source_artifact,
                n,
                ImportDisposition::IncompleteEvidence,
                format!("replay transcript linkage failed: {reason}"),
                Some(raw_sha256),
                Some(canonical_sha256),
            ));
        }
    };
    let run_manifest = relative_path(
        source_root,
        &source_root
            .join("runs")
            .join(&event.run_id)
            .join("manifest.json"),
    )
    .ok();
    let solution_set_sha256 = canonical_solution_set_sha256(&artifact.certificate.solutions)?;
    Ok(LegacyMigrationEntry {
        source_artifact,
        n,
        disposition: ImportDisposition::Admitted,
        reason:
            "offline content, initial/replay identity and recorded campaign completion verified"
                .to_owned(),
        source_artifact_sha256: Some(raw_sha256),
        source_artifact_canonical_sha256: Some(canonical_sha256),
        receipt: Some(relative_path(source_root, &receipt_path)?),
        receipt_sha256: Some(sha256_hex(&receipt_bytes)),
        campaign_run_id: Some(event.run_id),
        campaign_job_id: Some(artifact.job_id),
        initial_transcript: Some(initial),
        replay_transcript: Some(replay),
        run_manifest,
        certificate_solution_set_sha256: Some(solution_set_sha256),
    })
}

fn incomplete_entry(
    source_artifact: String,
    n: Option<CanonicalInt>,
    disposition: ImportDisposition,
    reason: String,
    source_artifact_sha256: Option<String>,
    source_artifact_canonical_sha256: Option<String>,
) -> LegacyMigrationEntry {
    LegacyMigrationEntry {
        source_artifact,
        n,
        disposition,
        reason,
        source_artifact_sha256,
        source_artifact_canonical_sha256,
        receipt: None,
        receipt_sha256: None,
        campaign_run_id: None,
        campaign_job_id: None,
        initial_transcript: None,
        replay_transcript: None,
        run_manifest: None,
        certificate_solution_set_sha256: None,
    }
}

fn successful_campaign_event(
    source_root: &Path,
    artifact_name: &str,
    artifact: &LegacyArtifact,
) -> Result<CampaignEvent, String> {
    let runs = source_root.join("runs");
    let mut matches = Vec::new();
    let entries = fs::read_dir(&runs).map_err(|error| format!("cannot read runs: {error}"))?;
    for run in entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
    {
        let results = run.join("results.jsonl");
        if !results.is_file() {
            continue;
        }
        let contents = fs::read_to_string(&results)
            .map_err(|error| format!("cannot read campaign results: {error}"))?;
        for line in contents.lines() {
            let value: Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some(result) = value.get("result") else {
                continue;
            };
            let output = result
                .get("output")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let output_matches = Path::new(output)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == artifact_name);
            let successful = value.get("exit_code").and_then(Value::as_i64) == Some(0)
                && result.get("command").and_then(Value::as_str) == Some("prove")
                && result
                    .get("status")
                    .and_then(Value::as_str)
                    .is_some_and(|status| status.starts_with("CERTIFIED_"))
                && result.get("job_id").and_then(Value::as_str) == Some(artifact.job_id.as_str())
                && output_matches;
            if successful {
                matches.push(CampaignEvent {
                    run_id: run
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default()
                        .to_owned(),
                    status: result
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                });
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(
            "no successful recorded CLI completion matches the artifact job identity".to_owned(),
        ),
        _ => Err("multiple successful recorded CLI completions match one artifact".to_owned()),
    }
}

#[derive(Clone, Debug)]
struct CampaignEvent {
    run_id: String,
    status: String,
}

fn legacy_status_name(status: &FamilyCertificateStatus) -> &'static str {
    match status {
        FamilyCertificateStatus::CertifiedEmpty => "CERTIFIED_EMPTY",
        FamilyCertificateStatus::CertifiedSolutions => "CERTIFIED_SOLUTIONS",
        FamilyCertificateStatus::Inconclusive => "INCONCLUSIVE",
    }
}

fn validate_retained_transcript(
    source_root: &Path,
    certificate: &UntrustedFamilyCertificate,
    problem: &super::problem::Problem,
    replay: Option<&LegacyTranscriptIdentity>,
) -> Result<LegacyTranscriptIdentity, String> {
    let UntrustedCompletenessProof::TrustedIntegralPoints { backend } = &certificate.proof else {
        return Err("certificate is not a trusted backend certificate".to_owned());
    };
    let expected_job = replay
        .map(|value| value.job_id.as_str())
        .unwrap_or(backend.evidence.job_id.as_str());
    let directory = source_root
        .join("certificates")
        .join("m7-adapter-evidence")
        .join(expected_job);
    let request_path = directory.join("request.json");
    let response_path = directory.join("response.json");
    let log_path = directory.join("backend.log");
    let request_bytes = fs::read(&request_path).map_err(|error| format!("request: {error}"))?;
    let response_bytes = fs::read(&response_path).map_err(|error| format!("response: {error}"))?;
    let log_bytes = fs::read(&log_path).map_err(|error| format!("backend log: {error}"))?;
    let request_sha256 = sha256_hex(&request_bytes);
    let response_sha256 = sha256_hex(&response_bytes);
    let log_sha256 = sha256_hex(&log_bytes);
    if replay.is_none()
        && (request_sha256 != backend.evidence.request_sha256
            || response_sha256 != backend.evidence.response_sha256
            || log_sha256 != backend.evidence.stderr_sha256)
    {
        return Err("initial transcript digest differs from certificate evidence".to_owned());
    }
    if let Some(expected) = replay
        && (request_sha256 != expected.request_sha256
            || response_sha256 != expected.response_sha256
            || log_sha256 != expected.log_sha256)
    {
        return Err("replay transcript digest changed after inspection".to_owned());
    }
    let request: SageRequest =
        serde_json::from_slice(&request_bytes).map_err(|error| format!("request JSON: {error}"))?;
    let response: SageResponse = parse_sage_response(&response_bytes)
        .map_err(|error| format!("response JSON: {error:?}"))?;
    let policy = policy_from_request(&request.policy);
    let completion = validate_sage_response(problem, &request, response.clone(), &policy)
        .map_err(|error| format!("backend contract: {error:?}"))?;
    if replay.is_none() {
        if backend.request != request || backend.response != response {
            return Err("retained initial request/response differs from certificate".to_owned());
        }
    } else if let Some(expected) = replay {
        if expected.job_id != request.request_id {
            return Err("replay job identity differs from request identity".to_owned());
        }
        compare_completion(problem, certificate, completion.points())?;
    }
    Ok(LegacyTranscriptIdentity {
        directory: relative_path(source_root, &directory).map_err(|error| error.to_string())?,
        request: relative_path(source_root, &request_path).map_err(|error| error.to_string())?,
        response: relative_path(source_root, &response_path).map_err(|error| error.to_string())?,
        log: relative_path(source_root, &log_path).map_err(|error| error.to_string())?,
        job_id: request.request_id,
        request_sha256,
        response_sha256,
        log_sha256,
        exit_code: if replay.is_none() {
            backend.evidence.exit_code
        } else {
            None
        },
        timed_out: false,
    })
}

fn find_replay_transcript(
    source_root: &Path,
    certificate: &UntrustedFamilyCertificate,
    problem: &super::problem::Problem,
    initial: &LegacyTranscriptIdentity,
) -> Result<LegacyTranscriptIdentity, String> {
    let directory = source_root.join("certificates").join("m7-adapter-evidence");
    let mut matches = Vec::new();
    for candidate in fs::read_dir(&directory)
        .map_err(|error| format!("cannot read adapter evidence: {error}"))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
    {
        let name = candidate
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if !name.ends_with("-1") {
            continue;
        }
        let request = candidate.join("request.json");
        let request_bytes = match fs::read(&request) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let parsed: SageRequest = match serde_json::from_slice(&request_bytes) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if parsed.problem.n != certificate.problem.n
            || parsed.policy != request_policy(certificate)?
        {
            continue;
        }
        let response_path = candidate.join("response.json");
        let log_path = candidate.join("backend.log");
        let response_bytes = match fs::read(&response_path) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let log_bytes = match fs::read(&log_path) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let job_id = parsed.request_id.clone();
        let candidate_identity = LegacyTranscriptIdentity {
            directory: relative_path(source_root, &candidate).map_err(|error| error.to_string())?,
            request: relative_path(source_root, &request).map_err(|error| error.to_string())?,
            response: relative_path(source_root, &response_path)
                .map_err(|error| error.to_string())?,
            log: relative_path(source_root, &log_path).map_err(|error| error.to_string())?,
            job_id,
            request_sha256: sha256_hex(&request_bytes),
            response_sha256: sha256_hex(&response_bytes),
            log_sha256: sha256_hex(&log_bytes),
            exit_code: None,
            timed_out: false,
        };
        if let Ok(value) = validate_retained_transcript(
            source_root,
            certificate,
            problem,
            Some(&candidate_identity),
        ) {
            if value.response_sha256 == initial.response_sha256 {
                // A response hash equal to the initial hash is not by itself
                // sufficient, but is harmless; full point-set comparison is
                // performed below and the request identity is distinct.
                matches.push(value);
            } else {
                matches.push(value);
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err("no complete matching replay transcript was retained".to_owned()),
        _ => Err("multiple matching replay transcripts are ambiguous".to_owned()),
    }
}

fn compare_completion(
    problem: &super::problem::Problem,
    certificate: &UntrustedFamilyCertificate,
    points: &[super::certificate::UntrustedIntegralPoint],
) -> Result<(), String> {
    let UntrustedCompletenessProof::TrustedIntegralPoints { backend } = &certificate.proof else {
        return Err("certificate proof kind changed".to_owned());
    };
    if canonical_points(points) != canonical_points(&backend.response.points) {
        return Err("initial and replay point sets differ".to_owned());
    }
    let filtered = filter_integral_points(problem, points);
    let PointFilterStatus::Filtered = filtered.status() else {
        return Err("replay point filtering is inconclusive".to_owned());
    };
    let keys = filtered
        .accepted()
        .iter()
        .map(|solution| (solution.q().clone(), solution.y().clone()))
        .collect::<Vec<_>>();
    let declared = certificate
        .solutions
        .iter()
        .map(|solution| (solution.q.clone(), solution.y.clone()))
        .collect::<Vec<_>>();
    if sorted_keys(keys) != sorted_keys(declared) {
        return Err("replay does not independently derive the declared S_N".to_owned());
    }
    Ok(())
}

fn build_migrated_record(
    source_root: &Path,
    entry: &LegacyMigrationEntry,
    report: &LegacyMigrationReport,
    inspection_digest: &str,
    migration_date: &str,
    report_reference: &ContentReference,
) -> Result<(AdmissionRecord, Vec<StoreObject>), PersistenceError> {
    let artifact_path = resolve_relative(source_root, &entry.source_artifact)?;
    let artifact_bytes =
        fs::read(&artifact_path).map_err(|error| io_error("read migrated artifact", error))?;
    if Some(sha256_hex(&artifact_bytes)) != entry.source_artifact_sha256 {
        return Err(PersistenceError::IntegrityFailure {
            reason: "migrated artifact changed".to_owned(),
        });
    }
    let artifact: LegacyArtifact = serde_json::from_slice(&artifact_bytes).map_err(|error| {
        PersistenceError::Serialization {
            reason: error.to_string(),
        }
    })?;
    let certificate = artifact.certificate;
    let certificate_bytes = serialize_family_certificate(&certificate).map_err(|error| {
        PersistenceError::Serialization {
            reason: error.to_string(),
        }
    })?;
    let certificate_reference =
        json_content_reference(&certificate_bytes, "application/vnd.cubealqot.family+json")?;
    let backend = match &certificate.proof {
        UntrustedCompletenessProof::TrustedIntegralPoints { backend } => backend,
        _ => {
            return Err(PersistenceError::InvalidRecord {
                reason: "historical migration requires trusted backend proof".to_owned(),
            });
        }
    };
    let initial = entry
        .initial_transcript
        .as_ref()
        .ok_or_else(|| incomplete_error("missing initial transcript"))?;
    let replay = entry
        .replay_transcript
        .as_ref()
        .ok_or_else(|| incomplete_error("missing replay transcript"))?;
    let (mut objects, initial_ref) = transcript_objects_from_identity(source_root, initial)?;
    let (replay_objects, replay_ref) = transcript_objects_from_identity(source_root, replay)?;
    objects.extend(replay_objects);
    let outer_reference = json_content_reference(&artifact_bytes, "application/json")?;
    objects.push(StoreObject::new(outer_reference, artifact_bytes));
    if let Some(receipt) = &entry.receipt {
        let bytes = fs::read(resolve_relative(source_root, receipt)?)
            .map_err(|error| io_error("read migrated receipt", error))?;
        let reference = json_content_reference(&bytes, "application/json")?;
        objects.push(StoreObject::new(reference, bytes));
    }
    if let Some(manifest) = &entry.run_manifest {
        let bytes = fs::read(resolve_relative(source_root, manifest)?)
            .map_err(|error| io_error("read migrated run manifest", error))?;
        let reference = json_content_reference(&bytes, "application/json")?;
        objects.push(StoreObject::new(reference, bytes));
    }
    let policy = BackendPolicyIdentity {
        backend_name: backend.response.backend.name.clone(),
        sage_version: backend.request.policy.sage_version.clone(),
        python_version: backend.request.policy.python_version.clone(),
        environment_manifest_sha256: None,
        helper_sha256: backend.request.policy.script_sha256.clone(),
        model_semantics: backend.request.policy.model_semantics.clone(),
        proof_settings: vec![
            "both_signs".to_owned(),
            "generators_proof".to_owned(),
            "proof_all".to_owned(),
            "rank_proof".to_owned(),
            "require_gens_certain".to_owned(),
        ],
    };
    let admission_id = format!("m7-admission-{}", sha256_hex(&certificate_bytes));
    let theorem = TheoremBinding {
        n: certificate.problem.n.clone(),
        status: certificate.status.clone(),
        proof_kind: certificate.proof_kind.clone(),
        certificate_schema_version: certificate.schema_version,
        rhs_version: certificate.rhs_version,
        raw_certificate_sha256: certificate_reference.raw_sha256.clone(),
        canonical_certificate_sha256: certificate_reference.canonical_sha256.clone(),
        solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions)?,
        solution_count: certificate.solutions.len() as u64,
    };
    let mut evidence = Vec::new();
    for object in &objects {
        if !evidence
            .iter()
            .any(|value: &ContentReference| value.object_digest == object.reference.object_digest)
        {
            evidence.push(object.reference.clone());
        }
    }
    let record = AdmissionRecord {
        schema_version: ADMISSION_SCHEMA_VERSION,
        admission_id: admission_id.clone(),
        operation_id: entry
            .campaign_job_id
            .clone()
            .ok_or_else(|| incomplete_error("missing original campaign job identity"))?,
        theorem,
        proof_kind: CertificateProofKind::TrustedIntegralPoints,
        provenance: AdmissionProvenance::MigratedRecordedLocalCampaign,
        policy: AdmissionPolicy {
            policy_id: RECORDED_LOCAL_CAMPAIGN_POLICY_ID.to_owned(),
            verifier_version: 1,
            certificate_schema_version: certificate.schema_version,
            rhs_version: certificate.rhs_version,
            completeness: CompletenessTrust::HistoricalBackend,
            backend: Some(policy.clone()),
        },
        certificate: certificate_reference.clone(),
        evidence,
        backend: Some(BackendEvidenceBinding {
            policy,
            initial: initial_ref.clone(),
            replay: replay_ref.clone(),
            point_set_sha256: backend.point_list_sha256.clone(),
            derived_solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions)?,
            comparison: PointSetComparison::Exact,
        }),
        source: Some(SourceReference {
            campaign_run_id: entry.campaign_run_id.clone(),
            receipt_sha256: entry.receipt_sha256.clone(),
            source_manifest_sha256: Some(report.source_manifest_sha256.clone()),
            initial_transcript: Some(initial_ref),
            replay_transcript: Some(replay_ref),
            campaign_output: Some(entry.source_artifact.clone()),
            migration_report: Some(report_reference.clone()),
            migration_date: Some(migration_date.to_owned()),
            migration_report_digest: Some(inspection_digest.to_owned()),
        }),
    };
    objects.push(StoreObject::new(
        certificate_reference.clone(),
        certificate_bytes,
    ));
    Ok((record, objects))
}

fn transcript_objects_from_identity(
    source_root: &Path,
    identity: &LegacyTranscriptIdentity,
) -> Result<(Vec<StoreObject>, TranscriptReference), PersistenceError> {
    let request_bytes = read_hashed(source_root, &identity.request, &identity.request_sha256)?;
    let response_bytes = read_hashed(source_root, &identity.response, &identity.response_sha256)?;
    let log_bytes = read_hashed(source_root, &identity.log, &identity.log_sha256)?;
    let request_ref = json_content_reference(&request_bytes, "application/json")?;
    let response_ref = json_content_reference(&response_bytes, "application/json")?;
    let log_ref = raw_content_reference(&log_bytes, "text/plain");
    Ok((
        vec![
            StoreObject::new(request_ref.clone(), request_bytes),
            StoreObject::new(response_ref.clone(), response_bytes),
            StoreObject::new(log_ref.clone(), log_bytes),
        ],
        TranscriptReference {
            job_id: identity.job_id.clone(),
            request_sha256: request_ref.raw_sha256,
            response_sha256: response_ref.raw_sha256,
            stderr_sha256: log_ref.raw_sha256,
            exit_code: identity.exit_code,
            timed_out: identity.timed_out,
        },
    ))
}

fn read_hashed(root: &Path, relative: &str, expected: &str) -> Result<Vec<u8>, PersistenceError> {
    let bytes = fs::read(resolve_relative(root, relative)?)
        .map_err(|error| io_error("read migrated evidence", error))?;
    if sha256_hex(&bytes) != expected {
        return Err(PersistenceError::IntegrityFailure {
            reason: format!("migrated evidence digest mismatch for {relative}"),
        });
    }
    Ok(bytes)
}

fn request_policy(
    certificate: &UntrustedFamilyCertificate,
) -> Result<super::sage::SageRequestPolicy, String> {
    let UntrustedCompletenessProof::TrustedIntegralPoints { backend } = &certificate.proof else {
        return Err("certificate is not trusted backend proof".to_owned());
    };
    Ok(backend.request.policy.clone())
}

fn policy_from_request(policy: &super::sage::SageRequestPolicy) -> SageBackendPolicy {
    SageBackendPolicy {
        distribution: policy.distribution.clone(),
        environment: policy.environment.clone(),
        conda_executable: policy.conda_executable.clone(),
        sage_version: policy.sage_version.clone(),
        python_version: policy.python_version.clone(),
        script_sha256: policy.script_sha256.clone(),
    }
}

fn canonical_points(
    points: &[super::certificate::UntrustedIntegralPoint],
) -> Vec<(CanonicalInt, CanonicalInt)> {
    let mut values = points
        .iter()
        .map(|point| (point.x.clone(), point.y.clone()))
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn sorted_keys(mut values: Vec<(CanonicalInt, CanonicalInt)>) -> Vec<(CanonicalInt, CanonicalInt)> {
    values.sort();
    values
}

fn file_manifest(root: &Path) -> Result<Vec<LegacyFileIdentity>, PersistenceError> {
    let mut paths = Vec::new();
    collect_files(root, root, &mut paths)?;
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let bytes = fs::read(root.join(&path))
                .map_err(|error| io_error("read legacy source file", error))?;
            Ok(LegacyFileIdentity {
                path,
                size: bytes.len() as u64,
                sha256: sha256_hex(&bytes),
            })
        })
        .collect()
}

fn collect_files(
    root: &Path,
    current: &Path,
    output: &mut Vec<String>,
) -> Result<(), PersistenceError> {
    for entry in
        fs::read_dir(current).map_err(|error| io_error("read legacy source directory", error))?
    {
        let path = entry
            .map_err(|error| io_error("read legacy source entry", error))?
            .path();
        if path.is_dir() {
            collect_files(root, &path, output)?;
        } else if path.is_file() {
            output.push(relative_path(root, &path)?);
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> Result<String, PersistenceError> {
    path.strip_prefix(root)
        .map_err(|_| PersistenceError::InvalidRecord {
            reason: format!("path is outside legacy root: {}", path.display()),
        })
        .map(|value| value.to_string_lossy().replace('\\', "/"))
}

fn resolve_relative(root: &Path, relative: &str) -> Result<PathBuf, PersistenceError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PersistenceError::InvalidRecord {
            reason: format!("legacy path is not relative: {relative}"),
        });
    }
    let resolved = root.join(path);
    if !resolved.starts_with(root) {
        return Err(PersistenceError::InvalidRecord {
            reason: format!("legacy path escapes source root: {relative}"),
        });
    }
    Ok(resolved)
}

fn canonical_json_sha256_local<T: Serialize>(value: &T) -> Result<String, PersistenceError> {
    let bytes = canonical_json_bytes(&serde_json::to_value(value).map_err(|error| {
        PersistenceError::Serialization {
            reason: error.to_string(),
        }
    })?)?;
    Ok(sha256_hex(&bytes))
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

fn io_error(operation: &str, error: std::io::Error) -> PersistenceError {
    PersistenceError::Io {
        operation: operation.to_owned(),
        reason: error.to_string(),
    }
}

fn incomplete_error(reason: &str) -> PersistenceError {
    PersistenceError::IncompleteEvidence {
        admission_id: "legacy-migration".to_owned(),
        reason: reason.to_owned(),
    }
}
