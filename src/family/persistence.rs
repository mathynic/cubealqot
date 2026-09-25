//! PP-01 persistence authority and wire schemas.
//!
//! This module freezes the boundary between serialized evidence and a
//! reusable theorem.  The `*Record` types are wire data and are intentionally
//! deserializable.  They never construct `CommittedAdmission` or a verified
//! theorem.  A committed admission can only be created by the later,
//! crate-internal durable-store loader after it has checked the commit marker,
//! referenced objects, exact certificate contents, and the registered local
//! authority.
//!
//! The initial authority model is deliberately narrow: an owner registers one
//! local store and its accepted policy.  The owner-controlled filesystem and
//! local writer are trusted against deliberate replacement of the whole store;
//! SHA-256 detects accidental changes and inconsistent references, but is not
//! authentication and does not prove backend enumeration completeness.
//!
//! Historical migration is an explicit provenance value.  It records that the
//! retained local campaign was accepted under the migration policy; it does
//! not turn a backend-trusted result into a self-contained proof and it does
//! not claim that Sage was just rerun.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::admission::{
    CertificateProofKind, CertificateVerification, FamilyCertificateStatus,
    TrustedBackendAdmission, UntrustedCompletenessProof, UntrustedFamilyCertificate,
    UntrustedFamilySolution, VerifiedFamilyCertificate, parse_family_certificate,
    serialize_family_certificate, verify_family_certificate, verify_persisted_complete_certificate,
};
use super::integer_io::CanonicalInt;
use super::problem::UntrustedProblem;
use super::sage::{
    SageBackendPolicy, SageRequest, SageRunEvidence, parse_sage_response, validate_sage_response,
};

pub const PERSISTENCE_SCHEMA_VERSION: u32 = 1;
pub const STORE_SCHEMA_VERSION: u32 = 1;
pub const ADMISSION_SCHEMA_VERSION: u32 = 1;
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const STORE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const IMPORT_SCHEMA_VERSION: u32 = 1;
pub const CANONICAL_JSON_ENCODING: &str = "json-sorted-keys-utf8-v1";
pub const HASH_ALGORITHM: &str = "SHA-256";
pub const DEFAULT_STORE_ROOT: &str = "out/m7-proof-store";
pub const PERSISTED_ADMISSION_POLICY_ID: &str = "cubealqot-m7-admission-v1";
pub const PERSISTED_STORE_ID: &str = "cubealqot-m7-proof-store-v1";
pub const RECORDED_LOCAL_CAMPAIGN_POLICY_ID: &str = "recorded-local-campaign-v1";
pub const SUPPORTED_VERIFIER_VERSION: u32 = 1;
pub const SUPPORTED_CERTIFICATE_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_RHS_VERSION: u32 = 1;

/// The completeness premise accepted by an admission policy.
///
/// This enum is intentionally not a public `trust_backend: bool`.  Backend
/// completeness and local admission provenance remain separate typed facts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CompletenessTrust {
    SelfContainedLocal,
    HistoricalBackend,
}

/// How the admission became eligible for the registered store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AdmissionProvenance {
    FreshLocalVerification,
    FreshBackendReplay,
    MigratedRecordedLocalCampaign,
}

/// Policy identity recorded in each immutable admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionPolicy {
    pub policy_id: String,
    pub verifier_version: u32,
    pub certificate_schema_version: u32,
    pub rhs_version: u32,
    pub completeness: CompletenessTrust,
    pub backend: Option<BackendPolicyIdentity>,
}

/// Versioned identity of the qualified backend policy.  Paths and mutable
/// process state are intentionally absent; a loader binds only to recorded
/// versions, helper identity, model semantics and proof settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendPolicyIdentity {
    pub backend_name: String,
    pub sage_version: String,
    pub python_version: String,
    pub environment_manifest_sha256: Option<String>,
    pub helper_sha256: String,
    pub model_semantics: String,
    pub proof_settings: Vec<String>,
}

/// The owner-selected policy accepted by a registered store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorePolicy {
    pub policy_id: String,
    pub verifier_version: u32,
    pub certificate_schema_version: u32,
    pub rhs_version: u32,
    pub accepted_trust: CompletenessTrust,
    pub revoked_policy_ids: Vec<String>,
}

/// Top-level store identity.  This is wire data until explicitly registered
/// by the owner through `RegisteredStore::register`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoreManifest {
    pub schema_version: u32,
    pub store_id: String,
    pub authority: String,
    pub canonical_encoding: String,
    pub hash_algorithm: String,
    pub policy: StorePolicy,
}

impl StoreManifest {
    pub fn new(store_id: String, policy: StorePolicy) -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION,
            store_id,
            authority: "trusted-local-writer-v1".to_owned(),
            canonical_encoding: CANONICAL_JSON_ENCODING.to_owned(),
            hash_algorithm: HASH_ALGORITHM.to_owned(),
            policy,
        }
    }
}

/// Exact theorem identity bound by an admission record.
///
/// The full certificate object remains the mathematical source of truth and
/// is referenced by `certificate`.  These fields make the immutable admission
/// identity explicit and let a loader reject mismatched object content before
/// it can be used by a later theorem-map builder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TheoremBinding {
    pub n: CanonicalInt,
    pub status: FamilyCertificateStatus,
    pub proof_kind: CertificateProofKind,
    pub certificate_schema_version: u32,
    pub rhs_version: u32,
    pub raw_certificate_sha256: String,
    pub canonical_certificate_sha256: String,
    pub solution_set_sha256: String,
    pub solution_count: u64,
}

/// Content-addressed reference with separate raw-byte and canonical-content
/// identities.  The raw digest detects formatting/byte changes; the canonical
/// digest identifies the parsed JSON meaning under the named encoding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContentReference {
    pub object_digest: String,
    pub raw_sha256: String,
    pub canonical_sha256: String,
    pub encoding: String,
    pub media_type: String,
}

/// Identity of an adapter transcript retained for a backend admission.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TranscriptReference {
    pub job_id: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub stderr_sha256: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PointSetComparison {
    Exact,
}

/// Backend evidence required for a trusted-completeness admission.  The
/// initial enumeration and admission replay remain separate identities, and
/// the exact point-set/derived-family comparison is retained explicitly.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackendEvidenceBinding {
    pub policy: BackendPolicyIdentity,
    pub initial: TranscriptReference,
    pub replay: TranscriptReference,
    pub point_set_sha256: String,
    pub derived_solution_set_sha256: String,
    pub comparison: PointSetComparison,
}

/// Historical campaign and receipt provenance.  Paths are descriptive only;
/// later store objects must be usable after the original campaign directory is
/// moved or unavailable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceReference {
    pub campaign_run_id: Option<String>,
    pub receipt_sha256: Option<String>,
    pub source_manifest_sha256: Option<String>,
    pub initial_transcript: Option<TranscriptReference>,
    pub replay_transcript: Option<TranscriptReference>,
    pub campaign_output: Option<String>,
    pub migration_report: Option<ContentReference>,
    /// The date supplied by the explicit historical-import commit operation.
    /// It is provenance metadata, not a mathematical premise.
    #[serde(default)]
    pub migration_date: Option<String>,
    /// Canonical digest of the offline inspection report that authorized this
    /// migration.  A source path alone is never sufficient identity.
    #[serde(default)]
    pub migration_report_digest: Option<String>,
}

/// Immutable admission record.  This is deliberately an untrusted wire type;
/// `serde_json::from_slice` can only produce this record, never a committed
/// capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionRecord {
    pub schema_version: u32,
    pub admission_id: String,
    pub operation_id: String,
    pub theorem: TheoremBinding,
    pub proof_kind: CertificateProofKind,
    pub provenance: AdmissionProvenance,
    pub policy: AdmissionPolicy,
    pub certificate: ContentReference,
    pub evidence: Vec<ContentReference>,
    pub backend: Option<BackendEvidenceBinding>,
    pub source: Option<SourceReference>,
}

/// Last-write commit marker.  PP-02 will publish this marker only after all
/// referenced objects are durable.  Deserializing it is still not enough to
/// create `CommittedAdmission`; the loader must supply the private capability.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdmissionCommitMarker {
    pub schema_version: u32,
    pub admission_id: String,
    pub record_raw_sha256: String,
    pub record_canonical_sha256: String,
}

/// Explicit immutable theorem selection.  Snapshot publication is PP-06, but
/// its identity and trust-policy fields are frozen here so later storage code
/// cannot silently invent a different authority contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotRecord {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub admission_ids: Vec<String>,
    pub theorem_map_sha256: String,
    pub policy_id: String,
    pub rhs_version: u32,
}

/// A reusable store snapshot.  This is an immutable selection record, not a
/// theorem authority by itself: runtime admission still comes from loading
/// the referenced committed records through `StoreReader`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoreSnapshot {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub store_id: String,
    pub policy_id: String,
    pub rhs_version: u32,
    pub admissions: Vec<StoreSnapshotAdmission>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StoreSnapshotAdmission {
    pub admission_id: String,
    pub theorem: TheoremBinding,
    pub allowed_q: Vec<CanonicalInt>,
    pub proof_kind: CertificateProofKind,
    pub provenance: AdmissionProvenance,
    pub completeness: CompletenessTrust,
    pub certificate: ContentReference,
    pub evidence: Vec<ContentReference>,
    pub backend: Option<BackendEvidenceBinding>,
    pub source: Option<SourceReference>,
}

/// Non-admission import outcome retained for auditability without entering the
/// admitted namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ImportDisposition {
    Admitted,
    IncompleteEvidence,
    Rejected,
    Conflicting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportRecord {
    pub schema_version: u32,
    pub import_id: String,
    pub source: String,
    pub disposition: ImportDisposition,
    pub reason: String,
}

/// Loader state.  None of these variants is a mathematical family status;
/// in particular, no state here means `CertifiedEmpty`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionLoadState {
    NotAdmitted,
    IncompleteEvidence,
    IntegrityFailure,
    UnsupportedPolicy,
    Revoked,
    Conflict,
    Loaded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistenceError {
    UnsupportedSchema {
        kind: &'static str,
        version: u32,
    },
    UnsupportedPolicy {
        policy_id: String,
    },
    InvalidManifest {
        reason: String,
    },
    InvalidRecord {
        reason: String,
    },
    Serialization {
        reason: String,
    },
    Io {
        operation: String,
        reason: String,
    },
    WriterBusy,
    InjectedFailure {
        point: FailurePoint,
    },
    MissingObject {
        digest: String,
    },
    IntegrityFailure {
        reason: String,
    },
    IncompatibleReplacement {
        admission_id: String,
    },
    IncompleteEvidence {
        admission_id: String,
        reason: String,
    },
    Revoked {
        policy_id: String,
    },
}

/// Failure boundaries used by PP-02 tests and by callers that need to model a
/// process interruption.  They are not mathematical results and must never be
/// translated into an empty theorem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailurePoint {
    BeforeObjectWrite,
    AfterObjectWrite,
    BeforeRecordPublish,
    AfterRecordPublish,
    BeforeCommitPublish,
    AfterCommitPublish,
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { kind, version } => {
                write!(formatter, "unsupported {kind} schema version {version}")
            }
            Self::UnsupportedPolicy { policy_id } => {
                write!(formatter, "unsupported admission policy {policy_id}")
            }
            Self::InvalidManifest { reason } => {
                write!(formatter, "invalid store manifest: {reason}")
            }
            Self::InvalidRecord { reason } => {
                write!(formatter, "invalid admission record: {reason}")
            }
            Self::Serialization { reason } => {
                write!(formatter, "persistence serialization error: {reason}")
            }
            Self::Io { operation, reason } => write!(formatter, "{operation}: {reason}"),
            Self::WriterBusy => write!(formatter, "proof store writer is already active"),
            Self::InjectedFailure { point } => write!(formatter, "injected failure at {point:?}"),
            Self::MissingObject { digest } => {
                write!(formatter, "missing proof-store object {digest}")
            }
            Self::IntegrityFailure { reason } => {
                write!(formatter, "proof-store integrity failure: {reason}")
            }
            Self::IncompatibleReplacement { admission_id } => {
                write!(
                    formatter,
                    "incompatible replacement for admission {admission_id}"
                )
            }
            Self::IncompleteEvidence {
                admission_id,
                reason,
            } => {
                write!(
                    formatter,
                    "admission {admission_id} has incomplete evidence: {reason}"
                )
            }
            Self::Revoked { policy_id } => {
                write!(formatter, "admission policy {policy_id} is revoked")
            }
        }
    }
}

impl std::error::Error for PersistenceError {}

/// A content-addressed object staged for publication.  `object_digest` is the
/// raw-byte SHA-256 and is therefore the filename under `objects/`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreObject {
    pub reference: ContentReference,
    pub bytes: Vec<u8>,
}

impl StoreObject {
    pub fn new(reference: ContentReference, bytes: Vec<u8>) -> Self {
        Self { reference, bytes }
    }
}

/// Build a JSON object reference using the PP-01 canonical encoding.
pub fn json_content_reference(
    bytes: &[u8],
    media_type: &str,
) -> Result<ContentReference, PersistenceError> {
    let identity = canonical_json_identity(bytes)?;
    Ok(ContentReference {
        object_digest: identity.raw_sha256.clone(),
        raw_sha256: identity.raw_sha256,
        canonical_sha256: identity.canonical_sha256,
        encoding: identity.canonical_encoding,
        media_type: media_type.to_owned(),
    })
}

/// Reference for retained non-JSON transcript content.  Raw content has no
/// parsed canonical representation, so its canonical identity is explicitly
/// the same byte digest under `raw-bytes-v1`.
pub fn raw_content_reference(bytes: &[u8], media_type: &str) -> ContentReference {
    let digest = sha256_hex(bytes);
    ContentReference {
        object_digest: digest.clone(),
        raw_sha256: digest.clone(),
        canonical_sha256: digest,
        encoding: "raw-bytes-v1".to_owned(),
        media_type: media_type.to_owned(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishResult {
    Committed { admission_id: String },
    AlreadyCommitted { admission_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedAdmission {
    result: PublishResult,
    store_root: PathBuf,
}

impl PublishedAdmission {
    /// Bind a new artifact to an admission already validated by a
    /// `StoreReader`. This carries no theorem authority by itself.
    pub fn already_committed(root: impl Into<PathBuf>, admission_id: impl Into<String>) -> Self {
        Self {
            result: PublishResult::AlreadyCommitted {
                admission_id: admission_id.into(),
            },
            store_root: root.into(),
        }
    }

    pub fn result(&self) -> &PublishResult {
        &self.result
    }

    pub fn admission_id(&self) -> &str {
        match &self.result {
            PublishResult::Committed { admission_id }
            | PublishResult::AlreadyCommitted { admission_id } => admission_id,
        }
    }

    pub fn store_root(&self) -> &Path {
        &self.store_root
    }
}

/// Publish a locally verified theorem to the managed persistent store.  The
/// certificate is rechecked at this boundary; callers cannot turn a bounded
/// result or serialized status into an admission.
pub fn persist_local_admission(
    root: &Path,
    certificate: &UntrustedFamilyCertificate,
) -> Result<PublishedAdmission, PersistenceError> {
    let verified = match verify_family_certificate(certificate) {
        CertificateVerification::Verified(value) => value,
        CertificateVerification::Rejected { reason } => {
            return Err(PersistenceError::InvalidRecord { reason });
        }
        CertificateVerification::Inconclusive { reason } => {
            return Err(PersistenceError::IncompleteEvidence {
                admission_id: admission_id_for(certificate)?,
                reason,
            });
        }
    };
    let (record, certificate_object) = local_record(certificate)?;
    if verified.problem().n() != &record.theorem.n {
        return Err(PersistenceError::IntegrityFailure {
            reason: "verified local theorem does not match publication record".to_owned(),
        });
    }
    publish_admission(root, record, vec![certificate_object])
}

/// Publish a successful trusted-backend admission together with both the
/// original and replay transcripts.  `TrustedBackendAdmission` is private-data
/// backed by the replay path, so publication cannot be requested with only a
/// backend certificate or `complete` flag.
pub fn persist_trusted_backend_admission(
    root: &Path,
    certificate: &UntrustedFamilyCertificate,
    initial_evidence: &SageRunEvidence,
    admission: &TrustedBackendAdmission,
) -> Result<PublishedAdmission, PersistenceError> {
    let verified = match verify_persisted_complete_certificate(certificate) {
        CertificateVerification::Verified(value) => value,
        CertificateVerification::Rejected { reason } => {
            return Err(PersistenceError::InvalidRecord { reason });
        }
        CertificateVerification::Inconclusive { reason } => {
            return Err(PersistenceError::IncompleteEvidence {
                admission_id: admission_id_for(certificate)?,
                reason,
            });
        }
    };
    if verified != *admission.verified() {
        return Err(PersistenceError::IntegrityFailure {
            reason: "replay admission theorem differs from persisted certificate".to_owned(),
        });
    }
    let (record, mut objects) = trusted_record(certificate, initial_evidence, admission)?;
    let (initial_objects, initial_reference) = transcript_objects(initial_evidence)?;
    let (replay_objects, replay_reference) = transcript_objects(admission.replay_evidence())?;
    objects.extend(initial_objects);
    objects.extend(replay_objects);
    if let Some(backend) = record.backend.as_ref() {
        if backend.initial != initial_reference || backend.replay != replay_reference {
            return Err(PersistenceError::IntegrityFailure {
                reason: "persisted transcript identity differs from backend certificate evidence"
                    .to_owned(),
            });
        }
    }
    publish_admission(root, record, objects)
}

/// Re-run an already admitted trusted-backend certificate explicitly.  A
/// refresh never overwrites the original admission: it receives a distinct
/// immutable identity derived from the original theorem identity and replay
/// job identity.
pub fn persist_trusted_backend_refresh(
    root: &Path,
    certificate: &UntrustedFamilyCertificate,
    initial_evidence: &SageRunEvidence,
    admission: &TrustedBackendAdmission,
) -> Result<PublishedAdmission, PersistenceError> {
    let verified = match verify_persisted_complete_certificate(certificate) {
        CertificateVerification::Verified(value) => value,
        CertificateVerification::Rejected { reason } => {
            return Err(PersistenceError::InvalidRecord { reason });
        }
        CertificateVerification::Inconclusive { reason } => {
            return Err(PersistenceError::IncompleteEvidence {
                admission_id: admission_id_for(certificate)?,
                reason,
            });
        }
    };
    if verified != *admission.verified() {
        return Err(PersistenceError::IntegrityFailure {
            reason: "refresh replay theorem differs from persisted certificate".to_owned(),
        });
    }
    let (mut record, objects) = trusted_record(certificate, initial_evidence, admission)?;
    let base_id = record.admission_id.clone();
    record.admission_id = format!(
        "{base_id}-refresh-{}",
        sha256_hex(admission.replay_evidence().job_id.as_bytes())
    );
    record.operation_id = format!("backend-refresh-{}", admission.replay_evidence().job_id);
    publish_admission(root, record, objects)
}

fn store_policy() -> StorePolicy {
    StorePolicy {
        policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
        verifier_version: 1,
        certificate_schema_version: 1,
        rhs_version: 1,
        accepted_trust: CompletenessTrust::HistoricalBackend,
        revoked_policy_ids: Vec::new(),
    }
}

pub fn admission_id_for_certificate(
    certificate: &UntrustedFamilyCertificate,
) -> Result<String, PersistenceError> {
    let bytes = serialize_family_certificate(certificate).map_err(|error| {
        PersistenceError::Serialization {
            reason: error.to_string(),
        }
    })?;
    Ok(format!("m7-admission-{}", sha256_hex(&bytes)))
}

fn admission_id_for(certificate: &UntrustedFamilyCertificate) -> Result<String, PersistenceError> {
    admission_id_for_certificate(certificate)
}

fn certificate_object(
    certificate: &UntrustedFamilyCertificate,
) -> Result<(ContentReference, StoreObject), PersistenceError> {
    let bytes = serialize_family_certificate(certificate).map_err(|error| {
        PersistenceError::Serialization {
            reason: error.to_string(),
        }
    })?;
    let reference = json_content_reference(&bytes, "application/vnd.cubealqot.family+json")?;
    Ok((reference.clone(), StoreObject::new(reference, bytes)))
}

fn theorem_binding(
    certificate: &UntrustedFamilyCertificate,
    reference: &ContentReference,
) -> Result<TheoremBinding, PersistenceError> {
    if matches!(certificate.status, FamilyCertificateStatus::Inconclusive) {
        return Err(PersistenceError::IncompleteEvidence {
            admission_id: admission_id_for(certificate)?,
            reason: "inconclusive certificates cannot be published".to_owned(),
        });
    }
    let solution_count = u64::try_from(certificate.solutions.len()).map_err(|_| {
        PersistenceError::InvalidRecord {
            reason: "solution count exceeds persisted representation".to_owned(),
        }
    })?;
    Ok(TheoremBinding {
        n: certificate.problem.n.clone(),
        status: certificate.status.clone(),
        proof_kind: certificate.proof_kind.clone(),
        certificate_schema_version: certificate.schema_version,
        rhs_version: certificate.rhs_version,
        raw_certificate_sha256: reference.raw_sha256.clone(),
        canonical_certificate_sha256: reference.canonical_sha256.clone(),
        solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions)?,
        solution_count,
    })
}

fn local_record(
    certificate: &UntrustedFamilyCertificate,
) -> Result<(AdmissionRecord, StoreObject), PersistenceError> {
    if certificate.proof_kind != CertificateProofKind::Local {
        return Err(PersistenceError::InvalidRecord {
            reason: "local publication requires a local certificate".to_owned(),
        });
    }
    let (reference, object) = certificate_object(certificate)?;
    let admission_id = admission_id_for(certificate)?;
    let theorem = theorem_binding(certificate, &reference)?;
    let record = AdmissionRecord {
        schema_version: ADMISSION_SCHEMA_VERSION,
        admission_id: admission_id.clone(),
        operation_id: format!("local-proof-{admission_id}"),
        theorem,
        proof_kind: CertificateProofKind::Local,
        provenance: AdmissionProvenance::FreshLocalVerification,
        policy: AdmissionPolicy {
            policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
            verifier_version: 1,
            certificate_schema_version: certificate.schema_version,
            rhs_version: certificate.rhs_version,
            completeness: CompletenessTrust::SelfContainedLocal,
            backend: None,
        },
        certificate: reference,
        evidence: Vec::new(),
        backend: None,
        source: None,
    };
    Ok((record, object))
}

fn backend_policy_identity(
    certificate: &UntrustedFamilyCertificate,
) -> Result<BackendPolicyIdentity, PersistenceError> {
    let UntrustedCompletenessProof::TrustedIntegralPoints { backend } = &certificate.proof else {
        return Err(PersistenceError::InvalidRecord {
            reason: "backend publication requires a trusted-integral-points certificate".to_owned(),
        });
    };
    Ok(BackendPolicyIdentity {
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
    })
}

fn trusted_record(
    certificate: &UntrustedFamilyCertificate,
    initial_evidence: &SageRunEvidence,
    admission: &TrustedBackendAdmission,
) -> Result<(AdmissionRecord, Vec<StoreObject>), PersistenceError> {
    if certificate.proof_kind != CertificateProofKind::TrustedIntegralPoints {
        return Err(PersistenceError::InvalidRecord {
            reason: "trusted publication requires a trusted certificate".to_owned(),
        });
    }
    let (certificate_reference, certificate_object) = certificate_object(certificate)?;
    let (initial_objects, initial) = transcript_objects(initial_evidence)?;
    let (replay_objects, replay) = transcript_objects(admission.replay_evidence())?;
    let backend = match &certificate.proof {
        UntrustedCompletenessProof::TrustedIntegralPoints { backend } => backend,
        UntrustedCompletenessProof::Local { .. } => unreachable!(),
    };
    let policy = backend_policy_identity(certificate)?;
    if backend.evidence.job_id != initial.job_id
        || backend.evidence.request_sha256 != initial.request_sha256
        || backend.evidence.response_sha256 != initial.response_sha256
        || backend.evidence.stderr_sha256 != initial.stderr_sha256
    {
        return Err(PersistenceError::IntegrityFailure {
            reason: "initial Sage transcript does not match the certificate evidence".to_owned(),
        });
    }
    let mut evidence = Vec::new();
    for object in initial_objects.iter().chain(replay_objects.iter()) {
        if !evidence.iter().any(|reference: &ContentReference| {
            reference.object_digest == object.reference.object_digest
        }) {
            evidence.push(object.reference.clone());
        }
    }
    let theorem = theorem_binding(certificate, &certificate_reference)?;
    let admission_id = admission_id_for(certificate)?;
    let record = AdmissionRecord {
        schema_version: ADMISSION_SCHEMA_VERSION,
        admission_id: admission_id.clone(),
        operation_id: format!("backend-replay-{admission_id}"),
        theorem,
        proof_kind: CertificateProofKind::TrustedIntegralPoints,
        provenance: AdmissionProvenance::FreshBackendReplay,
        policy: AdmissionPolicy {
            policy_id: PERSISTED_ADMISSION_POLICY_ID.to_owned(),
            verifier_version: 1,
            certificate_schema_version: certificate.schema_version,
            rhs_version: certificate.rhs_version,
            completeness: CompletenessTrust::HistoricalBackend,
            backend: Some(policy.clone()),
        },
        certificate: certificate_reference,
        evidence,
        backend: Some(BackendEvidenceBinding {
            policy,
            initial,
            replay,
            point_set_sha256: backend.point_list_sha256.clone(),
            derived_solution_set_sha256: canonical_solution_set_sha256(&certificate.solutions)?,
            comparison: PointSetComparison::Exact,
        }),
        source: None,
    };
    let mut objects = vec![certificate_object];
    objects.extend(initial_objects);
    objects.extend(replay_objects);
    Ok((record, objects))
}

fn transcript_objects(
    evidence: &SageRunEvidence,
) -> Result<(Vec<StoreObject>, TranscriptReference), PersistenceError> {
    let request = transcript_object(
        &evidence.request_path,
        evidence.request_sha256.as_str(),
        "application/json",
    )?;
    let response = transcript_object(
        &evidence.stdout_path,
        evidence.stdout_sha256.as_str(),
        "application/json",
    )?;
    let stderr = transcript_object(
        &evidence.stderr_path,
        evidence.stderr_sha256.as_str(),
        "text/plain",
    )?;
    Ok((
        vec![request.0, response.0, stderr.0],
        TranscriptReference {
            job_id: evidence.job_id.clone(),
            request_sha256: request.1.raw_sha256,
            response_sha256: response.1.raw_sha256,
            stderr_sha256: stderr.1.raw_sha256,
            exit_code: evidence.exit_code,
            timed_out: evidence.timed_out,
        },
    ))
}

fn transcript_object(
    path: &Path,
    expected_digest: &str,
    media_type: &str,
) -> Result<(StoreObject, ContentReference), PersistenceError> {
    let bytes = fs::read(path).map_err(|error| io_error("read Sage transcript", error))?;
    let reference = if media_type == "application/json" {
        json_content_reference(&bytes, media_type)?
    } else {
        raw_content_reference(&bytes, media_type)
    };
    if reference.raw_sha256 != expected_digest {
        return Err(PersistenceError::IntegrityFailure {
            reason: format!("Sage transcript digest mismatch for {}", path.display()),
        });
    }
    Ok((StoreObject::new(reference.clone(), bytes), reference))
}

fn publish_admission(
    root: &Path,
    record: AdmissionRecord,
    objects: Vec<StoreObject>,
) -> Result<PublishedAdmission, PersistenceError> {
    let mut writer = StoreWriter::create(
        root,
        StoreManifest::new(PERSISTED_STORE_ID.to_owned(), store_policy()),
    )?;
    let result = if record.proof_kind == CertificateProofKind::TrustedIntegralPoints {
        writer.publish_trusted_backend(&record, &objects)?
    } else {
        writer.publish(&record, &objects)?
    };
    drop(writer);
    Ok(PublishedAdmission {
        result,
        store_root: root.to_path_buf(),
    })
}

/// Writer ownership is represented by an exclusive create-new lock file.  A
/// writer holds it for its lifetime; readers never acquire it and never read
/// staging.  PP-02 deliberately documents the remaining filesystem limit:
/// sudden hardware loss can still defeat a platform's durability guarantees.
pub struct StoreWriter {
    root: PathBuf,
    manifest: StoreManifest,
    lock: Option<File>,
}

impl StoreWriter {
    pub fn create(root: &Path, manifest: StoreManifest) -> Result<Self, PersistenceError> {
        validate_manifest(&manifest)?;
        fs::create_dir_all(root).map_err(|error| io_error("create proof store", error))?;
        let lock_path = root.join("store.lock");
        let mut lock = match open_store_lock(&lock_path, true) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let file =
                    open_store_lock(&lock_path, false).map_err(|_| PersistenceError::WriterBusy)?;
                file
            }
            Err(error) => return Err(io_error("create proof-store lock", error)),
        };
        if let Err(error) = lock
            .try_lock_exclusive()
            .and_then(|_| lock.set_len(0))
            .and_then(|_| lock.write_all(std::process::id().to_string().as_bytes()))
            .and_then(|_| lock.sync_all())
        {
            let _ = lock.unlock();
            return Err(io_error("lock proof store", error));
        }
        let result = initialize_layout(root, &manifest);
        if let Err(error) = result {
            let _ = lock.unlock();
            return Err(error);
        }
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            lock: Some(lock),
        })
    }

    pub fn reader(&self) -> StoreReader {
        StoreReader {
            root: self.root.clone(),
            manifest: self.manifest.clone(),
        }
    }

    pub fn publish(
        &mut self,
        record: &AdmissionRecord,
        objects: &[StoreObject],
    ) -> Result<PublishResult, PersistenceError> {
        if record.proof_kind == CertificateProofKind::TrustedIntegralPoints {
            return Err(PersistenceError::InvalidRecord {
                reason: "raw trusted backend records require the validated publication path"
                    .to_owned(),
            });
        }
        self.publish_inner(record, objects, None)
    }

    /// Publish a trusted-backend record only from the crate's validated
    /// admission and migration paths.  The public wire-record writer must not
    /// be able to mint backend completeness from deserialized flags.
    pub(crate) fn publish_trusted_backend(
        &mut self,
        record: &AdmissionRecord,
        objects: &[StoreObject],
    ) -> Result<PublishResult, PersistenceError> {
        if record.proof_kind != CertificateProofKind::TrustedIntegralPoints {
            return Err(PersistenceError::InvalidRecord {
                reason: "trusted backend publication requires a trusted proof kind".to_owned(),
            });
        }
        self.publish_inner(record, objects, None)
    }

    pub fn publish_with_failure(
        &mut self,
        record: &AdmissionRecord,
        objects: &[StoreObject],
        point: FailurePoint,
    ) -> Result<PublishResult, PersistenceError> {
        self.publish_inner(record, objects, Some(point))
    }

    fn publish_inner(
        &mut self,
        record: &AdmissionRecord,
        objects: &[StoreObject],
        failure: Option<FailurePoint>,
    ) -> Result<PublishResult, PersistenceError> {
        validate_admission_schema(record).map_err(|error| PersistenceError::InvalidRecord {
            reason: error.to_string(),
        })?;
        validate_component(&record.admission_id)?;

        let admissions_dir = self.root.join("admissions");
        let commit_path = admissions_dir.join(format!("{}.commit.json", record.admission_id));
        let record_path = admissions_dir.join(format!("{}.json", record.admission_id));
        if commit_path.is_file() {
            let existing = self.reader().read_committed_record(&record.admission_id)?;
            if existing
                .as_ref()
                .is_some_and(|value| records_equivalent_for_reuse(value, record))
            {
                return Ok(PublishResult::AlreadyCommitted {
                    admission_id: record.admission_id.clone(),
                });
            }
            return Err(PersistenceError::IncompatibleReplacement {
                admission_id: record.admission_id.clone(),
            });
        }
        if record_path.is_file() {
            let existing_bytes = fs::read(&record_path)
                .map_err(|error| io_error("read existing admission", error))?;
            let existing = parse_admission_record(&existing_bytes).map_err(|error| {
                PersistenceError::IntegrityFailure {
                    reason: error.to_string(),
                }
            })?;
            if !records_equivalent_for_reuse(&existing, record) {
                return Err(PersistenceError::IncompatibleReplacement {
                    admission_id: record.admission_id.clone(),
                });
            }
        }

        let record_bytes =
            serde_json::to_vec(record).map_err(|error| PersistenceError::Serialization {
                reason: error.to_string(),
            })?;
        let record_identity = canonical_json_identity(&record_bytes)?;
        let stage_id = record_identity.canonical_sha256.clone();
        let stage_root = self.root.join("staging").join(&stage_id);
        let stage_objects = stage_root.join("objects");
        fs::create_dir_all(&stage_objects)
            .map_err(|error| io_error("create admission staging", error))?;

        let required = required_object_references(record);
        for reference in &required {
            let supplied = objects
                .iter()
                .find(|object| object.reference.object_digest == reference.object_digest);
            if let Some(object) = supplied {
                validate_store_object(object)?;
                if object.reference != **reference {
                    return Err(PersistenceError::IntegrityFailure {
                        reason: format!(
                            "supplied object reference differs for {}",
                            reference.object_digest
                        ),
                    });
                }
            }
            let stage_path = stage_objects.join(&reference.object_digest);
            let final_path = self.root.join("objects").join(&reference.object_digest);
            if stage_path.is_file() {
                if let Some(object) = supplied {
                    verify_file_bytes(&stage_path, &object.bytes, false)?;
                } else {
                    verify_object_file(&stage_path, reference)?;
                }
            } else if final_path.is_file() {
                verify_object_file(&final_path, reference)?;
            } else if let Some(object) = supplied {
                maybe_fail(failure, FailurePoint::BeforeObjectWrite)?;
                write_new_synced(&stage_path, &object.bytes)?;
                maybe_fail(failure, FailurePoint::AfterObjectWrite)?;
            } else {
                return Err(PersistenceError::MissingObject {
                    digest: reference.object_digest.clone(),
                });
            }
        }
        sync_directory(&stage_objects);

        for reference in &required {
            let stage_path = stage_objects.join(&reference.object_digest);
            let final_path = self.root.join("objects").join(&reference.object_digest);
            if stage_path.is_file() {
                publish_new_file(&stage_path, &final_path, reference)?;
            }
        }
        sync_directory(&self.root.join("objects"));

        let stage_record = stage_root.join("admission.json");
        if !stage_record.is_file() {
            write_new_synced(&stage_record, &record_bytes)?;
        } else {
            verify_file_bytes(&stage_record, &record_bytes, true)?;
        }
        maybe_fail(failure, FailurePoint::BeforeRecordPublish)?;
        publish_new_bytes(&stage_record, &record_path, &record_bytes)?;
        sync_directory(&admissions_dir);
        maybe_fail(failure, FailurePoint::AfterRecordPublish)?;

        let marker = AdmissionCommitMarker {
            schema_version: ADMISSION_SCHEMA_VERSION,
            admission_id: record.admission_id.clone(),
            record_raw_sha256: record_identity.raw_sha256,
            record_canonical_sha256: record_identity.canonical_sha256,
        };
        let marker_bytes =
            serde_json::to_vec(&marker).map_err(|error| PersistenceError::Serialization {
                reason: error.to_string(),
            })?;
        let stage_marker = stage_root.join("commit.json");
        if !stage_marker.is_file() {
            write_new_synced(&stage_marker, &marker_bytes)?;
        } else {
            verify_file_bytes(&stage_marker, &marker_bytes, true)?;
        }
        maybe_fail(failure, FailurePoint::BeforeCommitPublish)?;
        publish_new_bytes(&stage_marker, &commit_path, &marker_bytes)?;
        sync_directory(&admissions_dir);
        maybe_fail(failure, FailurePoint::AfterCommitPublish)?;

        let _ = fs::remove_dir_all(&stage_root);
        Ok(PublishResult::Committed {
            admission_id: record.admission_id.clone(),
        })
    }
}

fn open_store_lock(path: &Path, create_new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    options.open(path)
}

impl Drop for StoreWriter {
    fn drop(&mut self) {
        if let Some(lock) = self.lock.take() {
            let _ = lock.unlock();
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoreReader {
    root: PathBuf,
    manifest: StoreManifest,
}

impl StoreReader {
    pub fn open(root: &Path) -> Result<Self, PersistenceError> {
        let manifest_bytes = fs::read(root.join("store.json"))
            .map_err(|error| io_error("read proof-store manifest", error))?;
        let manifest = parse_store_manifest(&manifest_bytes)?;
        validate_manifest(&manifest)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
        })
    }

    pub fn manifest(&self) -> &StoreManifest {
        &self.manifest
    }

    pub fn read_committed_record(
        &self,
        admission_id: &str,
    ) -> Result<Option<AdmissionRecord>, PersistenceError> {
        validate_component(admission_id)?;
        let admissions = self.root.join("admissions");
        let commit_path = admissions.join(format!("{admission_id}.commit.json"));
        if !commit_path.is_file() {
            return Ok(None);
        }
        let marker_bytes = fs::read(&commit_path)
            .map_err(|error| io_error("read admission commit marker", error))?;
        let marker: AdmissionCommitMarker =
            serde_json::from_slice(&marker_bytes).map_err(|error| {
                PersistenceError::IntegrityFailure {
                    reason: format!("invalid commit marker: {error}"),
                }
            })?;
        if marker.schema_version != ADMISSION_SCHEMA_VERSION || marker.admission_id != admission_id
        {
            return Err(PersistenceError::IntegrityFailure {
                reason: "commit marker identity or schema does not match".to_owned(),
            });
        }
        let record_path = admissions.join(format!("{admission_id}.json"));
        if !record_path.is_file() {
            return Err(PersistenceError::IntegrityFailure {
                reason: "commit marker exists without its admission record".to_owned(),
            });
        }
        let record_bytes =
            fs::read(&record_path).map_err(|error| io_error("read admission record", error))?;
        let identity = canonical_json_identity(&record_bytes)?;
        if marker.record_raw_sha256 != identity.raw_sha256
            || marker.record_canonical_sha256 != identity.canonical_sha256
        {
            return Err(PersistenceError::IntegrityFailure {
                reason: "commit marker does not match admission record".to_owned(),
            });
        }
        let record = parse_admission_record(&record_bytes).map_err(|error| {
            PersistenceError::IntegrityFailure {
                reason: error.to_string(),
            }
        })?;
        validate_admission_schema(&record).map_err(|error| PersistenceError::IntegrityFailure {
            reason: error.to_string(),
        })?;
        match self.policy_state(&record.policy.policy_id) {
            AdmissionLoadState::Revoked => {
                return Err(PersistenceError::Revoked {
                    policy_id: record.policy.policy_id,
                });
            }
            AdmissionLoadState::UnsupportedPolicy => {
                return Err(PersistenceError::UnsupportedPolicy {
                    policy_id: record.policy.policy_id,
                });
            }
            _ => {}
        }
        if matches!(
            record.provenance,
            AdmissionProvenance::FreshBackendReplay
                | AdmissionProvenance::MigratedRecordedLocalCampaign
        ) && record.evidence.is_empty()
        {
            return Err(PersistenceError::IncompleteEvidence {
                admission_id: admission_id.to_owned(),
                reason: "backend provenance has no retained evidence objects".to_owned(),
            });
        }
        let references = required_object_references(&record);
        for reference in references {
            let path = self.root.join("objects").join(&reference.object_digest);
            if !path.is_file() {
                return Err(PersistenceError::MissingObject {
                    digest: reference.object_digest.clone(),
                });
            }
            verify_object_file(&path, reference)?;
        }
        Ok(Some(record))
    }

    /// Load one committed theorem and run the exact certificate verifier in
    /// this process.  A missing commit marker is `NotAdmitted`; it is never an
    /// empty theorem.  Trusted-backend certificates use the persisted
    /// completeness premise and therefore do not launch Sage or inspect the
    /// current backend installation.
    pub fn load_admission(&self, admission_id: &str) -> Result<AdmissionLoad, PersistenceError> {
        let Some(record) = self.read_committed_record(admission_id)? else {
            return Ok(AdmissionLoad::NotAdmitted);
        };
        if !accepted_policy_id(&self.manifest.policy.policy_id, &record.policy.policy_id)
            || record.policy.verifier_version != self.manifest.policy.verifier_version
            || record.policy.certificate_schema_version
                != self.manifest.policy.certificate_schema_version
            || record.policy.rhs_version != self.manifest.policy.rhs_version
            || !policy_accepts_completeness(
                &self.manifest.policy.accepted_trust,
                &record.policy.completeness,
            )
        {
            return Err(PersistenceError::UnsupportedPolicy {
                policy_id: record.policy.policy_id.clone(),
            });
        }
        let certificate_bytes = self.read_object_bytes(&record.certificate)?;
        let certificate = parse_family_certificate(&certificate_bytes).map_err(|error| {
            PersistenceError::IntegrityFailure {
                reason: format!("certificate object is not a family certificate: {error}"),
            }
        })?;
        validate_persisted_record_identity(&record, &certificate, &certificate_bytes)?;
        let verification = match record.proof_kind {
            CertificateProofKind::Local => verify_family_certificate(&certificate),
            CertificateProofKind::TrustedIntegralPoints => {
                verify_persisted_complete_certificate(&certificate)
            }
        };
        let verified = match verification {
            CertificateVerification::Verified(value) => value,
            CertificateVerification::Rejected { reason } => {
                return Err(PersistenceError::IntegrityFailure {
                    reason: format!("persisted certificate verification rejected: {reason}"),
                });
            }
            CertificateVerification::Inconclusive { reason } => {
                return Err(PersistenceError::IncompleteEvidence {
                    admission_id: admission_id.to_owned(),
                    reason,
                });
            }
        };
        if record.proof_kind == CertificateProofKind::TrustedIntegralPoints {
            validate_persisted_backend_evidence(self, &record, &certificate, &verified)?;
        }
        validate_verified_record_identity(&record, &certificate, &verified)?;
        Ok(AdmissionLoad::Loaded(LoadedAdmission {
            committed: CommittedAdmission::from_validated_record(
                self.manifest.store_id.clone(),
                record,
            ),
            certificate,
            verified,
        }))
    }

    /// Find a previously admitted completion for the exact serialized family
    /// input. Every committed entry is loaded through the normal verifier;
    /// malformed or unsupported entries are errors, never skipped as if they
    /// were absent.
    pub fn load_admission_for_problem(
        &self,
        problem: &UntrustedProblem,
    ) -> Result<Option<LoadedAdmission>, PersistenceError> {
        let admissions = self.root.join("admissions");
        let mut ids = Vec::new();
        for entry in fs::read_dir(&admissions)
            .map_err(|error| io_error("read proof-store admissions", error))?
        {
            let entry =
                entry.map_err(|error| io_error("read proof-store admission entry", error))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".commit.json") {
                ids.push(id.to_owned());
            }
        }
        ids.sort();
        let mut matching: Option<LoadedAdmission> = None;
        for id in ids {
            let AdmissionLoad::Loaded(loaded) = self.load_admission(&id)? else {
                continue;
            };
            if loaded.certificate().problem != *problem {
                continue;
            }
            if let Some(previous) = &matching {
                if previous.certificate() != loaded.certificate() {
                    return Err(PersistenceError::IntegrityFailure {
                        reason: format!("conflicting committed admissions for N={}", problem.n),
                    });
                }
            } else {
                matching = Some(loaded);
            }
        }
        Ok(matching)
    }

    fn read_object_bytes(&self, reference: &ContentReference) -> Result<Vec<u8>, PersistenceError> {
        let path = self.root.join("objects").join(&reference.object_digest);
        if !path.is_file() {
            return Err(PersistenceError::MissingObject {
                digest: reference.object_digest.clone(),
            });
        }
        let bytes = fs::read(&path).map_err(|error| io_error("read proof-store object", error))?;
        validate_store_object(&StoreObject::new(reference.clone(), bytes.clone()))?;
        Ok(bytes)
    }

    pub fn policy_state(&self, policy_id: &str) -> AdmissionLoadState {
        if self
            .manifest
            .policy
            .revoked_policy_ids
            .iter()
            .any(|value| value == policy_id)
        {
            AdmissionLoadState::Revoked
        } else if accepted_policy_id(&self.manifest.policy.policy_id, policy_id) {
            AdmissionLoadState::Loaded
        } else {
            AdmissionLoadState::UnsupportedPolicy
        }
    }
}

/// Result of the PP-03 offline loader.  `Loaded` is the only branch that
/// carries a verified certificate and committed-store capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionLoad {
    NotAdmitted,
    Loaded(LoadedAdmission),
}

/// Offline admission capability.  The constructor is private so callers
/// cannot turn an untrusted record, hash or `complete` flag into a theorem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedAdmission {
    committed: CommittedAdmission,
    certificate: UntrustedFamilyCertificate,
    verified: VerifiedFamilyCertificate,
}

impl LoadedAdmission {
    pub fn committed(&self) -> &CommittedAdmission {
        &self.committed
    }

    pub fn certificate(&self) -> &UntrustedFamilyCertificate {
        &self.certificate
    }

    pub fn n(&self) -> &CanonicalInt {
        self.verified.problem().n()
    }

    pub fn status(&self) -> &FamilyCertificateStatus {
        self.verified.certificate_status()
    }

    pub fn proof_kind(&self) -> &CertificateProofKind {
        self.verified.proof_kind()
    }

    pub fn solutions(&self) -> &[UntrustedFamilySolution] {
        self.verified.solutions()
    }

    pub(crate) fn verified(&self) -> &VerifiedFamilyCertificate {
        &self.verified
    }
}

fn required_object_references(record: &AdmissionRecord) -> Vec<&ContentReference> {
    let mut references = Vec::with_capacity(2 + record.evidence.len());
    references.push(&record.certificate);
    references.extend(record.evidence.iter());
    if let Some(reference) = record
        .source
        .as_ref()
        .and_then(|source| source.migration_report.as_ref())
    {
        references.push(reference);
    }
    references
}

fn records_equivalent_for_reuse(left: &AdmissionRecord, right: &AdmissionRecord) -> bool {
    if left == right {
        return true;
    }
    if !matches!(
        (&left.provenance, &right.provenance),
        (
            AdmissionProvenance::MigratedRecordedLocalCampaign,
            AdmissionProvenance::MigratedRecordedLocalCampaign
        )
    ) {
        return false;
    }
    let mut normalized_left = left.clone();
    let mut normalized_right = right.clone();
    if let Some(source) = normalized_left.source.as_mut() {
        source.migration_date = None;
    }
    if let Some(source) = normalized_right.source.as_mut() {
        source.migration_date = None;
    }
    normalized_left == normalized_right
}

fn initialize_layout(root: &Path, manifest: &StoreManifest) -> Result<(), PersistenceError> {
    for directory in ["objects", "admissions", "snapshots", "imports", "staging"] {
        fs::create_dir_all(root.join(directory))
            .map_err(|error| io_error("create proof-store directory", error))?;
    }
    let path = root.join("store.json");
    let expected = canonical_json_bytes(&serde_json::to_value(manifest).map_err(|error| {
        PersistenceError::Serialization {
            reason: error.to_string(),
        }
    })?)?;
    if path.is_file() {
        let existing =
            fs::read(&path).map_err(|error| io_error("read existing store manifest", error))?;
        if canonical_json_identity(&existing)?.canonical_sha256 != sha256_hex(&expected) {
            return Err(PersistenceError::IntegrityFailure {
                reason: "existing store manifest differs".to_owned(),
            });
        }
    } else {
        write_new_synced(&path, &expected)?;
        sync_directory(root);
    }
    Ok(())
}

fn validate_store_object(object: &StoreObject) -> Result<(), PersistenceError> {
    if object.reference.object_digest != object.reference.raw_sha256
        || sha256_hex(&object.bytes) != object.reference.raw_sha256
    {
        return Err(PersistenceError::IntegrityFailure {
            reason: "object bytes do not match their raw content reference".to_owned(),
        });
    }
    if object.reference.encoding == CANONICAL_JSON_ENCODING {
        let identity = canonical_json_identity(&object.bytes)?;
        if identity.canonical_sha256 != object.reference.canonical_sha256 {
            return Err(PersistenceError::IntegrityFailure {
                reason: "JSON object canonical digest does not match its reference".to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_object_file(path: &Path, reference: &ContentReference) -> Result<(), PersistenceError> {
    let bytes = fs::read(path).map_err(|error| io_error("read proof-store object", error))?;
    let object = StoreObject::new(reference.clone(), bytes);
    validate_store_object(&object)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), PersistenceError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("create staged proof-store object", error))?;
    file.write_all(bytes)
        .map_err(|error| io_error("write staged proof-store object", error))?;
    file.flush()
        .map_err(|error| io_error("flush staged proof-store object", error))?;
    file.sync_all()
        .map_err(|error| io_error("sync staged proof-store object", error))?;
    Ok(())
}

fn verify_file_bytes(
    path: &Path,
    expected: &[u8],
    allow_empty_expected: bool,
) -> Result<(), PersistenceError> {
    let actual =
        fs::read(path).map_err(|error| io_error("read staged proof-store object", error))?;
    if allow_empty_expected && expected.is_empty() {
        return Ok(());
    }
    if actual != expected {
        return Err(PersistenceError::IncompatibleReplacement {
            admission_id: path.display().to_string(),
        });
    }
    Ok(())
}

fn publish_new_file(
    stage_path: &Path,
    final_path: &Path,
    reference: &ContentReference,
) -> Result<(), PersistenceError> {
    if final_path.is_file() {
        verify_object_file(final_path, reference)?;
        fs::remove_file(stage_path)
            .map_err(|error| io_error("remove duplicate staged object", error))?;
        return Ok(());
    }
    match fs::hard_link(stage_path, final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_object_file(final_path, reference)?;
        }
        Err(error) => return Err(io_error("publish proof-store object", error)),
    }
    fs::remove_file(stage_path).map_err(|error| io_error("remove published staged object", error))
}

fn publish_new_bytes(
    stage_path: &Path,
    final_path: &Path,
    expected: &[u8],
) -> Result<(), PersistenceError> {
    if final_path.is_file() {
        verify_file_bytes(final_path, expected, false)?;
        fs::remove_file(stage_path)
            .map_err(|error| io_error("remove duplicate staged record", error))?;
        return Ok(());
    }
    match fs::hard_link(stage_path, final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_file_bytes(final_path, expected, false)?;
        }
        Err(error) => return Err(io_error("publish proof-store record", error)),
    }
    fs::remove_file(stage_path).map_err(|error| io_error("remove published staged record", error))
}

fn validate_component(value: &str) -> Result<(), PersistenceError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
    {
        return Err(PersistenceError::InvalidRecord {
            reason: "store identity contains a path separator or is empty".to_owned(),
        });
    }
    Ok(())
}

fn maybe_fail(failure: Option<FailurePoint>, point: FailurePoint) -> Result<(), PersistenceError> {
    if failure == Some(point) {
        Err(PersistenceError::InjectedFailure { point })
    } else {
        Ok(())
    }
}

fn sync_directory(path: &Path) {
    if let Ok(file) = File::open(path) {
        let _ = file.sync_all();
    }
}

fn io_error(operation: &str, error: io::Error) -> PersistenceError {
    PersistenceError::Io {
        operation: operation.to_owned(),
        reason: error.to_string(),
    }
}

/// Registered read-only view of the owner-selected store authority.
///
/// No backend launcher or theorem constructor is exposed here.  Durable
/// publication is provided separately by `StoreWriter`; this read-only view
/// never accepts staging or an uncommitted admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredStore {
    root: PathBuf,
    manifest: StoreManifest,
}

impl RegisteredStore {
    pub fn register(
        root: impl Into<PathBuf>,
        manifest: StoreManifest,
    ) -> Result<Self, PersistenceError> {
        validate_manifest(&manifest)?;
        Ok(Self {
            root: root.into(),
            manifest,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &StoreManifest {
        &self.manifest
    }

    pub fn policy_state(&self, policy_id: &str) -> AdmissionLoadState {
        if self
            .manifest
            .policy
            .revoked_policy_ids
            .iter()
            .any(|value| value == policy_id)
        {
            AdmissionLoadState::Revoked
        } else if accepted_policy_id(&self.manifest.policy.policy_id, policy_id) {
            AdmissionLoadState::Loaded
        } else {
            AdmissionLoadState::UnsupportedPolicy
        }
    }

    /// Perform only PP-01 schema/authority assessment.  A wire record can
    /// never become a loaded admission through this public method: even when a
    /// caller supplies a string pretending to be a commit marker, a valid
    /// record remains `NotAdmitted` until PP-02/PP-03 validate the real marker,
    /// object bytes and exact certificate through the private capability path.
    pub fn assess_record(
        &self,
        record: &AdmissionRecord,
        commit_marker: Option<&str>,
    ) -> AdmissionLoadState {
        if commit_marker.is_none() {
            return AdmissionLoadState::NotAdmitted;
        }
        match self.policy_state(&record.policy.policy_id) {
            AdmissionLoadState::Revoked => return AdmissionLoadState::Revoked,
            AdmissionLoadState::UnsupportedPolicy => {
                return AdmissionLoadState::UnsupportedPolicy;
            }
            AdmissionLoadState::Loaded => {}
            _ => unreachable!(),
        }
        if record.schema_version != ADMISSION_SCHEMA_VERSION {
            return AdmissionLoadState::IntegrityFailure;
        }
        if record.proof_kind != record.theorem.proof_kind {
            return AdmissionLoadState::IntegrityFailure;
        }
        if matches!(
            record.proof_kind,
            CertificateProofKind::TrustedIntegralPoints
        ) != record.backend.is_some()
        {
            return AdmissionLoadState::IntegrityFailure;
        }
        if record.backend.as_ref().map(|value| &value.policy) != record.policy.backend.as_ref() {
            return AdmissionLoadState::IntegrityFailure;
        }
        if !policy_matches_proof_kind(record) {
            return AdmissionLoadState::IntegrityFailure;
        }
        if !policy_accepts_completeness(
            &self.manifest.policy.accepted_trust,
            &record.policy.completeness,
        ) || record.policy.verifier_version != self.manifest.policy.verifier_version
            || record.policy.certificate_schema_version
                != self.manifest.policy.certificate_schema_version
            || record.policy.rhs_version != self.manifest.policy.rhs_version
        {
            return AdmissionLoadState::UnsupportedPolicy;
        }
        if matches!(
            record.provenance,
            AdmissionProvenance::FreshBackendReplay
                | AdmissionProvenance::MigratedRecordedLocalCampaign
        ) && record.evidence.is_empty()
        {
            return AdmissionLoadState::IncompleteEvidence;
        }
        AdmissionLoadState::NotAdmitted
    }
}

/// The only type that can be consumed by the later offline loader/map builder.
/// Fields and constructor are private so arbitrary JSON cannot construct it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedAdmission {
    record: AdmissionRecord,
    capability: LoadCapability,
}

impl CommittedAdmission {
    pub fn record(&self) -> &AdmissionRecord {
        &self.record
    }

    pub fn admission_id(&self) -> &str {
        &self.record.admission_id
    }

    pub fn store_id(&self) -> &str {
        &self.capability.store_id
    }

    #[allow(dead_code)]
    pub(crate) fn from_validated_record(store_id: String, record: AdmissionRecord) -> Self {
        Self {
            capability: LoadCapability {
                store_id,
                admission_id: record.admission_id.clone(),
            },
            record,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoadCapability {
    store_id: String,
    admission_id: String,
}

/// Result of hashing one JSON object.  Raw bytes and canonical content are
/// intentionally separate identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalJsonIdentity {
    pub raw_sha256: String,
    pub canonical_sha256: String,
    pub canonical_encoding: String,
}

pub fn canonical_json_identity(bytes: &[u8]) -> Result<CanonicalJsonIdentity, PersistenceError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|error| PersistenceError::Serialization {
            reason: error.to_string(),
        })?;
    let canonical = canonical_json_bytes(&value)?;
    Ok(CanonicalJsonIdentity {
        raw_sha256: sha256_hex(bytes),
        canonical_sha256: sha256_hex(&canonical),
        canonical_encoding: CANONICAL_JSON_ENCODING.to_owned(),
    })
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, PersistenceError> {
    let normalized = normalize_json(value);
    serde_json::to_vec(&normalized).map_err(|error| PersistenceError::Serialization {
        reason: error.to_string(),
    })
}

pub fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String, PersistenceError> {
    let value = serde_json::to_value(value).map_err(|error| PersistenceError::Serialization {
        reason: error.to_string(),
    })?;
    Ok(sha256_hex(&canonical_json_bytes(&value)?))
}

/// Canonical identity of the complete family solution set stored in a
/// certificate.  Ordering is normalized here so persistence cannot make
/// mathematical equality depend on backend point ordering.
pub fn canonical_solution_set_sha256(
    solutions: &[UntrustedFamilySolution],
) -> Result<String, PersistenceError> {
    let mut sorted = solutions.to_vec();
    sorted.sort_by(|left, right| {
        left.q
            .cmp(&right.q)
            .then_with(|| left.y.cmp(&right.y))
            .then_with(|| left.curve_x.cmp(&right.curve_x))
            .then_with(|| left.curve_y.cmp(&right.curve_y))
    });
    canonical_json_sha256(&sorted)
}

fn validate_persisted_record_identity(
    record: &AdmissionRecord,
    certificate: &UntrustedFamilyCertificate,
    certificate_bytes: &[u8],
) -> Result<(), PersistenceError> {
    let identity = canonical_json_identity(certificate_bytes)?;
    if identity.raw_sha256 != record.certificate.raw_sha256
        || identity.canonical_sha256 != record.certificate.canonical_sha256
    {
        return Err(PersistenceError::IntegrityFailure {
            reason: "certificate object identity differs from its admission reference".to_owned(),
        });
    }
    if certificate.schema_version != record.theorem.certificate_schema_version
        || certificate.rhs_version != record.theorem.rhs_version
        || certificate.problem.n != record.theorem.n
        || certificate.status != record.theorem.status
        || certificate.proof_kind != record.theorem.proof_kind
    {
        return Err(PersistenceError::IntegrityFailure {
            reason: "certificate content differs from its theorem binding".to_owned(),
        });
    }
    if record.policy.certificate_schema_version != certificate.schema_version
        || record.policy.rhs_version != certificate.rhs_version
    {
        return Err(PersistenceError::UnsupportedPolicy {
            policy_id: record.policy.policy_id.clone(),
        });
    }
    if let UntrustedCompletenessProof::TrustedIntegralPoints { backend } = &certificate.proof {
        let binding =
            record
                .backend
                .as_ref()
                .ok_or_else(|| PersistenceError::IncompleteEvidence {
                    admission_id: record.admission_id.clone(),
                    reason: "trusted certificate has no backend evidence binding".to_owned(),
                })?;
        let request_policy = &backend.request.policy;
        if binding.policy.backend_name != backend.response.backend.name
            || binding.policy.sage_version != request_policy.sage_version
            || binding.policy.python_version != request_policy.python_version
            || binding.policy.helper_sha256 != request_policy.script_sha256
            || binding.policy.model_semantics != request_policy.model_semantics
        {
            return Err(PersistenceError::IntegrityFailure {
                reason: "persisted backend policy differs from certificate request/response"
                    .to_owned(),
            });
        }
        let expected_proof_settings = vec![
            "both_signs".to_owned(),
            "generators_proof".to_owned(),
            "proof_all".to_owned(),
            "rank_proof".to_owned(),
            "require_gens_certain".to_owned(),
        ];
        if binding.policy.proof_settings != expected_proof_settings {
            return Err(PersistenceError::UnsupportedPolicy {
                policy_id: record.policy.policy_id.clone(),
            });
        }
        if binding.point_set_sha256 != backend.point_list_sha256 {
            return Err(PersistenceError::IntegrityFailure {
                reason: "persisted backend point-set identity differs from certificate".to_owned(),
            });
        }
        let derived = canonical_solution_set_sha256(&certificate.solutions)?;
        if binding.derived_solution_set_sha256 != derived {
            return Err(PersistenceError::IntegrityFailure {
                reason: "persisted backend derived-set identity differs from certificate"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_verified_record_identity(
    record: &AdmissionRecord,
    certificate: &UntrustedFamilyCertificate,
    verified: &VerifiedFamilyCertificate,
) -> Result<(), PersistenceError> {
    if verified.problem().n() != &record.theorem.n
        || verified.certificate_status() != &record.theorem.status
        || verified.proof_kind() != &record.theorem.proof_kind
    {
        return Err(PersistenceError::IntegrityFailure {
            reason: "verified theorem identity differs from admission record".to_owned(),
        });
    }
    let solution_count = u64::try_from(verified.solutions().len()).map_err(|_| {
        PersistenceError::IntegrityFailure {
            reason: "solution count exceeds persisted representation".to_owned(),
        }
    })?;
    let solution_digest = canonical_solution_set_sha256(verified.solutions())?;
    if solution_count != record.theorem.solution_count
        || solution_digest != record.theorem.solution_set_sha256
        || certificate.solutions.len() != verified.solutions().len()
    {
        return Err(PersistenceError::IntegrityFailure {
            reason: "verified complete solution set differs from theorem binding".to_owned(),
        });
    }
    Ok(())
}

fn validate_persisted_backend_evidence(
    reader: &StoreReader,
    record: &AdmissionRecord,
    certificate: &UntrustedFamilyCertificate,
    verified: &VerifiedFamilyCertificate,
) -> Result<(), PersistenceError> {
    let UntrustedCompletenessProof::TrustedIntegralPoints { backend } = &certificate.proof else {
        return Err(PersistenceError::IntegrityFailure {
            reason: "trusted admission record contains a non-trusted certificate".to_owned(),
        });
    };
    let binding = record
        .backend
        .as_ref()
        .ok_or_else(|| PersistenceError::IncompleteEvidence {
            admission_id: record.admission_id.clone(),
            reason: "trusted admission has no backend evidence binding".to_owned(),
        })?;
    if binding.initial != transcript_reference_from_certificate(&backend.evidence) {
        return Err(PersistenceError::IntegrityFailure {
            reason: "persisted initial transcript identity differs from certificate evidence"
                .to_owned(),
        });
    }
    validate_transcript_reference_status(record, &binding.initial, "initial")?;
    validate_transcript_reference_status(record, &binding.replay, "replay")?;

    let initial_request_bytes = evidence_bytes(reader, record, &binding.initial.request_sha256)?;
    let initial_response_bytes = evidence_bytes(reader, record, &binding.initial.response_sha256)?;
    let replay_request_bytes = evidence_bytes(reader, record, &binding.replay.request_sha256)?;
    let replay_response_bytes = evidence_bytes(reader, record, &binding.replay.response_sha256)?;
    let initial_request: SageRequest =
        serde_json::from_slice(&initial_request_bytes).map_err(|error| {
            PersistenceError::IntegrityFailure {
                reason: format!("invalid persisted initial request: {error}"),
            }
        })?;
    let replay_request: SageRequest =
        serde_json::from_slice(&replay_request_bytes).map_err(|error| {
            PersistenceError::IntegrityFailure {
                reason: format!("invalid persisted replay request: {error}"),
            }
        })?;
    let initial_response = parse_sage_response(&initial_response_bytes).map_err(|error| {
        PersistenceError::IntegrityFailure {
            reason: format!("invalid persisted initial response: {error:?}"),
        }
    })?;
    let replay_response = parse_sage_response(&replay_response_bytes).map_err(|error| {
        PersistenceError::IntegrityFailure {
            reason: format!("invalid persisted replay response: {error:?}"),
        }
    })?;
    if initial_request != backend.request || initial_response != backend.response {
        return Err(PersistenceError::IntegrityFailure {
            reason: "persisted initial transcript does not match certificate request/response"
                .to_owned(),
        });
    }
    if initial_request.request_id != binding.initial.job_id
        || replay_request.request_id != binding.replay.job_id
    {
        return Err(PersistenceError::IntegrityFailure {
            reason: "transcript job identity does not match its request object".to_owned(),
        });
    }
    let policy = backend_policy_from_request(&backend.request);
    validate_sage_response(
        verified.problem(),
        &initial_request,
        initial_response,
        &policy,
    )
    .map_err(|error| PersistenceError::IntegrityFailure {
        reason: format!("persisted initial transcript failed backend validation: {error:?}"),
    })?;
    let replay_completion = validate_sage_response(
        verified.problem(),
        &replay_request,
        replay_response,
        &policy,
    )
    .map_err(|error| PersistenceError::IntegrityFailure {
        reason: format!("persisted replay transcript failed backend validation: {error:?}"),
    })?;
    let mut expected_points = backend.response.points.clone();
    let mut replay_points = replay_completion.points().to_vec();
    sort_persisted_points(&mut expected_points);
    sort_persisted_points(&mut replay_points);
    if expected_points != replay_points {
        return Err(PersistenceError::IntegrityFailure {
            reason: "persisted replay point set differs from certificate".to_owned(),
        });
    }
    Ok(())
}

fn evidence_bytes(
    reader: &StoreReader,
    record: &AdmissionRecord,
    raw_sha256: &str,
) -> Result<Vec<u8>, PersistenceError> {
    let reference = record
        .evidence
        .iter()
        .find(|reference| reference.raw_sha256 == raw_sha256)
        .ok_or_else(|| PersistenceError::IncompleteEvidence {
            admission_id: record.admission_id.clone(),
            reason: format!("retained transcript object is missing: {raw_sha256}"),
        })?;
    reader.read_object_bytes(reference)
}

fn validate_transcript_reference_status(
    record: &AdmissionRecord,
    reference: &TranscriptReference,
    label: &str,
) -> Result<(), PersistenceError> {
    if reference.timed_out || reference.exit_code.is_some_and(|code| code != 0) {
        return Err(PersistenceError::IncompleteEvidence {
            admission_id: record.admission_id.clone(),
            reason: format!("persisted {label} transcript did not terminate successfully"),
        });
    }
    if reference.exit_code.is_none()
        && record.provenance != AdmissionProvenance::MigratedRecordedLocalCampaign
    {
        return Err(PersistenceError::IncompleteEvidence {
            admission_id: record.admission_id.clone(),
            reason: format!("persisted {label} transcript has no exit status"),
        });
    }
    Ok(())
}

fn transcript_reference_from_certificate(
    evidence: &super::admission::SageTranscriptEvidence,
) -> TranscriptReference {
    TranscriptReference {
        job_id: evidence.job_id.clone(),
        request_sha256: evidence.request_sha256.clone(),
        response_sha256: evidence.response_sha256.clone(),
        stderr_sha256: evidence.stderr_sha256.clone(),
        exit_code: evidence.exit_code,
        timed_out: evidence.timed_out,
    }
}

fn backend_policy_from_request(request: &SageRequest) -> SageBackendPolicy {
    SageBackendPolicy {
        distribution: request.policy.distribution.clone(),
        environment: request.policy.environment.clone(),
        conda_executable: request.policy.conda_executable.clone(),
        sage_version: request.policy.sage_version.clone(),
        python_version: request.policy.python_version.clone(),
        script_sha256: request.policy.script_sha256.clone(),
    }
}

fn sort_persisted_points(points: &mut [super::certificate::UntrustedIntegralPoint]) {
    points.sort_by(|left, right| left.x.cmp(&right.x).then_with(|| left.y.cmp(&right.y)));
}

pub fn parse_store_manifest(bytes: &[u8]) -> Result<StoreManifest, PersistenceError> {
    serde_json::from_slice(bytes).map_err(|error| PersistenceError::Serialization {
        reason: error.to_string(),
    })
}

pub fn parse_admission_record(bytes: &[u8]) -> Result<AdmissionRecord, PersistenceError> {
    serde_json::from_slice(bytes).map_err(|error| PersistenceError::Serialization {
        reason: error.to_string(),
    })
}

pub fn validate_manifest(manifest: &StoreManifest) -> Result<(), PersistenceError> {
    if manifest.schema_version != STORE_SCHEMA_VERSION {
        return Err(PersistenceError::UnsupportedSchema {
            kind: "store",
            version: manifest.schema_version,
        });
    }
    if manifest.authority != "trusted-local-writer-v1" {
        return Err(PersistenceError::InvalidManifest {
            reason: "only the registered trusted-local-writer-v1 authority is supported".to_owned(),
        });
    }
    if manifest.canonical_encoding != CANONICAL_JSON_ENCODING {
        return Err(PersistenceError::InvalidManifest {
            reason: "canonical JSON encoding does not match the supported version".to_owned(),
        });
    }
    if manifest.hash_algorithm != HASH_ALGORITHM {
        return Err(PersistenceError::InvalidManifest {
            reason: "hash algorithm does not match the supported version".to_owned(),
        });
    }
    if manifest.store_id.is_empty() || manifest.policy.policy_id.is_empty() {
        return Err(PersistenceError::InvalidManifest {
            reason: "store and policy identities must be non-empty".to_owned(),
        });
    }
    if manifest.policy.verifier_version != SUPPORTED_VERIFIER_VERSION
        || manifest.policy.certificate_schema_version != SUPPORTED_CERTIFICATE_SCHEMA_VERSION
        || manifest.policy.rhs_version != SUPPORTED_RHS_VERSION
    {
        return Err(PersistenceError::UnsupportedPolicy {
            policy_id: manifest.policy.policy_id.clone(),
        });
    }
    Ok(())
}

pub fn validate_admission_schema(record: &AdmissionRecord) -> Result<(), PersistenceError> {
    if record.schema_version != ADMISSION_SCHEMA_VERSION {
        return Err(PersistenceError::UnsupportedSchema {
            kind: "admission",
            version: record.schema_version,
        });
    }
    if record.policy.verifier_version != SUPPORTED_VERIFIER_VERSION
        || record.policy.certificate_schema_version != SUPPORTED_CERTIFICATE_SCHEMA_VERSION
        || record.policy.rhs_version != SUPPORTED_RHS_VERSION
    {
        return Err(PersistenceError::UnsupportedPolicy {
            policy_id: record.policy.policy_id.clone(),
        });
    }
    if record.theorem.certificate_schema_version != record.policy.certificate_schema_version
        || record.theorem.rhs_version != record.policy.rhs_version
    {
        return Err(PersistenceError::InvalidRecord {
            reason: "theorem schema/RHS versions differ from admission policy".to_owned(),
        });
    }
    if record.theorem.raw_certificate_sha256 != record.certificate.raw_sha256
        || record.theorem.canonical_certificate_sha256 != record.certificate.canonical_sha256
    {
        return Err(PersistenceError::InvalidRecord {
            reason: "theorem certificate identities differ from certificate object reference"
                .to_owned(),
        });
    }
    if record.proof_kind != record.theorem.proof_kind {
        return Err(PersistenceError::InvalidRecord {
            reason: "proof kind differs from theorem binding".to_owned(),
        });
    }
    if matches!(
        record.proof_kind,
        CertificateProofKind::TrustedIntegralPoints
    ) != record.backend.is_some()
    {
        return Err(PersistenceError::InvalidRecord {
            reason: "trusted backend proof requires exactly one backend evidence binding"
                .to_owned(),
        });
    }
    if record.backend.as_ref().map(|value| &value.policy) != record.policy.backend.as_ref() {
        return Err(PersistenceError::InvalidRecord {
            reason: "backend evidence policy differs from admission policy".to_owned(),
        });
    }
    if !policy_matches_proof_kind(record) {
        return Err(PersistenceError::InvalidRecord {
            reason: "completeness trust does not match proof kind".to_owned(),
        });
    }
    Ok(())
}

fn policy_matches_proof_kind(record: &AdmissionRecord) -> bool {
    match record.proof_kind {
        CertificateProofKind::Local => {
            matches!(
                record.policy.completeness,
                CompletenessTrust::SelfContainedLocal
            ) && record.backend.is_none()
        }
        CertificateProofKind::TrustedIntegralPoints => {
            matches!(
                record.policy.completeness,
                CompletenessTrust::HistoricalBackend
            ) && record.backend.is_some()
        }
    }
}

/// `HistoricalBackend` is the managed-store policy that can retain both
/// backend-trusted historical admissions and stronger self-contained local
/// admissions.  A local-only policy remains strict.  This lets the default
/// PP-04 store persist both successful proving paths without weakening the
/// trust label carried by an individual record.
fn policy_accepts_completeness(accepted: &CompletenessTrust, actual: &CompletenessTrust) -> bool {
    matches!(
        (accepted, actual),
        (
            CompletenessTrust::SelfContainedLocal,
            CompletenessTrust::SelfContainedLocal
        ) | (
            CompletenessTrust::HistoricalBackend,
            CompletenessTrust::HistoricalBackend
        ) | (
            CompletenessTrust::HistoricalBackend,
            CompletenessTrust::SelfContainedLocal
        )
    )
}

/// The default historical store accepts the explicit legacy-campaign import
/// policy in addition to its normal PP-04 policy.  This is an allow-list, not
/// a wildcard: arbitrary record policy names remain unsupported.
fn accepted_policy_id(store_policy_id: &str, record_policy_id: &str) -> bool {
    store_policy_id == PERSISTED_ADMISSION_POLICY_ID
        && matches!(
            record_policy_id,
            PERSISTED_ADMISSION_POLICY_ID | RECORDED_LOCAL_CAMPAIGN_POLICY_ID
        )
}

/// Detect incompatible complete records for one N.  Identical mathematical
/// content may have multiple evidence records; different solution identities
/// are a conflict and must not be silently selected.
pub fn conflict_state(records: &[AdmissionRecord]) -> AdmissionLoadState {
    for (index, left) in records.iter().enumerate() {
        for right in records.iter().skip(index + 1) {
            if left.theorem.n == right.theorem.n
                && (left.theorem.solution_set_sha256 != right.theorem.solution_set_sha256
                    || left.theorem.status != right.theorem.status)
            {
                return AdmissionLoadState::Conflict;
            }
        }
    }
    AdmissionLoadState::Loaded
}

fn normalize_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in object {
                sorted.insert(key.clone(), normalize_json(value));
            }
            let mut normalized = Map::new();
            for (key, value) in sorted {
                normalized.insert(key, value);
            }
            Value::Object(normalized)
        }
        Value::Array(values) => Value::Array(values.iter().map(normalize_json).collect()),
        other => other.clone(),
    }
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
