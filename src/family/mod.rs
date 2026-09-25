//! Independent family-proof subsystem.
//!
//! This namespace is intentionally separate from the native search pipeline.
//! Its boundary types preserve uncertainty until a later, independently
//! qualified verifier can establish a theorem.

pub mod admission;
pub mod bounded;
pub mod certificate;
pub mod integer_io;
pub mod local;
pub mod local_certificate;
pub mod migration;
pub mod mw_points;
pub mod oracle;
pub mod persistence;
pub mod pocklington;
pub mod point_filter;
pub mod primality;
pub mod problem;
pub mod sage;
pub mod theorem_map;

pub use admission::{
    CertificateProofKind, CertificateVerification, FamilyCertificateStatus, SageTranscriptEvidence,
    TrustedBackendAdmission, TrustedBackendAdmissionVerification, UntrustedCompletenessProof,
    UntrustedFamilyCertificate, UntrustedFamilySolution, UntrustedTrustedBackendProof,
    VerifiedFamilyCertificate, admit_trusted_backend_certificate,
    admit_trusted_backend_certificate_with_evidence, build_local_family_certificate,
    build_trusted_family_certificate, canonical_point_list_sha256, parse_family_certificate,
    serialize_family_certificate, verify_family_certificate,
};
pub use bounded::{
    BoundedDiscovery, BoundedDiscoveryResult, DeterministicU64PrimeOracle, PrimeProofOracle,
    discover_bounded, discover_bounded_with,
};
pub use certificate::{
    AdmissionError, UntrustedCertificate, UntrustedIntegralPoint, VerifiedIntegralPoint,
    VerifiedTheorem,
};
pub use integer_io::CanonicalInt;
pub use local::{
    MAX_SUPPORTED_MODULUS, ModulusError, SquareResidueTable, is_square_mod_composite,
    is_square_mod_prime_power, is_square_residue_mod,
};
pub use local_certificate::{
    LocalCertificateStatus, LocalSearchResult, UntrustedLocalCertificate, UntrustedModulusFactor,
    UntrustedUnitResidue, VerifiedLocalCertificate, search_local_certificate,
    verify_local_certificate,
};
pub use migration::{
    LEGACY_MIGRATION_SCHEMA_VERSION, LegacyFileIdentity, LegacyMigrationCommitEntry,
    LegacyMigrationCommitReport, LegacyMigrationEntry, LegacyMigrationInspection,
    LegacyMigrationReport, LegacyTranscriptIdentity, commit_legacy_campaigns,
    commit_legacy_proof_library, inspect_legacy_campaigns, inspect_legacy_proof_library,
    parse_legacy_migration_report, serialize_legacy_migration_report,
};
pub use mw_points::{
    CanonicalRational, MW_POINT_FILE_KIND, MW_POINT_FILE_SCHEMA_VERSION, MwPoint, MwPointFile,
    MwPointFileError, MwPointFileLimits, SageDiscoveryPoint, load_mw_point_file,
    load_mw_point_file_with_limits, parse_mw_point_file, parse_mw_point_file_with_limits,
};
pub use oracle::{FamilyStatus, IntegralPointsOracle, OracleError, OracleResult};
pub use persistence::{
    AdmissionCommitMarker, AdmissionLoad, AdmissionLoadState, AdmissionPolicy, AdmissionProvenance,
    AdmissionRecord, BackendEvidenceBinding, BackendPolicyIdentity, CanonicalJsonIdentity,
    CommittedAdmission, CompletenessTrust, ContentReference, DEFAULT_STORE_ROOT, FailurePoint,
    ImportDisposition, ImportRecord, LoadedAdmission, PERSISTED_ADMISSION_POLICY_ID,
    PERSISTED_STORE_ID, PersistenceError, PointSetComparison, PublishResult, PublishedAdmission,
    RECORDED_LOCAL_CAMPAIGN_POLICY_ID, RegisteredStore, STORE_SNAPSHOT_SCHEMA_VERSION,
    SnapshotRecord, SourceReference, StoreManifest, StoreObject, StorePolicy, StoreReader,
    StoreSnapshot, StoreSnapshotAdmission, StoreWriter, TheoremBinding, TranscriptReference,
    admission_id_for_certificate, canonical_json_bytes, canonical_json_identity,
    canonical_json_sha256, canonical_solution_set_sha256, conflict_state, json_content_reference,
    parse_admission_record, parse_store_manifest, persist_local_admission,
    persist_trusted_backend_admission, persist_trusted_backend_refresh, raw_content_reference,
    validate_admission_schema, validate_manifest,
};
pub use point_filter::{
    CheckedPoint, DeterministicPointPrimeOracle, PointDecision, PointFilterResult,
    PointFilterStatus, PointPrimeOracle, PointPrimeStatus, PointRejectionReason,
    VerifiedFamilySolution, filter_integral_points, filter_integral_points_with_prime_oracle,
};
pub use primality::{
    CompositeWitness, DETERMINISTIC_BASES, NotPrimeReason, PROVEN_U64_MAX, PrimeStatus,
    ProvenPrime, classify_u64,
};
pub use problem::FamilyProblem;
pub use sage::{
    ORIGINAL_INTEGRAL_MODEL, QUALIFIED_MW04_BASE_SHA256, QUALIFIED_MW04_HELPER_SHA256,
    QUALIFIED_MW04_MW02_SHA256, SAGE_ADAPTER_SCHEMA_VERSION, SageAdapter, SageAdapterConfig,
    SageAdapterResult, SageBackendPolicy, SageGenerator, SageRational, SageRequest,
    SageRequestPolicy, SageResponse, SageResponseBackend, SageResponseModel, SageResponseProof,
    SageRunEvidence, SageValidatedCompletion, SageValidationError, UntrustedSageResponse,
    parse_sage_response, validate_sage_response,
};
pub use theorem_map::{
    DecompositionEligibility, EligibleDecomposition, ExclusionWitness, ImportReport, ImportSkip,
    LoadedTheoremMap, LookupDecision, MapImportError, TheoremMap, TheoremMapSnapshot,
    TheoremRecord, eligible_decompositions, import_certificates,
};
