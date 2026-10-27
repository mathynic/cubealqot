//! Immutable theorem-map admission and exact decomposition lookup.
//!
//! Only a `VerifiedFamilyCertificate` produced by the M7-13 admission
//! boundary can enter `TheoremMap`.  Serialized snapshots are export-only;
//! there is intentionally no snapshot deserializer that creates a verified
//! map.  Missing, incomplete, and unsupported certificates are reported and
//! skipped, never represented as empty solution sets.

use std::collections::{BTreeMap, HashSet};

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::admission::{
    CertificateProofKind, CertificateVerification, FamilyCertificateStatus,
    UntrustedFamilyCertificate, VerifiedFamilyCertificate, serialize_family_certificate,
    verify_family_certificate,
};
use super::integer_io::CanonicalInt;
use super::persistence::{
    LoadedAdmission, STORE_SNAPSHOT_SCHEMA_VERSION, StoreReader, StoreSnapshot,
    StoreSnapshotAdmission, canonical_json_bytes,
};
use super::pocklington::{PrimeCertificateStatus, verify_prime_certificate};
use super::problem::{ProblemBuildResult, UntrustedCofactorFactor, validate_problem};

pub const THEOREM_MAP_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TheoremRecord {
    n: CanonicalInt,
    allowed_q: Vec<CanonicalInt>,
    certificate_digest: String,
    rhs_version: u32,
    schema_version: u32,
    proof_kind: CertificateProofKind,
}

impl TheoremRecord {
    pub fn n(&self) -> &CanonicalInt {
        &self.n
    }

    pub fn allowed_q(&self) -> &[CanonicalInt] {
        &self.allowed_q
    }

    pub fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }

    pub fn rhs_version(&self) -> u32 {
        self.rhs_version
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn proof_kind(&self) -> &CertificateProofKind {
        &self.proof_kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TheoremMapSnapshot {
    pub schema_version: u32,
    entries: Vec<TheoremRecord>,
}

impl TheoremMapSnapshot {
    pub fn entries(&self) -> &[TheoremRecord] {
        &self.entries
    }

    /// Digest of the canonical serialized theorem snapshot.  The digest is
    /// an identity for persistence compatibility; it is not an authority for
    /// admitting the snapshot as a theorem map.
    pub fn digest(&self) -> Result<String, String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("could not serialize theorem snapshot: {error}"))?;
        Ok(sha256_hex(&bytes))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TheoremMap {
    entries: BTreeMap<CanonicalInt, TheoremRecord>,
    // Derived only from admitted records; never serialized or used to exclude.
    native_cofactors: HashSet<u64>,
}

/// The trusted result of loading one immutable store snapshot.  The map is
/// built only from `StoreReader::load_admission`; the selection identity is
/// retained beside the mathematical map so checkpoint premises can bind both.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedTheoremMap {
    map: TheoremMap,
    snapshot_id: String,
    store_id: String,
    policy_id: String,
    admission_ids: Vec<String>,
}

impl LoadedTheoremMap {
    pub fn map(&self) -> &TheoremMap {
        &self.map
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn store_id(&self) -> &str {
        &self.store_id
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn admission_ids(&self) -> &[String] {
        &self.admission_ids
    }
}

impl TheoremMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether at least one admitted theorem relies on the qualified
    /// trusted-backend completeness contract.  This is provenance metadata;
    /// it does not alter lookup semantics.
    pub fn uses_backend_trust(&self) -> bool {
        self.entries.values().any(|record| {
            matches!(
                record.proof_kind,
                CertificateProofKind::TrustedIntegralPoints
            )
        })
    }

    /// Load a selected immutable snapshot through the offline admission
    /// boundary.  Snapshot fields are claims: every selected admission is
    /// loaded and verified from the store, then compared field-for-field with
    /// the snapshot before it enters the theorem map.
    pub fn from_store_snapshot(
        reader: &StoreReader,
        snapshot: &StoreSnapshot,
    ) -> Result<LoadedTheoremMap, String> {
        validate_store_snapshot_identity(reader, snapshot)?;
        let mut map = Self::new();
        let mut admission_ids = Vec::with_capacity(snapshot.admissions.len());
        for selected in &snapshot.admissions {
            if admission_ids.iter().any(|id| id == &selected.admission_id) {
                return Err(format!(
                    "store snapshot selects admission more than once: {}",
                    selected.admission_id
                ));
            }
            let loaded = match reader
                .load_admission(&selected.admission_id)
                .map_err(|error| error.to_string())?
            {
                super::persistence::AdmissionLoad::Loaded(value) => value,
                super::persistence::AdmissionLoad::NotAdmitted => {
                    return Err(format!(
                        "store snapshot admission is not committed: {}",
                        selected.admission_id
                    ));
                }
            };
            let expected = snapshot_admission(&loaded);
            if expected != *selected {
                return Err(format!(
                    "store snapshot admission content differs from committed record: {}",
                    selected.admission_id
                ));
            }
            map.insert_persisted(&loaded)
                .map_err(|error| format!("theorem-map import failed: {error:?}"))?;
            admission_ids.push(selected.admission_id.clone());
        }
        Ok(LoadedTheoremMap {
            map,
            snapshot_id: snapshot.snapshot_id.clone(),
            store_id: snapshot.store_id.clone(),
            policy_id: snapshot.policy_id.clone(),
            admission_ids,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Negative pre-check for factored native roots. A hit still requires the
    /// complete arbitrary-precision lookup and its existing witness checks.
    pub(crate) fn contains_native_cofactor(&self, n: u64) -> bool {
        self.native_cofactors.contains(&n)
    }

    #[cfg(test)]
    pub(crate) fn test_only_single(n: &str, allowed_q: &[&str]) -> Self {
        let n = CanonicalInt::from_decimal(n).unwrap();
        let mut allowed_q = allowed_q
            .iter()
            .map(|q| CanonicalInt::from_decimal(q).unwrap())
            .collect::<Vec<_>>();
        allowed_q.sort();
        let mut map = Self::new();
        map.insert_record(TheoremRecord {
            n,
            allowed_q,
            certificate_digest: "test-only-digest".to_owned(),
            rhs_version: 1,
            schema_version: 1,
            proof_kind: CertificateProofKind::Local,
        })
        .unwrap();
        map
    }

    /// Admit a complete certificate already verified by M7-13.  The
    /// certificate and verified object are cross-checked before any map
    /// mutation.  Trusted-backend callers must pass the result of the fresh
    /// approved replay, not offline content verification.
    pub fn insert_verified(
        &mut self,
        certificate: &UntrustedFamilyCertificate,
        verified: &VerifiedFamilyCertificate,
    ) -> Result<(), MapImportError> {
        let record = record_from_verified(certificate, verified)?;
        self.insert_record(record)
    }

    /// Admit a certificate loaded from the registered persistent store.  The
    /// loader owns the private committed capability; callers cannot recreate
    /// this path from an admission record, digest or serialized `complete`
    /// flag.  Backend-trusted content reaches this method only after the
    /// persisted completeness premise and exact offline checks succeeded.
    pub fn insert_persisted(&mut self, loaded: &LoadedAdmission) -> Result<(), MapImportError> {
        self.insert_verified(loaded.certificate(), loaded.verified())
    }

    fn insert_record(&mut self, record: TheoremRecord) -> Result<(), MapImportError> {
        if let Some(existing) = self.entries.get(record.n()) {
            if existing != &record {
                return Err(MapImportError::ConflictingCompleteEntries {
                    n: record.n().clone(),
                    first_digest: existing.certificate_digest.clone(),
                    second_digest: record.certificate_digest.clone(),
                });
            }
            return Ok(());
        }
        if let Some(n) = record.n.as_bigint().to_u64() {
            self.native_cofactors.insert(n);
        }
        self.entries.insert(record.n.clone(), record);
        Ok(())
    }

    /// Look up an eligible decomposition exactly.  The relation `m=N*q` is
    /// checked using arbitrary precision integers; no q or N narrowing is
    /// performed.  A listed q is in the complete theorem's `S_N` and
    /// continues; an absent q is excluded with the admitted theorem witness.
    /// This raw lookup does not establish q primality, N > 1, or coprimality.
    pub fn lookup(&self, m: &CanonicalInt, n: &CanonicalInt, q: &CanonicalInt) -> LookupDecision {
        if m.as_bigint() != &(n.as_bigint() * q.as_bigint()) {
            return LookupDecision::Continue {
                reason: "decomposition is not exactly m=N*q".to_owned(),
            };
        }
        let Some(record) = self.entries.get(n) else {
            return LookupDecision::Continue {
                reason: "no admitted complete theorem for N".to_owned(),
            };
        };
        if record.allowed_q.binary_search(q).is_ok() {
            return LookupDecision::Continue {
                reason: "q is in the admitted S_N set".to_owned(),
            };
        }
        LookupDecision::Excluded(ExclusionWitness {
            m: m.clone(),
            n: n.clone(),
            q: q.clone(),
            certificate_digest: record.certificate_digest.clone(),
            proof_kind: record.proof_kind.clone(),
        })
    }

    /// Export metadata and allowed q values.  This snapshot is not an
    /// admission input and has no deserialization path to `TheoremMap`.
    pub fn snapshot(&self) -> TheoremMapSnapshot {
        TheoremMapSnapshot {
            schema_version: THEOREM_MAP_SCHEMA_VERSION,
            entries: self.entries.values().cloned().collect(),
        }
    }

    /// Digest the exact canonical snapshot represented by this admitted map.
    pub fn snapshot_digest(&self) -> Result<String, String> {
        self.snapshot().digest()
    }

    /// Summarize the admitted proof trust carried by this map.  This is
    /// metadata for run reporting and compatibility, never a replacement for
    /// certificate admission.
    pub fn admitted_proof_policy(&self) -> &'static str {
        let mut saw_local = false;
        let mut saw_backend = false;
        for record in self.entries.values() {
            match record.proof_kind {
                CertificateProofKind::Local => saw_local = true,
                CertificateProofKind::TrustedIntegralPoints => saw_backend = true,
            }
        }
        match (saw_local, saw_backend) {
            (false, false) => "no-theorem-map",
            (true, false) => "self-contained-local",
            (false, true) => "trusted-backend",
            (true, true) => "mixed-local-and-trusted-backend",
        }
    }
}

fn snapshot_admission(loaded: &LoadedAdmission) -> StoreSnapshotAdmission {
    let record = loaded.committed().record();
    StoreSnapshotAdmission {
        admission_id: record.admission_id.clone(),
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
    }
}

fn validate_store_snapshot_identity(
    reader: &StoreReader,
    snapshot: &StoreSnapshot,
) -> Result<(), String> {
    if snapshot.schema_version != STORE_SNAPSHOT_SCHEMA_VERSION {
        return Err(format!(
            "unsupported store snapshot schema version {}",
            snapshot.schema_version
        ));
    }
    if snapshot.store_id != reader.manifest().store_id {
        return Err("store snapshot belongs to a different proof store".to_owned());
    }
    if snapshot.policy_id != reader.manifest().policy.policy_id
        || snapshot.rhs_version != reader.manifest().policy.rhs_version
    {
        return Err("store snapshot policy or RHS identity does not match the store".to_owned());
    }
    let mut identity = snapshot.clone();
    identity.snapshot_id.clear();
    let value = serde_json::to_value(&identity).map_err(|error| error.to_string())?;
    let bytes = canonical_json_bytes(&value).map_err(|error| error.to_string())?;
    let expected = format!("m7-snapshot-{}", sha256_hex(&bytes));
    if snapshot.snapshot_id != expected {
        return Err("store snapshot identity digest does not match its contents".to_owned());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExclusionWitness {
    m: CanonicalInt,
    n: CanonicalInt,
    q: CanonicalInt,
    certificate_digest: String,
    proof_kind: CertificateProofKind,
}

impl ExclusionWitness {
    pub fn m(&self) -> &CanonicalInt {
        &self.m
    }

    pub fn n(&self) -> &CanonicalInt {
        &self.n
    }

    pub fn q(&self) -> &CanonicalInt {
        &self.q
    }

    pub fn certificate_digest(&self) -> &str {
        &self.certificate_digest
    }

    pub fn proof_kind(&self) -> &CertificateProofKind {
        &self.proof_kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LookupDecision {
    Excluded(ExclusionWitness),
    Continue { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportSkip {
    pub n: Option<CanonicalInt>,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportReport {
    admitted: Vec<CanonicalInt>,
    skipped: Vec<ImportSkip>,
}

impl ImportReport {
    pub fn admitted(&self) -> &[CanonicalInt] {
        &self.admitted
    }

    pub fn skipped(&self) -> &[ImportSkip] {
        &self.skipped
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MapImportError {
    InvalidCertificate {
        reason: String,
    },
    ConflictingCompleteEntries {
        n: CanonicalInt,
        first_digest: String,
        second_digest: String,
    },
}

/// Import untrusted certificates using the offline admission boundary.
/// Local complete certificates are admitted.  Trusted-backend certificates
/// are explicitly skipped because they require fresh approved replay.
pub fn import_certificates(
    certificates: &[UntrustedFamilyCertificate],
) -> Result<(TheoremMap, ImportReport), MapImportError> {
    let mut map = TheoremMap::new();
    let mut report = ImportReport::default();
    for certificate in certificates {
        match verify_family_certificate(certificate) {
            CertificateVerification::Verified(verified) => {
                let n = verified.problem().n().clone();
                map.insert_verified(certificate, &verified)?;
                report.admitted.push(n);
            }
            CertificateVerification::Inconclusive { reason } => {
                report.skipped.push(ImportSkip {
                    n: Some(certificate.problem.n.clone()),
                    reason,
                });
            }
            CertificateVerification::Rejected { reason } => {
                return Err(MapImportError::InvalidCertificate { reason });
            }
        }
    }
    Ok((map, report))
}

fn record_from_verified(
    certificate: &UntrustedFamilyCertificate,
    verified: &VerifiedFamilyCertificate,
) -> Result<TheoremRecord, MapImportError> {
    if certificate.schema_version != super::admission::FAMILY_CERTIFICATE_SCHEMA_VERSION
        || certificate.rhs_version != super::admission::FAMILY_RHS_VERSION
        || certificate.status == FamilyCertificateStatus::Inconclusive
        || certificate.proof_kind != *verified.proof_kind()
        || certificate.status
            != match verified.certificate_status() {
                FamilyCertificateStatus::CertifiedEmpty => FamilyCertificateStatus::CertifiedEmpty,
                FamilyCertificateStatus::CertifiedSolutions => {
                    FamilyCertificateStatus::CertifiedSolutions
                }
                FamilyCertificateStatus::Inconclusive => FamilyCertificateStatus::Inconclusive,
            }
        || certificate.solutions != verified.solutions()
    {
        return Err(MapImportError::InvalidCertificate {
            reason: "certificate and admitted theorem object do not match".to_owned(),
        });
    }
    let problem = match validate_problem(&certificate.problem) {
        ProblemBuildResult::Certified(problem) => problem,
        ProblemBuildResult::Rejected { reason } | ProblemBuildResult::Inconclusive { reason } => {
            return Err(MapImportError::InvalidCertificate { reason });
        }
    };
    if problem != *verified.problem() {
        return Err(MapImportError::InvalidCertificate {
            reason: "certificate Problem differs from admitted theorem object".to_owned(),
        });
    }
    let mut allowed_q = verified
        .solutions()
        .iter()
        .map(|solution| solution.q.clone())
        .collect::<Vec<_>>();
    allowed_q.sort();
    if allowed_q.windows(2).any(|window| window[0] == window[1]) {
        return Err(MapImportError::InvalidCertificate {
            reason: "admitted theorem contains duplicate q values".to_owned(),
        });
    }
    let bytes = serialize_family_certificate(certificate).map_err(|error| {
        MapImportError::InvalidCertificate {
            reason: format!("certificate serialization failed: {error}"),
        }
    })?;
    Ok(TheoremRecord {
        n: problem.n().clone(),
        allowed_q,
        certificate_digest: sha256_hex(&bytes),
        rhs_version: certificate.rhs_version,
        schema_version: certificate.schema_version,
        proof_kind: certificate.proof_kind.clone(),
    })
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EligibleDecomposition {
    m: CanonicalInt,
    n: CanonicalInt,
    q: CanonicalInt,
}

impl EligibleDecomposition {
    pub fn m(&self) -> &CanonicalInt {
        &self.m
    }

    pub fn n(&self) -> &CanonicalInt {
        &self.n
    }

    pub fn q(&self) -> &CanonicalInt {
        &self.q
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecompositionEligibility {
    Eligible {
        decompositions: Vec<EligibleDecomposition>,
        skipped: Vec<String>,
    },
    Inconclusive {
        partial: Vec<EligibleDecomposition>,
        skipped: Vec<String>,
        reason: String,
    },
    Rejected {
        reason: String,
    },
}

/// Determine which prime factors of an exact decomposition may serve as the
/// free q.  Only exponent-one factors are eligible; exponent-two-and-higher
/// factors are recorded as skipped.  Prime-proof uncertainty is inconclusive,
/// never a negative lookup result.
pub fn eligible_decompositions(
    m: &CanonicalInt,
    factors: &[UntrustedCofactorFactor],
) -> DecompositionEligibility {
    let Some(m_value) = m.as_bigint().to_biguint() else {
        return DecompositionEligibility::Rejected {
            reason: "m must be positive".to_owned(),
        };
    };
    if m_value.is_zero() || factors.is_empty() {
        return DecompositionEligibility::Rejected {
            reason: "a positive m and nonempty factorization are required".to_owned(),
        };
    }
    let mut product = BigUint::one();
    let mut previous: Option<BigUint> = None;
    let mut eligible = Vec::new();
    let mut skipped = Vec::new();
    for factor in factors {
        let Some(prime) = factor.prime.as_bigint().to_biguint() else {
            return DecompositionEligibility::Rejected {
                reason: "factor primes must be positive".to_owned(),
            };
        };
        if prime <= BigUint::one() || factor.exponent == 0 {
            return DecompositionEligibility::Rejected {
                reason: "factor primes and exponents are invalid".to_owned(),
            };
        }
        if previous.as_ref().is_some_and(|old| old >= &prime) {
            return DecompositionEligibility::Rejected {
                reason: "factorization must be strictly increasing".to_owned(),
            };
        }
        previous = Some(prime.clone());
        product *= prime.pow(factor.exponent);
        let Some(certificate) = factor.certificate.as_ref() else {
            return DecompositionEligibility::Inconclusive {
                partial: eligible,
                skipped,
                reason: format!("missing prime proof for factor {}", factor.prime),
            };
        };
        match verify_prime_certificate(certificate) {
            PrimeCertificateStatus::ProvenPrime(_) => {}
            PrimeCertificateStatus::Rejected { reason } => {
                return DecompositionEligibility::Rejected { reason };
            }
            PrimeCertificateStatus::Inconclusive { reason } => {
                return DecompositionEligibility::Inconclusive {
                    partial: eligible,
                    skipped,
                    reason,
                };
            }
        }
        if factor.exponent != 1 {
            skipped.push(format!(
                "factor {} has exponent {}",
                factor.prime, factor.exponent
            ));
            continue;
        }
        let n_value = &m_value / &prime;
        if n_value == BigUint::one() {
            skipped.push(format!("free factor {} would produce N=1", factor.prime));
            continue;
        }
        eligible.push(EligibleDecomposition {
            m: m.clone(),
            n: canonical_biguint(n_value),
            q: factor.prime.clone(),
        });
    }
    if product != m_value {
        return DecompositionEligibility::Rejected {
            reason: "factor product does not equal m".to_owned(),
        };
    }
    DecompositionEligibility::Eligible {
        decompositions: eligible,
        skipped,
    }
}

fn canonical_biguint(value: BigUint) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("BigUint formatting is canonical")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_record(n: &str, q: &str) -> TheoremRecord {
        TheoremRecord {
            n: CanonicalInt::from_decimal(n).unwrap(),
            allowed_q: vec![CanonicalInt::from_decimal(q).unwrap()],
            certificate_digest: "test-only-digest".to_owned(),
            rhs_version: 1,
            schema_version: 1,
            proof_kind: CertificateProofKind::Local,
        }
    }

    #[test]
    fn native_index_tracks_insertions_without_narrowing_wide_cofactors() {
        let mut map = TheoremMap::new();
        assert!(!map.contains_native_cofactor(3));
        map.insert_record(test_record("3", "2")).unwrap();
        map.insert_record(test_record("18446744073709551615", "2"))
            .unwrap();
        map.insert_record(test_record("18446744073709551618", "2"))
            .unwrap();
        map.insert_record(test_record("3", "2")).unwrap();
        assert!(map.contains_native_cofactor(3));
        assert!(map.contains_native_cofactor(u64::MAX));
        assert!(!map.contains_native_cofactor(2));
        assert_eq!(map.native_cofactors.len(), 2);
        assert_eq!(map.len(), 3);
        assert_eq!(map.clone(), map);

        let n = CanonicalInt::from_decimal("18446744073709551618").unwrap();
        let q = CanonicalInt::from_decimal("5").unwrap();
        let m = CanonicalInt::from_decimal(&(n.as_bigint() * q.as_bigint()).to_string()).unwrap();
        assert!(matches!(
            map.lookup(&m, &n, &q),
            LookupDecision::Excluded(_)
        ));
    }

    #[test]
    fn test_only_wide_lookup_preserves_bigints_and_emits_witness() {
        let n = CanonicalInt::from_decimal("18446744073709551557").unwrap();
        let listed_q = CanonicalInt::from_decimal("18446744073709551533").unwrap();
        let mut map = TheoremMap::new();
        map.insert_record(test_record(&n.to_string(), &listed_q.to_string()))
            .unwrap();
        let listed_m =
            CanonicalInt::from_decimal(&(n.as_bigint() * listed_q.as_bigint()).to_string())
                .unwrap();
        assert!(matches!(
            map.lookup(&listed_m, &n, &listed_q),
            LookupDecision::Continue { .. }
        ));

        let unlisted_q = CanonicalInt::from_decimal("18446744009551615").unwrap();
        let unlisted_m =
            CanonicalInt::from_decimal(&(n.as_bigint() * unlisted_q.as_bigint()).to_string())
                .unwrap();
        match map.lookup(&unlisted_m, &n, &unlisted_q) {
            LookupDecision::Excluded(witness) => {
                assert_eq!(witness.m(), &unlisted_m);
                assert_eq!(witness.n(), &n);
                assert_eq!(witness.q(), &unlisted_q);
            }
            other => panic!("wide admitted lookup did not exclude: {other:?}"),
        }
    }

    #[test]
    fn test_only_conflicting_complete_entries_are_an_import_error() {
        let mut map = TheoremMap::new();
        map.insert_record(test_record("3", "2")).unwrap();
        let error = map.insert_record(test_record("3", "5")).unwrap_err();
        assert!(matches!(
            error,
            MapImportError::ConflictingCompleteEntries { n, .. }
                if n == CanonicalInt::from_decimal("3").unwrap()
        ));
    }

    #[test]
    fn test_nonempty_membership_truth_table_covers_q_two_and_q_less_than_n() {
        let mut map = TheoremMap::new();
        map.insert_record(test_record("3", "2")).unwrap();
        let n = CanonicalInt::from_decimal("3").unwrap();
        let listed_q = CanonicalInt::from_decimal("2").unwrap();
        assert!(matches!(
            map.lookup(&CanonicalInt::from_decimal("6").unwrap(), &n, &listed_q),
            LookupDecision::Continue { .. }
        ));

        let unlisted_q = CanonicalInt::from_decimal("5").unwrap();
        assert!(matches!(
            map.lookup(&CanonicalInt::from_decimal("15").unwrap(), &n, &unlisted_q),
            LookupDecision::Excluded(_)
        ));
    }
}
