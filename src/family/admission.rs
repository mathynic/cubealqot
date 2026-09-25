//! Versioned family certificates and their independent admission boundary.
//!
//! The wire representation is untrusted data.  Verification rebuilds the
//! exact `Problem`, checks every arithmetic identity, and derives the status
//! from the proof rather than trusting a serialized status or completeness
//! bit.  A trusted-backend certificate is deliberately only an offline
//! content record: admission requires a fresh run of the approved adapter.

use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::certificate::UntrustedIntegralPoint;
use super::integer_io::CanonicalInt;
use super::local_certificate::{
    LocalCertificateStatus, UntrustedLocalCertificate, verify_local_certificate,
};
use super::oracle::FamilyStatus;
use super::pocklington::{
    PrimeCertificateStatus, UntrustedPrimeCertificate, verify_prime_certificate,
};
use super::point_filter::{PointFilterStatus, VerifiedFamilySolution, filter_integral_points};
use super::problem::{Problem, ProblemBuildResult, UntrustedProblem, validate_problem};
use super::sage::{
    SageAdapter, SageAdapterResult, SageBackendPolicy, SageRequest, SageRequestPolicy,
    SageRunEvidence, SageValidatedCompletion, UntrustedSageResponse, validate_sage_response,
};

pub const FAMILY_CERTIFICATE_SCHEMA_VERSION: u32 = 1;
pub const FAMILY_RHS_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CertificateProofKind {
    Local,
    TrustedIntegralPoints,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FamilyCertificateStatus {
    CertifiedEmpty,
    CertifiedSolutions,
    Inconclusive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedFamilySolution {
    pub q: CanonicalInt,
    pub y: CanonicalInt,
    pub curve_x: CanonicalInt,
    pub curve_y: CanonicalInt,
    pub q_prime: Option<UntrustedPrimeCertificate>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SageTranscriptEvidence {
    pub job_id: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub stderr_sha256: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

impl From<&SageRunEvidence> for SageTranscriptEvidence {
    fn from(evidence: &SageRunEvidence) -> Self {
        Self {
            job_id: evidence.job_id.clone(),
            request_sha256: evidence.request_sha256.clone(),
            response_sha256: evidence.stdout_sha256.clone(),
            stderr_sha256: evidence.stderr_sha256.clone(),
            exit_code: evidence.exit_code,
            timed_out: evidence.timed_out,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedTrustedBackendProof {
    pub request: SageRequest,
    pub response: UntrustedSageResponse,
    pub evidence: SageTranscriptEvidence,
    pub point_list_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum UntrustedCompletenessProof {
    Local {
        certificate: UntrustedLocalCertificate,
    },
    TrustedIntegralPoints {
        backend: UntrustedTrustedBackendProof,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedFamilyCertificate {
    pub schema_version: u32,
    pub rhs_version: u32,
    pub proof_kind: CertificateProofKind,
    pub status: FamilyCertificateStatus,
    pub problem: UntrustedProblem,
    pub a: CanonicalInt,
    pub d: CanonicalInt,
    pub curve_coefficients: [CanonicalInt; 5],
    pub solutions: Vec<UntrustedFamilySolution>,
    pub proof: UntrustedCompletenessProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedFamilyCertificate {
    status: FamilyCertificateStatus,
    proof_kind: CertificateProofKind,
    problem: Problem,
    solutions: Vec<UntrustedFamilySolution>,
}

impl VerifiedFamilyCertificate {
    pub fn status(&self) -> FamilyStatus {
        match self.status {
            FamilyCertificateStatus::CertifiedEmpty => FamilyStatus::CertifiedEmpty,
            FamilyCertificateStatus::CertifiedSolutions => FamilyStatus::CertifiedSolutions,
            FamilyCertificateStatus::Inconclusive => FamilyStatus::Inconclusive,
        }
    }

    pub fn certificate_status(&self) -> &FamilyCertificateStatus {
        &self.status
    }

    pub fn proof_kind(&self) -> &CertificateProofKind {
        &self.proof_kind
    }

    pub fn problem(&self) -> &Problem {
        &self.problem
    }

    pub fn solutions(&self) -> &[UntrustedFamilySolution] {
        &self.solutions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateVerification {
    Verified(VerifiedFamilyCertificate),
    Rejected { reason: String },
    Inconclusive { reason: String },
}

/// A successful trusted-backend admission together with the second transcript
/// needed to persist the initial-versus-replay comparison.  The ordinary
/// `CertificateVerification` API remains available for callers that only
/// need the verified theorem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedBackendAdmission {
    verified: VerifiedFamilyCertificate,
    replay_evidence: SageRunEvidence,
}

impl TrustedBackendAdmission {
    pub fn verified(&self) -> &VerifiedFamilyCertificate {
        &self.verified
    }

    pub fn replay_evidence(&self) -> &SageRunEvidence {
        &self.replay_evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustedBackendAdmissionVerification {
    Verified(TrustedBackendAdmission),
    Rejected { reason: String },
    Inconclusive { reason: String },
}

pub fn serialize_family_certificate(
    certificate: &UntrustedFamilyCertificate,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(certificate)
}

pub fn parse_family_certificate(
    bytes: &[u8],
) -> Result<UntrustedFamilyCertificate, serde_json::Error> {
    serde_json::from_slice(bytes)
}

pub fn canonical_point_list_sha256(
    points: &[UntrustedIntegralPoint],
) -> Result<String, serde_json::Error> {
    let mut sorted = points.to_vec();
    sorted.sort_by(|left, right| left.x.cmp(&right.x).then_with(|| left.y.cmp(&right.y)));
    let bytes = serde_json::to_vec(&sorted)?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(hex_lower(&digest.finalize()))
}

pub fn build_local_family_certificate(
    input: &UntrustedProblem,
    problem: &Problem,
    local: UntrustedLocalCertificate,
) -> Result<UntrustedFamilyCertificate, String> {
    let rebuilt = certified_problem(input)?;
    if &rebuilt != problem {
        return Err("local certificate builder received a mismatched Problem".to_owned());
    }
    let verified = match verify_local_certificate(&local) {
        LocalCertificateStatus::Verified(value) => value,
        LocalCertificateStatus::Rejected { reason } => return Err(reason),
        LocalCertificateStatus::Inconclusive { reason } => return Err(reason),
    };
    if verified.problem() != problem {
        return Err("local proof problem identity mismatch".to_owned());
    }
    let mut solutions = Vec::new();
    for q in verified.solutions() {
        solutions.push(solution_from_q(problem, q)?);
    }
    sort_solutions(&mut solutions);
    Ok(UntrustedFamilyCertificate {
        schema_version: FAMILY_CERTIFICATE_SCHEMA_VERSION,
        rhs_version: FAMILY_RHS_VERSION,
        proof_kind: CertificateProofKind::Local,
        status: status_for(&solutions),
        problem: input.clone(),
        a: problem.a().clone(),
        d: problem.d().clone(),
        curve_coefficients: problem.curve().coefficients(),
        solutions,
        proof: UntrustedCompletenessProof::Local { certificate: local },
    })
}

pub fn build_trusted_family_certificate(
    input: &UntrustedProblem,
    problem: &Problem,
    completion: &SageValidatedCompletion,
    evidence: SageTranscriptEvidence,
) -> Result<UntrustedFamilyCertificate, String> {
    let rebuilt = certified_problem(input)?;
    if &rebuilt != problem {
        return Err("trusted certificate builder received a mismatched Problem".to_owned());
    }
    let policy = policy_from_request(&completion.request().policy);
    let checked = validate_sage_response(
        problem,
        completion.request(),
        completion.response().clone(),
        &policy,
    )
    .map_err(|error| format!("backend contract validation failed: {error:?}"))?;
    let filtered = filter_integral_points(problem, checked.points());
    let accepted = match filtered.status() {
        PointFilterStatus::Filtered => filtered.accepted(),
        PointFilterStatus::Inconclusive { reason } => return Err(reason.clone()),
    };
    let mut solutions = accepted
        .iter()
        .map(|solution| solution_record(problem, solution))
        .collect::<Result<Vec<_>, _>>()?;
    sort_solutions(&mut solutions);
    let point_list_sha256 = canonical_point_list_sha256(checked.points())
        .map_err(|error| format!("point-list digest failed: {error}"))?;
    Ok(UntrustedFamilyCertificate {
        schema_version: FAMILY_CERTIFICATE_SCHEMA_VERSION,
        rhs_version: FAMILY_RHS_VERSION,
        proof_kind: CertificateProofKind::TrustedIntegralPoints,
        status: status_for(&solutions),
        problem: input.clone(),
        a: problem.a().clone(),
        d: problem.d().clone(),
        curve_coefficients: problem.curve().coefficients(),
        solutions,
        proof: UntrustedCompletenessProof::TrustedIntegralPoints {
            backend: UntrustedTrustedBackendProof {
                request: completion.request().clone(),
                response: checked.response().clone(),
                evidence,
                point_list_sha256,
            },
        },
    })
}

pub fn verify_family_certificate(
    certificate: &UntrustedFamilyCertificate,
) -> CertificateVerification {
    match verify_core(certificate) {
        Ok(CoreVerified::Local { problem, solutions }) => {
            finish_verified(certificate, problem, solutions, CertificateProofKind::Local)
        }
        Ok(CoreVerified::TrustedOffline { .. }) => CertificateVerification::Inconclusive {
            reason: "trusted backend content requires fresh approved-backend replay".to_owned(),
        },
        Err(VerificationFailure::Rejected(reason)) => CertificateVerification::Rejected { reason },
        Err(VerificationFailure::Inconclusive(reason)) => {
            CertificateVerification::Inconclusive { reason }
        }
    }
}

/// Verify a certificate whose completeness premise was supplied by the
/// immutable proof store.  This deliberately shares `verify_core` with the
/// ordinary admission path: the only difference is the source of the
/// completeness premise for a trusted-backend certificate.  No adapter is
/// constructed or launched here.
pub(crate) fn verify_persisted_complete_certificate(
    certificate: &UntrustedFamilyCertificate,
) -> CertificateVerification {
    match verify_core(certificate) {
        Ok(CoreVerified::Local { problem, solutions }) => {
            finish_verified(certificate, problem, solutions, CertificateProofKind::Local)
        }
        Ok(CoreVerified::TrustedOffline { problem, solutions }) => finish_verified(
            certificate,
            problem,
            solutions,
            CertificateProofKind::TrustedIntegralPoints,
        ),
        Err(VerificationFailure::Rejected(reason)) => CertificateVerification::Rejected { reason },
        Err(VerificationFailure::Inconclusive(reason)) => {
            CertificateVerification::Inconclusive { reason }
        }
    }
}

pub fn admit_trusted_backend_certificate(
    certificate: &UntrustedFamilyCertificate,
    adapter: &SageAdapter,
) -> CertificateVerification {
    if matches!(&certificate.proof, UntrustedCompletenessProof::Local { .. }) {
        return verify_family_certificate(certificate);
    }
    match admit_trusted_backend_certificate_with_evidence(certificate, adapter) {
        TrustedBackendAdmissionVerification::Verified(value) => {
            CertificateVerification::Verified(value.verified)
        }
        TrustedBackendAdmissionVerification::Rejected { reason } => {
            CertificateVerification::Rejected { reason }
        }
        TrustedBackendAdmissionVerification::Inconclusive { reason } => {
            CertificateVerification::Inconclusive { reason }
        }
    }
}

/// Perform the approved replay and retain its evidence for PP-04 durable
/// publication.  No durable state is written here; callers publish only after
/// this function returns `Verified`.
pub fn admit_trusted_backend_certificate_with_evidence(
    certificate: &UntrustedFamilyCertificate,
    adapter: &SageAdapter,
) -> TrustedBackendAdmissionVerification {
    let backend = match &certificate.proof {
        UntrustedCompletenessProof::TrustedIntegralPoints { backend } => backend,
        UntrustedCompletenessProof::Local { .. } => {
            return match verify_family_certificate(certificate) {
                CertificateVerification::Verified(_) => {
                    TrustedBackendAdmissionVerification::Rejected {
                        reason: "trusted admission requires a trusted-backend certificate"
                            .to_owned(),
                    }
                }
                CertificateVerification::Rejected { reason } => {
                    TrustedBackendAdmissionVerification::Rejected { reason }
                }
                CertificateVerification::Inconclusive { reason } => {
                    TrustedBackendAdmissionVerification::Inconclusive { reason }
                }
            };
        }
    };
    let offline = match verify_core(certificate) {
        Ok(CoreVerified::TrustedOffline { problem, solutions }) => (problem, solutions),
        Ok(CoreVerified::Local { .. }) => unreachable!(),
        Err(VerificationFailure::Rejected(reason)) => {
            return TrustedBackendAdmissionVerification::Rejected { reason };
        }
        Err(VerificationFailure::Inconclusive(reason)) => {
            return TrustedBackendAdmissionVerification::Inconclusive { reason };
        }
    };
    let expected_policy = policy_from_request(&backend.request.policy);
    if adapter.config().policy != expected_policy {
        return TrustedBackendAdmissionVerification::Rejected {
            reason: "approved Sage adapter policy does not match certificate policy".to_owned(),
        };
    }
    let discovery_points = match backend.request.validated_discovery_points(&offline.0) {
        Ok(points) => points,
        Err(reason) => {
            return TrustedBackendAdmissionVerification::Rejected {
                reason: format!("embedded discovery points are invalid: {reason}"),
            };
        }
    };
    let replay =
        match adapter.enumerate_with_discovery_points(&offline.0, discovery_points.as_deref()) {
            SageAdapterResult::Complete {
                completion,
                evidence,
            } => (completion, evidence),
            SageAdapterResult::Inconclusive { reason, .. } => {
                return TrustedBackendAdmissionVerification::Inconclusive { reason };
            }
        };
    if canonical_points(replay.0.points()) != canonical_points(&backend.response.points) {
        return TrustedBackendAdmissionVerification::Rejected {
            reason: "approved backend replay point set differs from certificate".to_owned(),
        };
    }
    let replay_filter = filter_integral_points(&offline.0, replay.0.points());
    let replay_solutions = match replay_filter.status() {
        PointFilterStatus::Filtered => replay_filter
            .accepted()
            .iter()
            .map(|value| solution_record(&offline.0, value))
            .collect::<Result<Vec<_>, _>>(),
        PointFilterStatus::Inconclusive { reason } => {
            return TrustedBackendAdmissionVerification::Inconclusive {
                reason: reason.clone(),
            };
        }
    };
    let mut replay_solutions = match replay_solutions {
        Ok(value) => value,
        Err(reason) => return TrustedBackendAdmissionVerification::Rejected { reason },
    };
    sort_solutions(&mut replay_solutions);
    if replay_solutions != certificate.solutions
        || status_for(&replay_solutions) != certificate.status
    {
        return TrustedBackendAdmissionVerification::Rejected {
            reason: "replayed backend result does not derive the declared family result".to_owned(),
        };
    }
    let verified = match finish_verified(
        certificate,
        offline.0,
        offline.1,
        CertificateProofKind::TrustedIntegralPoints,
    ) {
        CertificateVerification::Verified(value) => value,
        CertificateVerification::Rejected { reason } => {
            return TrustedBackendAdmissionVerification::Rejected { reason };
        }
        CertificateVerification::Inconclusive { reason } => {
            return TrustedBackendAdmissionVerification::Inconclusive { reason };
        }
    };
    TrustedBackendAdmissionVerification::Verified(TrustedBackendAdmission {
        verified,
        replay_evidence: replay.1,
    })
}

enum CoreVerified {
    Local {
        problem: Problem,
        solutions: Vec<UntrustedFamilySolution>,
    },
    TrustedOffline {
        problem: Problem,
        solutions: Vec<UntrustedFamilySolution>,
    },
}

enum VerificationFailure {
    Rejected(String),
    Inconclusive(String),
}

fn verify_core(
    certificate: &UntrustedFamilyCertificate,
) -> Result<CoreVerified, VerificationFailure> {
    if certificate.schema_version != FAMILY_CERTIFICATE_SCHEMA_VERSION {
        return Err(VerificationFailure::Rejected(
            "unsupported family certificate schema version".to_owned(),
        ));
    }
    if certificate.rhs_version != FAMILY_RHS_VERSION {
        return Err(VerificationFailure::Rejected(
            "unsupported canonical RHS version".to_owned(),
        ));
    }
    let problem = match validate_problem(&certificate.problem) {
        ProblemBuildResult::Certified(problem) => problem,
        ProblemBuildResult::Rejected { reason } => {
            return Err(VerificationFailure::Rejected(reason));
        }
        ProblemBuildResult::Inconclusive { reason } => {
            return Err(VerificationFailure::Inconclusive(reason));
        }
    };
    if certificate.a != *problem.a()
        || certificate.d != *problem.d()
        || certificate.curve_coefficients != problem.curve().coefficients()
    {
        return Err(VerificationFailure::Rejected(
            "stored A, D, or curve coefficients do not match the validated Problem".to_owned(),
        ));
    }
    let kind_matches = matches!(
        (&certificate.proof_kind, &certificate.proof),
        (
            CertificateProofKind::Local,
            UntrustedCompletenessProof::Local { .. }
        ) | (
            CertificateProofKind::TrustedIntegralPoints,
            UntrustedCompletenessProof::TrustedIntegralPoints { .. }
        )
    );
    if !kind_matches {
        return Err(VerificationFailure::Rejected(
            "proof kind does not match proof payload".to_owned(),
        ));
    }
    match &certificate.proof {
        UntrustedCompletenessProof::Local { certificate: local } => {
            let local_verified = match verify_local_certificate(local) {
                LocalCertificateStatus::Verified(value) => value,
                LocalCertificateStatus::Rejected { reason } => {
                    return Err(VerificationFailure::Rejected(reason));
                }
                LocalCertificateStatus::Inconclusive { reason } => {
                    return Err(VerificationFailure::Inconclusive(reason));
                }
            };
            if local_verified.problem() != &problem {
                return Err(VerificationFailure::Rejected(
                    "embedded local proof has a different Problem".to_owned(),
                ));
            }
            let mut expected = local_verified
                .solutions()
                .iter()
                .map(|q| solution_from_q(&problem, q))
                .collect::<Result<Vec<_>, _>>()
                .map_err(VerificationFailure::Rejected)?;
            sort_solutions(&mut expected);
            validate_declared_solutions(&problem, certificate, &expected)?;
            Ok(CoreVerified::Local {
                problem,
                solutions: expected,
            })
        }
        UntrustedCompletenessProof::TrustedIntegralPoints { backend } => {
            validate_transcript(backend)?;
            let policy = policy_from_request(&backend.request.policy);
            let completion = validate_sage_response(
                &problem,
                &backend.request,
                backend.response.clone(),
                &policy,
            )
            .map_err(|error| {
                VerificationFailure::Inconclusive(format!("backend contract: {error:?}"))
            })?;
            let filtered = filter_integral_points(&problem, completion.points());
            let mut expected = match filtered.status() {
                PointFilterStatus::Filtered => filtered
                    .accepted()
                    .iter()
                    .map(|value| solution_record(&problem, value))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(VerificationFailure::Rejected)?,
                PointFilterStatus::Inconclusive { reason } => {
                    return Err(VerificationFailure::Inconclusive(reason.clone()));
                }
            };
            sort_solutions(&mut expected);
            validate_declared_solutions(&problem, certificate, &expected)?;
            Ok(CoreVerified::TrustedOffline {
                problem,
                solutions: expected,
            })
        }
    }
}

fn validate_declared_solutions(
    problem: &Problem,
    certificate: &UntrustedFamilyCertificate,
    expected: &[UntrustedFamilySolution],
) -> Result<(), VerificationFailure> {
    let mut declared = certificate.solutions.clone();
    sort_solutions(&mut declared);
    for solution in &declared {
        validate_solution(problem, solution)?;
    }
    if declared != expected {
        return Err(VerificationFailure::Rejected(
            "declared solutions do not equal the independently derived set".to_owned(),
        ));
    }
    if status_for(&declared) != certificate.status {
        return Err(VerificationFailure::Rejected(
            "serialized status does not match the verified solution set".to_owned(),
        ));
    }
    Ok(())
}

fn validate_solution(
    problem: &Problem,
    solution: &UntrustedFamilySolution,
) -> Result<(), VerificationFailure> {
    if solution.q.as_bigint() < &BigInt::from(2u8) {
        return Err(VerificationFailure::Rejected(
            "q is outside the prime domain".to_owned(),
        ));
    }
    let certificate = solution.q_prime.as_ref().ok_or_else(|| {
        VerificationFailure::Inconclusive("solution has no prime certificate".to_owned())
    })?;
    let claimed = match certificate {
        UntrustedPrimeCertificate::U64 { n } | UntrustedPrimeCertificate::Pocklington { n, .. } => {
            n
        }
    };
    if claimed != &solution.q {
        return Err(VerificationFailure::Rejected(
            "q prime certificate claims a different q".to_owned(),
        ));
    }
    match verify_prime_certificate(certificate) {
        PrimeCertificateStatus::ProvenPrime(_) => {}
        PrimeCertificateStatus::Rejected { reason } => {
            return Err(VerificationFailure::Rejected(reason));
        }
        PrimeCertificateStatus::Inconclusive { reason } => {
            return Err(VerificationFailure::Inconclusive(reason));
        }
    }
    if gcd(&solution.q, problem.n()) != BigInt::one() {
        return Err(VerificationFailure::Rejected(
            "q is not coprime to N".to_owned(),
        ));
    }
    if solution.y.as_bigint().sign() == Sign::Minus {
        return Err(VerificationFailure::Rejected(
            "family y must use the nonnegative representative".to_owned(),
        ));
    }
    if solution.y.as_bigint() * solution.y.as_bigint()
        != problem.rhs(&solution.q).as_bigint().clone()
        || solution.curve_x != problem.curve_x(&solution.q)
        || solution.curve_y != canonical_bigint(problem.d().as_bigint() * solution.y.as_bigint())
        || solution.curve_y.as_bigint() * solution.curve_y.as_bigint()
            != problem.curve_rhs(&solution.curve_x).as_bigint().clone()
    {
        return Err(VerificationFailure::Rejected(
            "solution does not satisfy the exact family and curve equations".to_owned(),
        ));
    }
    Ok(())
}

fn finish_verified(
    certificate: &UntrustedFamilyCertificate,
    problem: Problem,
    solutions: Vec<UntrustedFamilySolution>,
    proof_kind: CertificateProofKind,
) -> CertificateVerification {
    CertificateVerification::Verified(VerifiedFamilyCertificate {
        status: certificate.status.clone(),
        proof_kind,
        problem,
        solutions,
    })
}

fn certified_problem(input: &UntrustedProblem) -> Result<Problem, String> {
    match validate_problem(input) {
        ProblemBuildResult::Certified(problem) => Ok(problem),
        ProblemBuildResult::Rejected { reason } | ProblemBuildResult::Inconclusive { reason } => {
            Err(reason)
        }
    }
}

fn solution_from_q(problem: &Problem, q: &CanonicalInt) -> Result<UntrustedFamilySolution, String> {
    let rhs = problem.rhs(q).as_bigint().clone();
    let y =
        isqrt_nonnegative(&rhs).ok_or_else(|| "local solution q has nonsquare RHS".to_owned())?;
    let y = canonical_bigint(y);
    let q_u64 = q
        .as_bigint()
        .to_u64()
        .ok_or_else(|| "local solution q exceeds the u64 prime certificate domain".to_owned())?;
    Ok(UntrustedFamilySolution {
        q: q.clone(),
        y: y.clone(),
        curve_x: problem.curve_x(q),
        curve_y: canonical_bigint(problem.d().as_bigint() * y.as_bigint()),
        q_prime: Some(UntrustedPrimeCertificate::U64 {
            n: canonical_u64(q_u64),
        }),
    })
}

fn solution_record(
    problem: &Problem,
    solution: &VerifiedFamilySolution,
) -> Result<UntrustedFamilySolution, String> {
    let q_u64 =
        solution.q().as_bigint().to_u64().ok_or_else(|| {
            "backend returned a relevant q outside the u64 prime domain".to_owned()
        })?;
    Ok(UntrustedFamilySolution {
        q: solution.q().clone(),
        y: solution.y().clone(),
        curve_x: problem.curve_x(solution.q()),
        curve_y: canonical_bigint(problem.d().as_bigint() * solution.y().as_bigint()),
        q_prime: Some(UntrustedPrimeCertificate::U64 {
            n: canonical_u64(q_u64),
        }),
    })
}

fn validate_transcript(backend: &UntrustedTrustedBackendProof) -> Result<(), VerificationFailure> {
    if backend.evidence.timed_out || backend.evidence.exit_code != Some(0) {
        return Err(VerificationFailure::Inconclusive(
            "backend transcript did not terminate successfully".to_owned(),
        ));
    }
    for (label, value) in [
        ("request", &backend.evidence.request_sha256),
        ("response", &backend.evidence.response_sha256),
        ("stderr", &backend.evidence.stderr_sha256),
        ("point list", &backend.point_list_sha256),
    ] {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(VerificationFailure::Rejected(format!(
                "{label} digest is not a lowercase/uppercase SHA-256 hex value"
            )));
        }
    }
    let actual = canonical_point_list_sha256(&backend.response.points)
        .map_err(|error| VerificationFailure::Rejected(format!("point-list digest: {error}")))?;
    if actual != backend.point_list_sha256 {
        return Err(VerificationFailure::Rejected(
            "point-list digest does not match the retained points".to_owned(),
        ));
    }
    Ok(())
}

fn policy_from_request(policy: &SageRequestPolicy) -> SageBackendPolicy {
    SageBackendPolicy {
        distribution: policy.distribution.clone(),
        environment: policy.environment.clone(),
        conda_executable: policy.conda_executable.clone(),
        sage_version: policy.sage_version.clone(),
        python_version: policy.python_version.clone(),
        script_sha256: policy.script_sha256.clone(),
    }
}

fn status_for(solutions: &[UntrustedFamilySolution]) -> FamilyCertificateStatus {
    if solutions.is_empty() {
        FamilyCertificateStatus::CertifiedEmpty
    } else {
        FamilyCertificateStatus::CertifiedSolutions
    }
}

fn sort_solutions(solutions: &mut [UntrustedFamilySolution]) {
    solutions.sort_by(|left, right| left.q.cmp(&right.q).then_with(|| left.y.cmp(&right.y)));
}

fn canonical_points(points: &[UntrustedIntegralPoint]) -> Vec<(CanonicalInt, CanonicalInt)> {
    let mut values = points
        .iter()
        .map(|point| (point.x.clone(), point.y.clone()))
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn gcd(left: &CanonicalInt, right: &CanonicalInt) -> BigInt {
    let mut left = left.as_bigint().abs();
    let mut right = right.as_bigint().abs();
    while !right.is_zero() {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    left
}

fn isqrt_nonnegative(value: &BigInt) -> Option<BigInt> {
    let value = value.to_biguint()?;
    let root = isqrt(&value);
    if &root * &root == value {
        Some(BigInt::from_biguint(Sign::Plus, root))
    } else {
        None
    }
}

fn isqrt(value: &BigUint) -> BigUint {
    if value.is_zero() {
        return BigUint::zero();
    }
    let mut low = BigUint::zero();
    let mut high = BigUint::one() << ((value.bits() + 1) / 2 + 1);
    while low < high {
        let mid = (&low + &high + BigUint::one()) >> 1usize;
        if &mid * &mid <= *value {
            low = mid;
        } else {
            high = mid - BigUint::one();
        }
    }
    low
}

fn canonical_bigint(value: BigInt) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("BigInt formatting is canonical")
}

fn canonical_u64(value: u64) -> CanonicalInt {
    CanonicalInt::from_decimal(&value.to_string()).expect("u64 formatting is canonical")
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
