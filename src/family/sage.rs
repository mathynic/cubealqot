//! Production Sage 10.8 subprocess adapter.
//!
//! The adapter is an evidence-preserving, fail-closed transport boundary.  A
//! complete result is emitted only after a successful process exit, exact
//! request/response identity checks, proof/basis/model checks, and exact
//! original-curve validation of every returned affine point.  It is still an
//! untrusted backend result until a later certificate-admission turn.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::certificate::UntrustedIntegralPoint;
use super::integer_io::CanonicalInt;
pub use super::mw_points::SageDiscoveryPoint;
use super::mw_points::{MwPoint, request_points};
use super::problem::Problem;

pub const SAGE_ADAPTER_SCHEMA_VERSION: u32 = 1;
pub const ORIGINAL_INTEGRAL_MODEL: &str = "original_integral_model";
pub const QUALIFIED_SAGE_HELPER_SHA256: &str =
    "88196fd1f3a90b1bbad9a6a5a6a0c46ce8d8b0fa1d99fdff31727c3923f56c9a";
pub const QUALIFIED_MW04_HELPER_SHA256: &str =
    "027675a9b441f6ad92b6ca853884cf8e2385b28b11e4113777dc46866cc07857";
pub const QUALIFIED_MW04_BASE_SHA256: &str =
    "88196fd1f3a90b1bbad9a6a5a6a0c46ce8d8b0fa1d99fdff31727c3923f56c9a";

fn configured_conda_executable() -> String {
    const KEY: &str = "CUBEALQOT_CONDA_EXECUTABLE";
    if let Ok(value) = std::env::var(KEY) {
        if !value.trim().is_empty() {
            return value.trim().to_owned();
        }
    }

    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env.local");
    if let Ok(contents) = fs::read_to_string(config) {
        for line in contents.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == KEY {
                let value = value
                    .trim()
                    .trim_matches(|character| character == '\'' || character == '"');
                if !value.is_empty() {
                    return value.to_owned();
                }
            }
        }
    }

    "conda".to_owned()
}
pub const QUALIFIED_MW04_MW02_SHA256: &str =
    "19ca0c840d8d2fb7c96a23242063335e67f8e490f911cda5d1435e7eeb0b8241";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SageBackendPolicy {
    pub distribution: String,
    pub environment: String,
    pub conda_executable: String,
    pub sage_version: String,
    pub python_version: String,
    pub script_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub problem: SageProblemIdentity,
    pub policy: SageRequestPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery_points: Option<Vec<SageDiscoveryPoint>>,
}

impl SageRequest {
    pub fn for_problem(request_id: String, problem: &Problem, policy: &SageBackendPolicy) -> Self {
        Self::for_problem_with_discovery_points(request_id, problem, policy, None)
    }

    pub fn for_problem_with_discovery_points(
        request_id: String,
        problem: &Problem,
        policy: &SageBackendPolicy,
        discovery_points: Option<&[MwPoint]>,
    ) -> Self {
        Self {
            schema_version: SAGE_ADAPTER_SCHEMA_VERSION,
            request_id,
            problem: SageProblemIdentity::from_problem(problem),
            policy: SageRequestPolicy::from_backend_policy(policy),
            discovery_points: request_points(discovery_points),
        }
    }

    /// Rebuild the immutable discovery witnesses embedded in this request.
    ///
    /// Replay must use this value rather than reopening the point-file path
    /// that produced the initial request.  The curve membership check is
    /// repeated against the exact validated Problem so a malformed or
    /// mutated certificate cannot turn a hint into proof authority.
    pub fn validated_discovery_points(
        &self,
        problem: &Problem,
    ) -> Result<Option<Vec<MwPoint>>, String> {
        self.discovery_points
            .as_ref()
            .map(|points| {
                points
                    .iter()
                    .map(|point| point.validate_on_problem(problem))
                    .collect()
            })
            .transpose()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageRequestPolicy {
    pub distribution: String,
    pub environment: String,
    pub conda_executable: String,
    pub sage_version: String,
    pub python_version: String,
    pub script_sha256: String,
    pub proof_all: bool,
    pub rank_proof: bool,
    pub generators_proof: bool,
    pub require_gens_certain: bool,
    pub both_signs: bool,
    pub model_semantics: String,
}

impl SageRequestPolicy {
    fn from_backend_policy(policy: &SageBackendPolicy) -> Self {
        Self {
            distribution: policy.distribution.clone(),
            environment: policy.environment.clone(),
            conda_executable: policy.conda_executable.clone(),
            sage_version: policy.sage_version.clone(),
            python_version: policy.python_version.clone(),
            script_sha256: policy.script_sha256.clone(),
            proof_all: true,
            rank_proof: true,
            generators_proof: true,
            require_gens_certain: true,
            both_signs: true,
            model_semantics: ORIGINAL_INTEGRAL_MODEL.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageProblemIdentity {
    pub n: CanonicalInt,
    pub factors: Vec<SageFactorIdentity>,
    pub a: CanonicalInt,
    pub d: CanonicalInt,
    pub curve_coefficients: [CanonicalInt; 5],
}

impl SageProblemIdentity {
    fn from_problem(problem: &Problem) -> Self {
        Self {
            n: problem.n().clone(),
            factors: problem
                .factors()
                .iter()
                .map(|factor| SageFactorIdentity {
                    prime: factor.prime().clone(),
                    exponent: factor.exponent(),
                })
                .collect(),
            a: problem.a().clone(),
            d: problem.d().clone(),
            curve_coefficients: problem.curve().coefficients(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageFactorIdentity {
    pub prime: CanonicalInt,
    pub exponent: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageResponseProof {
    pub proof_all: bool,
    pub rank_proven: bool,
    pub rank: CanonicalInt,
    pub generators: Vec<SageGenerator>,
    pub gens_certain: bool,
    pub both_signs: bool,
    pub integral_points_complete: bool,
    pub torsion_order: CanonicalInt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageGenerator {
    pub x: SageRational,
    pub y: SageRational,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageResponseModel {
    pub semantics: String,
    pub curve_coefficients: [CanonicalInt; 5],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageResponseBackend {
    pub name: String,
    pub sage_version: String,
    pub python_version: String,
    pub environment: String,
    pub distribution: String,
    pub script_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SageRational {
    pub value: String,
}

impl SageRational {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UntrustedSageResponse {
    pub schema_version: u32,
    pub request_id: String,
    pub ok: bool,
    pub complete: bool,
    pub problem: SageProblemIdentity,
    pub proof: SageResponseProof,
    pub model: SageResponseModel,
    pub points: Vec<UntrustedIntegralPoint>,
    pub backend: SageResponseBackend,
}

pub type SageResponse = UntrustedSageResponse;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SageValidatedCompletion {
    request: SageRequest,
    response: UntrustedSageResponse,
}

impl SageValidatedCompletion {
    pub fn request(&self) -> &SageRequest {
        &self.request
    }

    pub fn response(&self) -> &UntrustedSageResponse {
        &self.response
    }

    pub fn points(&self) -> &[UntrustedIntegralPoint] {
        &self.response.points
    }

    pub fn proof(&self) -> &SageResponseProof {
        &self.response.proof
    }

    pub fn backend(&self) -> &SageResponseBackend {
        &self.response.backend
    }

    pub fn model(&self) -> &SageResponseModel {
        &self.response.model
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SageValidationError {
    MalformedResponse { reason: String },
    SchemaVersionMismatch { expected: u32, actual: u32 },
    RequestIdentityMismatch { expected: String, actual: String },
    ProblemIdentityMismatch { reason: String },
    PolicyMismatch { reason: String },
    NotComplete { reason: String },
    BackendIdentityMismatch { reason: String },
    UnsupportedModelSemantics { actual: String },
    ProofContract { reason: String },
    OffCurvePoint { index: usize },
    DiscoveryPointMismatch { index: usize, reason: String },
}

pub fn parse_sage_response(bytes: &[u8]) -> Result<UntrustedSageResponse, SageValidationError> {
    serde_json::from_slice(bytes).map_err(|error| SageValidationError::MalformedResponse {
        reason: error.to_string(),
    })
}

pub fn validate_sage_response(
    problem: &Problem,
    request: &SageRequest,
    response: UntrustedSageResponse,
    policy: &SageBackendPolicy,
) -> Result<SageValidatedCompletion, SageValidationError> {
    if request.schema_version != SAGE_ADAPTER_SCHEMA_VERSION {
        return Err(SageValidationError::SchemaVersionMismatch {
            expected: SAGE_ADAPTER_SCHEMA_VERSION,
            actual: request.schema_version,
        });
    }
    if response.schema_version != SAGE_ADAPTER_SCHEMA_VERSION {
        return Err(SageValidationError::SchemaVersionMismatch {
            expected: SAGE_ADAPTER_SCHEMA_VERSION,
            actual: response.schema_version,
        });
    }
    if response.request_id != request.request_id {
        return Err(SageValidationError::RequestIdentityMismatch {
            expected: request.request_id.clone(),
            actual: response.request_id,
        });
    }
    if !response.ok || !response.complete {
        return Err(SageValidationError::NotComplete {
            reason: "backend did not return a successful complete response".to_owned(),
        });
    }

    let expected_problem = SageProblemIdentity::from_problem(problem);
    if request.problem != expected_problem {
        return Err(SageValidationError::ProblemIdentityMismatch {
            reason: "request problem identity does not match validated Problem".to_owned(),
        });
    }
    if response.problem != request.problem {
        return Err(SageValidationError::ProblemIdentityMismatch {
            reason: "response problem identity does not match request".to_owned(),
        });
    }

    let expected_policy = SageRequestPolicy::from_backend_policy(policy);
    if request.policy != expected_policy {
        return Err(SageValidationError::PolicyMismatch {
            reason: "request proof/backend policy does not match the selected M7 policy".to_owned(),
        });
    }
    validate_backend(&response.backend, policy)?;

    if response.model.semantics != ORIGINAL_INTEGRAL_MODEL {
        return Err(SageValidationError::UnsupportedModelSemantics {
            actual: response.model.semantics,
        });
    }
    if response.model.curve_coefficients != expected_problem.curve_coefficients {
        return Err(SageValidationError::ProblemIdentityMismatch {
            reason: "response model coefficients do not match the original curve".to_owned(),
        });
    }
    if let Some(discovery_points) = &request.discovery_points {
        for (index, point) in discovery_points.iter().enumerate() {
            point
                .validate_on_problem(problem)
                .map_err(|reason| SageValidationError::DiscoveryPointMismatch { index, reason })?;
        }
    }
    validate_proof(&response.proof, &request.policy)?;

    let mut point_set = BTreeSet::new();
    for (index, point) in response.points.iter().enumerate() {
        if point.y.as_bigint() * point.y.as_bigint()
            != problem.curve_rhs(&point.x).as_bigint().clone()
        {
            return Err(SageValidationError::OffCurvePoint { index });
        }
        if !point_set.insert((point.x.clone(), point.y.clone())) {
            return Err(SageValidationError::ProofContract {
                reason: format!("duplicate affine point at index {index}"),
            });
        }
    }

    Ok(SageValidatedCompletion {
        request: request.clone(),
        response,
    })
}

fn validate_backend(
    backend: &SageResponseBackend,
    policy: &SageBackendPolicy,
) -> Result<(), SageValidationError> {
    let checks = [
        (backend.name.as_str(), "SageMath", "backend name"),
        (
            backend.sage_version.as_str(),
            policy.sage_version.as_str(),
            "Sage version",
        ),
        (
            backend.python_version.as_str(),
            policy.python_version.as_str(),
            "Python version",
        ),
        (
            backend.environment.as_str(),
            policy.environment.as_str(),
            "conda environment",
        ),
        (
            backend.distribution.as_str(),
            policy.distribution.as_str(),
            "WSL distribution",
        ),
        (
            backend.script_sha256.as_str(),
            policy.script_sha256.as_str(),
            "helper script digest",
        ),
    ];
    for (actual, expected, label) in checks {
        if actual != expected {
            return Err(SageValidationError::BackendIdentityMismatch {
                reason: format!("{label}: expected {expected:?}, got {actual:?}"),
            });
        }
    }
    Ok(())
}

fn validate_proof(
    proof: &SageResponseProof,
    policy: &SageRequestPolicy,
) -> Result<(), SageValidationError> {
    if !policy.proof_all || !proof.proof_all {
        return Err(SageValidationError::ProofContract {
            reason: "Sage proof.all(True) was not established".to_owned(),
        });
    }
    if !policy.rank_proof || !proof.rank_proven {
        return Err(SageValidationError::ProofContract {
            reason: "rank proof was not established".to_owned(),
        });
    }
    if !policy.generators_proof || !proof.gens_certain {
        return Err(SageValidationError::ProofContract {
            reason: "Mordell-Weil generators are not proven certain".to_owned(),
        });
    }
    if !policy.require_gens_certain || !proof.both_signs || !proof.integral_points_complete {
        return Err(SageValidationError::ProofContract {
            reason: "integral-point completeness settings are not established".to_owned(),
        });
    }
    let rank =
        nonnegative_usize(&proof.rank).map_err(|reason| SageValidationError::ProofContract {
            reason: format!("invalid proven rank: {reason}"),
        })?;
    if proof.generators.len() != rank {
        return Err(SageValidationError::ProofContract {
            reason: format!(
                "generator count {} does not equal proven rank {rank}",
                proof.generators.len()
            ),
        });
    }
    if proof.torsion_order.as_bigint() <= &BigInt::zero() {
        return Err(SageValidationError::ProofContract {
            reason: "torsion order must be positive".to_owned(),
        });
    }
    for generator in &proof.generators {
        for coordinate in [&generator.x.value, &generator.y.value] {
            validate_rational(coordinate).map_err(|reason| SageValidationError::ProofContract {
                reason: format!("invalid generator coordinate: {reason}"),
            })?;
        }
    }
    Ok(())
}

fn nonnegative_usize(value: &CanonicalInt) -> Result<usize, String> {
    if value.as_bigint().sign() == Sign::Minus {
        return Err("rank is negative".to_owned());
    }
    value
        .as_bigint()
        .to_usize()
        .ok_or_else(|| "rank exceeds the implementation index width".to_owned())
}

fn validate_rational(value: &str) -> Result<(), String> {
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.len() > 2 || parts.iter().any(|part| part.is_empty()) {
        return Err("not a canonical rational".to_owned());
    }
    let numerator = CanonicalInt::from_decimal(parts[0])
        .map_err(|_| "invalid rational numerator".to_owned())?;
    if parts.len() == 2 {
        let denominator = CanonicalInt::from_decimal(parts[1])
            .map_err(|_| "invalid rational denominator".to_owned())?;
        if denominator.as_bigint() <= &BigInt::zero() {
            return Err("rational denominator must be positive".to_owned());
        }
        let gcd = gcd(
            numerator.as_bigint().clone().abs(),
            denominator.as_bigint().clone(),
        );
        if gcd != BigInt::from(1u8) {
            return Err("rational is not reduced".to_owned());
        }
    }
    Ok(())
}

fn gcd(mut left: BigInt, mut right: BigInt) -> BigInt {
    while !right.is_zero() {
        let remainder = left % &right;
        left = right;
        right = remainder;
    }
    left.abs()
}

#[derive(Clone, Debug)]
pub struct SageAdapterConfig {
    pub launcher: PathBuf,
    pub helper: PathBuf,
    pub powershell_executable: String,
    pub distribution: String,
    pub conda_executable: String,
    pub environment: String,
    pub timeout: Duration,
    pub evidence_dir: PathBuf,
    pub policy: SageBackendPolicy,
    pub extra_launcher_args: Vec<String>,
}

impl SageAdapterConfig {
    pub fn m7_default(evidence_dir: PathBuf) -> io::Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let helper = root.join("scripts/m7/sage_integral_points.py");
        let script_sha256 = sha256_file(&helper)?;
        if script_sha256 != QUALIFIED_SAGE_HELPER_SHA256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Sage helper digest is not the qualified PQ-02 helper: expected {}, got {}",
                    QUALIFIED_SAGE_HELPER_SHA256, script_sha256
                ),
            ));
        }
        let policy = SageBackendPolicy {
            distribution: "Ubuntu-26.04".to_owned(),
            environment: "cubealqot-m7".to_owned(),
            conda_executable: configured_conda_executable(),
            sage_version: "10.8".to_owned(),
            python_version: "3.14.7".to_owned(),
            script_sha256,
        };
        Ok(Self {
            launcher: root.join("scripts/m7/invoke-sage.ps1"),
            helper,
            powershell_executable: "powershell.exe".to_owned(),
            distribution: policy.distribution.clone(),
            conda_executable: policy.conda_executable.clone(),
            environment: policy.environment.clone(),
            timeout: Duration::from_secs(60),
            evidence_dir,
            policy,
            extra_launcher_args: Vec::new(),
        })
    }

    /// MW-04 entrypoint.  This is selected only for requests carrying
    /// discovery witnesses; the legacy helper remains available for
    /// historical no-hint proofs while the active campaign is running.
    pub fn m7_mw04_default(evidence_dir: PathBuf) -> io::Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let helper = root.join("scripts/m7/sage_integral_points_mw04.py");
        let base_helper = root.join("scripts/m7/sage_integral_points.py");
        let mw02_helper = root.join("scripts/m7/mw02_rank_basis.py");
        let script_sha256 = sha256_file(&helper)?;
        if script_sha256 != QUALIFIED_MW04_HELPER_SHA256
            || sha256_file(&base_helper)? != QUALIFIED_MW04_BASE_SHA256
            || sha256_file(&mw02_helper)? != QUALIFIED_MW04_MW02_SHA256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MW-04 Sage implementation dependency digest is not qualified",
            ));
        }
        let policy = SageBackendPolicy {
            distribution: "Ubuntu-26.04".to_owned(),
            environment: "cubealqot-m7".to_owned(),
            conda_executable: configured_conda_executable(),
            sage_version: "10.8".to_owned(),
            python_version: "3.14.7".to_owned(),
            script_sha256,
        };
        Ok(Self {
            launcher: root.join("scripts/m7/invoke-sage.ps1"),
            helper,
            powershell_executable: "powershell.exe".to_owned(),
            distribution: policy.distribution.clone(),
            conda_executable: policy.conda_executable.clone(),
            environment: policy.environment.clone(),
            timeout: Duration::from_secs(60),
            evidence_dir,
            policy,
            extra_launcher_args: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SageRunEvidence {
    pub job_id: String,
    pub request_path: PathBuf,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub request_sha256: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SageAdapterResult {
    Complete {
        completion: SageValidatedCompletion,
        evidence: SageRunEvidence,
    },
    Inconclusive {
        reason: String,
        partial_points: Vec<UntrustedIntegralPoint>,
        evidence: Option<SageRunEvidence>,
    },
}

#[derive(Debug)]
pub struct SageAdapter {
    config: SageAdapterConfig,
}

impl SageAdapter {
    pub fn new(config: SageAdapterConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SageAdapterConfig {
        &self.config
    }

    pub fn enumerate(&self, problem: &Problem) -> SageAdapterResult {
        self.enumerate_with_discovery_points(problem, None)
    }

    pub fn enumerate_with_discovery_points(
        &self,
        problem: &Problem,
        discovery_points: Option<&[MwPoint]>,
    ) -> SageAdapterResult {
        let job_id = next_job_id();
        let request = SageRequest::for_problem_with_discovery_points(
            job_id.clone(),
            problem,
            &self.config.policy,
            discovery_points,
        );
        let job_dir = self.config.evidence_dir.join(&job_id);
        if let Err(error) = fs::create_dir_all(&job_dir) {
            return inconclusive(format!("could not create evidence directory: {error}"));
        }
        let request_path = job_dir.join("request.json");
        let stdout_path = job_dir.join("response.json");
        let stderr_path = job_dir.join("backend.log");
        let request_bytes = match serde_json::to_vec_pretty(&request) {
            Ok(mut bytes) => {
                bytes.push(b'\n');
                bytes
            }
            Err(error) => {
                return inconclusive(format!("could not serialize Sage request: {error}"));
            }
        };
        if let Err(error) = fs::write(&request_path, &request_bytes) {
            return inconclusive(format!("could not retain Sage request: {error}"));
        }

        let process = self.run_process(&request_path);
        let evidence = match retain_evidence(
            &job_id,
            &request_path,
            &stdout_path,
            &stderr_path,
            &request_bytes,
            &process.stdout,
            &process.stderr,
            process.status,
            process.timed_out,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                return SageAdapterResult::Inconclusive {
                    reason: format!("could not retain Sage transcript: {error}"),
                    partial_points: Vec::new(),
                    evidence: None,
                };
            }
        };

        if process.timed_out {
            return SageAdapterResult::Inconclusive {
                reason: format!(
                    "Sage backend deadline expired after {:?}",
                    self.config.timeout
                ),
                partial_points: Vec::new(),
                evidence: Some(evidence),
            };
        }
        let Some(status) = process.status else {
            return SageAdapterResult::Inconclusive {
                reason: "Sage process did not report an exit status".to_owned(),
                partial_points: Vec::new(),
                evidence: Some(evidence),
            };
        };
        if !status.success() {
            return SageAdapterResult::Inconclusive {
                reason: format!("Sage backend exited unsuccessfully: {status}"),
                partial_points: Vec::new(),
                evidence: Some(evidence),
            };
        }

        let response = match parse_sage_response(&process.stdout) {
            Ok(response) => response,
            Err(error) => {
                return SageAdapterResult::Inconclusive {
                    reason: format!("Sage response was malformed: {error:?}"),
                    partial_points: Vec::new(),
                    evidence: Some(evidence),
                };
            }
        };
        if !response.ok || !response.complete {
            return SageAdapterResult::Inconclusive {
                reason: "Sage returned partial or non-complete output".to_owned(),
                partial_points: response.points,
                evidence: Some(evidence),
            };
        }
        match validate_sage_response(problem, &request, response, &self.config.policy) {
            Ok(completion) => SageAdapterResult::Complete {
                completion,
                evidence,
            },
            Err(error) => SageAdapterResult::Inconclusive {
                reason: format!("Sage completion failed contract validation: {error:?}"),
                partial_points: Vec::new(),
                evidence: Some(evidence),
            },
        }
    }

    fn run_process(&self, request_path: &Path) -> ProcessOutput {
        let mut command = Command::new(&self.config.powershell_executable);
        command
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-File")
            .arg(&self.config.launcher)
            .arg("-RequestFile")
            .arg(request_path)
            .arg("-HelperFile")
            .arg(&self.config.helper)
            .arg("-Distribution")
            .arg(&self.config.distribution)
            .arg("-CondaExecutable")
            .arg(&self.config.conda_executable)
            .arg("-Environment")
            .arg(&self.config.environment)
            .args(&self.config.extra_launcher_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                return ProcessOutput {
                    stdout: Vec::new(),
                    stderr: error.to_string().into_bytes(),
                    status: None,
                    timed_out: false,
                };
            }
        };
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let stdout_thread = thread::spawn(move || read_pipe(stdout));
        let stderr_thread = thread::spawn(move || read_pipe(stderr));
        let deadline = Instant::now() + self.config.timeout;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() >= deadline => {
                    timed_out = true;
                    terminate_process_tree(&mut child);
                    break child.wait().ok();
                }
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => break child.wait().ok(),
            }
        };
        let stdout = stdout_thread.join().unwrap_or_else(|_| Vec::new());
        let stderr = stderr_thread.join().unwrap_or_else(|_| Vec::new());
        ProcessOutput {
            stdout,
            stderr,
            status,
            timed_out,
        }
    }
}

struct ProcessOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: Option<ExitStatus>,
    timed_out: bool,
}

fn read_pipe<R: Read>(mut reader: R) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.read_to_end(&mut bytes);
    bytes
}

fn terminate_process_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

fn retain_evidence(
    job_id: &str,
    request_path: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
    request: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    status: Option<ExitStatus>,
    timed_out: bool,
) -> io::Result<SageRunEvidence> {
    File::create(stdout_path)?.write_all(stdout)?;
    File::create(stderr_path)?.write_all(stderr)?;
    Ok(SageRunEvidence {
        job_id: job_id.to_owned(),
        request_path: request_path.to_path_buf(),
        stdout_path: stdout_path.to_path_buf(),
        stderr_path: stderr_path.to_path_buf(),
        request_sha256: sha256_bytes(request),
        stdout_sha256: sha256_bytes(stdout),
        stderr_sha256: sha256_bytes(stderr),
        exit_code: status.and_then(|status| status.code()),
        timed_out,
    })
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn next_job_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "m7-sage-{}-{}-{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn inconclusive(reason: String) -> SageAdapterResult {
    SageAdapterResult::Inconclusive {
        reason,
        partial_points: Vec::new(),
        evidence: None,
    }
}
