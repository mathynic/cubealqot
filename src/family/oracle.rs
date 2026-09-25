use crate::family::certificate::UntrustedIntegralPoint;

pub use crate::family::problem::FamilyProblem;

/// The result of asking a backend for integral points.  `Complete` is still
/// an untrusted backend assertion until a verifier admits it; it is not a
/// `FamilyStatus`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleResult {
    Complete {
        points: Vec<UntrustedIntegralPoint>,
    },
    Inconclusive {
        reason: String,
        partial_points: Vec<UntrustedIntegralPoint>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OracleError {
    BackendUnavailable { backend: String, reason: String },
    RequestFailed { backend: String, reason: String },
}

pub trait IntegralPointsOracle {
    fn integral_points(&self, problem: &FamilyProblem) -> Result<OracleResult, OracleError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FamilyStatus {
    CertifiedEmpty,
    CertifiedSolutions,
    Inconclusive,
}

/// Convert only the pre-verification backend boundary to state.  No backend
/// result can become certified during M7-04; future verifier code must return
/// a `VerifiedTheorem` after checking the original equation and completeness.
pub fn status_from_oracle(result: Result<OracleResult, OracleError>) -> FamilyStatus {
    match result {
        Ok(OracleResult::Complete { .. }) | Ok(OracleResult::Inconclusive { .. }) | Err(_) => {
            FamilyStatus::Inconclusive
        }
    }
}
