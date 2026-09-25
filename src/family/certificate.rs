use serde::{Deserialize, Serialize};

use crate::family::integer_io::CanonicalInt;

/// A point received from an external backend.  Deserialization does not
/// validate the original equation or establish completeness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedIntegralPoint {
    pub x: CanonicalInt,
    pub y: CanonicalInt,
}

/// Backend-supplied metadata.  It identifies an artifact but is not itself a
/// proof of completeness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedCompletenessProof {
    pub kind: String,
    pub artifact_digest: Option<String>,
}

/// Wire data is always untrusted, including when its `complete` bit is true.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UntrustedCertificate {
    pub schema_version: u32,
    pub n: CanonicalInt,
    pub backend: String,
    pub complete: bool,
    pub points: Vec<UntrustedIntegralPoint>,
    pub proof: Option<UntrustedCompletenessProof>,
}

/// A point owned by an admitted theorem.  It is intentionally distinct from
/// `UntrustedIntegralPoint` and has no deserialization implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedIntegralPoint {
    x: CanonicalInt,
    y: CanonicalInt,
}

impl VerifiedIntegralPoint {
    pub fn x(&self) -> &CanonicalInt {
        &self.x
    }

    pub fn y(&self) -> &CanonicalInt {
        &self.y
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    IncompleteClaim,
    CompletenessUnverified,
}

/// A theorem admitted by a future independently qualified verifier.
///
/// No public constructor exists in this scaffold.  In particular,
/// deserializing `UntrustedCertificate { complete: true, .. }` cannot create
/// this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTheorem {
    n: CanonicalInt,
    points: Vec<VerifiedIntegralPoint>,
}

impl VerifiedTheorem {
    pub fn n(&self) -> &CanonicalInt {
        &self.n
    }

    pub fn points(&self) -> &[VerifiedIntegralPoint] {
        &self.points
    }
}

/// The M7-04 boundary intentionally has no trusted admission path yet.
/// Later verifier work must supply independently established evidence instead
/// of turning a serialized flag into a theorem.
pub fn admit(certificate: UntrustedCertificate) -> Result<VerifiedTheorem, AdmissionError> {
    if !certificate.complete {
        return Err(AdmissionError::IncompleteClaim);
    }
    Err(AdmissionError::CompletenessUnverified)
}
