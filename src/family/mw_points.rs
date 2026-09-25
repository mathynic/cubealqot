//! Exact, untrusted-input parsing for Mordell--Weil point candidates.
//!
//! A point file is research input, not a basis or a completeness claim.  The
//! parser nevertheless performs the exact checks needed before a candidate can
//! cross the Rust/Sage request boundary: canonical rational syntax, exact
//! original-model identity, and exact curve membership.  Discovery points are
//! deliberately separate from integral backend points and carry no theorem
//! authority.

use std::fmt;
use std::fs;
use std::path::Path;

use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::integer_io::CanonicalInt;
use super::problem::Problem;

pub const MW_POINT_FILE_KIND: &str = "m7_mw_point_candidates";
pub const MW_POINT_FILE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MwPointFileLimits {
    pub max_points: usize,
}

impl Default for MwPointFileLimits {
    fn default() -> Self {
        Self {
            max_points: 1_000_000,
        }
    }
}

/// A reduced rational in the canonical wire form `p` or `p/q`, with `q > 0`.
///
/// This type validates syntax and reduction, but not curve membership.  The
/// latter requires a `Problem` and is performed by `parse_mw_point_file` or
/// `validate_on_problem`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalRational {
    text: String,
    numerator: BigInt,
    denominator: BigInt,
}

impl CanonicalRational {
    pub fn parse(value: &str) -> Result<Self, String> {
        let parts = value.split('/').collect::<Vec<_>>();
        if parts.len() > 2 || parts.iter().any(|part| part.is_empty()) {
            return Err("rational must be p or p/q".to_owned());
        }

        let numerator = CanonicalInt::from_decimal(parts[0])
            .map_err(|_| "invalid rational numerator".to_owned())?
            .into_bigint();
        let denominator = if parts.len() == 1 {
            BigInt::from(1u8)
        } else {
            CanonicalInt::from_decimal(parts[1])
                .map_err(|_| "invalid rational denominator".to_owned())?
                .into_bigint()
        };

        if denominator <= BigInt::zero() {
            return Err("rational denominator must be positive".to_owned());
        }
        if parts.len() == 2 && denominator == BigInt::from(1u8) {
            return Err("denominator one must be omitted".to_owned());
        }
        if gcd(numerator.clone().abs(), denominator.clone()) != BigInt::from(1u8) {
            return Err("rational is not reduced".to_owned());
        }

        Ok(Self {
            text: value.to_owned(),
            numerator,
            denominator,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    fn numerator(&self) -> &BigInt {
        &self.numerator
    }

    fn denominator(&self) -> &BigInt {
        &self.denominator
    }
}

impl Serialize for CanonicalRational {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.text)
    }
}

struct CanonicalRationalVisitor;

impl<'de> Visitor<'de> for CanonicalRationalVisitor {
    type Value = CanonicalRational;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a canonical rational string p or p/q")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        CanonicalRational::parse(value).map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }
}

impl<'de> Deserialize<'de> for CanonicalRational {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CanonicalRationalVisitor)
    }
}

/// A canonical point retained in a validated point-file result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MwPoint {
    x: CanonicalRational,
    y: CanonicalRational,
}

impl MwPoint {
    pub fn x(&self) -> &CanonicalRational {
        &self.x
    }

    pub fn y(&self) -> &CanonicalRational {
        &self.y
    }

    pub fn validate_on_problem(&self, problem: &Problem) -> bool {
        point_on_curve(self, problem)
    }

    fn to_request_point(&self) -> SageDiscoveryPoint {
        SageDiscoveryPoint {
            x: self.x.clone(),
            y: self.y.clone(),
        }
    }
}

/// Canonical coordinate data embedded in a Sage request.
///
/// This wire type validates rational syntax when a historical request is
/// deserialized, but it is not a verified curve point by itself.  Callers that
/// admit or replay a request must validate it against the exact `Problem`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SageDiscoveryPoint {
    x: CanonicalRational,
    y: CanonicalRational,
}

impl SageDiscoveryPoint {
    pub fn x(&self) -> &CanonicalRational {
        &self.x
    }

    pub fn y(&self) -> &CanonicalRational {
        &self.y
    }

    pub fn validate_on_problem(&self, problem: &Problem) -> Result<MwPoint, String> {
        let point = MwPoint {
            x: self.x.clone(),
            y: self.y.clone(),
        };
        if point_on_curve(&point, problem) {
            Ok(point)
        } else {
            Err("point is not on the exact original curve".to_owned())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MwPointFile {
    n: CanonicalInt,
    curve_coefficients: [CanonicalInt; 5],
    points: Vec<MwPoint>,
}

impl MwPointFile {
    pub fn n(&self) -> &CanonicalInt {
        &self.n
    }

    pub fn curve_coefficients(&self) -> &[CanonicalInt; 5] {
        &self.curve_coefficients
    }

    pub fn points(&self) -> &[MwPoint] {
        &self.points
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MwPointFileError {
    Io {
        reason: String,
    },
    MalformedJson {
        reason: String,
    },
    KindMismatch {
        actual: String,
    },
    SchemaVersionMismatch {
        expected: u32,
        actual: u32,
    },
    ProblemIdentity {
        reason: String,
    },
    InvalidRational {
        index: usize,
        coordinate: &'static str,
        reason: String,
    },
    OffCurve {
        index: usize,
    },
    ResourceLimit {
        actual: usize,
        maximum: usize,
    },
}

impl fmt::Display for MwPointFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { reason } => write!(formatter, "point file I/O error: {reason}"),
            Self::MalformedJson { reason } => {
                write!(formatter, "malformed point file JSON: {reason}")
            }
            Self::KindMismatch { actual } => {
                write!(formatter, "unsupported point file kind: {actual:?}")
            }
            Self::SchemaVersionMismatch { expected, actual } => {
                write!(
                    formatter,
                    "point file schema version {actual}, expected {expected}"
                )
            }
            Self::ProblemIdentity { reason } => {
                write!(formatter, "point file problem mismatch: {reason}")
            }
            Self::InvalidRational {
                index,
                coordinate,
                reason,
            } => write!(
                formatter,
                "point {index} has invalid {coordinate} rational: {reason}"
            ),
            Self::OffCurve { index } => {
                write!(
                    formatter,
                    "point {index} is not on the exact original curve"
                )
            }
            Self::ResourceLimit { actual, maximum } => write!(
                formatter,
                "point file contains {actual} points, exceeding the limit {maximum}"
            ),
        }
    }
}

impl std::error::Error for MwPointFileError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMwPointFile {
    kind: String,
    schema_version: u32,
    n: CanonicalInt,
    curve_coefficients: [CanonicalInt; 5],
    points: Vec<RawMwPoint>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMwPoint {
    x: String,
    y: String,
}

pub fn parse_mw_point_file(
    bytes: &[u8],
    problem: &Problem,
) -> Result<MwPointFile, MwPointFileError> {
    parse_mw_point_file_with_limits(bytes, problem, MwPointFileLimits::default())
}

pub fn parse_mw_point_file_with_limits(
    bytes: &[u8],
    problem: &Problem,
    limits: MwPointFileLimits,
) -> Result<MwPointFile, MwPointFileError> {
    let raw: RawMwPointFile =
        serde_json::from_slice(bytes).map_err(|error| MwPointFileError::MalformedJson {
            reason: error.to_string(),
        })?;

    if raw.kind != MW_POINT_FILE_KIND {
        return Err(MwPointFileError::KindMismatch { actual: raw.kind });
    }
    if raw.schema_version != MW_POINT_FILE_SCHEMA_VERSION {
        return Err(MwPointFileError::SchemaVersionMismatch {
            expected: MW_POINT_FILE_SCHEMA_VERSION,
            actual: raw.schema_version,
        });
    }
    let expected_coefficients = problem.curve().coefficients();
    if raw.n != *problem.n() {
        return Err(MwPointFileError::ProblemIdentity {
            reason: "N does not match the validated Problem".to_owned(),
        });
    }
    if raw.curve_coefficients != expected_coefficients {
        return Err(MwPointFileError::ProblemIdentity {
            reason: "curve coefficients do not match the original model".to_owned(),
        });
    }
    if raw.points.len() > limits.max_points {
        return Err(MwPointFileError::ResourceLimit {
            actual: raw.points.len(),
            maximum: limits.max_points,
        });
    }

    let mut points = Vec::with_capacity(raw.points.len());
    for (index, raw_point) in raw.points.into_iter().enumerate() {
        let x = CanonicalRational::parse(&raw_point.x).map_err(|reason| {
            MwPointFileError::InvalidRational {
                index,
                coordinate: "x",
                reason,
            }
        })?;
        let y = CanonicalRational::parse(&raw_point.y).map_err(|reason| {
            MwPointFileError::InvalidRational {
                index,
                coordinate: "y",
                reason,
            }
        })?;
        let point = MwPoint { x, y };
        if !point_on_curve(&point, problem) {
            return Err(MwPointFileError::OffCurve { index });
        }
        points.push(point);
    }

    Ok(MwPointFile {
        n: raw.n,
        curve_coefficients: raw.curve_coefficients,
        points,
    })
}

pub fn load_mw_point_file(path: &Path, problem: &Problem) -> Result<MwPointFile, MwPointFileError> {
    load_mw_point_file_with_limits(path, problem, MwPointFileLimits::default())
}

pub fn load_mw_point_file_with_limits(
    path: &Path,
    problem: &Problem,
    limits: MwPointFileLimits,
) -> Result<MwPointFile, MwPointFileError> {
    let bytes = fs::read(path).map_err(|error| MwPointFileError::Io {
        reason: error.to_string(),
    })?;
    parse_mw_point_file_with_limits(&bytes, problem, limits)
}

pub(crate) fn request_points(points: Option<&[MwPoint]>) -> Option<Vec<SageDiscoveryPoint>> {
    points.map(|points| points.iter().map(MwPoint::to_request_point).collect())
}

fn point_on_curve(point: &MwPoint, problem: &Problem) -> bool {
    let coefficients = problem.curve().coefficients();
    let a1 = coefficients[0].as_bigint();
    let a2 = coefficients[1].as_bigint();
    let a3 = coefficients[2].as_bigint();
    let a4 = coefficients[3].as_bigint();
    let a6 = coefficients[4].as_bigint();
    let nx = point.x.numerator();
    let dx = point.x.denominator();
    let ny = point.y.numerator();
    let dy = point.y.denominator();

    // Multiply the general Weierstrass equation by dy^2*dx^3.  No floating
    // point or bounded integer conversion is involved.
    let lhs = ny.pow(2) * dx.pow(3) + a1 * nx * ny * dy * dx.pow(2) + a3 * ny * dy * dx.pow(3);
    let rhs = nx.pow(3) * dy.pow(2)
        + a2 * nx.pow(2) * dx * dy.pow(2)
        + a4 * nx * dx.pow(2) * dy.pow(2)
        + a6 * dx.pow(3) * dy.pow(2);
    lhs == rhs
}

fn gcd(mut left: BigInt, mut right: BigInt) -> BigInt {
    while !right.is_zero() {
        let remainder = left % &right;
        left = right;
        right = remainder;
    }
    left.abs()
}
