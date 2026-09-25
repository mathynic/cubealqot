//! Canonical decimal representation for arbitrary-size signed integers.

use std::{fmt, str::FromStr};

use num_bigint::BigInt;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A signed integer serialized as its canonical base-ten string.
///
/// JSON numbers are deliberately not used: they do not provide a portable
/// width-independent contract for values outside common machine integer
/// ranges.  Canonical input rejects signs such as `+1`, leading zeroes, and
/// negative zero, so one mathematical value has one wire representation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalInt(BigInt);

impl CanonicalInt {
    pub fn from_decimal(value: &str) -> Result<Self, ParseCanonicalIntError> {
        let parsed = BigInt::from_str(value).map_err(|_| ParseCanonicalIntError)?;
        if parsed.to_string() != value {
            return Err(ParseCanonicalIntError);
        }
        Ok(Self(parsed))
    }

    pub fn as_bigint(&self) -> &BigInt {
        &self.0
    }

    pub fn into_bigint(self) -> BigInt {
        self.0
    }
}

impl fmt::Display for CanonicalInt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for CanonicalInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

struct CanonicalIntVisitor;

impl<'de> de::Visitor<'de> for CanonicalIntVisitor {
    type Value = CanonicalInt;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a canonical signed decimal integer string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        CanonicalInt::from_decimal(value)
            .map_err(|_| E::custom(format!("invalid canonical decimal integer: {value:?}")))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }
}

impl<'de> Deserialize<'de> for CanonicalInt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(CanonicalIntVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseCanonicalIntError;

impl fmt::Display for ParseCanonicalIntError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("integer is not a canonical signed decimal string")
    }
}

impl std::error::Error for ParseCanonicalIntError {}
