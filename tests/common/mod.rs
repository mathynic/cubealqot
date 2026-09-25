//! Shared support for integration tests.
//!
//! The helpers in this module deliberately do not calculate any aliquot sums.
//! They only load and validate the frozen test inputs used by later milestones.

use std::{fs, path::PathBuf};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct FixtureFile {
    pub schema_version: u32,
    pub vectors: Vec<SmokeVector>,
}

#[derive(Debug, Deserialize)]
pub struct SmokeVector {
    pub m: u32,
    pub s: u128,
    pub trace: Vec<String>,
    pub expected_stage: String,
    pub rejection: String,
}

pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

pub fn read_fixture(name: &str) -> FixtureFile {
    let path = fixture_path(name);
    let contents = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read fixture {}: {error}", path.display()));

    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("could not parse fixture {}: {error}", path.display()))
}

pub fn assert_smoke_vector_shape(vector: &SmokeVector) {
    assert!(vector.m > 1, "fixture m must be greater than one");
    assert!(vector.s > 0, "fixture aliquot sum must be positive");
    assert!(!vector.trace.is_empty(), "fixture trace must not be empty");
    assert_eq!(
        vector.trace.last().map(String::as_str),
        Some(vector.expected_stage.as_str()),
        "fixture trace must end at the expected stage"
    );
    assert!(
        !vector.rejection.is_empty(),
        "fixture rejection must be named"
    );
}

pub fn assert_unique_m(vectors: &[SmokeVector]) {
    for (index, left) in vectors.iter().enumerate() {
        assert!(
            vectors[index + 1..].iter().all(|right| right.m != left.m),
            "fixture contains duplicate m={}",
            left.m
        );
    }
}
