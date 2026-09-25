//! Tests for the test harness itself.
//!
//! This module is intentionally independent of the search implementation. It
//! establishes fixture loading and trace-shape contracts before the search
//! pipeline modules are introduced.

mod common;

use common::{assert_smoke_vector_shape, assert_unique_m, read_fixture};

#[test]
fn frozen_smoke_fixture_loads() {
    let fixture = read_fixture("vectors.json");

    assert_eq!(fixture.schema_version, 1);
    assert!(!fixture.vectors.is_empty());
    assert_unique_m(&fixture.vectors);

    for vector in &fixture.vectors {
        assert_smoke_vector_shape(vector);
    }
}

#[test]
fn reviewed_plan_smoke_seeds_are_present() {
    let fixture = read_fixture("vectors.json");
    let actual: Vec<u32> = fixture.vectors.iter().map(|vector| vector.m).collect();

    assert_eq!(actual, [2, 7, 6, 12, 15, 18, 21]);
}

#[test]
#[ignore = "manual harness check: this test must fail when explicitly run"]
fn deliberate_failure_proves_scaffold_is_live() {
    panic!("deliberate scaffold failure");
}
