//! Arithmetic building blocks for the cube aliquot-sum search.
//!
//! Search stages are introduced incrementally as small, independently testable
//! modules.

pub mod cross;
pub mod exact;
pub mod factor;
pub mod family;
pub mod filters;
pub mod numth;
pub mod profile;
pub mod spf;
pub mod stats;
pub mod survivors;
pub mod tables;
pub mod validate;

pub use cross::CrossHit;
pub use factor::{Candidate, Factor, MAX_OMEGA, Prime, Root, factor_into};
pub use spf::{FLAT_SPF_LIMIT, MAX_BASE_PRIME_LIMIT, SEGMENT_WIDTH, SegmentedSpf, build_spf};
pub use survivors::partition_range;
