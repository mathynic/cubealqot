use std::{fs, path::PathBuf};

use cubealqot::{Candidate, Factor, MAX_OMEGA, cross, survivors};

fn candidate(m: u64, factors: &[(u64, u32)]) -> Candidate {
    let mut slots = [Factor::default(); MAX_OMEGA];
    for (slot, &(p, e)) in slots.iter_mut().zip(factors) {
        *slot = Factor { p, e };
    }
    Candidate::from_factors(m, slots, factors.len() as u8)
}

fn temp_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cubealqot-cross-wide-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

#[test]
fn wide_prime_cross_hit_is_exact_and_aggregated() {
    let source = 4_294_967_389u64;
    assert_eq!(cross::exact_cross_hit_value(5, source, 1), Some(1));
    assert_eq!(cross::cross_hit(5, source, 1).map(|hit| hit.val), Some(1));

    let mut candidate = candidate(5 * source, &[(5, 1), (source, 1)]);
    let hits = cross::cross_hits(&mut candidate);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].target, 5);
    assert_eq!(hits[0].source, source);
    assert_eq!(hits[0].val, 1);
    assert_eq!(candidate.cross_val[0], 1);
}

#[test]
fn wide_cross_hit_is_preserved_in_singleton_jsonl_diagnostics() {
    let source = 4_294_967_389u64;
    let m = 5 * source;
    let output_path = temp_path("jsonl");

    let output =
        survivors::stream_jsonl_range(&output_path, m, m, 1, cubealqot::filters::Stage::F1)
            .expect("wide diagnostic singleton should run");
    assert_eq!(output.stats.tested, 1);
    assert_eq!(output.records_written, 1);

    let records = survivors::read_jsonl(&output_path).expect("JSONL should parse");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].m, m);
    assert_eq!(records[0].cross.len(), 1);
    assert_eq!(records[0].cross[0].t, 5);
    assert_eq!(records[0].cross[0].s, source);
    assert_eq!(records[0].cross[0].v, 1);

    let _ = fs::remove_file(output_path);
}
