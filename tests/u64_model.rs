use std::{fs, path::PathBuf};

use cubealqot::survivors::{
    Checkpoint, ShardMetadata, config_hash, read_checkpoint, write_checkpoint,
};
use cubealqot::tables::SigmaTable;
use cubealqot::{Candidate, Factor, MAX_OMEGA, Prime, partition_range};

fn temp_path(label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cubealqot-u64-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

#[test]
fn sigma_table_accepts_the_widened_maximum_exponent() {
    let table = SigmaTable::build(5, 63);
    assert_eq!(table.stride, 64);
    assert_eq!(table.sigma(2u64, 63), table.tab[2usize * 64 + 63]);
}

#[test]
fn wide_root_and_prime_are_representable_without_narrowing() {
    let root = u64::from(u32::MAX) + 1;
    let prime: Prime = u64::from(u32::MAX) + 15;
    let mut factors = [Factor::default(); MAX_OMEGA];
    factors[0] = Factor { p: prime, e: 63 };

    let candidate = Candidate::from_factors(root, factors, 1);
    assert_eq!(candidate.m, root);
    assert_eq!(candidate.f[0], Factor { p: prime, e: 63 });
    assert_eq!(MAX_OMEGA, 15);
}

#[test]
fn checkpoint_positions_round_trip_at_u64_boundaries() {
    for value in [
        u64::from(u32::MAX) - 1,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::from(u32::MAX) + 2,
        u64::MAX - 1,
        u64::MAX,
    ] {
        let path = temp_path("checkpoint");
        let checkpoint = Checkpoint::new_for_range(
            value,
            value,
            value,
            Default::default(),
            config_hash("u64-model"),
            vec![ShardMetadata {
                start_m: value,
                end_m: value,
                path: "output.jsonl".to_owned(),
                bytes: 0,
            }],
        );
        write_checkpoint(&path, &checkpoint).expect("checkpoint should write");
        let round_trip = read_checkpoint(&path).expect("checkpoint should parse");
        assert_eq!(round_trip.range_start, value);
        assert_eq!(round_trip.range_end, value);
        assert_eq!(round_trip.next_m, value);
        assert_eq!(round_trip.completed_output_shards[0].start_m, value);
        assert_eq!(round_trip.completed_output_shards[0].end_m, value);
        let _ = fs::remove_file(path);
    }
}

#[test]
fn partitioning_crosses_u32_boundary_and_handles_u64_max_without_sentinel() {
    let crossing = partition_range(u64::from(u32::MAX) - 2, u64::from(u32::MAX) + 2, 2)
        .expect("crossing range should partition");
    assert_eq!(
        crossing,
        vec![
            (u64::from(u32::MAX) - 2, u64::from(u32::MAX)),
            (u64::from(u32::MAX) + 1, u64::from(u32::MAX) + 2)
        ]
    );

    let at_max =
        partition_range(u64::MAX - 2, u64::MAX, 2).expect("u64 max range should partition");
    assert_eq!(
        at_max,
        vec![(u64::MAX - 2, u64::MAX - 1), (u64::MAX, u64::MAX)]
    );
}

#[test]
fn wide_execution_reaches_the_segmented_factorizer() {
    let output = cubealqot::survivors::collect_range(
        u64::from(u32::MAX) + 1,
        u64::from(u32::MAX) + 1,
        1,
        cubealqot::filters::Stage::F1,
    )
    .expect("the segmented factorizer should accept the first widened root");
    assert_eq!(output.stats.tested, 1);
    assert_eq!(output.records[0].m, u64::from(u32::MAX) + 1);
    assert_eq!(output.records[0].factors, vec![[2, 32]]);
}
