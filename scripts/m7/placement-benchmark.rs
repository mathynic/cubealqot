//! Compiled only in the isolated benchmark workspace created by the wrapper.
//!
//! PP-08 deliberately loads a sealed theorem snapshot through the committed
//! store. Benchmark startup is therefore offline; Sage is not a hidden
//! admission dependency of either placement arm.
use std::{fs, io::Write, path::Path, sync::atomic::Ordering, time::Instant};

use cubealqot::{
    family::{LoadedTheoremMap, StoreReader, StoreSnapshot, TheoremMap},
    filters::{self, Stage},
    survivors,
};
use serde_json::{json, Value};

const BENCHMARK_SCHEMA_VERSION: u32 = 2;

fn write_new(path: &Path, value: &Value) {
    let tmp = path.with_extension("pending");
    let mut file = fs::File::create(&tmp).unwrap();
    file.write_all(serde_json::to_string_pretty(value).unwrap().as_bytes()).unwrap();
    file.sync_all().unwrap();
    assert!(!path.exists());
    fs::rename(tmp, path).unwrap();
}

fn local_map() -> TheoremMap {
    let input: cubealqot::family::problem::UntrustedProblem = serde_json::from_value(json!({
        "n":"14","factors":[
            {"prime":"2","exponent":1,"certificate":{"kind":"u64","n":"2"}},
            {"prime":"7","exponent":1,"certificate":{"kind":"u64","n":"7"}}
        ]
    })).unwrap();
    let problem = match cubealqot::family::problem::validate_problem(&input) {
        cubealqot::family::problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("{other:?}"),
    };
    let local = match cubealqot::family::search_local_certificate(
        &input, &problem, &(2..=16).collect::<Vec<_>>()) {
        cubealqot::family::LocalSearchResult::Found(certificate) => certificate,
        other => panic!("{other:?}"),
    };
    let certificate = cubealqot::family::build_local_family_certificate(&input, &problem, local).unwrap();
    let verified = match cubealqot::family::verify_family_certificate(&certificate) {
        cubealqot::family::CertificateVerification::Verified(verified) => verified,
        other => panic!("{other:?}"),
    };
    let mut map = TheoremMap::new();
    map.insert_verified(&certificate, &verified).unwrap();
    map
}

enum BenchmarkMap { Local(TheoremMap), Loaded(LoadedTheoremMap) }

impl BenchmarkMap {
    fn map(&self) -> &TheoremMap {
        match self { Self::Local(map) => map, Self::Loaded(loaded) => loaded.map() }
    }
}

fn run(start: u64, end: u64, threads: usize, map: &BenchmarkMap, before: bool)
    -> (survivors::RunOutput, f64)
{
    filters::BENCHMARK_BEFORE_F2.store(before, Ordering::Relaxed);
    let timer = Instant::now();
    let output = match map {
        BenchmarkMap::Local(map) => survivors::collect_range_with_family_map(start, end, threads, Stage::F8, map),
        BenchmarkMap::Loaded(loaded) => survivors::collect_range_with_loaded_family_map(start, end, threads, Stage::F8, loaded),
    }.unwrap();
    let seconds = timer.elapsed().as_secs_f64();
    assert_eq!(output.stats.tested, end - start + 1);
    output.stats.check_invariants_for(&filters::benchmark_family_stages()).unwrap();
    (output, seconds)
}

fn premises_identity(config: &Value, map: &BenchmarkMap) -> Value {
    match map {
        BenchmarkMap::Local(_) => json!({
            "admission_mode": config["admission_mode"], "snapshot_id": Value::Null,
            "store_id": Value::Null, "policy_id": Value::Null, "admission_ids": [],
            "backend_trusted": false,
        }),
        BenchmarkMap::Loaded(loaded) => json!({
            "admission_mode": config["admission_mode"], "snapshot_id": loaded.snapshot_id(),
            "store_id": loaded.store_id(), "policy_id": loaded.policy_id(),
            "admission_ids": loaded.admission_ids(),
            "backend_trusted": loaded.map().uses_backend_trust(),
        }),
    }
}

fn main() {
    let arg = std::env::args().nth(1).expect("run directory required");
    let dir = Path::new(&arg);
    let config: Value = serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(config["benchmark_contract_version"], BENCHMARK_SCHEMA_VERSION);
    let get = |key: &str| config[key].as_u64().unwrap();
    let (start, end, chunk, threads) = (get("start"), get("end"), get("chunk_size"), get("threads") as usize);
    assert!(chunk > 0 && start <= end);

    let map = if config["local_smoke"] == true {
        BenchmarkMap::Local(local_map())
    } else {
        let store_path = dir.join("proof-store");
        let reader = StoreReader::open(&store_path).unwrap();
        let snapshot: StoreSnapshot = serde_json::from_slice(&fs::read(dir.join("theorem-snapshot.json")).unwrap()).unwrap();
        BenchmarkMap::Loaded(TheoremMap::from_store_snapshot(&reader, &snapshot).unwrap())
    };
    let identity = premises_identity(&config, &map);
    let map_digest = map.map().snapshot_digest().unwrap();
    eprintln!("Loaded {} families offline; map {}; identity {}", map.map().len(), map_digest, identity);

    let warm_end = end.min(start.saturating_add(9999));
    let (before, _) = run(start, warm_end, threads, &map, true);
    let (after, _) = run(start, warm_end, threads, &map, false);
    assert_eq!(before.records, after.records, "F8 records differ in warmup");
    let plain = survivors::collect_range(start, warm_end, threads, Stage::F8).unwrap();
    let solutions = |output: &survivors::RunOutput| output.records.iter().filter(|r| r.rejection.is_none()).map(|r| serde_json::to_string(r).unwrap()).collect::<Vec<_>>();
    assert_eq!(solutions(&plain), solutions(&after), "No-map solutions differ");

    let pairs = dir.join("pairs"); fs::create_dir_all(&pairs).unwrap();
    let mut lo = start; let mut index = 0u64; let (mut total_before, mut total_after) = (0.0, 0.0);
    let mut tested = 0u64; let (mut before_wins, mut after_wins) = (0, 0);
    loop {
        let hi = end.min(lo.saturating_add(chunk - 1));
        let file = pairs.join(format!("{index:06}-{lo}-{hi}.json"));
        let record: Value = if file.exists() {
            let value: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
            assert_eq!(value["benchmark_schema_version"], BENCHMARK_SCHEMA_VERSION);
            assert_eq!(value["map_digest"], map_digest);
            assert_eq!(value["premises_identity"], identity);
            assert_eq!(value["start"], lo); assert_eq!(value["end"], hi);
            assert_eq!(value["equal_f8_records"], true); value
        } else {
            eprintln!("Pair {index}: {lo}..={hi}, {} first", if index % 2 == 0 { "before F2" } else { "after F2" });
            let (before, before_time, after, after_time) = if index % 2 == 0 {
                let (before, before_time) = run(lo, hi, threads, &map, true);
                let (after, after_time) = run(lo, hi, threads, &map, false);
                (before, before_time, after, after_time)
            } else {
                let (after, after_time) = run(lo, hi, threads, &map, false);
                let (before, before_time) = run(lo, hi, threads, &map, true);
                (before, before_time, after, after_time)
            };
            if before.records != after.records {
                write_new(&dir.join(format!("MISMATCH-{index}.json")), &json!({"before":before.records,"after":after.records}));
                panic!("Placement changed F8 records; benchmark stopped");
            }
            let value = json!({
                "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION, "start": lo, "end": hi,
                "map_digest": map_digest, "premises_identity": identity, "equal_f8_records": true,
                "before_seconds": before_time, "after_seconds": after_time,
                "before_stats": before.stats, "after_stats": after.stats, "f8_records": after.records,
                "first": if index % 2 == 0 { "before" } else { "after" },
            });
            write_new(&file, &value); value
        };
        let before_time = record["before_seconds"].as_f64().unwrap(); let after_time = record["after_seconds"].as_f64().unwrap();
        total_before += before_time; total_after += after_time; tested += hi - lo + 1;
        if before_time < after_time { before_wins += 1; } else { after_wins += 1; }
        let summary = json!({
            "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION, "complete": hi == end, "config": config,
            "map_digest": map_digest, "premises_identity": identity, "families": map.map().len(),
            "tested_per_placement": tested, "before_seconds": total_before, "after_seconds": total_after,
            "before_candidates_per_second": tested as f64 / total_before, "after_candidates_per_second": tested as f64 / total_after,
            "before_time_reduction_percent": 100.0 * (total_after - total_before) / total_after,
            "before_faster_pairs": before_wins, "after_faster_pairs": after_wins,
            "completed_pairs": index + 1, "equal_f8_records": true,
        });
        fs::write(dir.join("summary.json"), serde_json::to_vec_pretty(&summary).unwrap()).unwrap();
        eprintln!("Through {hi}: before={total_before:.2}s after={total_after:.2}s; pair {before_time:.3}s/{after_time:.3}s");
        if hi == end { println!("{summary}"); break; }
        lo = hi + 1; index += 1;
    }
}
