//! Benchmark-only six-empty-family lookup. Does not admit or export theorems.
use cubealqot::{
    Candidate,
    factor::{Factor, MAX_OMEGA},
    filters,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    hint::black_box,
    time::{Duration, Instant},
};
const NS: [u64; 6] = [2, 3, 4, 5, 9, 35];
const PRIMES: [u32; 23] = [
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];
fn lookup(c: &Candidate, map: &BTreeSet<u64>) -> bool {
    c.f[..c.omega as usize]
        .iter()
        .any(|f| f.e == 1 && map.contains(&(c.m / f.p)))
}
fn prefix(c: &mut Candidate, ctx: &filters::CanonicalContext, stop: u8) -> bool {
    if filters::f1(c).is_some() {
        return true;
    }
    if stop == 1 {
        return false;
    }
    if filters::f2(c).is_some() {
        return true;
    }
    if stop == 2 {
        return false;
    }
    rest(c, ctx, stop)
}
fn rest(c: &mut Candidate, ctx: &filters::CanonicalContext, stop: u8) -> bool {
    if filters::f3_adic3::f3_with_context(&ctx.f3, c).is_some() {
        return true;
    }
    if stop == 3 {
        return false;
    }
    let residues: Vec<u32> = PRIMES
        .iter()
        .map(|p| (c.m % u64::from(*p)) as u32)
        .collect();
    filters::f4(&ctx.f4, c, &residues).is_some()
        || filters::f4b(&ctx.f4, c).is_some()
        || filters::f56(c).is_some()
        || filters::f7(&ctx.f7, c).is_some()
}
fn measure<F: FnMut(&mut Candidate) -> bool>(rows: &mut [Candidate], mut f: F) -> (f64, f64, f64) {
    let mut samples = Vec::new();
    for _ in 0..1 {
        let start = Instant::now();
        let mut count = 0u64;
        while start.elapsed() < Duration::from_millis(120) {
            for c in rows.iter_mut() {
                c.s_cache = None;
                c.exact_s_cache = None;
                black_box(f(black_box(c)));
                count += 1;
            }
        }
        samples.push(start.elapsed().as_nanos() as f64 / count as f64);
    }
    (samples[0], samples[0], samples[0])
}
fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut unique = BTreeMap::new();
    for file in fs::read_dir(root.join("out")).unwrap() {
        let p = file.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("jsonl") {
            continue;
        }
        for line in fs::read_to_string(p).unwrap().lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            if v["stage"] != "F8" {
                continue;
            }
            let m = v["m"].as_u64().unwrap();
            let mut f = [Factor::default(); MAX_OMEGA];
            let a = v["factors"].as_array().unwrap();
            let mut product = 1u128;
            for (i, x) in a.iter().enumerate() {
                f[i] = Factor {
                    p: x[0].as_u64().unwrap(),
                    e: x[1].as_u64().unwrap() as u32,
                };
                product *= u128::from(f[i].p).pow(f[i].e);
            }
            assert_eq!(product, u128::from(m));
            unique.insert(m, Candidate::from_factors(m, f, a.len() as u8));
        }
    }
    let mut survivors: Vec<_> = unique.into_values().collect();
    let min = survivors.first().unwrap().m;
    let max = survivors.last().unwrap().m;
    let spf = cubealqot::build_spf(1_200_000);
    let primes: Vec<u64> = (2..spf.len())
        .filter(|i| spf[*i] == 0)
        .map(|i| i as u64)
        .collect();
    let mut mixed = Vec::new();
    let mut seed = 123456789u64;
    for _ in 0..4096 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let m = min + seed % (max - min + 1);
        let mut x = m;
        let mut f = [Factor::default(); MAX_OMEGA];
        let mut k = 0;
        for &p in &primes {
            if p > x / p {
                break;
            }
            if x % p == 0 {
                let mut e = 0;
                while x % p == 0 {
                    x /= p;
                    e += 1
                }
                f[k] = Factor { p, e };
                k += 1
            }
        }
        if x > 1 {
            f[k] = Factor { p: x, e: 1 };
            k += 1
        }
        mixed.push(Candidate::from_factors(m, f, k as u8));
    }
    let map: BTreeSet<u64> = NS.into_iter().collect();
    let ctx = filters::CanonicalContext::new(&PRIMES, 63);
    for (name, rows) in [
        ("saved_F8_survivors", &mut survivors),
        ("uniform_large_control", &mut mixed),
    ] {
        for c in rows.iter_mut() {
            if lookup(c, &map) {
                assert!(!cubealqot::exact::is_square_exact(
                    &cubealqot::exact::exact_s_exact(c)
                ));
            }
        }
        let hits = rows.iter().filter(|c| lookup(c, &map)).count();
        let mut rejects = [0usize; 3];
        for c in rows.iter_mut() {
            for s in 1..=3 {
                if prefix(c, &ctx, s) {
                    rejects[s as usize - 1] += 1
                }
            }
        }
        println!(
            "DATA {name} count={} min={} max={} family_hits={hits} prefix_rejects={rejects:?}",
            rows.len(),
            rows.iter().map(|c| c.m).min().unwrap(),
            rows.iter().map(|c| c.m).max().unwrap()
        );
        let mut timings = vec![Vec::new(); 10];
        for round in 0..7 {
            for offset in 0..10 {
                let mode = (offset + round * 3) % 10;
                let label = [
                    "loop_baseline",
                    "F1_only",
                    "F2_only",
                    "F3_only",
                    "six_empty_lookup",
                    "F1_F2",
                    "F1_F2_F3",
                    "lookup_then_F1_F7",
                    "F1_F2_then_lookup_then_rest",
                    "F1_F7_then_lookup",
                ][mode];
                let (median, _, _) = measure(rows, |c| match mode {
                    0 => false,
                    1 => filters::f1(c).is_some(),
                    2 => filters::f2(c).is_some(),
                    3 => filters::f3_adic3::f3_with_context(&ctx.f3, c).is_some(),
                    4 => lookup(c, &map),
                    5 => prefix(c, &ctx, 2),
                    6 => prefix(c, &ctx, 3),
                    7 => lookup(c, &map) || prefix(c, &ctx, 7),
                    8 => prefix(c, &ctx, 2) || lookup(c, &map) || rest(c, &ctx, 7),
                    _ => prefix(c, &ctx, 7) || lookup(c, &map),
                });
                timings[mode].push(median);
                black_box(label);
            }
        }
        for (mode, samples) in timings.iter_mut().enumerate() {
            samples.sort_by(f64::total_cmp);
            let label = [
                "loop_baseline",
                "F1_only",
                "F2_only",
                "F3_only",
                "six_empty_lookup",
                "F1_F2",
                "F1_F2_F3",
                "lookup_then_F1_F7",
                "F1_F2_then_lookup_then_rest",
                "F1_F7_then_lookup",
            ][mode];
            println!(
                "TIME {name} {label} median_ns={:.2} min_ns={:.2} max_ns={:.2}",
                samples[3], samples[0], samples[6]
            );
        }
    }
}
