use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use cubealqot::{Candidate, build_spf, exact, filters, survivors};

const END: u64 = 10_000;
const LARGE_END: u64 = 50_000;

fn bench_exact_baseline(c: &mut Criterion) {
    let spf = build_spf(u32::try_from(END).expect("benchmark bound fits u32"));
    c.bench_function("exact_baseline_2_to_10000", |benchmark| {
        benchmark.iter(|| {
            let mut checksum = 0u128;
            for m in 2..=END {
                let candidate = Candidate::new(m, &spf);
                checksum = checksum.wrapping_add(exact::aliquot_sum(&candidate));
            }
            black_box(checksum);
        });
    });
}

fn bench_canonical_pipeline(c: &mut Criterion) {
    c.bench_function("canonical_pipeline_2_to_10000_1_thread", |benchmark| {
        benchmark.iter(|| {
            let output = survivors::collect_range(2, END, 1, filters::Stage::F8)
                .expect("benchmark range should be valid");
            black_box(output.stats.tested);
        });
    });
}

fn bench_canonical_pipeline_four_threads(c: &mut Criterion) {
    c.bench_function("canonical_pipeline_2_to_10000_4_threads", |benchmark| {
        benchmark.iter(|| {
            let output = survivors::collect_range(2, END, 4, filters::Stage::F8)
                .expect("benchmark range should be valid");
            black_box(output.stats.tested);
        });
    });
}

fn bench_canonical_pipeline_larger_bounded(c: &mut Criterion) {
    c.bench_function("canonical_pipeline_2_to_50000_1_thread", |benchmark| {
        benchmark.iter(|| {
            let output = survivors::collect_range(2, LARGE_END, 1, filters::Stage::F8)
                .expect("larger benchmark range should be valid");
            black_box(output.stats.tested);
        });
    });
}

fn bench_pipeline_setup(c: &mut Criterion) {
    c.bench_function("pipeline_setup_spf_and_tables", |benchmark| {
        benchmark.iter(|| {
            let spf = build_spf(u32::try_from(END).expect("benchmark bound fits u32"));
            let context = filters::CanonicalContext::new(
                &[
                    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
                    83, 89, 97,
                ],
                20,
            );
            black_box((spf.len(), context.f4.sigma_tables.len()));
        });
    });
}

criterion_group!(
    baseline,
    bench_exact_baseline,
    bench_canonical_pipeline,
    bench_canonical_pipeline_four_threads,
    bench_canonical_pipeline_larger_bounded,
    bench_pipeline_setup
);
criterion_main!(baseline);
