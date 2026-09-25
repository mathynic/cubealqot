use std::{fs, path::PathBuf};

use cubealqot::{Candidate, Factor, MAX_OMEGA, exact, filters, survivors};
use num_bigint::BigUint;
use num_traits::One;

const SIEVE_PRIMES: [u32; 23] = [
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

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
        "cubealqot-wide-exact-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos()
    ));
    path
}

fn independent_is_square(n: &BigUint) -> bool {
    if *n < BigUint::from(2u8) {
        return true;
    }
    let mut low = BigUint::from(0u8);
    let mut high = BigUint::one() << n.bits().div_ceil(2) + 1;
    while low < high {
        let mid = (&low + &high + BigUint::one()) >> 1;
        if &mid * &mid <= *n {
            low = mid;
        } else {
            high = mid - BigUint::one();
        }
    }
    &low * &low == *n
}

#[test]
fn canonical_f8_uses_exact_arithmetic_for_a_factored_wide_candidate() {
    let p = 2_305_843_041_732_208_837u64;
    let m = 3 * p;
    let mut candidate = candidate(m, &[(3, 1), (p, 1)]);
    let context = filters::CanonicalContext::new(&SIEVE_PRIMES, 63);
    let residues = cubealqot::tables::init_residues(&SIEVE_PRIMES, m);

    let predicates = filters::evaluate_ungated_wide(&context, &mut candidate, &residues);
    assert!(predicates.f1.is_none());
    assert!(predicates.f2.is_none());
    assert!(predicates.f3.is_none());
    assert!(predicates.f4.is_none());
    assert!(predicates.f4b.is_none());
    assert!(predicates.f56.is_none(), "wide-prime F5/F6 must defer");
    assert!(predicates.f7.is_none());

    let expected_s = BigUint::parse_bytes(
        b"159379542993077713749040226483863394953154501972726675569",
        10,
    )
    .expect("expected exact S should parse");
    assert_eq!(exact::exact_s_big(&candidate), expected_s);
    assert!(!independent_is_square(&expected_s));

    let trace = filters::run_canonical(&context, &mut candidate, &residues);
    assert_eq!(trace.evaluated, filters::Stage::ALL.to_vec());
    assert_eq!(
        trace.outcome,
        filters::Outcome::exact_nonsquare(),
        "canonical F8 must agree with the independent exact square test"
    );
}

#[test]
fn wide_sigma_overflow_does_not_abort_an_earlier_rejection_record() {
    let m = 3_778_300_846_320u64;
    let output_path = temp_path("output");
    let factors = vec![
        [2, 4],
        [3, 1],
        [5, 1],
        [7, 1],
        [11, 1],
        [13, 1],
        [17, 1],
        [19, 1],
        [23, 1],
        [29, 1],
        [73, 1],
    ];

    let run = survivors::stream_jsonl_range(&output_path, m, m, 1, filters::Stage::F1)
        .expect("wide exact arithmetic must not abort an F1 record");
    assert_eq!(run.stats.tested, 1);
    assert_eq!(run.records_written, 1);

    let records = survivors::read_jsonl(&output_path).expect("record should be parseable");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].m, m);
    assert_eq!(records[0].factors, factors);
    assert!(records[0].stage != filters::Stage::F8);
    assert!(records[0].rejection.is_some());

    let _ = fs::remove_file(output_path);
}
