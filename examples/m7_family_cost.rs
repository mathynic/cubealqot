//! Release benchmark for the admitted M7-16 family lookup placement.
//!
//! Setup admits the real local N=14 theorem, then times the same production
//! `lookup_family_map` and witness path after F1, after F2, and after F7.
//! Factorization and theorem admission are outside the timed loop.

use std::{
    collections::BTreeSet,
    hint::black_box,
    path::Path,
    time::{Duration, Instant},
};

use cubealqot::{
    Candidate, Factor, MAX_OMEGA, build_spf,
    family::pocklington::UntrustedPrimeCertificate,
    family::problem::UntrustedCofactorFactor,
    family::{
        CertificateVerification, LocalSearchResult, TheoremMap, build_local_family_certificate,
        search_local_certificate, verify_family_certificate,
    },
    filters::{self, CanonicalContext},
    survivors, tables,
};

const SIEVE_PRIMES: [u32; 23] = [
    5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

#[derive(Clone, Copy)]
enum Placement {
    AfterF1,
    AfterF2,
    AfterF7,
}

impl Placement {
    const ALL: [Self; 3] = [Self::AfterF1, Self::AfterF2, Self::AfterF7];

    fn name(self) -> &'static str {
        match self {
            Self::AfterF1 => "after-F1",
            Self::AfterF2 => "after-F2",
            Self::AfterF7 => "after-F7",
        }
    }
}

fn integer(value: &str) -> cubealqot::family::CanonicalInt {
    cubealqot::family::CanonicalInt::from_decimal(value).unwrap()
}

fn real_n14_map() -> TheoremMap {
    let input = cubealqot::family::problem::UntrustedProblem {
        n: integer("14"),
        factors: vec![
            UntrustedCofactorFactor {
                prime: integer("2"),
                exponent: 1,
                certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("2") }),
            },
            UntrustedCofactorFactor {
                prime: integer("7"),
                exponent: 1,
                certificate: Some(UntrustedPrimeCertificate::U64 { n: integer("7") }),
            },
        ],
    };
    let problem = match cubealqot::family::problem::validate_problem(&input) {
        cubealqot::family::problem::ProblemBuildResult::Certified(problem) => problem,
        other => panic!("N=14 setup was not certified: {other:?}"),
    };
    let local = match search_local_certificate(&input, &problem, &(2..=16).collect::<Vec<_>>()) {
        LocalSearchResult::Found(certificate) => certificate,
        other => panic!("N=14 local theorem setup failed: {other:?}"),
    };
    let certificate = build_local_family_certificate(&input, &problem, local).unwrap();
    let verified = match verify_family_certificate(&certificate) {
        CertificateVerification::Verified(value) => value,
        other => panic!("N=14 local theorem verification failed: {other:?}"),
    };
    let mut map = TheoremMap::new();
    map.insert_verified(&certificate, &verified).unwrap();
    let snapshot = map.snapshot();
    println!(
        "THEOREM n=14 entries={} digest={}",
        snapshot.entries().len(),
        snapshot.entries()[0].certificate_digest()
    );
    map
}

fn from_factors(m: u64, factors: &[[u64; 2]]) -> Candidate {
    let mut native = [Factor::default(); MAX_OMEGA];
    for (index, [p, e]) in factors.iter().copied().enumerate() {
        native[index] = Factor {
            p,
            e: u32::try_from(e).unwrap(),
        };
    }
    Candidate::from_factors(m, native, factors.len() as u8)
}

fn ordinary_rows(end: u64) -> Vec<Candidate> {
    let spf = build_spf(u32::try_from(end).unwrap());
    (2..=end).map(|m| Candidate::new(m, &spf)).collect()
}

fn saved_rows(root: &Path) -> Vec<Candidate> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    let mut paths = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("jsonl"))
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        for record in survivors::read_jsonl(&path).unwrap() {
            if seen.insert(record.m) {
                rows.push(from_factors(record.m, &record.factors));
            }
        }
    }
    rows
}

fn run_placement(
    candidate: &mut Candidate,
    context: &CanonicalContext,
    residues: &[u32],
    map: &TheoremMap,
    placement: Placement,
) -> u8 {
    if filters::f1(candidate).is_some() {
        return 1;
    }
    if matches!(placement, Placement::AfterF1)
        && filters::lookup_family_map(map, candidate).is_some()
    {
        return 2;
    }
    if filters::f2(candidate).is_some() {
        return 3;
    }
    if matches!(placement, Placement::AfterF2)
        && filters::lookup_family_map(map, candidate).is_some()
    {
        return 4;
    }
    if filters::f3_adic3::f3_with_context(&context.f3, candidate).is_some() {
        return 5;
    }
    if filters::f4(&context.f4, candidate, residues).is_some() {
        return 6;
    }
    if filters::f4b(&context.f4, candidate).is_some() {
        return 7;
    }
    if filters::f56(candidate).is_some() {
        return 8;
    }
    if filters::f7_special::f7(&context.f7, candidate).is_some() {
        return 9;
    }
    if matches!(placement, Placement::AfterF7)
        && filters::lookup_family_map(map, candidate).is_some()
    {
        return 10;
    }
    if cubealqot::exact::is_square_exact(&cubealqot::exact::exact_s_exact(candidate)) {
        11
    } else {
        12
    }
}

fn measure(
    rows: &mut [Candidate],
    context: &CanonicalContext,
    map: &TheoremMap,
    placement: Placement,
) -> (u128, u64, u64) {
    let start = Instant::now();
    let mut iterations = 0u64;
    let mut family_exclusions = 0u64;
    let mut last_status = 0u8;
    while start.elapsed() < Duration::from_millis(350) {
        for candidate in rows.iter_mut() {
            candidate.s_cache = None;
            candidate.exact_s_cache = None;
            candidate.s_mod_sieve.clear();
            candidate.foreign_zeros.clear();
            let residues = tables::init_residues(&context.f4.sieve_primes, candidate.m);
            last_status = black_box(run_placement(
                black_box(candidate),
                context,
                &residues,
                map,
                placement,
            ));
            if last_status == 2 || last_status == 4 || last_status == 10 {
                family_exclusions += 1;
            }
            iterations += 1;
        }
    }
    black_box(last_status);
    (
        start.elapsed().as_nanos() / u128::from(iterations.max(1)),
        iterations,
        family_exclusions,
    )
}

fn benchmark(name: &str, mut rows: Vec<Candidate>, context: &CanonicalContext, map: &TheoremMap) {
    println!("DATASET {name} count={}", rows.len());
    for placement in Placement::ALL {
        let (ns, iterations, family_exclusions) = measure(&mut rows, context, map, placement);
        println!(
            "RESULT dataset={name} placement={} ns_per_candidate={} iterations={} family_exclusions={}",
            placement.name(),
            ns,
            iterations,
            family_exclusions
        );
    }
}

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let map = real_n14_map();
    let context = CanonicalContext::new(&SIEVE_PRIMES, 63);
    benchmark("ordinary_2_50000", ordinary_rows(50_000), &context, &map);
    benchmark(
        "saved_jsonl_deduplicated",
        saved_rows(&root.join("out")),
        &context,
        &map,
    );
}
