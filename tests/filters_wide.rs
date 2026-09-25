use cubealqot::exact::{exact_s_exact, is_square_exact};
use cubealqot::filters::{self, F4Context, F7Context};
use cubealqot::tables::init_residues;
use cubealqot::{Candidate, Factor, MAX_OMEGA};

fn candidate(m: u64, factors: &[(u64, u32)]) -> Candidate {
    let mut slots = [Factor::default(); MAX_OMEGA];
    for (slot, &(p, e)) in slots.iter_mut().zip(factors) {
        *slot = Factor { p, e };
    }
    Candidate::from_factors(m, slots, factors.len() as u8)
}

#[test]
fn ungated_f2_f3_and_f4_are_sound_for_a_wide_candidate() {
    let factors = &[(641u64, 1), (6_700_417, 1)][..];
    let mut candidate = candidate(4_294_967_297, factors);
    let exact_s = exact_s_exact(&candidate);
    let context = filters::CanonicalContext::new(&[5, 7, 11, 13, 17], 63);
    let residues = init_residues(&context.f4.sieve_primes, candidate.m);

    let f2 = filters::f2_adic2::analyze(&mut candidate);
    assert_eq!(f2.v2_s, exact_s.valuation(2));
    assert_eq!(u64::from(f2.unit8), exact_s.unit_modulus(2, f2.v2_s, 8));

    let f3 = filters::f3_adic3::analyze_with_context(&context.f3, &mut candidate);
    assert_eq!(f3.v3_s, exact_s.valuation(3));
    assert_eq!(u64::from(f3.unit3), exact_s.unit_mod(3, f3.v3_s) % 3);

    let f4_rejection = filters::f4(&context.f4, &mut candidate, &residues);
    for (&q, &residue) in context.f4.sieve_primes.iter().zip(&candidate.s_mod_sieve) {
        let expected = exact_s.to_biguint() % q;
        assert_eq!(
            residue,
            expected.to_u32_digits().first().copied().unwrap_or(0)
        );
    }
    if f4_rejection.is_some() {
        assert!(!is_square_exact(&exact_s));
    }
}

#[test]
fn ungated_f4b_uses_exact_wide_s_without_narrowing() {
    let factors = &[(641u64, 1), (6_700_417, 1)][..];
    let mut candidate = candidate(4_294_967_297, factors);
    let context = F4Context::new(&[5, 7, 11, 13, 17], 63);
    let residues = init_residues(&context.sieve_primes, candidate.m);
    let _ = filters::f4(&context, &mut candidate, &residues);
    let exact_s = exact_s_exact(&candidate);
    for analysis in filters::f4b_foreign::analyze(&context, &mut candidate) {
        assert_eq!(analysis.v, exact_s.valuation(u64::from(analysis.q)));
        assert_eq!(
            u64::from(analysis.unit),
            exact_s.unit_mod(u64::from(analysis.q), analysis.v)
        );
    }
}

#[test]
fn ungated_filters_handle_an_exact_s_beyond_u128() {
    let mut candidate = candidate(1u64 << 63, &[(2, 63)]);
    let exact_s = exact_s_exact(&candidate);
    assert!(exact_s.is_big());
    let context = filters::CanonicalContext::new(&[5, 7, 11], 63);
    let residues = init_residues(&context.f4.sieve_primes, candidate.m);

    let f2 = filters::f2_adic2::analyze(&mut candidate);
    assert_eq!(f2.v2_s, exact_s.valuation(2));
    assert_eq!(u64::from(f2.unit8), exact_s.unit_modulus(2, f2.v2_s, 8));
    let f3 = filters::f3_adic3::analyze_with_context(&context.f3, &mut candidate);
    assert_eq!(f3.v3_s, exact_s.valuation(3));
    assert_eq!(u64::from(f3.unit3), exact_s.unit_mod(3, f3.v3_s));
    let _ = filters::f4(&context.f4, &mut candidate, &residues);
    assert_eq!(filters::f56(&mut candidate), None);

    let mut ungated_candidate = {
        let mut slots = [cubealqot::Factor::default(); MAX_OMEGA];
        slots[0] = cubealqot::Factor { p: 2, e: 63 };
        Candidate::from_factors(1u64 << 63, slots, 1)
    };
    let ungated_residues = init_residues(&context.f4.sieve_primes, ungated_candidate.m);
    let predicates =
        filters::evaluate_ungated_wide(&context, &mut ungated_candidate, &ungated_residues);
    assert_eq!(predicates.evaluated.len(), 7);
    match predicates.exact {
        filters::WideOutcome::ExactNonsquare => {
            assert!(!is_square_exact(&exact_s_exact(&ungated_candidate)))
        }
        filters::WideOutcome::Solution { y } => {
            let sum = exact_s_exact(&ungated_candidate);
            assert_eq!(y.to_biguint() * y.to_biguint(), sum.to_biguint());
        }
    }
}

#[test]
fn wide_prime_f5_f6_case_defers_instead_of_narrowing() {
    let mut candidate = candidate(8_589_934_622, &[(2, 1), (4_294_967_311, 1)]);
    assert!(filters::f56_local::analyze(&mut candidate).is_empty());
    assert_eq!(filters::f56(&mut candidate), None);
}

#[test]
fn f5_f6_handles_a_wide_root_when_all_local_primes_are_supported() {
    let mut candidate = candidate(5 * (1u64 << 60), &[(2, 60), (5, 1)]);
    let exact_s = exact_s_exact(&candidate);
    for local in filters::f56_local::analyze(&mut candidate) {
        assert_eq!(local.v_s, exact_s.valuation(local.target));
        assert_eq!(
            u64::from(local.unit),
            exact_s.unit_mod(local.target, local.v_s)
        );
    }
    if filters::f56(&mut candidate).is_some() {
        assert!(!is_square_exact(&exact_s));
    }
}

#[test]
fn f7_accepts_wide_exponents_and_preserves_family_tags() {
    let candidate = candidate(38_654_705_673, &[(2, 32), (3, 2)]);
    let context = F7Context::default();
    assert_eq!(
        filters::f7_special::family_tag(&candidate),
        Some(filters::FamilyTag::Sq)
    );
    assert!(
        filters::f7_special::analyze(&context, &candidate)
            .checks
            .len()
            > 0
    );
}

#[test]
fn every_widened_ungated_rejection_is_exactly_sound() {
    let context = filters::CanonicalContext::new(&[5, 7, 11, 13, 17], 63);
    let cases = [
        (4_294_967_296u64, vec![(2, 32)]),
        (4_294_967_297, vec![(641, 1), (6_700_417, 1)]),
        (5 * (1u64 << 60), vec![(2, 60), (5, 1)]),
        (1u64 << 63, vec![(2, 63)]),
        (8_589_934_622, vec![(2, 1), (4_294_967_311, 1)]),
        (38_654_705_673, vec![(2, 32), (3, 2)]),
    ];

    for (m, factors) in cases {
        let mut candidate = candidate(m, &factors);
        let residues = init_residues(&context.f4.sieve_primes, m);
        let predicates = filters::evaluate_ungated_wide(&context, &mut candidate, &residues);
        let exact_square = is_square_exact(&exact_s_exact(&candidate));
        let any_rejection = [
            predicates.f1,
            predicates.f2,
            predicates.f3,
            predicates.f4,
            predicates.f4b,
            predicates.f56,
            predicates.f7,
        ]
        .into_iter()
        .any(|rejection| rejection.is_some());

        assert!(!exact_square || !any_rejection, "false rejection for m={m}");
        if any_rejection {
            assert!(!exact_square, "rejection was not exact for m={m}");
        }
    }
}
