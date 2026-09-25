use cubealqot::cross::exact_t_j_big;
use cubealqot::exact::{
    ExactNat, exact_s_big, exact_s_exact, exact_sigma, exact_sigma_big, exact_sigma_exact,
    is_square_exact, isqrt_exact,
};
use cubealqot::{Candidate, Factor, MAX_OMEGA};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

fn candidate(m: u64, factors: &[(u64, u32)]) -> Candidate {
    let mut slots = [Factor::default(); MAX_OMEGA];
    for (slot, &(p, e)) in slots.iter_mut().zip(factors) {
        *slot = Factor { p, e };
    }
    Candidate::from_factors(m, slots, factors.len() as u8)
}

#[test]
fn small_exact_tier_matches_the_existing_u128_path() {
    for m in 2u32..=2_000 {
        let spf = cubealqot::build_spf(m);
        let candidate = Candidate::new(m, &spf);
        let old = exact_sigma(&candidate);
        let tiered = exact_sigma_exact(&candidate);
        assert_eq!(tiered.as_u128(), Some(old), "m={m}");
        assert_eq!(
            exact_sigma_big(&candidate).to_u128(),
            Some(old),
            "forced BigUint sigma m={m}"
        );
        assert_eq!(
            exact_s_exact(&candidate).as_u128(),
            Some(cubealqot::exact::aliquot_sum(&candidate))
        );
        assert_eq!(
            exact_s_big(&candidate).to_u128(),
            Some(cubealqot::exact::aliquot_sum(&candidate)),
            "forced BigUint S m={m}"
        );
    }
}

#[test]
fn widened_candidates_match_independent_factor_formula() {
    for (m, factors) in [
        (4_294_967_297u64, &[(641u64, 1), (6_700_417, 1)][..]),
        (809_964_431u64, &[(21_517u64, 1), (37_643, 1)][..]),
        (1u64 << 63, &[(2u64, 63)][..]),
        (
            614_889_782_588_491_410u64,
            &[
                (2u64, 1),
                (3, 1),
                (5, 1),
                (7, 1),
                (11, 1),
                (13, 1),
                (17, 1),
                (19, 1),
                (23, 1),
                (29, 1),
                (31, 1),
                (37, 1),
                (41, 1),
                (43, 1),
                (47, 1),
            ][..],
        ),
    ] {
        let candidate = candidate(m, factors);
        let sigma = exact_sigma_big(&candidate);
        let expected = factors.iter().fold(BigUint::from(1u8), |product, &(p, e)| {
            let mut term = BigUint::from(1u8);
            let mut sum = BigUint::from(0u8);
            for _ in 0..=3 * e {
                sum += &term;
                term *= p;
            }
            product * sum
        });
        assert_eq!(sigma, expected, "m={m}");
        assert_eq!(exact_sigma_exact(&candidate).to_biguint(), expected);
        assert_eq!(
            exact_s_exact(&candidate).to_biguint(),
            exact_s_big(&candidate)
        );
    }
}

#[test]
fn selected_wide_values_match_python_oracle_vectors() {
    let vectors = [
        (
            4_294_967_297u64,
            &[(641u64, 1), (6_700_417, 1)][..],
            "79351968415989838310876708880",
            "123805846385268483319201807",
        ),
        (
            809_964_431u64,
            &[(21_517u64, 1), (37_643, 1)][..],
            "531409806257616871158756000",
            "38813646038232182881009",
        ),
    ];
    for (m, factors, sigma, sum) in vectors {
        let candidate = candidate(m, factors);
        assert_eq!(
            exact_sigma_big(&candidate),
            sigma.parse::<BigUint>().expect("oracle sigma is valid"),
            "sigma m={m}"
        );
        assert_eq!(
            exact_s_big(&candidate),
            sum.parse::<BigUint>().expect("oracle sum is valid"),
            "S m={m}"
        );
    }
}

#[test]
fn biguint_square_test_and_integer_root_are_exact() {
    let root: BigUint = (BigUint::from(1u8) << 127u32) + BigUint::from(12_345u32);
    let square: BigUint = &root * &root;
    let exact = ExactNat::from_biguint(square.clone());
    assert!(exact.is_big());
    assert!(is_square_exact(&exact));
    assert_eq!(isqrt_exact(&exact).to_biguint(), root);

    for neighbor in [&square - BigUint::from(1u8), &square + BigUint::from(1u8)] {
        assert!(!is_square_exact(&ExactNat::from_biguint(neighbor)));
    }
}

#[test]
fn biguint_valuation_and_unit_extraction_match_repeated_division() {
    let q = 7u64;
    let mut value = BigUint::from(123_456_789u64);
    value *= BigUint::from(q).pow(37);
    value *= BigUint::from(5u8);
    let exact = ExactNat::from_biguint(value.clone());
    assert_eq!(exact.valuation(q), 37);
    assert_eq!(exact.unit_mod(q, 37), 5 % q);
}

#[test]
fn widened_prime_power_term_has_exact_big_valuation() {
    let term = exact_t_j_big(4_294_967_297, 1);
    let mut remainder = term.clone();
    let q = 3u64;
    let mut valuation = 0;
    while &remainder % q == BigUint::from(0u8) {
        remainder /= q;
        valuation += 1;
    }
    assert_eq!(valuation, 1);
}
