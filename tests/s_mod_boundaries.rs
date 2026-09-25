use cubealqot::{Candidate, Factor, MAX_OMEGA, build_spf, exact};
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
fn s_mod_u128_max_does_not_overflow() {
    let candidate = Candidate::new(2u64, &build_spf(2));
    assert_eq!(exact::s_mod(&candidate, u128::MAX), 7);
}

#[test]
fn s_mod_matches_independent_biguint_boundary_matrix() {
    let mut candidates = vec![
        Candidate::new(2u64, &build_spf(2)),
        Candidate::new(6u64, &build_spf(6)),
        candidate(1u64 << 63, &[(2, 63)]),
    ];
    let moduli = [
        10u128,
        (1u128 << 127) - 1,
        1u128 << 127,
        (1u128 << 127) + 1,
        u128::MAX,
    ];
    let mut saw_sigma_at_least_cube = false;
    let mut saw_sigma_below_cube = false;

    for candidate in &mut candidates {
        let sigma = exact::exact_sigma_big(candidate);
        let cube = BigUint::from(candidate.m).pow(3);
        let exact_s = &sigma - &cube;
        for modulus in moduli {
            let modulus_big = BigUint::from(modulus);
            let expected = (&exact_s % &modulus_big)
                .to_u128()
                .expect("residue must fit the modulus");
            assert_eq!(exact::s_mod(candidate, modulus), expected);

            let sigma_mod = (&sigma % &modulus_big)
                .to_u128()
                .expect("sigma residue must fit the modulus");
            let cube_mod = (&cube % &modulus_big)
                .to_u128()
                .expect("cube residue must fit the modulus");
            saw_sigma_at_least_cube |= sigma_mod >= cube_mod;
            saw_sigma_below_cube |= sigma_mod < cube_mod;
        }
    }

    assert!(saw_sigma_at_least_cube);
    assert!(saw_sigma_below_cube);
}
