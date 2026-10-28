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

#[test]
fn modular_paths_match_direct_biguint_sums_across_all_bit_tiers() {
    let cases: &[&[(u64, u32)]] = &[
        &[(2, 1)],
        &[(2, 63)],
        &[(3, 40)],
        &[(2, 12), (5, 13)],
        &[(3, 1), (2_305_843_041_732_208_837, 1)],
        &[(18_446_744_073_709_551_557, 1)],
        &[
            (3, 1),
            (5, 1),
            (17, 1),
            (257, 1),
            (641, 1),
            (65_537, 1),
            (6_700_417, 1),
        ],
        &[(2, 1), (3, 2), (5, 3), (7, 1), (11, 1), (13, 1)],
    ];
    for factors in cases {
        let mut m = 1u128;
        let mut sigma = BigUint::from(1u8);
        for &(p, e) in *factors {
            m *= u128::from(p).pow(e);
            // Independent direct sum, without modular arithmetic or the
            // production sigma helper and its exponent-one identity.
            let mut term = BigUint::from(1u8);
            let mut sum = BigUint::from(0u8);
            for _ in 0..=3 * e {
                sum += &term;
                term *= p;
            }
            sigma *= sum;
        }
        let m = u64::try_from(m).unwrap();
        let candidate = candidate(m, factors);
        let s = &sigma - BigUint::from(m).pow(3);
        for bits in 1..128 {
            let power = 1u128 << bits;
            for modulus in [power - 1, power, power + 1] {
                let big_modulus = BigUint::from(modulus);
                assert_eq!(
                    exact::s_mod(&candidate, modulus),
                    (&s % &big_modulus).to_u128().unwrap(),
                    "S: m={m}, modulus={modulus}"
                );
                assert_eq!(
                    exact::sigma_mod(&candidate, modulus),
                    (&sigma % &big_modulus).to_u128().unwrap(),
                    "sigma: m={m}, modulus={modulus}"
                );
            }
        }
    }
}

#[test]
fn power_of_two_sums_match_biguint_for_all_native_prime_power_exponents() {
    for p in [2u64, 3, 5, 17, 65_537, 18_446_744_073_709_551_557] {
        let mut m = p;
        for exponent in 1..=63 {
            let c = candidate(m, &[(p, exponent)]);
            // Direct wide summation is independent of the factored formula
            // and of wrapping arithmetic with deferred masks.
            let mut term = BigUint::from(1u8);
            let mut sigma = BigUint::from(0u8);
            for _ in 0..=3 * exponent {
                sigma += &term;
                term *= p;
            }
            let s = sigma - BigUint::from(m).pow(3);
            for bits in 0..128 {
                let modulus = 1u128 << bits;
                let expected = (&s % BigUint::from(modulus)).to_u128().unwrap();
                assert_eq!(
                    exact::s_mod(&c, modulus),
                    expected,
                    "p={p}, exponent={exponent}, bits={bits}"
                );
            }
            let Some(next) = m.checked_mul(p) else {
                break;
            };
            m = next;
        }
    }
}
