use cubealqot::cross::{self, CrossHit};
use cubealqot::numth::{modpow, multiplicative_order, valuation};
use cubealqot::{Candidate, build_spf};

fn primes_up_to(max: u32) -> Vec<u32> {
    (2..=max)
        .filter(|&n| (2..=((n as f64).sqrt() as u32)).all(|d| n % d != 0))
        .collect()
}

fn direct_t(source: u64, exponent: u32) -> u128 {
    let mut power = 1u128;
    let mut sum = 0u128;
    for _ in 0..=3 * exponent {
        sum += power;
        power *= u128::from(source);
    }
    sum
}

#[test]
fn multiplicative_order_is_minimal_for_small_prime_moduli() {
    for p in primes_up_to(101) {
        for g in 1..p {
            let order = multiplicative_order(p, g);
            assert_eq!(modpow(u64::from(g), u64::from(order), u64::from(p)), 1);

            for divisor in primes_up_to(order) {
                if order % divisor == 0 {
                    assert_ne!(
                        modpow(u64::from(g), u64::from(order / divisor), u64::from(p)),
                        1,
                        "p={p}, g={g}, order={order}, divisor={divisor}"
                    );
                }
            }
        }
    }
}

#[test]
fn lte_cross_hits_match_exact_tj_division_exhaustively() {
    let max = 10_000;
    let spf = build_spf(max);
    let mut hit_count = 0;

    for m in 2..=max {
        let mut candidate = Candidate::new(m, &spf);
        let actual = cross::cross_hits(&mut candidate);

        for target_factor in candidate.f[..candidate.omega as usize]
            .iter()
            .filter(|factor| factor.p >= 5)
        {
            for source_factor in candidate.f[..candidate.omega as usize]
                .iter()
                .filter(|factor| factor.p != target_factor.p)
            {
                let target = target_factor.p;
                let tj = direct_t(source_factor.p, source_factor.e);
                let expected = if tj % u128::from(target) == 0 {
                    Some(valuation(tj, u128::from(target)))
                } else {
                    None
                };
                let found = actual.iter().find(|hit| {
                    hit.target == target
                        && hit.source == source_factor.p
                        && hit.e_source == source_factor.e
                });

                match (expected, found) {
                    (None, None) => {}
                    (Some(value), Some(hit)) => {
                        hit_count += 1;
                        assert_eq!(hit.val, value, "m={m}, hit={hit:?}");
                    }
                    (expected, found) => {
                        panic!("m={m}, expected={expected:?}, found={found:?}");
                    }
                }
            }
        }
    }

    assert!(hit_count > 0);
}

#[test]
fn both_lte_shapes_have_explicit_witnesses() {
    let congruent_one = cross::cross_hit(5, 11, 3).expect("5 divides sigma(11^9)");
    assert_eq!(
        congruent_one,
        CrossHit {
            target: 5,
            source: 11,
            e_source: 3,
            val: 1
        }
    );

    let order_branch = cross::cross_hit(5, 2, 1).expect("5 divides sigma(2^3)");
    assert_eq!(order_branch.val, 1);
}
