use cubealqot::{Factor, MAX_OMEGA, Prime, SegmentedSpf};

fn factors_for(segment: &SegmentedSpf, m: u64) -> Vec<Factor> {
    let mut factors = [Factor::default(); MAX_OMEGA];
    let omega = segment.factor_into(m, &mut factors);
    factors[..omega as usize].to_vec()
}

fn reconstruct(factors: &[Factor]) -> u128 {
    factors.iter().fold(1u128, |product, factor| {
        product * u128::from(factor.p).pow(factor.e)
    })
}

fn independently_prime(p: Prime) -> bool {
    if p < 2 {
        return false;
    }
    let mut divisor = 2u64;
    while divisor <= p / divisor {
        if p % divisor == 0 {
            return false;
        }
        divisor += 1;
    }
    true
}

#[test]
fn known_wide_factors_are_canonical_and_reconstruct_exactly() {
    let cases = [
        (4_294_967_297u64, &[(641u64, 1), (6_700_417, 1)][..]),
        (809_964_431u64, &[(21_517u64, 1), (37_643, 1)][..]),
        (4_294_967_311u64, &[(4_294_967_311u64, 1)][..]),
        (12_884_901_888u64, &[(2u64, 32), (3, 1)][..]),
        (1u64 << 32, &[(2u64, 32)][..]),
        (1u64 << 40, &[(2u64, 40)][..]),
    ];

    for (m, expected) in cases {
        let segment = SegmentedSpf::try_new(m, m).expect("controlled wide root should factor");
        let factors = factors_for(&segment, m);
        assert_eq!(
            factors
                .iter()
                .map(|factor| (factor.p, factor.e))
                .collect::<Vec<_>>(),
            expected,
            "m={m}"
        );
        assert_eq!(reconstruct(&factors), u128::from(m), "m={m}");
        assert!(factors.iter().all(|factor| independently_prime(factor.p)));
    }
}

#[test]
fn segmented_factorization_crosses_the_u32_boundary_without_truncation() {
    let start = u64::from(u32::MAX) - 2;
    let end = u64::from(u32::MAX) + 2;
    let segment = SegmentedSpf::try_new(start, end).expect("boundary range should factor");
    for m in start..=end {
        let factors = factors_for(&segment, m);
        assert_eq!(reconstruct(&factors), u128::from(m), "m={m}");
        assert!(factors.iter().all(|factor| factor.p >= 2));
        assert!(factors.windows(2).all(|pair| pair[0].p < pair[1].p));
    }
}

#[test]
fn unsupported_base_prime_horizon_fails_before_allocating_a_segment() {
    let end = (cubealqot::spf::MAX_BASE_PRIME_LIMIT as u64 + 1).pow(2);
    let error = SegmentedSpf::try_new(end, end)
        .expect_err("the configured base-prime horizon must reject this range");
    assert!(error.contains("base-prime coverage"), "{error}");
}
