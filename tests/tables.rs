//! Differential tests for residue and table infrastructure.

use cubealqot::tables::{ResidueRunner, SigmaTable, SqSet, advance_residues, init_residues};

fn direct_power_sum(base: u32, exponent: u32, modulus: u32) -> u32 {
    let mut term = 1u128;
    let mut sum = 0u128;
    for _ in 0..exponent {
        sum = (sum + term) % u128::from(modulus);
        term = term * u128::from(base) % u128::from(modulus);
    }
    sum as u32
}

#[test]
fn sigma_table_matches_direct_power_sums() {
    for modulus in [1, 2, 3, 5, 7, 11, 16, 25, 64] {
        let max_e = 12;
        let table = SigmaTable::build(modulus, max_e);

        assert_eq!(table.modulus, modulus);
        assert_eq!(table.stride, max_e + 1);
        assert_eq!(table.tab.len(), modulus as usize * (max_e + 1) as usize);

        for p in 0..=(modulus * 2 + 3) {
            for e in 0..=max_e {
                assert_eq!(
                    table.sigma(p, e),
                    direct_power_sum(p, 3 * e + 1, modulus),
                    "p={p}, e={e}, modulus={modulus}"
                );
            }
        }
    }
}

#[test]
fn square_set_matches_direct_square_residues() {
    for modulus in 1..=64 {
        let squares = SqSet::build(modulus);
        for residue in 0..=(modulus * 2 + 3) {
            let expected = (0..modulus).any(|value| value * value % modulus == residue % modulus);
            assert_eq!(
                squares.contains(residue),
                expected,
                "r={residue}, q={modulus}"
            );
        }
    }
}

#[test]
fn residue_runner_tracks_m_process_then_advance_exhaustively() {
    let moduli = [5u32, 7, 11, 13];
    let start = 2u32;
    let mut runner = ResidueRunner::new(&moduli, start);

    for m in start..=10_000 {
        let expected = moduli.iter().map(|q| m % q).collect::<Vec<_>>();
        assert_eq!(runner.current(), expected);

        // The callback observes the current m residue before the increment.
        let mut observed = None;
        runner.process_then_advance(|residues| observed = Some(residues.to_vec()));
        assert_eq!(observed, Some(expected));
    }
}

#[test]
fn low_level_residue_helpers_track_chunk_boundaries() {
    let moduli = [5u32, 7, 11, 13];
    let mut residues = init_residues(&moduli, 10_000u64);

    for m in 10_000..=20_000 {
        assert_eq!(residues, moduli.iter().map(|q| m % q).collect::<Vec<_>>());
        advance_residues(&mut residues, &moduli);
    }
}

#[test]
#[should_panic(expected = "table exponent exceeds configured maximum")]
fn sigma_table_rejects_an_exponent_outside_its_stride() {
    let table = SigmaTable::build(7, 2);
    let _ = table.sigma(3u64, 3);
}
