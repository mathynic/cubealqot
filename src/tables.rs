//! Small arithmetic tables and power-sum primitives.

use bitvec::vec::BitVec;

/// Returns `(a^n mod modulus, sum_{i=0}^{n-1} a^i mod modulus)`.
///
/// The result is computed in `O(log n)` using the doubling identities for a
/// geometric sum. A zero modulus is invalid because modular reduction is
/// undefined in that case.
pub fn pow_sum(a: u64, n: u64, modulus: u64) -> (u64, u64) {
    assert!(modulus != 0, "modulus must be non-zero");

    let mut result_power = 1 % modulus;
    let mut result_sum = 0;
    let mut block_power = a % modulus;
    let mut block_sum = 1 % modulus;
    let mut remaining = n;

    while remaining != 0 {
        if remaining & 1 == 1 {
            // If R represents n terms and B represents k terms, appending B
            // after R gives S_(n+k) = S_n + a^n S_k.
            result_sum = ((result_sum as u128 + result_power as u128 * block_sum as u128)
                % modulus as u128) as u64;
            result_power = ((result_power as u128 * block_power as u128) % modulus as u128) as u64;
        }

        // Double the represented block: S_(2k) = S_k(1 + a^k).
        block_sum =
            ((block_sum as u128 * ((block_power + 1) % modulus) as u128) % modulus as u128) as u64;
        block_power = ((block_power as u128 * block_power as u128) % modulus as u128) as u64;
        remaining >>= 1;
    }

    (result_power, result_sum)
}

/// Precomputed `sigma(p^((3e))) mod modulus` values indexed by `p % modulus`
/// and `e`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigmaTable {
    pub modulus: u32,
    pub stride: u32,
    pub tab: Vec<u32>,
}

impl SigmaTable {
    /// Builds a table for exponents `0..=max_e`.
    pub fn build(modulus: u32, max_e: u32) -> Self {
        assert!(modulus != 0, "table modulus must be non-zero");
        assert!(max_e < u32::MAX, "table exponent is too large");

        let stride = max_e + 1;
        let len = (modulus as usize)
            .checked_mul(stride as usize)
            .expect("sigma table is too large");
        let mut tab = vec![0u32; len];

        for residue in 0..modulus {
            for exponent in 0..=max_e {
                let index = residue as usize * stride as usize + exponent as usize;
                tab[index] =
                    pow_sum(residue as u64, 3 * exponent as u64 + 1, modulus as u64).1 as u32;
            }
        }

        Self {
            modulus,
            stride,
            tab,
        }
    }

    /// Alias for [`SigmaTable::build`].
    pub fn new(modulus: u32, max_e: u32) -> Self {
        Self::build(modulus, max_e)
    }

    /// Returns the table entry for `sigma(p^(3e)) mod modulus`.
    pub fn sigma(&self, p: impl Into<u64>, e: u32) -> u32 {
        let p = p.into();
        assert!(e < self.stride, "table exponent exceeds configured maximum");
        self.tab[(p % u64::from(self.modulus)) as usize * self.stride as usize + e as usize]
    }
}

/// Bitset of square residues modulo a non-zero modulus.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqSet {
    pub modulus: u32,
    pub bits: BitVec,
}

impl SqSet {
    /// Builds the set by enumerating every residue's square.
    pub fn build(modulus: u32) -> Self {
        assert!(modulus != 0, "square-set modulus must be non-zero");
        let mut bits = BitVec::repeat(false, modulus as usize);
        for value in 0..modulus {
            let square = ((value as u128 * value as u128) % modulus as u128) as usize;
            bits.set(square, true);
        }
        Self { modulus, bits }
    }

    /// Alias for [`SqSet::build`].
    pub fn new(modulus: u32) -> Self {
        Self::build(modulus)
    }

    /// Returns whether `residue` is a square modulo this set's modulus.
    pub fn contains(&self, residue: u32) -> bool {
        self.bits[(residue % self.modulus) as usize]
    }
}

/// Initializes `q`-residues with `start % q` for every modulus.
pub fn init_residues(moduli: &[u32], start: impl Into<u64>) -> Vec<u32> {
    let start = start.into();
    moduli
        .iter()
        .map(|&modulus| {
            assert!(modulus != 0, "residue modulus must be non-zero");
            (start % u64::from(modulus)) as u32
        })
        .collect()
}

/// Advances each residue by one, wrapping at its corresponding modulus.
pub fn advance_residues(residues: &mut [u32], moduli: &[u32]) {
    assert_eq!(
        residues.len(),
        moduli.len(),
        "residue and modulus lengths must match"
    );

    for (residue, &modulus) in residues.iter_mut().zip(moduli) {
        assert!(modulus != 0, "residue modulus must be non-zero");
        assert!(*residue < modulus, "residue is outside its modulus");
        *residue += 1;
        if *residue == modulus {
            *residue = 0;
        }
    }
}

/// Stateful residue runner whose callback observes the current value before
/// the runner advances to the next integer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidueRunner {
    pub moduli: Vec<u32>,
    residues: Vec<u32>,
}

impl ResidueRunner {
    pub fn new(moduli: &[u32], start: impl Into<u64>) -> Self {
        Self {
            moduli: moduli.to_vec(),
            residues: init_residues(moduli, start),
        }
    }

    pub fn current(&self) -> &[u32] {
        &self.residues
    }

    pub fn advance(&mut self) {
        advance_residues(&mut self.residues, &self.moduli);
    }

    pub fn process_then_advance(&mut self, process: impl FnOnce(&[u32])) {
        process(&self.residues);
        self.advance();
    }
}

#[cfg(test)]
mod tests {
    use super::{ResidueRunner, SigmaTable, SqSet, pow_sum};

    #[test]
    fn zero_terms_have_empty_sum() {
        assert_eq!(pow_sum(7, 0, 11), (1, 0));
        assert_eq!(pow_sum(7, 0, 1), (0, 0));
    }

    #[test]
    fn table_and_square_set_have_expected_shapes() {
        let sigma = SigmaTable::build(7, 3);
        assert_eq!(sigma.tab.len(), 7 * 4);
        assert_eq!(sigma.sigma(3u64, 0), 1);

        let squares = SqSet::build(7);
        assert!(squares.contains(2));
        assert!(!squares.contains(3));
    }

    #[test]
    fn runner_exposes_before_advance_state() {
        let mut runner = ResidueRunner::new(&[5], 4u64);
        let mut observed = Vec::new();
        runner.process_then_advance(|residues| observed.extend_from_slice(residues));
        assert_eq!(observed, [4]);
        assert_eq!(runner.current(), [0]);
    }
}
