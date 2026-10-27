//! Modular arithmetic and valuation helpers.

/// Computes `(a * b) mod modulus` without overflowing a `u64` intermediate.
pub fn mod_mul(a: u64, b: u64, modulus: u64) -> u64 {
    assert!(modulus != 0, "modulus must be non-zero");
    ((a as u128 * b as u128) % modulus as u128) as u64
}

/// Computes `base^exponent mod modulus` by binary exponentiation.
pub fn modpow(base: u64, exponent: u64, modulus: u64) -> u64 {
    assert!(modulus != 0, "modulus must be non-zero");

    let mut result = 1 % modulus;
    let mut factor = base % modulus;
    let mut remaining = exponent;

    while remaining != 0 {
        if remaining & 1 == 1 {
            result = mod_mul(result, factor, modulus);
        }
        factor = mod_mul(factor, factor, modulus);
        remaining >>= 1;
    }

    result
}

/// Spelled with Rust's usual word separator; kept as a convenience alias for
/// the `modpow` name used in the number-theory plan.
pub fn mod_pow(base: u64, exponent: u64, modulus: u64) -> u64 {
    modpow(base, exponent, modulus)
}

/// Computes the greatest common divisor of two unsigned integers.
pub fn gcd(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

/// Computes the multiplicative order of `g` modulo the prime `p`.
///
/// The caller supplies a prime modulus and a unit `g`; the order is reduced
/// from `p - 1` by its prime divisors. The argument order follows the plan's
/// `(p, g)` convention.
pub fn multiplicative_order(p: u32, g: u32) -> u32 {
    assert!(p >= 2, "order modulus must be at least two");
    assert!(gcd(g % p, p) == 1, "order base must be a unit modulo p");

    let mut order = p - 1;
    let mut factor = 2u32;
    let mut remaining = order;
    while u64::from(factor) * u64::from(factor) <= u64::from(remaining) {
        if remaining % factor == 0 {
            while remaining % factor == 0 {
                remaining /= factor;
            }
            while order % factor == 0
                && modpow(u64::from(g), u64::from(order / factor), u64::from(p)) == 1
            {
                order /= factor;
            }
        }
        factor += 1;
    }
    if remaining > 1 {
        while order % remaining == 0
            && modpow(u64::from(g), u64::from(order / remaining), u64::from(p)) == 1
        {
            order /= remaining;
        }
    }
    order
}

/// Returns the Legendre symbol of `a` modulo the odd prime `p`.
pub fn legendre(a: u32, p: u32) -> i32 {
    assert!(
        p >= 3 && p % 2 == 1,
        "Legendre modulus must be an odd prime"
    );
    match modpow(u64::from(a % p), u64::from((p - 1) / 2), u64::from(p)) {
        0 => 0,
        1 => 1,
        value if value == u64::from(p - 1) => -1,
        _ => unreachable!("Euler criterion failed for a prime modulus"),
    }
}

/// Computes the exponent of `p` in the prime/composite factorization of `n`.
///
/// This helper accepts any `p >= 2`; callers that need a prime valuation can
/// enforce primality at their boundary. The valuation of zero is infinite and
/// therefore outside this finite return type, so zero is rejected.
pub fn valuation(mut n: u128, p: u128) -> u32 {
    assert!(n != 0, "valuation is undefined for zero");
    assert!(p >= 2, "valuation base must be at least two");
    if p == 2 {
        return n.trailing_zeros();
    }

    let mut exponent = 0;
    while n % p == 0 {
        n /= p;
        exponent += 1;
    }
    exponent
}

/// Alias for [`valuation`] using conventional number-theory notation.
pub fn v_p(n: u128, p: u128) -> u32 {
    valuation(n, p)
}

/// Returns the exponent of 2 in `n`.
pub fn v2(n: u128) -> u32 {
    valuation(n, 2)
}

/// Returns the exponent of 3 in `n`.
pub fn v3(n: u128) -> u32 {
    valuation(n, 3)
}

#[cfg(test)]
mod tests {
    use super::{legendre, modpow, multiplicative_order, v2, v3};

    #[test]
    fn exponent_zero_is_one_modulo_the_modulus() {
        assert_eq!(modpow(0, 0, 7), 1);
        assert_eq!(modpow(0, 0, 1), 0);
    }

    #[test]
    fn small_specialized_valuations_are_correct() {
        assert_eq!(v2(40), 3);
        assert_eq!(v3(81), 4);
    }

    #[test]
    fn multiplicative_order_has_expected_small_values() {
        assert_eq!(multiplicative_order(5, 2), 4);
        assert_eq!(multiplicative_order(7, 2), 3);
        assert_eq!(multiplicative_order(11, 10), 2);
    }

    #[test]
    fn legendre_symbol_matches_small_squares() {
        assert_eq!(legendre(0, 7), 0);
        assert_eq!(legendre(2, 7), 1);
        assert_eq!(legendre(3, 7), -1);
    }
}
