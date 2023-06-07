use std::collections::HashMap;

use crypto_bigint::CheckedMul;
use gcd::Gcd;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{AsNaturalNumber, AsRingElement, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

/// This struct holds precomputed values that are computationally expensive to compute
#[derive(Clone, Debug)]
pub struct PrecomputedValues {
    // A precomputed mapping of the party-id $j$ to the binomial coefficient ${n\choose j}$,
    // factored to "small enough" factors (i.e. of the size of elements in the ring)
    pub(crate) factored_binomial_coefficients: HashMap<u16, Vec<PaillierModulusSizedNumber>>,
    // The precomputed value $(4n!^{2})^{-1} mod(N)$ used for threshold_decryption (saved for
    // optimization reasons)
    pub(crate) four_n_factorial_squared_inverse_mod_n: LargeBiPrimeSizedNumber,
    // The precomputed value $n!$ divided into factors of the Paillier modulus size for efficient
    // exponentiation
    pub(crate) n_factorial: Vec<PaillierModulusSizedNumber>,
}

impl PrecomputedValues {
    pub fn new(n: u16, paillier_n: LargeBiPrimeSizedNumber) -> PrecomputedValues {
        // Factor the binomial coefficients by reducing the fractions ${n\choose j} = \frac{{n - j +
        // 1}\cdots n}{1\cdots j}$. This could be done once an for all for a given number of
        // participants `n`.
        //
        // The binomial coefficient formula is symmetric, i.e. ${n\choose j} = {n\choose {n - j}}$.
        // This allows us the following optimization: instead of computing the coeffecients for all
        // parties, compute it only for the smallest half $1 <= j <= n/2$
        //
        #[cfg(not(feature = "parallel"))]
        let iter = 1..=(n / 2);
        #[cfg(feature = "parallel")]
        let iter = (1..=(n / 2)).into_par_iter();

        let mut factored_binomial_coefficients: HashMap<u16, Vec<PaillierModulusSizedNumber>> =
            iter.flat_map(|j| {
                let factored_coefficient = Self::factor_binomial_coefficient(j, n);

                // Account for the coefficient's symmetric nature for the above mentioned
                // optimization
                if j == (n - j) {
                    vec![(j, factored_coefficient)]
                } else {
                    vec![
                        (j, factored_coefficient.clone()),
                        (n - j, factored_coefficient),
                    ]
                }
            })
            .collect();

        factored_binomial_coefficients.insert(n, vec![PaillierModulusSizedNumber::ONE]);

        let n_factorial = (2..=n).fold(
            LargeBiPrimeSizedNumber::ONE.as_ring_element(&paillier_n),
            |acc, i| acc * LargeBiPrimeSizedNumber::from(i).as_ring_element(&paillier_n),
        );

        let four_n_factorial_squared_inverse_mod_n = (LargeBiPrimeSizedNumber::from(4u8)
            .as_ring_element(&paillier_n)
            * n_factorial.pow_bounded_exp(&LargeBiPrimeSizedNumber::from(2u8), 2))
        .invert() // safe to invert here, can fail only if we accidentally factorized $N$
        .0
        .as_natural_number();

        let n_factorial = Self::combine_small_factors_to_modulus_sized_factors((2..=n).collect());

        PrecomputedValues {
            factored_binomial_coefficients,
            four_n_factorial_squared_inverse_mod_n,
            n_factorial,
        }
    }

    // Factor the binomial coefficients by reducing the fractions ${n\choose j} = \frac{{n - j +
    // 1}\cdots n}{1\cdots j}$.
    fn factor_binomial_coefficient(j: u16, n: u16) -> Vec<PaillierModulusSizedNumber> {
        let mut denominators: Vec<u16> = (2..=j).collect();

        let mut reduced_numerators: Vec<u16> = vec![];
        for numerator in (n - j + 1)..=n {
            if denominators.is_empty() {
                reduced_numerators.push(numerator);
            } else if numerator != 1 {
                let mut reduced_denominators: Vec<u16> = vec![];
                let mut reduced_numerator = numerator;

                for mut denominator in denominators {
                    let gcd = reduced_numerator.gcd(denominator);

                    if gcd != 1 {
                        reduced_numerator /= gcd;
                        denominator /= gcd;
                    }

                    if gcd != 1 || denominator != 1 {
                        reduced_denominators.push(denominator);
                    }
                }

                if reduced_numerator != 1 {
                    reduced_numerators.push(reduced_numerator);
                }

                denominators = reduced_denominators;
            }
        }

        Self::combine_small_factors_to_modulus_sized_factors(reduced_numerators)
    }

    fn combine_small_factors_to_modulus_sized_factors(
        small_factors: Vec<u16>,
    ) -> Vec<PaillierModulusSizedNumber> {
        let (mut modulus_sized_factors, last_factor) = small_factors.iter().fold(
            (vec![], PaillierModulusSizedNumber::ONE),
            |(factors, factor_acc), factor| {
                let factor = PaillierModulusSizedNumber::from(*factor);

                let mul_res = factor_acc.checked_mul(&factor);

                if bool::from(mul_res.is_some()) {
                    (factors, mul_res.unwrap())
                } else {
                    // We overflowed, so let's start next factor
                    let mut factors = factors;
                    factors.push(factor_acc);
                    (factors, factor)
                }
            },
        );

        modulus_sized_factors.push(last_factor);

        modulus_sized_factors
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::tests::N;

    fn factorial(num: u16) -> u64 {
        (1u64..=u64::from(num)).product()
    }

    #[rstest]
    #[case::args((3, HashMap::from([
    (1, vec![PaillierModulusSizedNumber::from(3u16)]),
    (2, vec![PaillierModulusSizedNumber::from(3u16)]),
    (3, vec![PaillierModulusSizedNumber::from(1u16)])
    ])))]
    #[case::args((5, HashMap::from([
    (1, vec![PaillierModulusSizedNumber::from(5u16)]),
    (2, vec![PaillierModulusSizedNumber::from(2u16 * 5)]),
    (3, vec![PaillierModulusSizedNumber::from(2u16 * 5)]),
    (4, vec![PaillierModulusSizedNumber::from(5u16)]),
    (5, vec![PaillierModulusSizedNumber::from(1u16)])
    ])))]
    #[case::args((6, HashMap::from([
    (1, vec![PaillierModulusSizedNumber::from(6u16)]),
    (2, vec![PaillierModulusSizedNumber::from(5u16 * 3)]),
    (3, vec![PaillierModulusSizedNumber::from(2u16 * 5 * 2)]),
    (4, vec![PaillierModulusSizedNumber::from(5u16 * 3)]),
    (5, vec![PaillierModulusSizedNumber::from(6u16)]),
    (6, vec![PaillierModulusSizedNumber::from(1u16)])
    ])))]
    fn constructs(#[case] args: (u16, HashMap<u16, Vec<PaillierModulusSizedNumber>>)) {
        let (n, factors) = args;
        let paillier_n = N;

        let precomputed_values = PrecomputedValues::new(n, paillier_n);

        assert_eq!(precomputed_values.factored_binomial_coefficients, factors);

        assert_eq!(
            (LargeBiPrimeSizedNumber::from(4 * factorial(n) * factorial(n))
                .as_ring_element(&paillier_n)
                * precomputed_values
                    .four_n_factorial_squared_inverse_mod_n
                    .as_ring_element(&paillier_n))
            .as_natural_number(),
            LargeBiPrimeSizedNumber::ONE
        );
    }
}
