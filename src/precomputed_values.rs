// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;

use gcd::Gcd;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{AsNaturalNumber, AsRingElement, LargeBiPrimeSizedNumber, SecretKeyShareSizedNumber};

/// This struct holds precomputed values that are computationally expensive to compute
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecomputedValues {
    // A precomputed mapping of the party-id $j$ to the binomial coefficient ${n\choose j}$,
    pub(crate) factored_binomial_coefficients: HashMap<u16, SecretKeyShareSizedNumber>,
    // The precomputed value $(4n!^3)^{-1} mod(N)$ used for threshold_decryption (saved for
    // optimization reasons)
    pub(crate) four_n_factorial_cubed_inverse_mod_n: LargeBiPrimeSizedNumber,
    // The precomputed value $n!$
    pub(crate) n_factorial: SecretKeyShareSizedNumber,
}

impl PrecomputedValues {
    pub fn new(n: u16, paillier_n: LargeBiPrimeSizedNumber) -> PrecomputedValues {
        // Factor the binomial coefficients by reducing the fractions ${n\choose j} = \frac{{n - j +
        // 1}\cdots n}{1\cdots j}$. This could be done once and for all for a given number of
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

        let mut factored_binomial_coefficients: HashMap<u16, SecretKeyShareSizedNumber> = iter
            .flat_map(|j| {
                let factored_coefficient = Self::factor_binomial_coefficient(j, n);

                // Account for the coefficient's symmetric nature for the above mentioned
                // optimization
                if j == (n - j) {
                    vec![(j, factored_coefficient)]
                } else {
                    vec![(j, factored_coefficient), (n - j, factored_coefficient)]
                }
            })
            .collect();

        factored_binomial_coefficients.insert(n, SecretKeyShareSizedNumber::ONE);

        let n_factorial = (2..=n).fold(
            LargeBiPrimeSizedNumber::ONE.as_ring_element(&paillier_n),
            |acc, i| acc * LargeBiPrimeSizedNumber::from(i).as_ring_element(&paillier_n),
        );

        // safe to invert here, since N=PQ and the number is composed of extremely small prime
        // factors, in particular not from P or Q.
        let four_n_factorial_cubed_inverse_mod_n = (LargeBiPrimeSizedNumber::from(4u8)
            .as_ring_element(&paillier_n)
            * n_factorial.pow_bounded_exp(&LargeBiPrimeSizedNumber::from(3u8), 2))
        .invert()
        .0
        .as_natural_number();

        // Can't overflow
        let n_factorial = (2..=n)
            .map(SecretKeyShareSizedNumber::from)
            .reduce(|a, b| a.wrapping_mul(&b))
            .unwrap();

        PrecomputedValues {
            factored_binomial_coefficients,
            four_n_factorial_cubed_inverse_mod_n,
            n_factorial,
        }
    }

    // Factor the binomial coefficients by reducing the fractions ${n\choose j} = \frac{{n - j +
    // 1}\cdots n}{1\cdots j}$.
    fn factor_binomial_coefficient(j: u16, n: u16) -> SecretKeyShareSizedNumber {
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

        // Can't overflow
        reduced_numerators
            .iter()
            .map(|x| SecretKeyShareSizedNumber::from(*x))
            .reduce(|a, b| a.wrapping_mul(&b))
            .unwrap()
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
    (1, SecretKeyShareSizedNumber::from(3u16)),
    (2, SecretKeyShareSizedNumber::from(3u16)),
    (3, SecretKeyShareSizedNumber::from(1u16))
    ])))]
    #[case::args((5, HashMap::from([
    (1, SecretKeyShareSizedNumber::from(5u16)),
    (2, SecretKeyShareSizedNumber::from(2u16 * 5)),
    (3, SecretKeyShareSizedNumber::from(2u16 * 5)),
    (4, SecretKeyShareSizedNumber::from(5u16)),
    (5, SecretKeyShareSizedNumber::from(1u16))
    ])))]
    #[case::args((6, HashMap::from([
    (1, SecretKeyShareSizedNumber::from(6u16)),
    (2, SecretKeyShareSizedNumber::from(5u16 * 3)),
    (3, SecretKeyShareSizedNumber::from(2u16 * 5 * 2)),
    (4, SecretKeyShareSizedNumber::from(5u16 * 3)),
    (5, SecretKeyShareSizedNumber::from(6u16)),
    (6, SecretKeyShareSizedNumber::from(1u16))
    ])))]
    fn constructs(#[case] args: (u16, HashMap<u16, SecretKeyShareSizedNumber>)) {
        let (n, factors) = args;
        let paillier_n = N;

        let precomputed_values = PrecomputedValues::new(n, paillier_n);

        assert_eq!(precomputed_values.factored_binomial_coefficients, factors);

        assert_eq!(
            (LargeBiPrimeSizedNumber::from(4 * factorial(n) * factorial(n) * factorial(n))
                .as_ring_element(&paillier_n)
                * precomputed_values
                    .four_n_factorial_cubed_inverse_mod_n
                    .as_ring_element(&paillier_n))
            .as_natural_number(),
            LargeBiPrimeSizedNumber::ONE
        );
    }
}
