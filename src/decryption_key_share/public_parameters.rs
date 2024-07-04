// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;

use gcd::Gcd;
use group::PartyID;
use homomorphic_encryption::GroupsPublicParametersAccessors;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    encryption_key, AsNaturalNumber, AsRingElement, LargeBiPrimeSizedNumber,
    PaillierModulusSizedNumber, SecretKeyShareSizedNumber, MAX_PLAYERS,
};

/// The Public Parameters used for Threshold Decryption in Tiresias.
/// This struct holds precomputed values that are computationally expensive to compute, but do not
/// change with the decrypter set (unlike the adjusted lagrange coefficients), besides public
/// outputs from the DKG process (e.g., `base` and `public_verification_key`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicParameters {
    // The threshold $t$.
    pub threshold: PartyID,
    // The number of parties $n$.
    pub number_of_parties: PartyID,
    // The base $g$ for proofs of equality of discrete logs.
    pub base: PaillierModulusSizedNumber,
    // The public verification keys ${{v_i}}_i$ for proofs of equality of discrete logs.
    pub public_verification_keys: HashMap<PartyID, PaillierModulusSizedNumber>,
    // A precomputed mapping of the party-id $j$ to the binomial coefficient ${n\choose j}$.
    pub(crate) factored_binomial_coefficients: HashMap<PartyID, SecretKeyShareSizedNumber>,
    // The precomputed value $(4n!^3)^{-1} mod(N)$ used for threshold_decryption (saved for
    // optimization reasons).
    pub(crate) four_n_factorial_cubed_inverse_mod_n: LargeBiPrimeSizedNumber,
    // The precomputed value $n!$.
    pub(crate) n_factorial: SecretKeyShareSizedNumber,
    pub encryption_scheme_public_parameters: encryption_key::PublicParameters,
}

impl PublicParameters {
    pub fn new(
        threshold: PartyID,
        number_of_parties: PartyID,
        base: PaillierModulusSizedNumber,
        public_verification_keys: HashMap<PartyID, PaillierModulusSizedNumber>,
        encryption_scheme_public_parameters: encryption_key::PublicParameters,
    ) -> crate::Result<PublicParameters> {
        if usize::from(number_of_parties) > MAX_PLAYERS {
            return Err(crate::Error::SanityCheckError(
                crate::SanityCheckError::InvalidParams(),
            ));
        }

        let paillier_associate_bi_prime = *encryption_scheme_public_parameters
            .plaintext_space_public_parameters()
            .modulus;

        // Factor the binomial coefficients by reducing the fractions ${n\choose j} = \frac{{n - j +
        // 1}\cdots n}{1\cdots j}$. This could be done once and for all for a given number of
        // participants `n`.
        //
        // The binomial coefficient formula is symmetric, i.e. ${n\choose j} = {n\choose {n - j}}$.
        // This allows us the following optimization: instead of computing the coeffecients for all
        // parties, compute it only for the smallest half $1 <= j <= n/2$
        //
        #[cfg(not(feature = "parallel"))]
        let iter = 1..=(number_of_parties / 2);
        #[cfg(feature = "parallel")]
        let iter = (1..=(number_of_parties / 2)).into_par_iter();

        let mut factored_binomial_coefficients: HashMap<u16, SecretKeyShareSizedNumber> = iter
            .flat_map(|j| {
                let factored_coefficient = Self::factor_binomial_coefficient(j, number_of_parties);

                // Account for the coefficient's symmetric nature for the above-mentioned
                // optimization.
                if j == (number_of_parties - j) {
                    vec![(j, factored_coefficient)]
                } else {
                    vec![
                        (j, factored_coefficient),
                        (number_of_parties - j, factored_coefficient),
                    ]
                }
            })
            .collect();

        factored_binomial_coefficients.insert(number_of_parties, SecretKeyShareSizedNumber::ONE);

        let n_factorial = (2..=number_of_parties).fold(
            LargeBiPrimeSizedNumber::ONE.as_ring_element(&paillier_associate_bi_prime),
            |acc, i| {
                acc * LargeBiPrimeSizedNumber::from(i).as_ring_element(&paillier_associate_bi_prime)
            },
        );

        // safe to invert here, since N=PQ and the number is composed of extremely small prime
        // factors, in particular not from P or Q.
        let four_n_factorial_cubed_inverse_mod_n = (LargeBiPrimeSizedNumber::from(4u8)
            .as_ring_element(&paillier_associate_bi_prime)
            * n_factorial.pow_bounded_exp(&LargeBiPrimeSizedNumber::from(3u8), 2))
        .invert()
        .0
        .as_natural_number();

        // Can't overflow
        let n_factorial = (2..=number_of_parties)
            .map(SecretKeyShareSizedNumber::from)
            .reduce(|a, b| a.wrapping_mul(&b))
            .unwrap();

        Ok(PublicParameters {
            threshold,
            number_of_parties,
            base,
            public_verification_keys,
            factored_binomial_coefficients,
            four_n_factorial_cubed_inverse_mod_n,
            n_factorial,
            encryption_scheme_public_parameters,
        })
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

impl AsRef<encryption_key::PublicParameters> for PublicParameters {
    fn as_ref(&self) -> &encryption_key::PublicParameters {
        &self.encryption_scheme_public_parameters
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::test_exports::{BASE, N};

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
        let encryption_scheme_public_parameters =
            crate::encryption_key::PublicParameters::new(N).unwrap();

        let public_parameters = PublicParameters::new(
            n,
            n,
            BASE,
            HashMap::new(),
            encryption_scheme_public_parameters,
        )
        .unwrap();

        assert_eq!(public_parameters.factored_binomial_coefficients, factors);

        assert_eq!(
            (LargeBiPrimeSizedNumber::from(4 * factorial(n) * factorial(n) * factorial(n))
                .as_ring_element(&N)
                * public_parameters
                    .four_n_factorial_cubed_inverse_mod_n
                    .as_ring_element(&N))
            .as_natural_number(),
            LargeBiPrimeSizedNumber::ONE
        );
    }
}
