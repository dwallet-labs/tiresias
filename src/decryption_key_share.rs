// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0
use std::{
    collections::{HashMap, HashSet},
    ops::Neg,
};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::{benchmark_combine_decryption_shares, benchmark_decryption_share};
use crypto_bigint::{modular::runtime_mod::DynResidueParams, rand_core::CryptoRngCore, NonZero};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    error::{ProtocolError, SanityCheckError},
    factorial_upper_bound,
    multiexp::multi_exponentiate,
    precomputed_values::PrecomputedValues,
    proofs::ProofOfEqualityOfDiscreteLogs,
    secret_key_share_size_upper_bound, AdjustedLagrangeCoefficientSizedNumber, AsNaturalNumber,
    AsRingElement, EncryptionKey, Error, LargeBiPrimeSizedNumber, Message,
    PaillierModulusSizedNumber, Result, SecretKeyShareSizedNumber, MAX_PLAYERS,
};

#[derive(Clone)]
pub struct DecryptionKeyShare {
    pub party_id: u16,          // The party's index in the protocol $P_j$
    pub threshold: u16,         // The threshold $t$
    pub number_of_parties: u16, // The number of parties $n$
    encryption_key: EncryptionKey,
    // The base $g$ for proofs of equality of discrete logs
    base: PaillierModulusSizedNumber,
    // The public verification key $v_j$ for proofs of equality of discrete logs
    public_verification_key: PaillierModulusSizedNumber,
    // $ d_j $
    decryption_key_share: SecretKeyShareSizedNumber,
    precomputed_values: PrecomputedValues,
}

impl DecryptionKeyShare {
    /// Construct a new `DecryptionKeyShare`.
    pub fn new(
        party_id: u16,
        threshold: u16,
        number_of_parties: u16,
        encryption_key: EncryptionKey,
        base: PaillierModulusSizedNumber,
        decryption_key_share: SecretKeyShareSizedNumber,
        precomputed_values: PrecomputedValues,
    ) -> DecryptionKeyShare {
        assert!(usize::from(number_of_parties) <= MAX_PLAYERS);

        let base = base
            .as_ring_element(&encryption_key.n2)
            .pow_bounded_exp(
                &precomputed_values.n_factorial,
                factorial_upper_bound(usize::from(number_of_parties)),
            )
            .as_natural_number();

        let public_verification_key = base
            .as_ring_element(&encryption_key.n2)
            .pow_bounded_exp(
                &decryption_key_share,
                secret_key_share_size_upper_bound(
                    usize::from(number_of_parties),
                    usize::from(threshold),
                ),
            )
            .as_natural_number();

        DecryptionKeyShare {
            party_id,
            threshold,
            number_of_parties,
            encryption_key,
            base,
            public_verification_key,
            decryption_key_share,
            precomputed_values,
        }
    }

    pub fn generate_decryption_shares(
        &self,
        ciphertexts: Vec<PaillierModulusSizedNumber>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Message> {
        let n2 = self.encryption_key.n2;

        #[cfg(not(feature = "parallel"))]
        let iter = ciphertexts.iter();
        #[cfg(feature = "parallel")]
        let iter = ciphertexts.par_iter();

        let decryption_share_bases: Vec<PaillierModulusSizedNumber> = iter
            .map(|ciphertext| {
                ciphertext
                    .as_ring_element(&n2)
                    .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                    .pow_bounded_exp(
                        &self.precomputed_values.n_factorial,
                        factorial_upper_bound(usize::from(self.number_of_parties)),
                    )
                    .as_natural_number()
            })
            .collect();

        #[cfg(not(feature = "parallel"))]
        let iter = decryption_share_bases.iter();
        #[cfg(feature = "parallel")]
        let iter = decryption_share_bases.par_iter();

        let decryption_shares: Vec<PaillierModulusSizedNumber> = iter
            .map(|decryption_share_base| {
                // $ c_i = c^{2n!d_i} $
                decryption_share_base
                    .as_ring_element(&n2)
                    .pow_bounded_exp(
                        &self.decryption_key_share,
                        secret_key_share_size_upper_bound(
                            usize::from(self.number_of_parties),
                            usize::from(self.threshold),
                        ),
                    )
                    .as_natural_number()
            })
            .collect();

        let decryption_shares_and_bases: Vec<(
            PaillierModulusSizedNumber,
            PaillierModulusSizedNumber,
        )> = decryption_share_bases
            .into_iter()
            .zip(decryption_shares.clone())
            .collect();

        if decryption_shares_and_bases.len() == 1 {
            let (decryption_share_base, decryption_share) =
                decryption_shares_and_bases.get(0).unwrap();

            let proof = ProofOfEqualityOfDiscreteLogs::prove(
                n2,
                self.number_of_parties,
                self.threshold,
                self.decryption_key_share,
                self.base,
                *decryption_share_base,
                self.public_verification_key,
                *decryption_share,
                rng,
            );

            return Ok(Message {
                decryption_shares,
                proof,
            });
        }

        let proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            self.number_of_parties,
            self.threshold,
            self.decryption_key_share,
            self.base,
            self.public_verification_key,
            decryption_shares_and_bases,
            rng,
        )
        .map_err(|_| Error::SanityCheckError(SanityCheckError::InvalidParams()))?;

        Ok(Message {
            decryption_shares,
            proof,
        })
    }

    pub fn compute_absolute_adjusted_lagrange_coefficient(
        party_id: u16,
        number_of_parties: u16,
        decrypters: Vec<u16>,
        precomputed_values: &PrecomputedValues,
    ) -> AdjustedLagrangeCoefficientSizedNumber {
        // The adjusted lagrange coefficient formula is given by:
        // $ 2n!\lambda_{0,j}^{S} =
        //   2{n\choose j}(-1)^{j-1}\Pi_{j'\in [n] \setminus S} (j'-j)\Pi_{j' \in S}j'} $
        // Here, we are only computing a part of that, namely:
        // $ 2{n\choose j}\Pi_{j'\in [n] \setminus S} |j'-j| $
        //
        // For two reasons:
        //  1. We cannot hold negative numbers in crypto-bigint, so we are computing the absolute
        // value.  2. The last part $ \Pi_{j' \in S}j'} $ is independent of $ j $,
        //     so as an optimization we are raising the result of the multi-exponentiation by it
        // once,     instead of every time.

        // Next multiply by ${n\choose j}$
        let adjusted_lagrange_coefficient: AdjustedLagrangeCoefficientSizedNumber =
            precomputed_values
                .factored_binomial_coefficients
                .get(&party_id)
                .unwrap()
                .resize();

        // Finally multiply by $^{\Pi_{j'\in [n] \setminus S} |(j'-j)|}$
        HashSet::<u16>::from_iter(1..=number_of_parties)
            .symmetric_difference(&HashSet::<u16>::from_iter(decrypters))
            .fold(adjusted_lagrange_coefficient, |acc, j_prime| {
                acc.wrapping_mul(&AdjustedLagrangeCoefficientSizedNumber::from(
                    j_prime.abs_diff(party_id),
                ))
            })
    }

    fn combine_decryption_shares_semi_honest(
        encryption_key: EncryptionKey,
        ciphertexts: Vec<PaillierModulusSizedNumber>,
        messages: HashMap<u16, Message>,
        precomputed_values: PrecomputedValues,
        absolute_adjusted_lagrange_coefficients: HashMap<
            u16,
            AdjustedLagrangeCoefficientSizedNumber,
        >,
    ) -> Vec<LargeBiPrimeSizedNumber> {
        // We can't calculate the lagrange coefficients using the standard equations involving
        // division, and division in the exponent in a ring requires knowing its order,
        // which we don't for the Paillier case because it is secret and knowing it implies
        // factorization. So instead, we are not calculating the lagrange coefficients
        // directly but the lagrange coefficients multiplied by $2n!$, which is guaranteed to be an
        // integer:
        //      $2n!\lambda_{0,j}^{S}=2n!\Pi_{j'\in S\setminus\{j\}}\frac{j'}{j'-j}=\frac{2n!\Pi_{j'
        // \in [n]\setminus S}(j'-j)\Pi_{j'\in S\setminus{j}}j'}{\Pi_{j'\in [n]\setminus{j}}(j'-j)}$
        // Or, more compcatly:
        //      $2n!\lambda_{0,j}^{S}=2{n\choose j}(-1)^{j-1}\Pi_{j'\in [n] \setminus S}
        // (j'-j)\Pi_{j' \in S}j'$.

        let n2 = encryption_key.n2;
        let params = DynResidueParams::new(&n2);

        let batch_size = ciphertexts.len();
        #[cfg(not(feature = "parallel"))]
        let iter = 0..batch_size;
        #[cfg(feature = "parallel")]
        let iter = (0..batch_size).into_par_iter();

        // The set $S$ of parties participating in the threshold decryption sessions
        let decrypters: Vec<u16> = messages.clone().into_keys().collect();

        let decrypters_requiring_inversion: Vec<u16> =
            decrypters
                .clone()
                .into_iter()
                .filter(|party_id| {
                    // Since we can't raise by a negative number with `crypto_bigint`,
                    // we raise to the power of the absolute value,
                    // and use an inverted base if the exponent should have been negative.
                    //
                    // We should invert if there are an odd numbers of elements larger than
                    // `j` in `decrypters` ($S$)
                    let inversion_factor = decrypters.iter().fold(1i16, |acc, j_prime| {
                        if party_id > j_prime {
                            acc.neg()
                        } else {
                            acc
                        }
                    });

                    inversion_factor == -1
                })
                .collect();

        // Compute $c_j' = c_{j}^{2n!\lambda_{0,j}^{S}}=c_{j}^{2{n\choose j}(-1)^{j-1}\Pi_{j'\in [n]
        // \setminus S} (j'-j)\Pi_{j' \in S}j'}$.
        iter.map(|i| {
            let decryption_shares_and_absolute_adjusted_lagrange_coefficients: Vec<(
                u16,
                PaillierModulusSizedNumber,
                AdjustedLagrangeCoefficientSizedNumber,
            )> = messages
                .clone()
                .into_iter()
                .map(|(party_id, message)| {
                    (
                        party_id,
                        *message.decryption_shares.get(i).unwrap(),
                        *absolute_adjusted_lagrange_coefficients
                            .get(&party_id)
                            .unwrap(),
                    )
                })
                .collect();

            let decryption_shares_needing_inversion_and_adjusted_lagrange_coefficients: Vec<(
                PaillierModulusSizedNumber,
                AdjustedLagrangeCoefficientSizedNumber,
            )> = decryption_shares_and_absolute_adjusted_lagrange_coefficients
                .clone()
                .into_iter()
                .filter(|(party_id, ..)| decrypters_requiring_inversion.contains(party_id))
                .map(
                    |(_, decryption_share, absolute_adjusted_lagrange_coefficient)| {
                        (decryption_share, absolute_adjusted_lagrange_coefficient)
                    },
                )
                .collect();

            let decryption_shares_not_needing_inversion_and_adjusted_lagrange_coefficients: Vec<(
                PaillierModulusSizedNumber,
                AdjustedLagrangeCoefficientSizedNumber,
            )> = decryption_shares_and_absolute_adjusted_lagrange_coefficients
                .into_iter()
                .filter(|(party_id, ..)| !decrypters_requiring_inversion.contains(party_id))
                .map(
                    |(_, decryption_share, absolute_adjusted_lagrange_coefficient)| {
                        (decryption_share, absolute_adjusted_lagrange_coefficient)
                    },
                )
                .collect();

            (
                decryption_shares_needing_inversion_and_adjusted_lagrange_coefficients,
                decryption_shares_not_needing_inversion_and_adjusted_lagrange_coefficients,
            )
        })
        .map(
            |(
                decryption_shares_needing_inversion_and_adjusted_lagrange_coefficients,
                decryption_shares_not_needing_inversion_and_adjusted_lagrange_coefficients,
            )| {
                #[allow(clippy::tuple_array_conversions)]
                let [c_prime_part_needing_inversion, c_prime_part_not_needing_inversion] = [
                    decryption_shares_needing_inversion_and_adjusted_lagrange_coefficients,
                    decryption_shares_not_needing_inversion_and_adjusted_lagrange_coefficients,
                ]
                .map(|bases_and_exponents| {
                    let exponent_bits = bases_and_exponents
                        .iter()
                        .map(|(_, exp)| exp.bits_vartime())
                        .max()
                        .unwrap();

                    multi_exponentiate(bases_and_exponents, exponent_bits, params)
                        .as_ring_element(&n2)
                });

                let c_prime =
                    c_prime_part_needing_inversion.invert().0 * c_prime_part_not_needing_inversion;

                // $^2{\Pi_{j' \in S}j'}$
                // This computation is independent of `j` so it could be done outside the loop
                let c_prime = decrypters
                    .iter()
                    .fold(
                        c_prime.pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2),
                        |acc, j_prime| {
                            let exp = PaillierModulusSizedNumber::from(*j_prime);
                            acc.pow_bounded_exp(&exp, exp.bits_vartime())
                        },
                    )
                    .as_natural_number();

                let paillier_n = NonZero::new(encryption_key.n.resize()).unwrap();

                // $c` >= 1$ so safe to perform a `.wrapping_sub()` here which will not overflow
                // After dividing a number $ x < N^2 $ by $N$2
                // we will get a number that is smaller than $N$, so we can safely `.split()`
                // and take the low part of the result.
                let (_, lo) =
                    ((c_prime.wrapping_sub(&PaillierModulusSizedNumber::ONE)) / paillier_n).split();

                let paillier_n = encryption_key.n;

                (lo.as_ring_element(&paillier_n)
                    * precomputed_values
                        .four_n_factorial_cubed_inverse_mod_n
                        .as_ring_element(&paillier_n))
                .as_natural_number()
            },
        )
        .collect()
    }

    /// finalize the threshold decryption round by combining all decryption shares from the
    /// threshold-decryption round and decrypting the ciphertext.
    ///
    /// `decryption_shares_and_proofs` and `ciphertexts` must be provided in matching order.
    /// `messages` should hold exactly `t` messages
    ///
    /// This is an associated function and not a method for there is a public operation
    /// which can be performed by non-threshold-decryption parties.
    ///
    /// Note: `base` is assumed to be raised by `n!` as in `new()`.
    #[allow(clippy::too_many_arguments)]
    pub fn combine_decryption_shares<Rng: CryptoRngCore + Send + Sync + Clone>(
        threshold: u16,
        number_of_parties: u16,
        encryption_key: EncryptionKey,
        ciphertexts: Vec<PaillierModulusSizedNumber>,
        messages: HashMap<u16, Message>,
        precomputed_values: PrecomputedValues,
        // The base $g$ for proofs of equality of discrete logs
        base: PaillierModulusSizedNumber,
        // The public verification keys ${{v_i}}_i$ for proofs of equality of discrete logs
        public_verification_keys: HashMap<u16, PaillierModulusSizedNumber>,
        absolute_adjusted_lagrange_coefficients: HashMap<
            u16,
            AdjustedLagrangeCoefficientSizedNumber,
        >,
        rng: &Rng,
    ) -> Result<Vec<LargeBiPrimeSizedNumber>> {
        let n2 = encryption_key.n2;
        let batch_size = ciphertexts.len();

        if messages.len() != usize::from(threshold)
            || messages
                .values()
                .any(|message| message.decryption_shares.len() != batch_size)
        {
            return Err(Error::SanityCheckError(SanityCheckError::InvalidParams()));
        };

        // The set $S$ of parties participating in the threshold decryption sessions
        let decrypters: Vec<u16> = messages.clone().into_keys().collect();

        #[cfg(not(feature = "parallel"))]
        let iter = ciphertexts.into_iter();
        #[cfg(feature = "parallel")]
        let iter = ciphertexts.into_par_iter();

        let decryption_share_bases: Vec<PaillierModulusSizedNumber> = iter
            .map(|ciphertext| {
                ciphertext
                    .as_ring_element(&n2)
                    .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                    .pow_bounded_exp(
                        &precomputed_values.n_factorial,
                        factorial_upper_bound(usize::from(number_of_parties)),
                    )
                    .as_natural_number()
            })
            .collect();

        #[cfg(not(feature = "parallel"))]
        let iter = decrypters.clone().into_iter();
        #[cfg(feature = "parallel")]
        let iter = decrypters.into_par_iter();
        let malicious_parties: Vec<u16> = iter
            .filter(|party_id| {
                let public_verification_key = *public_verification_keys.get(party_id).unwrap();
                let message = messages.get(party_id).unwrap();

                if batch_size == 1 {
                    let decryption_share_base = *decryption_share_bases.get(0).unwrap();
                    let decryption_share = *message.decryption_shares.get(0).unwrap();

                    message
                        .proof
                        .verify(
                            n2,
                            number_of_parties,
                            threshold,
                            base,
                            decryption_share_base,
                            public_verification_key,
                            decryption_share,
                            &mut rng.clone(),
                        )
                        .is_err()
                } else {
                    let decryption_shares_and_bases: Vec<(
                        PaillierModulusSizedNumber,
                        PaillierModulusSizedNumber,
                    )> = decryption_share_bases
                        .clone()
                        .into_iter()
                        .zip(message.decryption_shares.clone())
                        .collect();

                    message
                        .proof
                        .batch_verify(
                            n2,
                            number_of_parties,
                            threshold,
                            base,
                            public_verification_key,
                            decryption_shares_and_bases,
                            &mut rng.clone(),
                        )
                        .is_err()
                }
            })
            .collect();

        if !malicious_parties.is_empty() {
            return Err(Error::ProtocolError(
                ProtocolError::ProofVerificationError { malicious_parties },
            ));
        };

        Ok(Self::combine_decryption_shares_semi_honest(
            encryption_key,
            decryption_share_bases,
            messages,
            precomputed_values,
            absolute_adjusted_lagrange_coefficients,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use crypto_bigint::{CheckedMul, NonZero, RandomMod, Wrapping};
    use rand::seq::IteratorRandom;
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        secret_sharing::shamir::Polynomial,
        secret_sharing_polynomial_coefficient_size_upper_bound,
        tests::{BASE, CIPHERTEXT, N, N2, SECRET_KEY, WITNESS},
        LargeBiPrimeSizedNumber,
    };

    #[test]
    fn generates_decryption_share() {
        let n = 3;
        let t = 2;
        let j = 1;

        let encryption_key = EncryptionKey::new(N);

        let precomputed_values = PrecomputedValues::new(n, encryption_key.n);

        let decryption_key_share =
            DecryptionKeyShare::new(j, t, n, encryption_key, BASE, WITNESS, precomputed_values);

        let message = decryption_key_share
            .generate_decryption_shares(vec![CIPHERTEXT], &mut OsRng)
            .unwrap();

        let decryption_share_base = CIPHERTEXT
            .as_ring_element(&N2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u16 * (2 * 3)), 4)
            .as_natural_number();

        let decryption_share = *message.decryption_shares.get(0).unwrap();

        let expected_decryption_share = decryption_share_base
            .as_ring_element(&N2)
            .pow_bounded_exp(
                &WITNESS,
                secret_key_share_size_upper_bound(usize::from(n), usize::from(t)),
            )
            .as_natural_number();

        assert_eq!(expected_decryption_share, decryption_share);

        assert!(message
            .proof
            .verify(
                decryption_key_share.encryption_key.n2,
                n,
                t,
                decryption_key_share.base,
                decryption_share_base,
                decryption_key_share.public_verification_key,
                decryption_share,
                &mut OsRng
            )
            .is_ok());
    }

    #[test]
    fn generates_decryption_shares() {
        let t = 2;
        let n = 3;

        let encryption_key = &EncryptionKey::new(N);

        let precomputed_values = PrecomputedValues::new(n, encryption_key.n);

        let decryption_key_share = DecryptionKeyShare::new(
            1,
            t,
            n,
            encryption_key.clone(),
            BASE,
            WITNESS,
            precomputed_values,
        );

        let batch_size = 3;
        let plaintexts: Vec<LargeBiPrimeSizedNumber> = iter::repeat_with(|| {
            LargeBiPrimeSizedNumber::random_mod(
                &mut OsRng,
                &NonZero::new(encryption_key.n).unwrap(),
            )
        })
        .take(batch_size)
        .collect();

        let ciphertexts: Vec<PaillierModulusSizedNumber> = plaintexts
            .iter()
            .map(|m| encryption_key.encrypt(m, &mut OsRng))
            .collect();

        let message = decryption_key_share
            .generate_decryption_shares(ciphertexts.clone(), &mut OsRng)
            .unwrap();

        let decryption_share_bases: Vec<PaillierModulusSizedNumber> = ciphertexts
            .iter()
            .map(|ciphertext| {
                ciphertext
                    .as_ring_element(&encryption_key.n2)
                    .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u16 * (2 * 3)), 4)
                    .as_natural_number()
            })
            .collect();

        let expected_decryption_shares: Vec<PaillierModulusSizedNumber> = decryption_share_bases
            .iter()
            .map(|decryption_share_base| {
                decryption_share_base
                    .as_ring_element(&N2)
                    .pow_bounded_exp(
                        &WITNESS,
                        secret_key_share_size_upper_bound(usize::from(n), usize::from(t)),
                    )
                    .as_natural_number()
            })
            .collect();

        assert_eq!(message.decryption_shares, expected_decryption_shares);

        assert!(message
            .proof
            .batch_verify(
                decryption_key_share.encryption_key.n2,
                n,
                t,
                decryption_key_share.base,
                decryption_key_share.public_verification_key,
                decryption_share_bases
                    .into_iter()
                    .zip(message.decryption_shares)
                    .collect(),
                &mut OsRng
            )
            .is_ok());
    }

    #[rstest]
    #[case(2, 3, 1)]
    #[case(2, 3, 2)]
    #[case(5, 5, 1)]
    #[case(6, 10, 5)]
    fn decrypts(#[case] t: u16, #[case] n: u16, #[case] batch_size: usize) {
        let encryption_key = EncryptionKey::new(N);

        let precomputed_values = PrecomputedValues::new(n, encryption_key.n);

        // Do a "trusted dealer" setup, in real life we'd have the secret shares as an output of the
        // DKG.
        let mut coefficients: Vec<Wrapping<SecretKeyShareSizedNumber>> = iter::repeat_with(|| {
            Wrapping(SecretKeyShareSizedNumber::random_mod(
                &mut OsRng,
                &NonZero::new(SecretKeyShareSizedNumber::ONE.shl_vartime(
                    secret_sharing_polynomial_coefficient_size_upper_bound(
                        usize::from(n),
                        usize::from(t),
                    ),
                ))
                .unwrap(),
            ))
        })
        .take(usize::from(t))
        .collect();

        let secret_key: SecretKeyShareSizedNumber = SECRET_KEY.resize();

        coefficients[0] = Wrapping(
            secret_key
                .checked_mul(&precomputed_values.n_factorial)
                .unwrap(),
        );

        let polynomial = Polynomial::try_from(coefficients).unwrap();

        let base = BASE;

        let decrypters = (1..=n).choose_multiple(&mut OsRng, usize::from(t));

        let absolute_adjusted_lagrange_coefficients: HashMap<
            u16,
            AdjustedLagrangeCoefficientSizedNumber,
        > = decrypters
            .clone()
            .into_iter()
            .map(|j| {
                (
                    j,
                    DecryptionKeyShare::compute_absolute_adjusted_lagrange_coefficient(
                        j,
                        n,
                        decrypters.clone(),
                        &precomputed_values,
                    ),
                )
            })
            .collect();

        let decryption_key_shares: HashMap<u16, DecryptionKeyShare> = decrypters
            .clone()
            .into_iter()
            .map(|j| {
                let share = polynomial
                    .evaluate(&Wrapping(SecretKeyShareSizedNumber::from(j)))
                    .0;
                (
                    j,
                    DecryptionKeyShare::new(
                        j,
                        t,
                        n,
                        encryption_key.clone(),
                        base,
                        share,
                        precomputed_values.clone(),
                    ),
                )
            })
            .collect();

        let public_verification_keys: HashMap<u16, PaillierModulusSizedNumber> =
            decryption_key_shares
                .clone()
                .into_iter()
                .map(|(j, decryption_key_share)| (j, decryption_key_share.public_verification_key))
                .collect();

        let plaintexts: Vec<LargeBiPrimeSizedNumber> = iter::repeat_with(|| {
            LargeBiPrimeSizedNumber::random_mod(
                &mut OsRng,
                &NonZero::new(encryption_key.n).unwrap(),
            )
        })
        .take(batch_size)
        .collect();

        let ciphertexts: Vec<PaillierModulusSizedNumber> = plaintexts
            .iter()
            .map(|m| encryption_key.encrypt(m, &mut OsRng))
            .collect();

        let messages: HashMap<u16, Message> = decryption_key_shares
            .iter()
            .map(|(j, party)| {
                (
                    *j,
                    party
                        .generate_decryption_shares(ciphertexts.clone(), &mut OsRng)
                        .unwrap(),
                )
            })
            .collect();

        let base = decryption_key_shares
            .get(decrypters.first().unwrap())
            .unwrap()
            .base;

        assert_eq!(
            plaintexts,
            DecryptionKeyShare::combine_decryption_shares(
                t,
                n,
                encryption_key,
                ciphertexts,
                messages,
                precomputed_values,
                base,
                public_verification_keys,
                absolute_adjusted_lagrange_coefficients,
                &OsRng
            )
            .unwrap(),
        );
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use std::iter;

    use criterion::Criterion;
    use crypto_bigint::{CheckedMul, NonZero, RandomMod, Wrapping};
    use rand::seq::IteratorRandom;
    use rand_core::OsRng;
    use rayon::iter::IntoParallelIterator;

    use super::*;
    use crate::{
        secret_sharing::shamir::Polynomial, secret_sharing_polynomial_coefficient_size_upper_bound,
        LargeBiPrimeSizedNumber,
    };

    pub(crate) fn benchmark_decryption_share(c: &mut Criterion) {
        let mut g = c.benchmark_group("decryption_share()");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let base: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");
        let encryption_key = &EncryptionKey::new(n);

        for number_of_parties in [10, 100, 1000] {
            let precomputed_values = PrecomputedValues::new(number_of_parties, n);
            for batch_size in [1, 10, 100, 1000] {
                let plaintexts: Vec<LargeBiPrimeSizedNumber> = iter::repeat_with(|| {
                    LargeBiPrimeSizedNumber::random_mod(&mut OsRng, &NonZero::new(n).unwrap())
                })
                .take(batch_size)
                .collect();

                let ciphertexts: Vec<PaillierModulusSizedNumber> = plaintexts
                    .iter()
                    .map(|m| encryption_key.encrypt(m, &mut OsRng))
                    .collect();

                let mut secret_key_share_hex = "0".repeat(6109);
                secret_key_share_hex.push_str("A349650E0D97192CB51CAB4075A92EC3C6670BF6909FCB32A65D89D65D7E4B07314AB3BB8A6BC6380797048835E505C73336A5DF95DD28B2EC8FAACFE81CF1F669587DB97EECE29E193100892C8E6776018D80EB3E67F545A2DA1B145AA4890850735A7945D5287DC88B4E43B562334CB809F0B18E07983D82FF7BF9CD4D8703F9744E68C36AF3185EEA7597708B193C219B7B126E9112BA4B15B6D6F476C538BDCB4ADB49AB299FCF1FD501D00B590E208A4CCC6C5E3C6D3C21B5068072992EF2E0C8761EDFCEB5FBB6AFF7E3E341F50DEDDDCA41318130FC36944510D30DCEC98CE7E86D5A13992568B7D23974541F9DC07C29159B01C0CCF307EE7C20F2BFD2BAC9A0147C82B7E5695C6966FF840881214B7360B9516DC3C1CF98A5621C33CE7A4FF829E7EE11626B3601C35E07EE7CB86C80017EA7B1B7AD726A449576940FD73F9A3F99A62FF03A3DCF33E46EC3F33889AF86886097273E702384E1023C9D17B822AB9F63E11F00B835D25DACDE66B6BB6F9619D2293ED170D851699A08FF6DF247A748D8BD3AD2E5E91C65948DAACA2DFE93AAF1A1E417C6E3F7B1648794B5518F5422394244E8C2871CD927A039279CC763055EFCF43404A6926F4A13444F2CE36C157098D58231CC2FA8EDAE23278E468BD0F3B10C494F010728581B3558F5EF0BDAA37F1E7377D239BD2576706658A81AC698735DF38629F0BBA5FFCD16CB206C069232299874107AE99F84CCBD3F09D645CA8FB7B85B463D248133C169EE3F8B6D97C716715C8546D7F314041395E1EFE477F338235AF8BA1C2D94CB4B37B734BB5C7A0C15C4A0F7CFA6669CF2AA657EB780E34C4B7185D8BFEE33290D91419F9433108CEC89888C3A51B0BCFCAED8ABC20C8381DEF95B9B093E349A74A8EED3AAC43BFCFCEA53D344C151D19347ADA76F74030C41A104BD14BD4682142880513830306EC39E5471551D0314AF9466155AF8273E6132B31E01FE79FD3E8120723575C6F380038C582516A0715C4FEB79D094051A498C605DED92618ED97D9A4C3D6E313198AE34DA7DB4682C6ED5CB80D63AB5365C640263B8A6883E2BD5242C688451ADDDDD7D1FF3F84B5CF404730CC01ACE1188893B7CFD571F5468B0C27B84DB7EE30DDDBBC91152679DBAE614EABE0AF881B3C48327E76D93DCA92769A9C6CC73D64840269670EF207951C2361315FD6CE20306372792BDA8A94A916DF24CFDAB27CD0651B193421B1CBD88B0931E14E3E48BF5EAC2AA357C2DB8B47615308C5447F7B445BBE48370026978DD04620F1B376F48B24E1A36A214ADBC3C51BE0DBE4AB25F4851EFFD754A7B212247DE19AE00C25F5CE5787A86027E11D6F86D7EDD5F98FD69B733A4CE81ABD39E72253FB8CAFB5D32E51C5E0DC3D5382A85037BA106891BD29B3F5A2194256B9098BCDF7EE1FA6BBF760BAB6F13E094C1474E3F670B3E5B458BA57D4A03A");
                let secret_key_share =
                    SecretKeyShareSizedNumber::from_be_hex(secret_key_share_hex.as_str());

                let decryption_key_share = DecryptionKeyShare::new(
                    1,
                    number_of_parties,
                    number_of_parties,
                    encryption_key.clone(),
                    base,
                    secret_key_share,
                    precomputed_values.clone(),
                );

                g.bench_function(
                    format!("{number_of_parties} parties and {batch_size} decryptions"),
                    |bench| {
                        bench.iter(|| {
                            decryption_key_share
                                .generate_decryption_shares(ciphertexts.clone(), &mut OsRng)
                        });
                    },
                );
            }
        }

        g.finish();
    }

    pub(crate) fn benchmark_combine_decryption_shares(c: &mut Criterion) {
        let mut g = c.benchmark_group("combine_decryption_shares()");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let secret_key = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
        let base: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");
        let plaintext: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("23f6379f4b0435dd50c0eb12454495c99db09aed97fe498c0dba7c51f6c52ab7b8d8ba47896ee0c43d567a1b3611cb2d53ee74574acc9c4520106c0f6e5d0376817febb477bb729405387b6ae6e213b3b34c0eb0cbe5dff49452979ab7f0b514560b5c9b659732efd0d67a3d7b7512a5d97f1bde1c2263f741838a7c62d78133396715c9568c0524e20a3147cda4510ef2f32cefa6fb92caf3a26da63aba3693efce706303fe399b6c86664b1ccaa9fe6e1505d82c4dd9b0a60ea29ec88a91bf2656a3927ad39d561bfe4009f94398a9a7782383f063adeb922275efd950ef3739dee7854bbf93f939a947e3aec7344135e6b0623aff35e802311c10ede8b0d4");
        let ciphertext: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("0d1a2a781bf90133552b120beb2745bbe02b47cc4e5cc65b6eb5294770bd44b52ce581c4aec199687283360ab0c46bb3f0bb33733dbbf2d7e95a7c600ed20e990e8c3133f7ec238c0b47882363df7748757717443a3d1f9e85f0fb27e665844f591a0f922f42436688a72a71bdf7e93c764a84aff5b813c034787f5cf35a7102fe3be8c670ac26b83b08dabca47d9156ce09d7349ac73d269b7355d5266720654b83b09857add1a6c0be4677115f461ea15907e1472d3d7dcde351f9eff7e43968ae7012a67eeca940c25d3dd5694c5bbf1ed702bfd2094e424bb17bbf00270ded29320cd2e50af2283121ecf5f8593de49b18e465f3b1e1a39daca4d7382e4a610bdbd21dfd343108085b6e2c743f295df3785d3766b56c36efc0ea10ba3de8c16c43fcc051e7c27d835a481c0fdd48819ca9398043689027b00b275ca048018788a5133b280981afb0d6da7e64f3cf5f9e39e501fe7b80807b872ece22f6e4b6b0d8279656ceef614c87ce7ee314a339ef44c3adc4f5e5451b2649c215a358c0682095e19d52ed454d5f4e364397928996823cb02c61f8304561cb21e3bd0f4399f283b0b1ded686ace5dc653b240760c6437323fab45418b904d2eef8ab0639b4cba7cccee58f471413505ca0f8bb5a859769ad9465ddac949d22114cacaeadb72962816c49f50adc6338da7a54bdda29f8e6e667d832bd9c9f9841be8b18");
        let encryption_key = &EncryptionKey::new(n);

        for (threshold, number_of_parties) in [(6, 10), (67, 100), (667, 1000)] {
            let precomputed_values = PrecomputedValues::new(number_of_parties, n);
            // Do a "trusted dealer" setup, in real life we'd have the secret shares as an output of
            // the DKG.
            let mut coefficients: Vec<Wrapping<SecretKeyShareSizedNumber>> =
                iter::repeat_with(|| {
                    Wrapping(SecretKeyShareSizedNumber::random_mod(
                        &mut OsRng,
                        &NonZero::new(SecretKeyShareSizedNumber::ONE.shl_vartime(
                            secret_sharing_polynomial_coefficient_size_upper_bound(
                                usize::from(number_of_parties),
                                usize::from(threshold),
                            ),
                        ))
                        .unwrap(),
                    ))
                })
                .take(usize::from(threshold))
                .collect();

            let secret_key: SecretKeyShareSizedNumber = secret_key.resize();
            coefficients[0] = Wrapping(
                secret_key
                    .checked_mul(&precomputed_values.n_factorial)
                    .unwrap(),
            );

            let polynomial = Polynomial::try_from(coefficients).unwrap();

            let decrypters =
                (1..=number_of_parties).choose_multiple(&mut OsRng, usize::from(threshold));

            let absolute_adjusted_lagrange_coefficients: HashMap<
                u16,
                AdjustedLagrangeCoefficientSizedNumber,
            > = decrypters
                .clone()
                .into_iter()
                .map(|j| {
                    (
                        j,
                        DecryptionKeyShare::compute_absolute_adjusted_lagrange_coefficient(
                            j,
                            number_of_parties,
                            decrypters.clone(),
                            &precomputed_values,
                        ),
                    )
                })
                .collect();

            let decryption_key_shares: HashMap<u16, DecryptionKeyShare> = decrypters
                .into_par_iter()
                .map(|j| {
                    let share = polynomial
                        .evaluate(&Wrapping(SecretKeyShareSizedNumber::from(j)))
                        .0;
                    (
                        j,
                        DecryptionKeyShare::new(
                            j,
                            threshold,
                            number_of_parties,
                            encryption_key.clone(),
                            base,
                            share,
                            precomputed_values.clone(),
                        ),
                    )
                })
                .collect();

            let public_verification_keys: HashMap<u16, PaillierModulusSizedNumber> =
                decryption_key_shares
                    .clone()
                    .into_iter()
                    .map(|(j, decryption_key_share)| {
                        (j, decryption_key_share.public_verification_key)
                    })
                    .collect();

            for batch_size in [1, 10, 100, 1000] {
                let base = base
                    .as_ring_element(&encryption_key.n2)
                    .pow_bounded_exp(
                        &precomputed_values.n_factorial,
                        factorial_upper_bound(usize::from(number_of_parties)),
                    )
                    .as_natural_number();

                let plaintexts: Vec<LargeBiPrimeSizedNumber> = vec![plaintext; batch_size];
                let ciphertexts: Vec<PaillierModulusSizedNumber> = vec![ciphertext; batch_size];
                let decryption_share_base = ciphertext
                    .as_ring_element(&encryption_key.n2)
                    .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                    .pow_bounded_exp(
                        &precomputed_values.n_factorial,
                        factorial_upper_bound(usize::from(number_of_parties)),
                    )
                    .as_natural_number();

                let messages: HashMap<u16, Message> = decryption_key_shares
                    .par_iter()
                    .map(|(j, decryption_key_share)| {
                        // Generating this via `generate_decryption_shares` for all parties is too
                        // slow, so we're optimizing by doing `batch_size` decryptions over the same
                        // ciphertexts `combine_decryption_shares` has no
                        // knowledge of this and does not take advantage of this, so results should
                        // stay the same.
                        let decryption_share = decryption_share_base
                            .as_ring_element(&encryption_key.n2)
                            .pow_bounded_exp(
                                &decryption_key_share.decryption_key_share,
                                secret_key_share_size_upper_bound(
                                    usize::from(number_of_parties),
                                    usize::from(threshold),
                                ),
                            )
                            .as_natural_number();

                        let decryption_shares = vec![decryption_share; batch_size];

                        let decryption_shares_and_bases: Vec<(
                            PaillierModulusSizedNumber,
                            PaillierModulusSizedNumber,
                        )> = vec![(decryption_share_base, decryption_share); batch_size];

                        let proof = if batch_size == 1 {
                            ProofOfEqualityOfDiscreteLogs::prove(
                                encryption_key.n2,
                                number_of_parties,
                                threshold,
                                decryption_key_share.decryption_key_share,
                                decryption_key_share.base,
                                decryption_share_base,
                                decryption_key_share.public_verification_key,
                                decryption_share,
                                &mut OsRng,
                            )
                        } else {
                            ProofOfEqualityOfDiscreteLogs::batch_prove(
                                encryption_key.n2,
                                number_of_parties,
                                threshold,
                                decryption_key_share.decryption_key_share,
                                decryption_key_share.base,
                                decryption_key_share.public_verification_key,
                                decryption_shares_and_bases,
                                &mut OsRng,
                            )
                            .unwrap()
                        };

                        (
                            *j,
                            Message {
                                decryption_shares,
                                proof,
                            },
                        )
                    })
                    .collect();

                g.bench_function(
                    format!(
                        "semi-honest: {batch_size} decryptions with {threshold}-out-of-{number_of_parties} parties"
                    ),
                    |bench| {
                        bench.iter(|| {
                            let decrypted_ciphertexts =
                                DecryptionKeyShare::combine_decryption_shares_semi_honest(
                                    encryption_key.clone(),
                                    ciphertexts.clone(),
                                    messages.clone(),
                                    precomputed_values.clone(),
                                    absolute_adjusted_lagrange_coefficients.clone(),
                                );

                            assert_eq!(decrypted_ciphertexts, plaintexts);
                        });
                    },
                );

                g.bench_function(
                    format!(
                        "maliciously-secure: {batch_size} decryptions with {threshold}-out-of-{number_of_parties} parties"
                    ),
                    |bench| {
                        bench.iter(|| {
                            let decrypted_ciphertexts =
                                DecryptionKeyShare::combine_decryption_shares(
                                    threshold,
                                    number_of_parties,
                                    encryption_key.clone(),
                                    ciphertexts.clone(),
                                    messages.clone(),
                                    precomputed_values.clone(),
                                    base,
                                    public_verification_keys.clone(),
                                    absolute_adjusted_lagrange_coefficients.clone(),
                                    &OsRng
                                )
                                .unwrap();

                            assert_eq!(decrypted_ciphertexts, plaintexts);
                        });
                    },
                );
            }
        }

        g.finish();
    }
}
