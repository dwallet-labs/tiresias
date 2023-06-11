use std::{
    collections::{HashMap, HashSet},
    ops::Neg,
};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark_decryption_share;
use crypto_bigint::{rand_core::CryptoRngCore, NonZero, PowBoundedExp};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    error::{ProtocolError, SanityCheckError},
    precomputed_values::PrecomputedValues,
    proofs::ProofOfEqualityOfDiscreteLogs,
    AsNaturalNumber, AsRingElement, EncryptionKey, Error, LargeBiPrimeSizedNumber, Message,
    PaillierModulusSizedNumber, PaillierRingElement, Result, SecretKeyShareSizedNumber,
    MAX_PLAYERS, SECRET_KEY_SHARE_SIZE_UPPER_BOUND,
};

#[derive(Clone)]
pub struct DecryptionKeyShare {
    pub j: u16, // The party's index in the protocol $P_j$
    pub t: u16, // The threshold $t$
    pub n: u16, // The number of parties $n$
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
        j: u16,
        t: u16,
        n: u16,
        encryption_key: EncryptionKey,
        base: PaillierModulusSizedNumber,
        decryption_key_share: SecretKeyShareSizedNumber,
        precomputed_values: PrecomputedValues,
    ) -> DecryptionKeyShare {
        assert!(usize::from(n) <= MAX_PLAYERS);

        let base = precomputed_values
            .n_factorial
            .iter()
            .fold(base.as_ring_element(&encryption_key.n2), |acc, factor| {
                acc.pow_bounded_exp(factor, factor.bits_vartime())
            })
            .as_natural_number();

        let public_verification_key =
            <PaillierRingElement as PowBoundedExp<SecretKeyShareSizedNumber>>::pow_bounded_exp(
                &base.as_ring_element(&encryption_key.n2),
                &decryption_key_share,
                SECRET_KEY_SHARE_SIZE_UPPER_BOUND,
            )
            .as_natural_number();

        DecryptionKeyShare {
            j,
            t,
            n,
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
                // Computing n! could be too big for even relatively small numbers (e.g. 100),
                // so instead we compute the factorial in the exponent, in O(n) exponentiation
                // (which are performed within the ring, so the size isn't bloated)
                self.precomputed_values
                    .n_factorial
                    .iter()
                    .fold(
                        ciphertext
                            .as_ring_element(&n2)
                            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2),
                        |acc, factor| acc.pow_bounded_exp(factor, factor.bits_vartime()),
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
                <PaillierRingElement as PowBoundedExp<SecretKeyShareSizedNumber>>::pow_bounded_exp(
                    &decryption_share_base.as_ring_element(&n2),
                    &self.decryption_key_share,
                    SECRET_KEY_SHARE_SIZE_UPPER_BOUND,
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

            // TODO: add SID, PID?
            let proof = ProofOfEqualityOfDiscreteLogs::prove(
                n2,
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

    // TODO: multi-exponentiations
    // TODO: use non-constant time library here as it's all public computations?
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
    pub fn combine_decryption_shares(
        t: u16,
        n: u16,
        encryption_key: EncryptionKey,
        ciphertexts: Vec<PaillierModulusSizedNumber>,
        messages: HashMap<u16, Message>,
        precomputed_values: PrecomputedValues,
        // The base $g$ for proofs of equality of discrete logs
        base: PaillierModulusSizedNumber,
        // The public verification keys ${{v_i}}_i$ for proofs of equality of discrete logs
        public_verification_keys: HashMap<u16, PaillierModulusSizedNumber>,
    ) -> Result<Vec<LargeBiPrimeSizedNumber>> {
        let n2 = encryption_key.n2;
        let batch_size = ciphertexts.len();

        if messages.len() != usize::from(t)
            || messages
                .values()
                .any(|message| message.decryption_shares.len() != batch_size)
        {
            return Err(Error::SanityCheckError(SanityCheckError::InvalidParams()));
        };

        // The set $S$ of parties participating in the threshold decryption sessions
        let decrypters: Vec<u16> = messages.clone().into_keys().collect();

        #[cfg(not(feature = "parallel"))]
        let mut iter = ciphertexts.into_iter();
        #[cfg(feature = "parallel")]
        let iter = ciphertexts.into_par_iter();

        let ciphertexts: Vec<PaillierModulusSizedNumber> = iter
            .map(|ciphertext| {
                precomputed_values
                    .n_factorial
                    .iter()
                    .fold(
                        ciphertext
                            .as_ring_element(&n2)
                            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2),
                        |acc, factor| acc.pow_bounded_exp(factor, factor.bits_vartime()),
                    )
                    .as_natural_number()
            })
            .collect();

        #[cfg(not(feature = "parallel"))]
        let iter = decrypters.clone().into_iter();
        #[cfg(feature = "parallel")]
        let iter = decrypters.clone().into_par_iter();

        let malicious_parties: Vec<u16> = iter
            .filter(|j| {
                let public_verification_key = *public_verification_keys.get(j).unwrap();
                let message = messages.get(j).unwrap();

                if batch_size == 1 {
                    let ciphertext_squared_n_factorial = *ciphertexts.get(0).unwrap();
                    let decryption_share = *message.decryption_shares.get(0).unwrap();

                    message
                        .proof
                        .verify(
                            n2,
                            base,
                            ciphertext_squared_n_factorial,
                            public_verification_key,
                            decryption_share,
                        )
                        .is_err()
                } else {
                    let squared_ciphertexts_n_factorial_and_decryption_shares: Vec<(
                        PaillierModulusSizedNumber,
                        PaillierModulusSizedNumber,
                    )> = ciphertexts
                        .clone()
                        .into_iter()
                        .zip(message.decryption_shares.clone().into_iter())
                        .collect();

                    message
                        .proof
                        .batch_verify(
                            n2,
                            base,
                            public_verification_key,
                            squared_ciphertexts_n_factorial_and_decryption_shares,
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

        #[cfg(not(feature = "parallel"))]
        let iter = 0..batch_size;
        #[cfg(feature = "parallel")]
        let iter = (0..batch_size).into_par_iter();

        // We can't calculate the lagrange coefficients using the standard equations involves
        // division, and division in the exponent in a ring requires knowing its order,
        // which we don't for the Paillier case because it is secret and knowing it implies
        // factorization. So instead, we are not calculating the lagrange coefficients
        // directly but the lagrange coefficients multiplied by $2n!$, which is guaranteed to be an
        // integer.
        //
        // Another issue is with calculating $n!$, which might be too large to hold in memory.
        // However, ring operations always results in an element within the ring, so instead
        // we compute the exponent $c'=(c_{j})^{2n!\lambda_{0,j}^{S}}\mod(N^{2})$ in parts, i.e. by
        // raising $c_{j}$ by small factors of the adjusted lagrange coefficients:
        //      $2n!\lambda_{0,j}^{S}=2n!\Pi_{j'\in S\setminus\{j\}}\frac{j'}{j'-j}=\frac{2n!\Pi_{j'
        // \in [n]\setminus S}(j'-j)\Pi_{j'\in S\setminus{j}}j'}{\Pi_{j'\in [n]\setminus{j}}(j'-j)}$
        // Or, more compcatly:
        //      $2n!\lambda_{0,j}^{S}=2{n\choose j}(-1)^{j-1}\Pi_{j'\in [n] \setminus S}
        // (j'-j)\Pi_{j' \in S}j'$.
        //
        // In order to factor the adjusted lagrange coefficients, our only issue is to factor the
        // binomial coefficient $n\choose j$. However, this does not depend on the
        // ciphertext or the set of active parties in threshold decryption, so we can do
        // that once when creating `Self` in `Self::factored_binomial_coefficients()`.

        // Compute $c_j' = c_{j}^{2n!\lambda_{0,j}^{S}}=c_{j}^{2{n\choose j}(-1)^{j-1}\Pi_{j'\in [n]
        // \setminus S} (j'-j)\Pi_{j' \in S}j'}$.
        let plaintexts = iter
            .map(|i| {
                let v: Vec<(u16, PaillierModulusSizedNumber)> = messages
                    .clone()
                    .into_iter()
                    .map(|(j, message)| (j, *message.decryption_shares.get(i).unwrap()))
                    .collect();

                v
            })
            .map(|v| {
                #[cfg(not(feature = "parallel"))]
                let iter = v.into_iter();
                #[cfg(feature = "parallel")]
                let iter = v.into_par_iter();

                let c_prime = iter.map(|(j, decryption_share)| {
                    // $c_{j}^{2{n\choose j}}$
                    let c_j_prime = decryption_share
                        .as_ring_element(&n2)
                        .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2);

                    let c_j_prime = precomputed_values
                        .factored_binomial_coefficients
                        .get(&j)
                        .unwrap()
                        .iter()
                        .fold(c_j_prime, |acc, factor| {
                            acc.pow_bounded_exp(factor, factor.bits_vartime())
                        });

                    // $^{\Pi_{j'\in [n] \setminus S} (j'-j)}$
                    // Since we can't raise by a negative number with `crypto_bigint`, we do this in
                    // two parts. First, we compute on the absolute values:
                    // $^{\Pi_{j'\in [n] \setminus S} (|j'-j|)}$
                    let c_j_prime = HashSet::<u16>::from_iter(1..=n)
                        .symmetric_difference(&HashSet::<u16>::from_iter(decrypters.clone()))
                        .fold(c_j_prime, |acc, j_prime| {
                            let exp = PaillierModulusSizedNumber::from(j_prime.abs_diff(j));
                            acc.pow_bounded_exp(&exp, exp.bits_vartime())
                        });

                    // And secondly we invert only if needed.
                    // We `should_invert` if there are an odd numbers of elements larger than `j` in
                    // `decrypters` ($S$)
                    let should_invert =
                        decrypters.iter().fold(
                            1i16,
                            |acc, j_prime| if j > *j_prime { acc.neg() } else { acc },
                        );

                    if should_invert == -1 {
                        // We know we can invert safely because if we haven't, we reached
                        // factorization. We can't invert x in the Paillier
                        // ring if and only if GCD(x, N) != 1, and for our
                        // case this is guaranteed for `decryption_share` by the
                        // zero-knowledge proof, and therefore for all of its powers.
                        c_j_prime.invert().0
                    } else {
                        c_j_prime
                    }
                });

                #[cfg(not(feature = "parallel"))]
                let c_prime = c_prime.reduce(|a, b| a * b).unwrap();
                #[cfg(feature = "parallel")]
                let c_prime = c_prime.reduce(
                    || PaillierModulusSizedNumber::ONE.as_ring_element(&encryption_key.n2),
                    |a, b| a * b,
                );

                // $^{\Pi_{j' \in S}j'}$
                // This computation is independent of `j` so it could be done outside the loop
                let c_prime = decrypters
                    .iter()
                    .fold(c_prime, |acc, j_prime| {
                        let exp = PaillierModulusSizedNumber::from(*j_prime);
                        acc.pow_bounded_exp(&exp, exp.bits_vartime())
                    })
                    .as_natural_number();

                let paillier_n =
                    NonZero::new(PaillierModulusSizedNumber::from(&encryption_key.n)).unwrap();

                // $c` >= 1$ so safe to perform a `.wrapping_sub()` here which will not overflow
                // After dividing a number $ x < N^2 $ by $N$2
                // we will get a number that is smaller than $N$, so we can safely `.split()` and
                // take the low part of the result.
                let (_, lo) =
                    ((c_prime.wrapping_sub(&PaillierModulusSizedNumber::ONE)) / paillier_n).split();

                let paillier_n = encryption_key.n;

                (lo.as_ring_element(&paillier_n)
                    * precomputed_values
                        .four_n_factorial_squared_inverse_mod_n
                        .as_ring_element(&paillier_n))
                .as_natural_number()
            })
            .collect();

        Ok(plaintexts)
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use crypto_bigint::{NonZero, RandomMod, Wrapping};
    use rand_core::OsRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        secret_sharing::shamir::Polynomial,
        tests::{BASE, CIPHERTEXT, N, N2, SECRET_KEY},
        LargeBiPrimeSizedNumber, LargePrimeSizedNumber,
        SecretSharingPolynomialCoefficientSizedNumber,
        SECRET_SHARING_POLYNOMIAL_COEFFICIENT_SIZE_UPPER_BOUND,
    };

    // #[test]
    // fn generates_decryption_share() {
    //     let n = 3;
    //     let t = 2;
    //     let j = 1;
    //
    //     let encryption_key = EncryptionKey::new(N);
    //
    //     let precomputed_values = PrecomputedValues::new(n, encryption_key.n);
    //
    //     let decryption_key_share = DecryptionKeyShare::new(
    //         j,
    //         t,
    //         n,
    //         encryption_key,
    //         BASE,
    //         SECRET_KEY,
    //         precomputed_values,
    //     );
    //
    //     let message = decryption_key_share
    //         .generate_decryption_shares(vec![CIPHERTEXT], &mut OsRng)
    //         .unwrap();
    //
    //     let decryption_share_base = CIPHERTEXT
    //         .as_ring_element(&N2)
    //         .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u16 * (2 * 3)), 4)
    //         .as_natural_number();
    //
    //     let decryption_share = *message.decryption_shares.get(0).unwrap();
    //
    //     assert_eq!(
    //         decryption_share,
    //         decryption_share_base
    //             .as_ring_element(&N2)
    //             .pow(&SECRET_KEY)
    //             .as_natural_number()
    //     );
    //
    //     assert!(message
    //         .proof
    //         .verify(
    //             decryption_key_share.encryption_key.n2,
    //             decryption_key_share.base,
    //             decryption_share_base,
    //             decryption_key_share.public_verification_key,
    //             decryption_share
    //         )
    //         .is_ok());
    // }

    // #[test]
    // fn generates_decryption_shares() {
    //     let t = 2;
    //     let n = 3;
    //
    //     let encryption_key = &EncryptionKey::new(N);
    //
    //     let precomputed_values = PrecomputedValues::new(n, encryption_key.n);
    //
    //     let decryption_key_share = DecryptionKeyShare::new(
    //         1,
    //         t,
    //         n,
    //         encryption_key.clone(),
    //         BASE,
    //         SECRET_KEY,
    //         precomputed_values,
    //     );
    //
    //     let batch_size = 3;
    //     let plaintexts: Vec<LargeBiPrimeSizedNumber> = iter::repeat_with(|| {
    //         LargeBiPrimeSizedNumber::random_mod(
    //             &mut OsRng,
    //             &NonZero::new(encryption_key.n).unwrap(),
    //         )
    //     })
    //     .take(batch_size)
    //     .collect();
    //
    //     let ciphertexts: Vec<PaillierModulusSizedNumber> = plaintexts
    //         .iter()
    //         .map(|m| encryption_key.encrypt(m, &mut OsRng))
    //         .collect();
    //
    //     let message = decryption_key_share
    //         .generate_decryption_shares(ciphertexts.clone(), &mut OsRng)
    //         .unwrap();
    //
    //     let decryption_share_bases: Vec<PaillierModulusSizedNumber> = ciphertexts
    //         .iter()
    //         .map(|ciphertext| {
    //             ciphertext
    //                 .as_ring_element(&encryption_key.n2)
    //                 .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u16 * (2 * 3)), 4)
    //                 .as_natural_number()
    //         })
    //         .collect();
    //
    //     let expected_decryption_shares: Vec<PaillierModulusSizedNumber> = decryption_share_bases
    //         .iter()
    //         .map(|ciphertext| {
    //             ciphertext
    //                 .as_ring_element(&N2)
    //                 .pow(&SECRET_KEY)
    //                 .as_natural_number()
    //         })
    //         .collect();
    //
    //     assert_eq!(message.decryption_shares, expected_decryption_shares);
    //
    //     assert!(message
    //         .proof
    //         .batch_verify(
    //             decryption_key_share.encryption_key.n2,
    //             decryption_key_share.base,
    //             decryption_key_share.public_verification_key,
    //             decryption_share_bases
    //                 .into_iter()
    //                 .zip(message.decryption_shares)
    //                 .collect()
    //         )
    //         .is_ok());
    // }

    #[rstest]
    #[case(2, 3, 1)]
    #[case(2, 3, 2)]
    #[case(5, 5, 1)]
    #[case(6, 10, 5)]
    fn decrypts(#[case] t: u16, #[case] n: u16, #[case] batch_size: usize) {
        let encryption_key = EncryptionKey::new(N);

        // Do a "trusted dealer" setup, in real life we'd have the secret shares as an output of the
        // DKG.
        let mut coefficients: Vec<Wrapping<SecretKeyShareSizedNumber>> = iter::repeat_with(|| {
            Wrapping(SecretKeyShareSizedNumber::random_mod(
                &mut OsRng,
                &NonZero::new(
                    SecretKeyShareSizedNumber::ONE
                        .shl_vartime(SECRET_SHARING_POLYNOMIAL_COEFFICIENT_SIZE_UPPER_BOUND),
                )
                .unwrap(),
            ))
        })
        .take(usize::from(t))
        .collect();

        coefficients[0] = Wrapping(SecretKeyShareSizedNumber::from(SECRET_KEY));

        let polynomial = Polynomial::try_from(coefficients).unwrap();

        let precomputed_values = PrecomputedValues::new(n, encryption_key.n);

        // // TODO: why is this here?
        // let base = precomputed_values
        //     .n_factorial
        //     .iter()
        //     .fold(BASE.as_ring_element(&encryption_key.n2), |acc, factor| {
        //         acc.pow_bounded_exp(factor, factor.bits_vartime())
        //     })
        //     .as_natural_number();

        let base = BASE;

        let decryption_key_shares: HashMap<u16, DecryptionKeyShare> = (1..=t)
            .map(|j| {
                let share = polynomial
                    .evaluate(&Wrapping(SecretKeyShareSizedNumber::from(j)))
                    .0;
                println!("{:?}", share); // TODO: del
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

        let base = decryption_key_shares.get(&1).unwrap().base;

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
                public_verification_keys
            )
            .unwrap(),
        );
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use std::iter;

    use criterion::Criterion;
    use crypto_bigint::{NonZero, RandomMod, Wrapping};
    use rand_core::OsRng;
    use rayon::iter::IntoParallelIterator;

    use super::*;
    use crate::{
        secret_sharing::shamir::Polynomial, LargeBiPrimeSizedNumber, LargePrimeSizedNumber,
        SecretSharingPolynomialCoefficientSizedNumber,
        SECRET_SHARING_POLYNOMIAL_COEFFICIENT_SIZE_UPPER_BOUND,
    };

    pub(crate) fn benchmark_decryption_share(c: &mut Criterion) {
        let mut g = c.benchmark_group("decryption key share");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let n2 = n.square();
        let secret_key = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
        let base: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");
        let encryption_key = &EncryptionKey::new(n);

        // for num_parties in [10, 100, 1000, 10000] {
        //     let precomputed_values = PrecomputedValues::new(num_parties, n);
        //     for batch_size in [1, 10, 100, 1000] {
        //         let plaintexts: Vec<LargeBiPrimeSizedNumber> = iter::repeat_with(|| {
        //             LargeBiPrimeSizedNumber::random_mod(&mut OsRng, &NonZero::new(n).unwrap())
        //         })
        //         .take(batch_size)
        //         .collect();
        //
        //         let ciphertexts: Vec<PaillierModulusSizedNumber> = plaintexts
        //             .iter()
        //             .map(|m| encryption_key.encrypt(m, &mut OsRng))
        //             .collect();
        //
        //         // TODO: maybe do a proper setup here.
        //         let secret_key_share = SecretKeyShareSizedNumber::random(&mut OsRng);
        //
        //         let decryption_key_share = DecryptionKeyShare::new(
        //             1,
        //             num_parties,
        //             num_parties,
        //             encryption_key.clone(),
        //             base,
        //             secret_key_share,
        //             precomputed_values.clone(),
        //         );
        //
        //         g.bench_function(
        //             format!(
        //                 "decryption_share() for {num_parties} parties and {batch_size} decryptions"
        //             ),
        //             |bench| {
        //                 bench.iter(|| {
        //                     decryption_key_share
        //                         .generate_decryption_shares(ciphertexts.clone(), &mut OsRng)
        //                 });
        //             },
        //         );
        //     }
        // }

        // Do a "trusted dealer" setup, in real life we'd have the secret shares as an output of the
        // DKG.

        for (threshold, num_parties) in [(6, 10), (67, 100), (667, 1000)] {
            let mut coefficients: Vec<Wrapping<SecretKeyShareSizedNumber>> =
                iter::repeat_with(|| {
                    Wrapping(SecretKeyShareSizedNumber::random_mod(
                        &mut OsRng,
                        &NonZero::new(
                            SecretKeyShareSizedNumber::ONE.shl_vartime(
                                SECRET_SHARING_POLYNOMIAL_COEFFICIENT_SIZE_UPPER_BOUND,
                            ),
                        )
                        .unwrap(),
                    ))
                });

            coefficients[0] = Wrapping(SecretKeyShareSizedNumber::from(secret_key));

            let polynomial = Polynomial::try_from(coefficients).unwrap();

            let precomputed_values = PrecomputedValues::new(num_parties, n);

            let decryption_key_shares: HashMap<u16, DecryptionKeyShare> = (1..=threshold)
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
                            num_parties,
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
                let plaintexts: Vec<LargeBiPrimeSizedNumber> = iter::repeat_with(|| {
                    LargeBiPrimeSizedNumber::random_mod(&mut OsRng, &NonZero::new(n).unwrap())
                })
                .take(batch_size)
                .collect();

                let ciphertexts: Vec<PaillierModulusSizedNumber> = plaintexts
                    .iter()
                    .map(|m| encryption_key.encrypt(m, &mut OsRng))
                    .collect();

                let messages: HashMap<u16, Message> = decryption_key_shares
                    .iter()
                    .map(|(j, decryption_key_share)| {
                        (
                            *j,
                            decryption_key_share
                                .generate_decryption_shares(ciphertexts.clone(), &mut OsRng)
                                .unwrap(),
                        )
                    })
                    .collect();

                let base = precomputed_values
                    .n_factorial
                    .iter()
                    .fold(base.as_ring_element(&encryption_key.n2), |acc, factor| {
                        acc.pow_bounded_exp(factor, factor.bits_vartime())
                    })
                    .as_natural_number();

                g.bench_function(
                    format!(
                        "combine_decryption_shares() for {batch_size} decryptions with {threshold}-out-of-{num_parties} parties"
                    ),
                    |bench| {
                        bench.iter(
                            || {
                                let decrypted_ciphertexts =
                                    DecryptionKeyShare::combine_decryption_shares(
                                    threshold,
                                    num_parties,
                                    encryption_key.clone(),
                                    ciphertexts.clone(),
                                    messages.clone(),
                                    precomputed_values.clone(),
                                    base,
                                    public_verification_keys.clone()
                                ).unwrap();

                                assert_eq!(
                                    decrypted_ciphertexts,
                                    plaintexts
                                );
                            },
                        );
                    },
                );
            }
        }

        g.finish();
    }
}
