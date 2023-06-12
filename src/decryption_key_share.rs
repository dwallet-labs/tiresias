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
        let iter = ciphertexts.into_iter();
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
        tests::{BASE, CIPHERTEXT, N, N2, SECRET_KEY, WITNESS},
        LargeBiPrimeSizedNumber, SECRET_SHARING_POLYNOMIAL_COEFFICIENT_SIZE_UPPER_BOUND,
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

        let expected_decryption_share =
            <PaillierRingElement as PowBoundedExp<SecretKeyShareSizedNumber>>::pow_bounded_exp(
                &decryption_share_base.as_ring_element(&N2),
                &WITNESS,
                SECRET_KEY_SHARE_SIZE_UPPER_BOUND,
            )
            .as_natural_number();

        assert_eq!(expected_decryption_share, decryption_share);

        assert!(message
            .proof
            .verify(
                decryption_key_share.encryption_key.n2,
                decryption_key_share.base,
                decryption_share_base,
                decryption_key_share.public_verification_key,
                decryption_share
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
                <PaillierRingElement as PowBoundedExp<SecretKeyShareSizedNumber>>::pow_bounded_exp(
                    &decryption_share_base.as_ring_element(&N2),
                    &WITNESS,
                    SECRET_KEY_SHARE_SIZE_UPPER_BOUND,
                )
                .as_natural_number()
            })
            .collect();

        assert_eq!(message.decryption_shares, expected_decryption_shares);

        assert!(message
            .proof
            .batch_verify(
                decryption_key_share.encryption_key.n2,
                decryption_key_share.base,
                decryption_key_share.public_verification_key,
                decryption_share_bases
                    .into_iter()
                    .zip(message.decryption_shares)
                    .collect()
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
        secret_sharing::shamir::Polynomial, LargeBiPrimeSizedNumber,
        SECRET_SHARING_POLYNOMIAL_COEFFICIENT_SIZE_UPPER_BOUND,
    };

    pub(crate) fn benchmark_decryption_share(c: &mut Criterion) {
        let mut g = c.benchmark_group("decryption key share");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let secret_key = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
        let base: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");
        let encryption_key = &EncryptionKey::new(n);

        for num_parties in [10, 100, 1000, 10000] {
            let precomputed_values = PrecomputedValues::new(num_parties, n);
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

                let secret_key_share = SecretKeyShareSizedNumber::from_be_hex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003B9425A07BE38F6F78E811B48A4CFA1F643A20AC0C5F26B3494953A7ED57790917367B3EC21AA67AB4B1F1966D1DAF6AB8FE25292C257E47DF1CD38A6946904C11A24F6E5EB3CC8629128089C7927848D57F4A1ED1F471D2F0FFDC9DA1894C9EFD62B525B493A845E904CFAB9FBD62F962AFF15565BC3057D5ACDBB74AA52622238B8933EFE85713657646A4A95DFAF4E15CD0C9F1F36F68727810B4811C2E625390F094BDB0E0041968ED825CAEBBB4AE75C18B19593966775DE95A6F026C75661B8BB2B42703D75894E86C5F910EC4B344556E5150369A9C8AD6D5AA5096E67110DAAD9A83309E57D1FD855402AE52299EF60895E60FEA7A26D907CDD01B72D4483E18D6988F5EFEB75ABF92061FB9E632569C22B8339FD2B388DAE57E71E3932FBE3567BAF801C323F63AFF99A37C66B06E5225F70D0ECD2DAA20290C8E6EB6D6C46F7EF9EF065850BD51665AF87308B9E8AD2F31A5CCDEA7B8D2EA8C8E81D44D60264C97AB2E10CDF55F0E1D45C5D867DE913E7940498647B3165F8CCF87657971568255B12D221B476BD2EAA09C2CEA2A57950100D80CBCC1F87584417656BAD601CE7A559AEAF90C6070FD9C713C484B74D1409B786C82D650288A8C9B56CB20D4D7409B9805577DCABA8C95E6C59C84C7780FF7E1C43FA4C3A4E00B8E3C087D5F0C4A678C20675800CADDE7924AAD16C48271186605551D41006DD89CD8A3D8895F7516603CC6F31785120C147E3B25FC1C9B0740478F5876285E73CB0C701C408B254D2B7BB4BD3FD719C559D0F9221E86C6EB3655FD254455641E0084376641350D524A30609D326134479302E46BF0217617EB59343E91E4A1FFDD2D192938AED06FB8731963BB095781D0648ED4EEBD8B45AB7EFCE7AF91135B599418787830A848C59CB313C9A151AA79FC10D8B1E9FD42D837A132C316686063BFDAB8374D8D0E4E9BC7548B0EC1E3345D5598D80A43DD92F8F4F470CE08DB63457088A60F7C7F41743D9E8D5D6CDF9BAC5A789FF7D666DCF881DB115245DADBD85816218CFC227EC2BA829383D0F8C098FCD5647AE2140A11922399D0281D64D2082D367BBD1E82B15AB81DA8B3C8A6890979FD948C3110DA39E788D675F55A2C61C6C554CB336AB9ED605097F6D74EA0EEC6B1508C2BA88D3ED380E869DACBFA30E365EF5D0401B1F307DD3D9355174894A585D230155FA18BFE529964202E0687E1EB0A14A377728AC122D8635DB8FD4EA36D2FEC3E514D477F480E5F7BDC52F42CFA905D2DFB335F6BED494BF5FE8DB44CF9C42D2D6481684AAC7C5F0428D7B44BD1351A3EE9AF18873BFAEEE859BFE3772A71E4FCD28257388D04188942AD283D3A7B4B5AB0D7280FC28E93EA17E233FE13CA25B18F445341040F8639947D0C52F738A5A118528DF87237B57DC422EBF3DBFF90DC93678D2B0DAB1845D61054CF19657EB3CE8BB895B56D6C78DB1D4544868E771FFFCFD3DD02186512A326C8DDFAFFD6C9F24902C71EB7690AC7738F2E60B3C79BDEF77781B4B89119182630291AE83409AA46788B15D27A4A4C9A158B344D6F91206D23110734372A8C818AC96154F93BFC3D1704E481ACD823395F757679AEFBC7BB63991D3684D5633D03BE112B890984A0F3FC3E5E3CFFE500537B4EA478DB21361397B97C56B3A232037B29EED61E1E618D22A7A2C52155747E40FE1311366B1B3AA76493C831A1B1B5C3F1F554867A02F352F818C48A5997BE4D82C5B432C89339D23D77E2767640EF8740802DEC42453C9ECC1BF52EE737B11CF515A9FD265FFEC7E2043146173BAE5AB07B1A99B0674C9A99D61B0DA38709ADFDF524838DD81ACF91065ECFE50F0A09BD0BB23E453C28E25082E7D20F2FBA680F132170620A53A92A545E9CFBF0FA23D18806277EE87DC0B76D8428FB78B50AD751A8AD42AF5522F6188B328CFCA5A06CA88F4EAB5C8095B605D02BD41D7CEFFF0E9C65D8C3CF92921641957EC2B8E30FA569ACA5A44525537FACC8738306D2CD622B04E3F0197A03412334FB30F31AC47856D449BE3C9DC1935FC964AE07BEDB093DDFEC83206A532B316AC58620917C45464FEFD9BD1C47A6F18A6135C541C121EE30E65142A00FB33FB6CBF9A44C4BDCF8032F8B9FEBBEF49B698077F30C7640EB8AB893B24C157299739B3C627D2E1A368D4061D60C32F53AEDEEACDF2B47577984275BC9E2601597786842BB7313F95BD01104D5AF42593ADA3F7AFDF0448CED5F32F33B1D67E39D41984D876AB74E205372635841761AFF8A1BEEE3121527FA44FE3DCDA7F601454A17E756D86E2901B82CAD5F4731F454C6AB8AEDF47F445BB2089589F02F5366A760C397533277F3AA0361D6CACA5B700C243C273BF4052A41153CA8C4BE887587C43B2BE243188889A24A2A1E6528B9E41E252DA6E71CDF896B21CD4F886025CD3FB53E286990205A5E6D6D618B91C3322E024FD2C38CAA45034DFC2C90285A05519848F9B9A33A29CB4C6A6D7FE4743180D2E9C75CBFA25AB98406D22550F9168A506A87A5D3D2DC2AC0E3C18322AA4641C6D68A51ECDF2886C16045F8293ECE145DC0829C2AB12F66AC4E99A09E5234A8E418A419DAD265C420FF0FA74206FBEEAE13349619391BDC2A72E5C19C71AD0E9F8AA784540DDFAEFA03ABADFD73DAB0FA84B3659A5F0020A6511432ECA5BDEDC28F37249ECDDA26770AF9F9EA0F223EA787AF5329F172F76D48E002079AB91D57F354DB2C79C81A38EF8D456A53E56FE6D4045CB33B17C41B4AB422AEA47C8293A4AAE4A036164D44168BD84A89D1BBA229FADFDBBE9A5980C0015AEE5475ED139D6BAD0B4C4354ED4CD04A0E847BDDAC9871141D9DD81EAF24C5FA0292F37966C369D025278A6CA06EE2AA6716C20CF2683856F0DE73E95C45A14848DA7E72F2F15E5432EB6E4B0C77BA2B7BAD012F38CD076F8A971194A501DCE2BAC8ACFB2E1C39B7A638B061250B307E931B26D66869655DF698F5E865248895C996096AB74A241E175A82DC2AEE81D278E7F9E8CDF2B2E777D9FD25101B1F0AAB18D5A4697A9B591467787C5543D16D2AF8D8D348551D4D4B8B091DD671AAE4CD470B7A56E5EF311CA59AA711B2C135D7B5210FEAD4B62E24106333E9FB1E5EBC6381E2CE993E059B0EBC6A7E960030441A034FF422A8F9481D447E3E8D59CDA4EAFCCD1A1E186AB17AE1AC025552582AC6C48AFCF2BB180E9D6C2F9DBA9AFF0401FC89BA823EF20F4FC062FCF8514FF72F956B1769321CD11559B89B6DE468E19B5600FB8B372A5DC4783C1DF9F23D70B35E4076DC20A8ACA8CE77654890C1F67A646DC652CBE4D0AFB618883BB1C0CD5E23F697FC3711044785A624854B58A62F8BC66AF743C7319296BE798882D05F5F4999CA16A29FE520185DD7C1CCFD6A6FE79CBDD13B726C0B6E25924D50277F3E42EC6B1F986F137E2F3CB28F2F3C5ED899422BCA39B21A8F3702E43B5135A009775BA1E692FFC3C375BBC771F548F9E0EE1F6351EB51D621216CE9EDD946EE465CAF544E8711DE502E726DB12329A5952E5D6A93790A88A688EF3013E3FB0E611E8109E17B9057D83BAC08F63ED05A74B18E74F9E67838ABCE22B3382FB70CCC6C669FAB267102614824597A354F9EF02EDA7B9A86C5138F8D84CA0939C4B06157EBFE9403F7B0890B760169BD233D30137B583960C181FD59F231DB2254049628D2982A8EED01EA7723BAAC152DD96C5202F08EA97F6B5F77F8C8B3D5D333C340E8B694CAD1BC027432E590E58A2CDCD2A70A2875BC5EC8D07F3A71DB408C2A9F525E10B539E71E22A466D6E2FD83709EAE0A49661A575D2F35D477A76CE8E5F3652433AF52816F2ECA498C46D9E6D5EA293EB55A046B49D420B91CE0526562FA326E7C1389A7BC74407BD1A00F79DBF0AAB979520ECD9DB6E0AF6616EBCDD78226E506F6F2DEAF1B8AD51E7B6C35515D779342647CDE04D49C45E4BFB2517E263B6E92B53C42E667C453215E3D0886ABCDF671023C1884C45CF303A382A887540C950232C329FD88D120FB1A884D138B4A51F7970248ACCB954860243C00B53E129DFAC55B3C60323168E0270980F84C747C24FDF9E098005C5DCD3C34BD30E3FE68ABC36CED662773C9E3A2EFCBC558DEFB544CD2FBEE2AEEEA2561BBC21ED644F53CA43C18BB85AB3ECD79AFCCE47A71C58317FFFB1166C9DC966CD14D041308BE8D03908C8C52DF7AEBF79BEB61A0A84D6BF5A264B080236F4E2A645DC2C8F1AD96036F2374E58E34AA3DA3AFB97FD78AD80AA74498DFB1E938DCCCA81A452114B10C15B7735047019E430D587799CDD9B4F4D9756CF90A8E90186BCCCEF230C0801DA57EA3D2606014856A4D42DFE5387CD11D78296A723D9F49C7EA20C960C0C4C547E6E40DF61AE6B056B9A15B9E764A3ECBEE6B685529047F36B10F4C5498745C75E8365D1B18F42121CA6CE3744C32E3F0736C2603559ECC0EECEB25742B46F03F0C60ECC0FA5C9C27A2A75279A24FC6AEFE5AB9D38D0FAA058A9EA5517FFF632D5BFC2B9E807C3AFCEB1FE453FD6CBA45B3A69FCF8D7E8FAE29865C3DB8AD1C73F820F48CB02FE53C326503AED0FBEF8E7E231579A281974D0382FC42D983EB5D59A6C8EF3A801E1A341967B390F069B0D9CA1E295E7579C9989953C3949F31329256BFC9BC05823978DFB6D7918929D1DB41982BDB7232AD036053A171AC7BFD5330D252A9142CE2EA227D74DD2E60C41AF231DC7DBB68F6772CE7A54A51DB46AC4D99330DCC12BD1B61F969521C051E99B62EB698A4E358F27006496AFEF0238EC0CFB14354FA1B7B79FFC8921B43260860409912EF4AE47B081392CF60132E4962CB11F193CAD467D5BB35FF97438D24278AAD876EED2CA6E25E9B19510C09C7CA96FB0F25D2BF2067C9749486C149A2CCBF6896ABA42E6FE775097FE91C0BCE1EE3084026B816C41299AE638BE83F6C52EBBC86542B1E5A0B4ADB393D7A98E59258E3EECDA92F59FA9E9471BF94E544CFA25659EBC1B6634A9C3B5EB57EFFE11CA4344C9743181544A41234B66CD40D27094F15330F7A55BA99B4135A9FE76092A73EE1254EF31CB9BC84");

                let decryption_key_share = DecryptionKeyShare::new(
                    1,
                    num_parties,
                    num_parties,
                    encryption_key.clone(),
                    base,
                    secret_key_share,
                    precomputed_values.clone(),
                );

                g.bench_function(
                    format!(
                        "decryption_share() for {num_parties} parties and {batch_size} decryptions"
                    ),
                    |bench| {
                        bench.iter(|| {
                            decryption_key_share
                                .generate_decryption_shares(ciphertexts.clone(), &mut OsRng)
                        });
                    },
                );
            }
        }

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
                })
                .collect();

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
