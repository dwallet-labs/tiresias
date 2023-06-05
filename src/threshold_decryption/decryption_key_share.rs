#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark_decryption_share;
use crypto_bigint::rand_core::CryptoRngCore;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    proofs::ProofOfEqualityOfDiscreteLogs,
    threshold_decryption::{precomputed_values::PrecomputedValues, Message},
    AsNaturalNumber, AsRingElement, EncryptionKey, PaillierModulusSizedNumber,
};

#[derive(Clone)]
pub(in crate::threshold_decryption) struct DecryptionKeyShare {
    pub(in crate::threshold_decryption) encryption_key: EncryptionKey,
    // The base $g$ for proofs of equality of discrete logs
    pub(in crate::threshold_decryption) base: PaillierModulusSizedNumber,
    // The public verification key $v_j$ for proofs of equality of discrete logs
    pub(in crate::threshold_decryption) public_verification_key: PaillierModulusSizedNumber,
    // $ d_j $
    decryption_key_share: PaillierModulusSizedNumber,
    n_factorial: Vec<PaillierModulusSizedNumber>,
}

impl DecryptionKeyShare {
    /// Construct a new `DecryptionKeyShare`.
    pub(in crate::threshold_decryption) fn new(
        encryption_key: EncryptionKey,
        base: PaillierModulusSizedNumber,
        decryption_key_share: PaillierModulusSizedNumber,
        n_factorial: Vec<PaillierModulusSizedNumber>,
    ) -> DecryptionKeyShare {
        let base = n_factorial
            .iter()
            .fold(base.as_ring_element(&encryption_key.n2), |acc, factor| {
                acc.pow_bounded_exp(factor, factor.bits_vartime())
            })
            .as_natural_number();

        let public_verification_key = base
            .as_ring_element(&encryption_key.n2)
            .pow(&decryption_key_share)
            .as_natural_number();

        DecryptionKeyShare {
            encryption_key,
            base,
            public_verification_key,
            decryption_key_share,
            n_factorial,
        }
    }

    pub(in crate::threshold_decryption) fn generate_decryption_shares(
        &self,
        ciphertexts: Vec<PaillierModulusSizedNumber>,
        rng: &mut impl CryptoRngCore,
    ) -> Message {
        let n2 = self.encryption_key.n2;

        #[cfg(not(feature = "parallel"))]
        let iter = ciphertexts.iter();
        #[cfg(feature = "parallel")]
        let iter = ciphertexts.par_iter();

        let ciphertexts_squared_n_factorial: Vec<PaillierModulusSizedNumber> = iter
            .map(|ciphertext| {
                // Computing n! could be too big for even relatively small numbers (e.g. 100),
                // so instead we compute the factorial in the exponent, in O(n) exponentiations
                // (which are performed within the ring, so don't bloat the size)
                self.n_factorial
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
        let iter = ciphertexts_squared_n_factorial.iter();
        #[cfg(feature = "parallel")]
        let iter = ciphertexts_squared_n_factorial.par_iter();

        let decryption_shares: Vec<PaillierModulusSizedNumber> = iter
            .map(|ciphertext| {
                // $ c_i = c^{2n!d_i} $
                ciphertext
                    .as_ring_element(&n2)
                    .pow(&self.decryption_key_share)
                    .as_natural_number()
            })
            .collect();

        let squared_ciphertexts_n_factorial_and_decryption_shares: Vec<(
            PaillierModulusSizedNumber,
            PaillierModulusSizedNumber,
        )> = ciphertexts_squared_n_factorial
            .into_iter()
            .zip(decryption_shares.clone())
            .collect();

        if squared_ciphertexts_n_factorial_and_decryption_shares.len() == 1 {
            let (ciphertext_squared_n_factorial, decryption_share) =
                squared_ciphertexts_n_factorial_and_decryption_shares
                    .get(0)
                    .unwrap();

            // TODO: add SID, PID?
            let proof = ProofOfEqualityOfDiscreteLogs::prove(
                n2,
                self.decryption_key_share,
                self.base,
                *ciphertext_squared_n_factorial,
                self.public_verification_key,
                *decryption_share,
                rng,
            );

            return Message {
                decryption_shares,
                proof,
            };
        }
        let proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            self.decryption_key_share,
            self.base,
            self.public_verification_key,
            squared_ciphertexts_n_factorial_and_decryption_shares,
            rng,
        )
        .unwrap(); // TODO: should I return an error here? I know that this will never
                   // happen as the only case an error is generated is when the vector is
                   // empty and I send it with values, but this couples my to the
                   // implementation and could be a problem if in the future new errors may
                   // be generated

        Message {
            decryption_shares,
            proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use crypto_bigint::{NonZero, RandomMod};
    use rand_core::OsRng;

    use super::*;
    use crate::{
        tests::{BASE, CIPHERTEXT, N, N2, SECRET_KEY},
        LargeBiPrimeSizedNumber,
    };

    #[test]
    fn generates_decryption_share() {
        let n = 3;

        let encryption_key = EncryptionKey::new(N);

        let precomputed_values = PrecomputedValues::new(n);

        let decryption_key_share = DecryptionKeyShare::new(
            encryption_key,
            BASE,
            SECRET_KEY,
            precomputed_values.n_factorial,
        );

        let message = decryption_key_share.generate_decryption_shares(vec![CIPHERTEXT], &mut OsRng);

        let ciphertext_squared_n_factorial = CIPHERTEXT
            .as_ring_element(&N2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u16 * (2 * 3)), 4)
            .as_natural_number();

        let decryption_share = *message.decryption_shares.get(0).unwrap();

        assert_eq!(
            decryption_share,
            ciphertext_squared_n_factorial
                .as_ring_element(&N2)
                .pow(&SECRET_KEY)
                .as_natural_number()
        );

        assert!(message
            .proof
            .verify(
                decryption_key_share.encryption_key.n2,
                decryption_key_share.base,
                ciphertext_squared_n_factorial,
                decryption_key_share.public_verification_key,
                decryption_share
            )
            .is_ok());
    }

    #[test]
    fn generates_decryption_shares() {
        let n = 3;

        let encryption_key = &EncryptionKey::new(N);

        let precomputed_values = PrecomputedValues::new(n);

        let decryption_key_share = DecryptionKeyShare::new(
            encryption_key.clone(),
            BASE,
            SECRET_KEY,
            precomputed_values.n_factorial,
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

        let message =
            decryption_key_share.generate_decryption_shares(ciphertexts.clone(), &mut OsRng);

        let ciphertexts_squared_n_factorial: Vec<PaillierModulusSizedNumber> = ciphertexts
            .iter()
            .map(|ciphertext| {
                ciphertext
                    .as_ring_element(&encryption_key.n2)
                    .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u16 * (2 * 3)), 4)
                    .as_natural_number()
            })
            .collect();

        let expected_decryption_shares: Vec<PaillierModulusSizedNumber> =
            ciphertexts_squared_n_factorial
                .iter()
                .map(|ciphertext| {
                    ciphertext
                        .as_ring_element(&N2)
                        .pow(&SECRET_KEY)
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
                ciphertexts_squared_n_factorial
                    .into_iter()
                    .zip(message.decryption_shares)
                    .collect()
            )
            .is_ok());
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use std::iter;

    use criterion::Criterion;
    use crypto_bigint::{NonZero, RandomMod};
    use rand_core::OsRng;

    use super::*;
    use crate::LargeBiPrimeSizedNumber;

    pub(crate) fn benchmark_decryption_share(c: &mut Criterion) {
        let mut g = c.benchmark_group("decryption key share");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let n2 = n.square();
        let base: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("03B4EFB895D3A85104F1F93744F9DB8924911747DE87ACEC55F1BF37C4531FD7F0A5B498A943473FFA65B89A04FAC2BBDF76FF14D81EB0A0DAD7414CF697E554A93C8495658A329A1907339F9438C1048A6E14476F9569A14BD092BCB2730DCE627566808FD686008F46A47964732DC7DCD2E6ECCE83F7BCCAB2AFDF37144ED153A118B683FF6A3C6971B08DE53DA5D2FEEF83294C21998FC0D1E219A100B6F57F2A2458EA9ABCFA8C5D4DF14B286B71BF5D7AD4FFEEEF069B64E0FC4F1AB684D6B2F20EAA235892F360AA2ECBF361357405D77E5023DF7BEDC12F10F6C35F3BE1163BC37B6C97D62616260A2862F659EB1811B1DDA727847E810D0C2FA120B18E99C9008AA4625CF1862460F8AB3A41E3FDB552187E0408E60885391A52EE2A89DD2471ECBA0AD922DEA0B08474F0BED312993ECB90C90C0F44EF267124A6217BC372D36F8231EB76B0D31DDEB183283A46FAAB74052A01F246D1C638BC00A47D25978D7DF9513A99744D8B65F2B32E4D945B0BA3B7E7A797604173F218D116A1457D20A855A52BBD8AC15679692C5F6AC4A8AF425370EF1D4184322F317203BE9678F92BFD25C7E6820D70EE08809424720249B4C58B81918DA02CFD2CAB3C42A02B43546E64430F529663FCEFA51E87E63F0813DA52F3473506E9E98DCD3142D830F1C1CDF6970726C190EAE1B5D5A26BC30857B4DF639797895E5D61A5EE");
        let encryption_key = &EncryptionKey::new(n);

        for num_parties in [10, 100, 1000, 10000] {
            let precomputed_values = PrecomputedValues::new(num_parties);
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

                let secret_key_share =
                    PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());

                let decryption_key_share = DecryptionKeyShare::new(
                    encryption_key.clone(),
                    base,
                    secret_key_share,
                    precomputed_values.n_factorial.clone(),
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

        g.finish();
    }
}
