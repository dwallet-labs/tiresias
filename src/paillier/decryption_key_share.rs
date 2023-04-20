use crate::paillier::EncryptionKey;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding, NonZero};
use crypto_bigint::{U1024, U2048, U4096};

#[derive(Clone)]
pub struct DecryptionKeyShare {
    encryption_key: EncryptionKey,
    decryption_key_share: U4096, // $ d_i $
}

impl DecryptionKeyShare {
    pub fn new(encryption_key: EncryptionKey, decryption_key_share: U4096) -> DecryptionKeyShare {
        // TODO: should we do any validation checks here?
        DecryptionKeyShare {
            encryption_key,
            decryption_key_share,
        }
    }

    pub fn decryption_share(&self, ciphertext: &U4096, n: u32) -> U4096 {
        // $ c_i = c^{2n!d_i} $
        self.encryption_key
            .mod_n2(ciphertext)
            .pow(
                &(self.encryption_key.mod_n2(&U4096::from(2 * n))  // TODO: n!
                    * self.encryption_key.mod_n2(&self.decryption_key_share))
                .retrieve(),
            )
            .retrieve()
    }

    // Now this is for additive sharing, need to do shamir
    pub fn threshold_decrypt(&self, decryption_shares: Vec<U4096>) -> U2048 {
        let n = decryption_shares.len() as u32;

        // TODO: doc math
        let c_prime = decryption_shares
            .iter()
            .fold(self.encryption_key.one_mod_n2(), |acc, c| {
                acc * self.encryption_key.mod_n2(c).pow(&U4096::from(2 * n))
                // TODO: n!, lambda
            });

        (self
            .encryption_key
            .mod_n(&self.encryption_key.to_u2048_mod_n(
                &((c_prime - self.encryption_key.one_mod_n2()).retrieve()
                    / NonZero::new(self.encryption_key.n).unwrap()),
            ))
            * self
                .encryption_key
                .mod_n(&U2048::from(4 * (n.pow(2))))
                .invert()
                .0) // TODO: is it possible that it won't be invertible?
            .retrieve()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::rand_core::OsRng;
    use crypto_bigint::{CheckedSub, RandomMod};

    use crate::paillier::tests::CIPHERTEXT;
    use crate::paillier::tests::D;
    use crate::paillier::tests::N;
    use crate::paillier::tests::PLAINTEXT;
    use crate::paillier::tests::RANDOMNESS;

    #[test]
    fn decrypts() {
        let encryption_key = EncryptionKey::new(N);
        let d1 = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        let d2 = (encryption_key.mod_n2(&D) - encryption_key.mod_n2(&d1)).retrieve(); // This creates an additive sharing $ D = d1 + d2 $

        let decryption_key_share1 = DecryptionKeyShare::new(encryption_key.clone(), d1);
        let decryption_key_share2 = DecryptionKeyShare::new(encryption_key, d2);

        let c1 = decryption_key_share1.decryption_share(&CIPHERTEXT, 2);
        let c2 = decryption_key_share2.decryption_share(&CIPHERTEXT, 2);

        let decryption_shares = vec![c1, c2];

        assert_eq!(
            decryption_key_share1.threshold_decrypt(decryption_shares.clone()),
            PLAINTEXT
        );

        assert_eq!(
            decryption_key_share2.threshold_decrypt(decryption_shares),
            PLAINTEXT
        );
    }
}
