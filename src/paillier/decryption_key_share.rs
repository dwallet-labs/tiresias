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

    pub fn decryption_share(&self, ciphertext: &U4096) -> U4096 {
        todo!()
    }

    // Now this is for additive sharing, need to do shamir
    pub fn threshold_decrypt(&self, decryption_shares: Vec<U4096>) -> U2048 {
        todo!()
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

        let c1 = decryption_key_share1.decryption_share(&CIPHERTEXT);
        let c2 = decryption_key_share2.decryption_share(&CIPHERTEXT);

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
