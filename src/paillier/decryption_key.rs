use crate::paillier::EncryptionKey;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding, NonZero};
use crypto_bigint::{U1024, U2048, U4096};

struct DecryptionKey {
    encryption_key: EncryptionKey,
    d: U4096,
}

impl DecryptionKey {
    pub fn new(encryption_key: EncryptionKey, d: U4096) -> DecryptionKey {
        // TODO: should we do any validation checks here?
        DecryptionKey { encryption_key, d }
    }

    pub fn decrypt(&self, ciphertext: &U4096) -> U2048 {
        self.encryption_key.to_u2048_mod_n(
            &((
                (self.encryption_key.mod_n2(ciphertext).pow(&self.d) // $ c^d $
                        - self.encryption_key.one_mod_n2())
                .retrieve()
                // $ c^d - 1 mod N^2 = (1 + N)^{m*d mod N} - 1 mod N^2 = (1 + m*d*N - 1) mod N^2 = m*d*N mod N^2 $
            ) / NonZero::new(self.encryption_key.n).unwrap()), // $ (m*d*N) / N = m*d $
        ) // $ m*d mod N = m mod N $
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::CheckedSub;

    use crate::paillier::tests::CIPHERTEXT;
    use crate::paillier::tests::D;
    use crate::paillier::tests::N;
    use crate::paillier::tests::PLAINTEXT;
    use crate::paillier::tests::RANDOMNESS;

    #[test]
    fn decrypts() {
        let encryption_key = EncryptionKey::new(N);
        let decryption_key = DecryptionKey::new(encryption_key, D);
        assert_eq!(decryption_key.decrypt(&CIPHERTEXT), PLAINTEXT);
    }
}
