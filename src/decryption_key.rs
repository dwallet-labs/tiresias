use crate::{EncryptionKey, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};

#[derive(Clone)]
pub struct DecryptionKey {
    encryption_key: EncryptionKey,
    secret_key: PaillierModulusSizedNumber,
}

impl DecryptionKey {
    pub fn new(
        encryption_key: EncryptionKey,
        secret_key: PaillierModulusSizedNumber,
    ) -> DecryptionKey {
        DecryptionKey {
            encryption_key,
            secret_key,
        }
    }

    pub fn decrypt(&self, ciphertext: &PaillierModulusSizedNumber) -> LargeBiPrimeSizedNumber {
        ciphertext.as_ring_element(self.encryption_key.n2);
        self.encryption_key.to_u2048_mod_n(
            &((
                (self.encryption_key.mod_n2(ciphertext).pow(&self.secret_key) // $ c^d $
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
