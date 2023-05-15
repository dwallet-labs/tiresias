use crate::{AsNaturalNumber, AsRingElement};
use crate::{EncryptionKey, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};
use crypto_bigint::NonZero;

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
        let c = ciphertext.as_ring_element(&self.encryption_key.n2);
        let n = NonZero::new(PaillierModulusSizedNumber::from(&self.encryption_key.n)).unwrap();

        // $ D(c,d)=\left(\frac{(c^{d}\mod(N^{2}))-1}{N}\right)\mod(N) $
        let (_, lo): (LargeBiPrimeSizedNumber, LargeBiPrimeSizedNumber) = ((c
            .pow(&self.secret_key)
            .as_natural_number()
            .wrapping_sub(&PaillierModulusSizedNumber::ONE))
            / n)
            .split();

        let n = NonZero::new(self.encryption_key.n).unwrap();

        lo % n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests::CIPHERTEXT;
    use crate::tests::N;
    use crate::tests::PLAINTEXT;
    use crate::tests::SECRET_KEY_SHARE;

    #[test]
    fn decrypts() {
        let encryption_key = EncryptionKey::new(N);
        let decryption_key = DecryptionKey::new(encryption_key, SECRET_KEY_SHARE);
        assert_eq!(decryption_key.decrypt(&CIPHERTEXT), PLAINTEXT);
    }
}
