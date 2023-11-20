// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::NonZero;

use crate::{
    AsNaturalNumber, AsRingElement, EncryptionKey, LargeBiPrimeSizedNumber,
    PaillierModulusSizedNumber,
};

/// A paillier decryption key.
/// Holds both the `secret_key` and its corresponding `encryption_key`
#[derive(PartialEq, Clone)]
pub struct DecryptionKey {
    pub encryption_key: EncryptionKey,
    secret_key: PaillierModulusSizedNumber,
}

impl DecryptionKey {
    /// Create a `DecryptionKey` from a previously-generated `secret_key` and its corresponding
    /// `encryption_key`. Performs no validations
    pub fn new(
        encryption_key: EncryptionKey,
        secret_key: PaillierModulusSizedNumber,
    ) -> DecryptionKey {
        DecryptionKey {
            encryption_key,
            secret_key,
        }
    }

    /// Decrypts `ciphertext`
    /// Performs no validation (that the `ciphertext` is a valid Paillier ciphertext encrypted for
    /// `self.encryption_key.n`) - supplying a wrong ciphertext will return an undefined result.
    pub fn decrypt(&self, ciphertext: &PaillierModulusSizedNumber) -> LargeBiPrimeSizedNumber {
        let c = ciphertext.as_ring_element(&self.encryption_key.n2);
        let n = NonZero::new(self.encryption_key.n.resize()).unwrap();

        // $ D(c,d)=\left(\frac{(c^{d}\mod(N^{2}))-1}{N}\right)\mod(N) $
        let (_, lo): (LargeBiPrimeSizedNumber, LargeBiPrimeSizedNumber) = (((c
            .pow(&self.secret_key)
            .as_natural_number()
            .wrapping_sub(&PaillierModulusSizedNumber::ONE))
            / n)
            % n)
            .split();

        lo
    }
}

impl AsRef<EncryptionKey> for DecryptionKey {
    fn as_ref(&self) -> &EncryptionKey {
        &self.encryption_key
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::tests::{CIPHERTEXT, N, PLAINTEXT, SECRET_KEY};

    #[test]
    fn decrypts() {
        let encryption_key = EncryptionKey::new(N);
        let decryption_key = DecryptionKey::new(encryption_key, SECRET_KEY);
        assert_eq!(decryption_key.decrypt(&CIPHERTEXT), PLAINTEXT);

        let plaintext = LargeBiPrimeSizedNumber::from(42u8);
        let ciphertext = decryption_key
            .encryption_key
            .encrypt(&plaintext, &mut OsRng);
        assert_eq!(decryption_key.decrypt(&ciphertext), plaintext);
    }
}
