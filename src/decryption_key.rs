use crypto_bigint::NonZero;

use crate::{
    AsNaturalNumber, AsRingElement, EncryptionKey, LargeBiPrimeSizedNumber,
    PaillierModulusSizedNumber,
};

/// A paillier decryption key.
/// Holds both the `secret_key` and its corresponding `encryption_key`
pub struct DecryptionKey {
    pub encryption_key: EncryptionKey,
    secret_key: PaillierModulusSizedNumber,
}

impl DecryptionKey {
    /// Create a `DecryptionKey` from a previously-generated `secret_key` and its corresponding
    /// `encryption_key`. Performs no validations
    ///
    /// ## Example
    /// ```rust
    /// use threshold_paillier::{DecryptionKey, EncryptionKey, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber};
    ///
    /// let n: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    /// let secret_key: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
    /// let encryption_key = EncryptionKey::new(n);
    /// let decryption_key = DecryptionKey::new(encryption_key, secret_key);
    /// ```
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
    ///
    /// ## Example
    /// ```rust
    /// use rand_core::OsRng;
    /// use threshold_paillier::{LargeBiPrimeSizedNumber, PaillierModulusSizedNumber, EncryptionKey, DecryptionKey};
    ///
    /// let n: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    /// let secret_key: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");
    /// let encryption_key = EncryptionKey::new(n);
    /// let decryption_key = DecryptionKey::new(encryption_key, secret_key);
    ///
    /// let plaintext = LargeBiPrimeSizedNumber::from(42u8);
    /// let ciphertext = decryption_key.encryption_key.encrypt(&plaintext, &mut OsRng);
    ///
    /// assert_eq!(decryption_key.decrypt(&ciphertext), plaintext);
    /// ```
    pub fn decrypt(&self, ciphertext: &PaillierModulusSizedNumber) -> LargeBiPrimeSizedNumber {
        let c = ciphertext.as_ring_element(&self.encryption_key.n2);
        let n = NonZero::new(PaillierModulusSizedNumber::from(&self.encryption_key.n)).unwrap();

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
