use crate::{
    AsNaturalNumber, AsRingElement, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber,
    PaillierRingElement,
};
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{Pow, Random};

/// A Paillier encryption key, holding both `n` ($N$) and `n2` ($N^2$)
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    pub n: LargeBiPrimeSizedNumber,
    pub n2: PaillierModulusSizedNumber,
}

impl EncryptionKey {
    /// Create a new encryption key from the Paillier associated bi-prime `n` ($N$).
    ///
    /// Performs no validation: assuring `n` is valid requires knowledge of the factors `P` and `Q`, which therefore requires knowledge of the secret key.
    /// This API is used for encryption, which should be accessible for everyone, and therefore we can't assume knowledge of the secret key.
    /// Passing an invalid `n` as a parameter will yield invalid Paillier ciphertexts upon encryption.
    ///
    /// ## Example
    /// ```rust
    /// use threshold_paillier::{LargeBiPrimeSizedNumber, EncryptionKey};
    ///
    /// let n: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    /// let encryption_key = EncryptionKey::new(n);
    /// ```
    pub fn new(n: LargeBiPrimeSizedNumber) -> EncryptionKey {
        EncryptionKey { n, n2: n.square() }
    }

    /// Encrypt `plaintext` to `self.n` using `randomness`.
    ///
    /// This is the deterministic variant of the Paillier encryption scheme, as it takes the randomness as an input.
    ///
    /// ## Example
    /// ```rust
    /// use rand_core::OsRng;
    /// use threshold_paillier::{LargeBiPrimeSizedNumber, EncryptionKey};
    /// use crypto_bigint::Random;
    ///
    /// let n: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    /// let plaintext = LargeBiPrimeSizedNumber::from(42u8);
    /// let randomness = LargeBiPrimeSizedNumber::random(&mut OsRng);
    /// let encryption_key = EncryptionKey::new(n);
    ///
    /// let ciphertext = encryption_key.encrypt_with_randomness(&plaintext, &randomness);
    /// ```
    pub fn encrypt_with_randomness(
        &self,
        plaintext: &LargeBiPrimeSizedNumber,
        randomness: &LargeBiPrimeSizedNumber,
    ) -> PaillierModulusSizedNumber {
        let n: PaillierRingElement =
            PaillierModulusSizedNumber::from(self.n).as_ring_element(&self.n2);
        let one: PaillierRingElement = PaillierModulusSizedNumber::ONE.as_ring_element(&self.n2);
        let m: PaillierRingElement =
            PaillierModulusSizedNumber::from(plaintext).as_ring_element(&self.n2);
        let r: PaillierRingElement =
            PaillierModulusSizedNumber::from(randomness).as_ring_element(&self.n2);

        // $ c = (m*N + 1) * (r^N) mod N^2 $
        (
            (m * n + one) * // $ (m*N + 1) * $ 
                <PaillierRingElement as Pow<LargeBiPrimeSizedNumber>>::pow(&r, &self.n)
            // $ (r^N) $
        )
        .as_natural_number()
    }

    /// Encrypt `plaintext` to `self.n`.
    ///
    /// This is the probabilistic variant of the Paillier encryption scheme, that samples randomness from `rng`.
    ///
    /// ## Example
    /// ```rust
    /// use rand_core::OsRng;
    /// use threshold_paillier::{LargeBiPrimeSizedNumber, EncryptionKey};
    ///
    /// let n: LargeBiPrimeSizedNumber = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    /// let plaintext = LargeBiPrimeSizedNumber::from(42u8);
    /// let encryption_key = EncryptionKey::new(n);
    ///
    /// let ciphertext = encryption_key.encrypt(&plaintext, &mut OsRng);
    /// ```
    pub fn encrypt(
        &self,
        plaintext: &LargeBiPrimeSizedNumber,
        rng: &mut impl CryptoRngCore,
    ) -> PaillierModulusSizedNumber {
        let randomness = LargeBiPrimeSizedNumber::random(rng);

        self.encrypt_with_randomness(plaintext, &randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{CIPHERTEXT, N, PLAINTEXT, RANDOMNESS};

    #[test]
    fn encrypts() {
        let encryption_key = EncryptionKey::new(N);

        assert_eq!(
            encryption_key.encrypt_with_randomness(&PLAINTEXT, &RANDOMNESS),
            CIPHERTEXT
        )
    }
}
