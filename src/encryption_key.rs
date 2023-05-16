use crate::{
    AsNaturalNumber, AsRingElement, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber,
    PaillierRingElement,
};
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::{Pow, Random};

#[derive(Debug, Clone)]
/// A Paillier encryption key, holding both `n` ($N$) and `n2` ($N^2$)
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
    /// ```
    pub fn new(n: LargeBiPrimeSizedNumber) -> EncryptionKey {
        EncryptionKey { n, n2: n.square() }
    }

    /// Encrypt `plaintext` to `self.n` using `randomness`.
    ///
    /// This is the deterministic variant of the Paillier encryption scheme, as it takes the randomness as an input.
    ///
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
