// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

use crypto_bigint::{rand_core::CryptoRngCore, Random};

use crate::{
    AsNaturalNumber, AsRingElement, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber,
    PaillierRingElement,
};

/// A Paillier public encryption key, holding both the bi-prime `n` ($N=PQ$) and the Paillier
/// modulus `n2` ($N^2$)
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    pub n: LargeBiPrimeSizedNumber,
    pub n2: PaillierModulusSizedNumber,
}

impl EncryptionKey {
    /// Create a new encryption key from the Paillier associated bi-prime `n` ($N$).
    ///
    /// Performs no validation for `n`
    pub fn new(n: LargeBiPrimeSizedNumber) -> EncryptionKey {
        EncryptionKey { n, n2: n.square() }
    }

    /// Encrypt `plaintext` to `self.n` using `randomness`.
    ///
    /// This is the deterministic variant of the Paillier encryption scheme, as it takes the
    /// randomness as an input.
    pub fn encrypt_with_randomness(
        &self,
        plaintext: &LargeBiPrimeSizedNumber,
        randomness: &LargeBiPrimeSizedNumber,
    ) -> PaillierModulusSizedNumber {
        let n: PaillierRingElement = self.n.resize().as_ring_element(&self.n2);
        let one: PaillierRingElement = PaillierModulusSizedNumber::ONE.as_ring_element(&self.n2);
        let m: PaillierRingElement = plaintext.resize().as_ring_element(&self.n2);
        let r: PaillierRingElement = randomness.resize().as_ring_element(&self.n2);

        // $ c = (m*N + 1) * (r^N) mod N^2 $
        (
            (m * n + one) * // $ (m*N + 1) * $
                r.pow_bounded_exp(&self.n, LargeBiPrimeSizedNumber::BITS)
            // $ (r^N) $
        )
        .as_natural_number()
    }

    /// Encrypt `plaintext` to `self.n`.
    ///
    /// This is the probabilistic variant of the Paillier encryption scheme, that samples randomness
    /// from `rng`.
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
