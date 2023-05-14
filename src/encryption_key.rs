use crate::{
    AsNaturalNumber, AsRingElement, LargeBiPrimeSizedNumber, PaillierModulusSizedNumber,
    PaillierRingElement,
};
use crypto_bigint::Pow;

#[derive(Debug, Clone)]
pub struct EncryptionKey {
    n: LargeBiPrimeSizedNumber,
    n2: PaillierModulusSizedNumber,
}

impl EncryptionKey {
    pub fn new(n: LargeBiPrimeSizedNumber) -> EncryptionKey {
        EncryptionKey { n, n2: n.square() }
    }

    pub fn encrypt(
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

        ((m * n + one)
            * <LargeBiPrimeSizedNumber as Pow<PaillierModulusSizedNumber>>::pow(&r, &self.n))
        .as_natural_number() // $ c = (m*N + 1) * (r^N) mod N^2 $
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{CIPHERTEXT, N, PLAINTEXT, RANDOMNESS};

    #[test]
    fn encrypts() {
        let encryption_key = EncryptionKey::new(N);

        assert_eq!(encryption_key.encrypt(&PLAINTEXT, &RANDOMNESS), CIPHERTEXT)
    }
}
