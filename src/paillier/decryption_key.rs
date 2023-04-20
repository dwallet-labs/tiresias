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
        let c = self.encryption_key.mod_n2(ciphertext);

        let plaintext = c.pow(&self.d); // $ c^d mod N^2 = (1 + N)^{m*d mod N} mod N^2 = (1 + m*d*N) mod N^2 $
        let plaintext = (plaintext - self.encryption_key.one_mod_n2()).retrieve(); // $ c^d mod N^2 - 1 = m*d*N mod N^2 $
        let plaintext = plaintext / NonZero::new(N).unwrap(); // $ (c^d mod N^2 - 1) / N = m*d*N / N mod N^2 = m*d mod N $
        let plaintext = U2048::from_le_slice(&plaintext.to_le_bytes()[0..256]); // Trim zero-padding post-division and convert to U2048

        // Finally take mod N
        let N = encryption_key;
        let N_mod = DynResidueParams::new(&N);
        let plaintext = DynResidue::new(&plaintext, N_mod).retrieve();

        plaintext
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
        assert_eq!(PLAINTEXT, decrypt(&N, &D, &CIPHERTEXT));
    }
}
