use crate::paillier::u2048_to_u4096;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding};
use crypto_bigint::{U1024, U2048, U4096};

struct EncryptionKey {
    n: U4096,                               // the encryption key as a 4096-bit number
    n_mod_n2: DynResidue<{ U4096::LIMBS }>, // the encryption key $N mod N^2$
    n_mod_params: DynResidueParams<{ U2048::LIMBS }>,
    n2_mod_params: DynResidueParams<{ U4096::LIMBS }>,
}

impl EncryptionKey {
    pub fn new(n: U2048) -> EncryptionKey {
        let n_mod_params = DynResidueParams::new(&n);
        let n2: U4096 = n.square();
        let n2_mod_params = DynResidueParams::new(&n2);
        let n = U2048::ZERO.concat(&n);
        let n_mod_n2 = DynResidue::new(&n, n2_mod_params);

        EncryptionKey {
            n,
            n_mod_n2,
            n_mod_params,
            n2_mod_params,
        }
    }

    fn mod_n2(&self, x: U4096) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::new(&x, self.n2_mod_params)
    }

    fn u2048_mod_n2(&self, x: U2048) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::new(&u2048_to_u4096(x), self.n2_mod_params)
    }

    fn one_mod_n2(&self) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::one(self.n2_mod_params)
    }

    pub fn encrypt(&self, plaintext: U2048, randomness: U2048) -> U4096 {
        let m = self.u2048_mod_n2(plaintext);
        let r = self.u2048_mod_n2(randomness);

        let ciphertext = (((m * self.n_mod_n2) + self.one_mod_n2()) * (r.pow(&self.n))).retrieve(); // $ (m*N + 1) * (r^N) mod N^2 $

        ciphertext
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::tests::CIPHERTEXT;
    use crate::paillier::tests::N;
    use crate::paillier::tests::PLAINTEXT;
    use crate::paillier::tests::RANDOMNESS;

    #[test]
    fn test_encryption() {
        let encryption_key = EncryptionKey::new(N);
        assert_eq!(encryption_key.encrypt(PLAINTEXT, RANDOMNESS), CIPHERTEXT)
    }
}
