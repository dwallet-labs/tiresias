use crate::paillier::u2048_to_u4096;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding};
use crypto_bigint::{U1024, U2048, U4096};

pub struct EncryptionKey {
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

    pub(in crate::paillier) fn mod_n(&self, x: &U2048) -> DynResidue<{ U2048::LIMBS }> {
        DynResidue::new(x, self.n_mod_params)
    }

    pub(in crate::paillier) fn mod_n2(&self, x: &U4096) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::new(x, self.n2_mod_params)
    }

    pub(in crate::paillier) fn u2048_mod_n2(&self, x: &U2048) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::new(&u2048_to_u4096(x), self.n2_mod_params)
    }

    pub(in crate::paillier) fn one_mod_n2(&self) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::one(self.n2_mod_params)
    }

    pub(in crate::paillier) fn to_u2048_mod_n(&self, x: &U4096) -> U2048 {
        // Taking a 4096-bit number under $mod N$ should yield a 2048-bit number;
        // but before we can do that, we need to take only the lower-half (2048-bit) of the number, and perform modulus on that.
        self.mod_n(&U2048::from_le_slice(&x.to_le_bytes()[0..256]))
            .retrieve()
    }

    pub fn encrypt(&self, plaintext: &U2048, randomness: &U2048) -> U4096 {
        (
            ((self.u2048_mod_n2(plaintext) * self.n_mod_n2) + self.one_mod_n2())  // $ c = (m*N + 1) $
            * (self.u2048_mod_n2(randomness).pow(&self.n))
            // $ * (r^N) mod N^2 $
        )
        .retrieve()
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
    fn encrypts() {
        let encryption_key = EncryptionKey::new(N);

        assert_eq!(encryption_key.encrypt(&PLAINTEXT, &RANDOMNESS), CIPHERTEXT)
    }
}
