use crate::paillier::u2048_to_u4096;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding};
use crypto_bigint::{U1024, U2048, U4096};

#[derive(Debug, Clone)]
pub struct EncryptionKey {
    pub(crate) n: U4096,  // the encryption key $ N $ as a 4096-bit number
    pub(crate) n2: U4096, // $ N^2 $
    pub(crate) n_mod_n2: DynResidue<{ U4096::LIMBS }>, // the encryption key $N mod N^2$
    pub(crate) n_mod_params: DynResidueParams<{ U2048::LIMBS }>,
    pub(crate) n2_mod_params: DynResidueParams<{ U4096::LIMBS }>,
}

impl EncryptionKey {
    pub fn new(n: U2048) -> EncryptionKey {
        // TODO: assure N is non-zero
        let n_mod_params = DynResidueParams::new(&n);
        let n2: U4096 = n.square();
        let n2_mod_params = DynResidueParams::new(&n2);
        let n = U2048::ZERO.concat(&n);
        let n_mod_n2 = DynResidue::new(&n, n2_mod_params);

        EncryptionKey {
            n,
            n2,
            n_mod_n2,
            n_mod_params,
            n2_mod_params,
        }
    }

    pub(crate) fn mod_n(&self, x: &U2048) -> DynResidue<{ U2048::LIMBS }> {
        DynResidue::new(x, self.n_mod_params)
    }

    pub(crate) fn mod_n2(&self, x: &U4096) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::new(x, self.n2_mod_params)
    }

    pub(crate) fn u2048_mod_n2(&self, x: &U2048) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::new(&u2048_to_u4096(x), self.n2_mod_params)
    }

    pub(crate) fn one_mod_n2(&self) -> DynResidue<{ U4096::LIMBS }> {
        DynResidue::one(self.n2_mod_params)
    }

    pub(crate) fn to_u2048_mod_n(&self, x: &U4096) -> U2048 {
        // Taking a 4096-bit number under $mod N$ should yield a 2048-bit number;
        // however, the result would still be kept in a 4096-bit U4096 variable.
        // In order to get a U2048, we take only the lower-half (2048-bit) of the number.
        U2048::from_le_slice(
            &DynResidue::new(x, DynResidueParams::new(&self.n))
                .retrieve()
                .to_le_bytes()[0..256],
        )
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
