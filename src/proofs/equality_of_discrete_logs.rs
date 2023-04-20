use crate::paillier::EncryptionKey;
use crate::proofs::ProofError;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::RandomMod;
use crypto_bigint::U4096;
use crypto_bigint::{Concat, Encoding, NonZero};
use merlin::Transcript;
use rand_core::CryptoRngCore;

pub struct ProofOfEqualityOfDiscreteLogs {}

impl ProofOfEqualityOfDiscreteLogs {
    pub fn prove(
        encryption_key: EncryptionKey,
        d: &U4096,
        g: &U4096,
        h: &U4096,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let r = U4096::random_mod(rng, &NonZero::new(encryption_key.n).unwrap());
        // TODO: account for the security parameter kappa
        todo!()
    }

    pub fn verify(&self) -> Result<(), ProofError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    use crate::paillier::tests::D;
    use crate::paillier::tests::N;

    #[test]
    fn proof_verifies() {
        let encryption_key = EncryptionKey::new(N);
        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());

        let proof = ProofOfEqualityOfDiscreteLogs::prove(encryption_key, &D, &g, &h, &mut OsRng);
        assert!(proof.verify().is_ok())
    }
}
