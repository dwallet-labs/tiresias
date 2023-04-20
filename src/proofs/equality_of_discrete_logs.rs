use crate::paillier::EncryptionKey;
use crate::proofs::ProofError;
use crypto_bigint::consts::U4;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::RandomMod;
use crypto_bigint::U4096;
use crypto_bigint::{Concat, Encoding, NonZero};
use merlin::Transcript;
use rand_core::CryptoRngCore;

#[derive(Debug, Clone)]
pub struct ProofOfEqualityOfDiscreteLogs {
    a: U4096,
    b: U4096,
    g_hat: U4096,
    h_hat: U4096,
    w: U4096,
}

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
    fn valid_proof_verifies() {
        let encryption_key = EncryptionKey::new(N);
        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());

        let proof = ProofOfEqualityOfDiscreteLogs::prove(encryption_key, &D, &g, &h, &mut OsRng);

        assert!(proof.verify().is_ok());
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let encryption_key = EncryptionKey::new(N);

        /* First generate a truly random proof and make sure it fails */
        let invalid_proof = ProofOfEqualityOfDiscreteLogs {
            a: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
            b: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
            g_hat: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
            h_hat: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
            w: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
        };

        assert!(invalid_proof.verify().is_err());

        /* Now generate a valid proof, and make sure that if we change any field it fails */
        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());

        let valid_proof =
            ProofOfEqualityOfDiscreteLogs::prove(encryption_key.clone(), &D, &g, &h, &mut OsRng);

        let mut invalid_proof = valid_proof.clone();

        invalid_proof.a = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify().is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.b = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify().is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.g_hat =
            U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify().is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.h_hat =
            U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify().is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.w = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify().is_err());
    }
}
