use crate::paillier::EncryptionKey;
use crate::proofs::{ProofError, TranscriptProtocol};
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
        a: &U4096,
        b: &U4096,
        g: &U4096,
        h: &U4096,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let r = U4096::random_mod(rng, &NonZero::new(encryption_key.n).unwrap()); // TODO: account for the security parameter kappa
        let g_hat = encryption_key.mod_n2(g).pow(&r).retrieve();
        let h_hat = encryption_key.mod_n2(h).pow(&r).retrieve();

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append(b"a", &a);
        transcript.append(b"b", &b);
        transcript.append(b"g_hat", &g_hat);
        transcript.append(b"h_hat", &h_hat);

        let u = transcript.challenge(b"u");

        // let w = r.wrapping_sub(u.mul_wide(d)); // TODO: how can this be, what's the sizes here?
        let w = r; // TODO: use above line...

        ProofOfEqualityOfDiscreteLogs {
            a: a.clone(),
            b: b.clone(),
            g_hat,
            h_hat,
            w,
        }
    }

    // TODO: g, h comes from the verifier right? he should know it ahead of time?
    pub fn verify(
        &self,
        encryption_key: &EncryptionKey,
        g: &U4096,
        h: &U4096,
    ) -> Result<(), ProofError> {
        // TODO: need to check not zero for every member?

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append(b"a", &self.a);
        transcript.append(b"b", &self.b);
        transcript.append(b"g_hat", &self.g_hat);
        transcript.append(b"h_hat", &self.h_hat);

        let u = transcript.challenge(b"u");

        // TODO: in the paper, no mod is specified for the powers, is N^2 the correct mod?
        if (encryption_key.mod_n2(&g).pow(&self.w) * encryption_key.mod_n2(&self.a).pow(&u))
            .retrieve()
            == self.g_hat
            && (encryption_key.mod_n2(h).pow(&self.w) * encryption_key.mod_n2(&self.b).pow(&u))
                .retrieve()
                == self.h_hat
        {
            Ok(())
        } else {
            Err(ProofError {})
        }
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
        let a = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let b = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());

        let proof = ProofOfEqualityOfDiscreteLogs::prove(
            encryption_key.clone(),
            &D,
            &a,
            &b,
            &g,
            &h,
            &mut OsRng,
        );

        assert!(proof.verify(&encryption_key, &g, &h).is_ok());
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let encryption_key = EncryptionKey::new(N);

        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());

        /* First generate a truly random proof and make sure it fails */
        let invalid_proof = ProofOfEqualityOfDiscreteLogs {
            a: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
            b: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
            g_hat: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
            h_hat: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
            w: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap()),
        };

        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        /* Now generate a valid proof, and make sure that if we change any field it fails */
        let a = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let b = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());

        let valid_proof = ProofOfEqualityOfDiscreteLogs::prove(
            encryption_key.clone(),
            &D,
            &a,
            &b,
            &g,
            &h,
            &mut OsRng,
        );

        let mut invalid_proof = valid_proof.clone();

        invalid_proof.a = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.b = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.g_hat =
            U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.h_hat =
            U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        invalid_proof = valid_proof;
        invalid_proof.w = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());
    }
}
