use crate::paillier::EncryptionKey;
use crate::proofs::{ProofError, TranscriptProtocol};
use crypto_bigint::consts::U4;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{
    Concat, Encoding, NonZero, Random, RandomMod, U1024, U128, U2048, U256, U4096, U512,
};
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
        // TODO: just impl' U2304
        let r: U256 = U256::random(rng); // Sample $r \leftarrow [0,2^{2\kappa}N)$, where k is the security parameter.
                                         /* OMG is this ugly, can't we do better? */
        let r: U512 = U256::ZERO.concat(&r);
        let r: U1024 = U512::ZERO.concat(&r);
        let r: U2048 = U1024::ZERO.concat(&r);
        let (lo, hi) =
            U2048::random_mod(rng, &NonZero::new(encryption_key.n_2048).unwrap()).mul_wide(&r);
        let r: U4096 = hi.concat(&lo);

        let g_hat = encryption_key.mod_n2(g).pow(&r).retrieve();
        let h_hat = encryption_key.mod_n2(h).pow(&r).retrieve();

        let a = encryption_key.mod_n2(g).pow(&d).retrieve();
        let b = encryption_key.mod_n2(h).pow(&d).retrieve();

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append(b"a", &a);
        transcript.append(b"b", &b);
        transcript.append(b"g_hat", &g_hat);
        transcript.append(b"h_hat", &h_hat);

        let u: U128 = transcript.challenge(b"u");

        /* OMG is this ugly, can't we do better? */
        let u: U256 = U128::ZERO.concat(&u);
        let u: U512 = U256::ZERO.concat(&u);
        let u: U1024 = U512::ZERO.concat(&u);
        let u: U2048 = U1024::ZERO.concat(&u);
        let u: U4096 = U2048::ZERO.concat(&u);

        // let w = r.wrapping_sub(&u.wrapping_mul(d));
        let w = (encryption_key.mod_n2(&r)
            - (encryption_key.mod_n2(&u) * encryption_key.mod_n2(&d)))
        .retrieve(); // TODO should this be in naturals?

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

        let u: U128 = transcript.challenge(b"u");

        /* OMG is this ugly, can't we do better? */
        let u: U256 = U128::ZERO.concat(&u);
        let u: U512 = U256::ZERO.concat(&u);
        let u: U1024 = U512::ZERO.concat(&u);
        let u: U2048 = U1024::ZERO.concat(&u);
        let u: U4096 = U2048::ZERO.concat(&u);

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
        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n).unwrap());

        let proof =
            ProofOfEqualityOfDiscreteLogs::prove(encryption_key.clone(), &D, &g, &h, &mut OsRng);

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

        let valid_proof =
            ProofOfEqualityOfDiscreteLogs::prove(encryption_key.clone(), &D, &g, &h, &mut OsRng);

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
