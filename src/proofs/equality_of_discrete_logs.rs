use crate::paillier::EncryptionKey;
use crate::proofs::{ProofError, TranscriptProtocol};
use crypto_bigint::consts::U4;
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{
    Concat, Encoding, Limb, NonZero, Random, RandomMod, U1024, U128, U2048, U256, U4096, U512,
    U8192,
};
use merlin::Transcript;
use rand_core::CryptoRngCore;

#[derive(Debug, Clone)]
pub struct ProofOfEqualityOfDiscreteLogs {
    a: U4096,
    b: U4096,
    g_hat: U4096,
    h_hat: U4096,
    w: U8192,
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
                                         // Note that we use 2048-bit instead of N and that's even better
                                         /* OMG is this ugly, can't we do better? */
        let r: U512 = U256::ZERO.concat(&r);
        let r: U1024 = U512::ZERO.concat(&r);
        let r: U2048 = U1024::ZERO.concat(&r);
        let r: U4096 = r.concat(&U2048::random(rng));

        let g_hat = encryption_key
            .mod_n2(g)
            .pow_bounded_exp(&r, 256 + 2048)
            .retrieve();
        let h_hat = encryption_key
            .mod_n2(h)
            .pow_bounded_exp(&r, 256 + 2048)
            .retrieve();

        let a = encryption_key.mod_n2(g).pow(&d).retrieve();
        let b = encryption_key.mod_n2(h).pow(&d).retrieve();

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append_statement(b"a", &a);
        transcript.append_statement(b"b", &b);
        transcript.append_statement(b"g_hat", &g_hat);
        transcript.append_statement(b"h_hat", &h_hat);

        let u: U128 = transcript.challenge(b"u");

        /* OMG is this ugly, can't we do better? */
        let u: U256 = U128::ZERO.concat(&u);
        let u: U512 = U256::ZERO.concat(&u);
        let u: U1024 = U512::ZERO.concat(&u);
        let u: U2048 = U1024::ZERO.concat(&u);
        let u: U4096 = U2048::ZERO.concat(&u);

        let (lo, hi) = u.mul_wide(&d);
        let ud = hi.concat(&lo);
        let r: U8192 = U4096::ZERO.concat(&r);
        // TODO: I think this can never overflow, am I right?
        let w = r.wrapping_add(&ud);

        ProofOfEqualityOfDiscreteLogs {
            a: a.clone(),
            b: b.clone(),
            g_hat,
            h_hat,
            w,
        }
    }

    pub fn verify(
        &self,
        encryption_key: &EncryptionKey,
        g: &U4096,
        h: &U4096,
    ) -> Result<(), ProofError> {
        // TODO: need to check not zero for every member?

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append_statement(b"a", &self.a);
        transcript.append_statement(b"b", &self.b);
        transcript.append_statement(b"g_hat", &self.g_hat);
        transcript.append_statement(b"h_hat", &self.h_hat);

        let u: U128 = transcript.challenge(b"u");

        /* OMG is this ugly, can't we do better? */
        let u: U256 = U128::ZERO.concat(&u);
        let u: U512 = U256::ZERO.concat(&u);
        let u: U1024 = U512::ZERO.concat(&u);
        let u: U2048 = U1024::ZERO.concat(&u);
        let u: U4096 = U2048::ZERO.concat(&u);

        let n2 = U4096::ZERO.concat(&encryption_key.n2);
        let params = DynResidueParams::new(&n2);
        let g = U4096::ZERO.concat(&g);
        let g = DynResidue::new(&g, params);
        let h = U4096::ZERO.concat(&h);
        let h = DynResidue::new(&h, params);
        let a = U4096::ZERO.concat(&self.a);
        let a = DynResidue::new(&a, params);
        let b = U4096::ZERO.concat(&self.b);
        let b = DynResidue::new(&b, params);
        let u = U4096::ZERO.concat(&u);
        let g_hat = U4096::ZERO.concat(&self.g_hat);
        let h_hat = U4096::ZERO.concat(&self.h_hat);

        // TODO: not important here, but can I even == for BigInt? don't I lose constant-timeness?
        if (g.pow_bounded_exp(&self.w, 4096 + 128 + 1) * a.pow_bounded_exp(&u, 128).invert().0)
            .retrieve()
            == g_hat
            && (h.pow_bounded_exp(&self.w, 4096 + 128 + 1) * b.pow_bounded_exp(&u, 128).invert().0)
                .retrieve()
                == h_hat
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
        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());

        let proof =
            ProofOfEqualityOfDiscreteLogs::prove(encryption_key.clone(), &D, &g, &h, &mut OsRng);

        assert!(proof.verify(&encryption_key, &g, &h).is_ok());
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let encryption_key = EncryptionKey::new(N);

        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());

        /* First generate a truly random proof and make sure it fails */
        let invalid_proof = ProofOfEqualityOfDiscreteLogs {
            a: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap()),
            b: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap()),
            g_hat: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap()),
            h_hat: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap()),
            w: U8192::random_mod(
                &mut OsRng,
                &NonZero::new(U4096::ZERO.concat(&encryption_key.n2)).unwrap(),
            ),
        };

        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        /* Now generate a valid proof, and make sure that if we change any field it fails */
        let a = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        let b = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        let g = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        let h = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());

        let valid_proof =
            ProofOfEqualityOfDiscreteLogs::prove(encryption_key.clone(), &D, &g, &h, &mut OsRng);

        let mut invalid_proof = valid_proof.clone();

        invalid_proof.a = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.b = U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.g_hat =
            U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.h_hat =
            U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());

        invalid_proof = valid_proof;
        invalid_proof.w = U8192::random_mod(
            &mut OsRng,
            &NonZero::new(U4096::ZERO.concat(&encryption_key.n2)).unwrap(),
        );
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());
    }
}
