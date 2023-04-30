use crate::paillier::EncryptionKey;
use crate::proofs::{ProofError, TranscriptProtocol};
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
    w_hi: U4096,
    w_lo: U4096,
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
        // $u$ is a 128-bit number, multiplied by a 4096-bit $d$ => (4096 + 128)-bit number.
        // Add a (256+4096)-bit $r$ to get $ w = r + u*d $, a (4096 + 128 + 1)-bit number < 8096
        // => a wrapping_add of U8096 is safe here and will never overflow.
        // TODO: can we instead actually do r - ud since this will never overflow as r is much bigger?
        let w = r.wrapping_add(&ud);
        let (w_hi, w_lo) = w.split();

        ProofOfEqualityOfDiscreteLogs {
            a: a.clone(),
            b: b.clone(),
            g_hat,
            h_hat,
            w_hi,
            w_lo,
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

        let params = DynResidueParams::new(&encryption_key.n2);
        let g = DynResidue::new(&g, params);
        let h = DynResidue::new(&h, params);
        let a = DynResidue::new(&self.a, params);
        let b = DynResidue::new(&self.b, params);

        // TODO: not important here, but can I even == for BigInt? don't I lose constant-timeness?

        // We need to raise a 4096-bit number by a power of (4096 + 128 + 1)-bit exponent, but the API does not allow us this
        // so we split it to two exponentiations, one of the base (lo) 4096 * by the higher (128 + 1) bits * 2^(128 + 1)
        // $w = w_hi*2^{128+1} + w_lo$ => + $ g^w = g^{w_lo}*g^{{2^128+1}^{w_hi}} $
        let two_to_the_power_of_129 = U4096::ONE.shl_vartime(128 + 1); // 2^(128 + 1) is a (128 + 1 + 1)-bit number

        let g_to_the_power_of_w = g.pow_bounded_exp(&self.w_lo, 4096)
            * (g.pow_bounded_exp(&two_to_the_power_of_129, 128 + 1 + 1)
                .pow_bounded_exp(&self.w_hi, 128 + 1));

        let h_to_the_power_of_w = h.pow_bounded_exp(&self.w_lo, 4096)
            * (h.pow_bounded_exp(&two_to_the_power_of_129, 128 + 1 + 1)
                .pow_bounded_exp(&self.w_hi, 128 + 1));

        // We are operating in $Z_{N^2}$ and so every element in the ring except for $p$ or $q$ is invertible [TODO: verify]
        // Since $p$ and $q$ are secret, randomly finding an un-invertible number is a 1 to 2^2048 chance, which is much more than the statistical security of this proof.
        // Therefore, it is safe to assume the $a^u$ is invertible
        let a_to_the_power_of_minus_u = a.pow_bounded_exp(&u, 128).invert().0;
        let b_to_the_power_of_minus_u = b.pow_bounded_exp(&u, 128).invert().0;

        if (g_to_the_power_of_w * a_to_the_power_of_minus_u).retrieve() == self.g_hat
            && (h_to_the_power_of_w * b_to_the_power_of_minus_u).retrieve() == self.h_hat
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
            w_hi: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap()),
            w_lo: U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap()),
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
        invalid_proof.w_hi =
            U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        invalid_proof.w_lo =
            U4096::random_mod(&mut OsRng, &NonZero::new(encryption_key.n2).unwrap());
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());
    }
}
