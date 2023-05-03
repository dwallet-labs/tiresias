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
    w: U8192, // Use U4362 instead
}

impl ProofOfEqualityOfDiscreteLogs {
    pub fn prove(
        encryption_key: EncryptionKey,
        d: &U4096,
        g: &U4096,
        h: &U4096,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let g = encryption_key.mod_n2(g);
        let h = encryption_key.mod_n2(h);

        // Sample $r \leftarrow [0,2^{2\kappa}N^2)$, where k is the security parameter.
        // Note that we use 4096-bit instead of N^2 and that's even better
        // TODO: use specific type
        let r: U4096 = U256::random(rng).into();

        let r: U8192 = r.concat(&U4096::random(rng)); // TODO: use U4392::random instead of all of this.
        let (r_hi, r_lo) = r.split();

        let g_hat = g.pow_bounded_exp(&r_hi, 256);
        let g_hat = (g.pow(&r_lo) * (g_hat.pow(&U4096::MAX)) * g_hat).retrieve();

        let h_hat = h.pow_bounded_exp(&r_hi, 256);
        let h_hat = (h.pow(&r_lo) * (h_hat.pow(&U4096::MAX)) * h_hat).retrieve();

        let a = g.pow(&d).retrieve();
        let b = h.pow(&d).retrieve();

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append_statement(b"a", &a);
        transcript.append_statement(b"b", &b);
        transcript.append_statement(b"g_hat", &g_hat);
        transcript.append_statement(b"h_hat", &h_hat);

        let u: U128 = transcript.challenge(b"u");
        let u: U4096 = u.into(); // TODO: avoid this and multiply with the 128-bit directly, need to add missing type and implement wrapping_sub for different sizes

        let ud: U8192 = (u * d).into();

        // $u$ is a 128-bit number, multiplied by a 4096-bit $d$ => (4096 + 128)-bit number.
        // $r$ is a (256+4096)-bit number, so to get $ w = r - u*d $, which will never overflow (r is sampled randomly, the probability for r to be < ud < 1/2^128 which is the computational security parameter.
        // This results in a  a (4096 + 256)-bit number $w$
        // TODO: use specific type
        let w: U8192 = r.wrapping_sub(&ud);

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

        let u: U4096 = u.into(); // TODO: use the right exponent func so no need to have u as 4096-bit

        let params = DynResidueParams::new(&encryption_key.n2);
        let g = DynResidue::new(&g, params);
        let h = DynResidue::new(&h, params);
        let a = DynResidue::new(&self.a, params);
        let b = DynResidue::new(&self.b, params);

        // We need to raise a 4096-bit number by a power of (4096 + 128 + 1)-bit exponent, but the API does not allow us this
        // so we split it to two exponentiations, one of the base (lo) 4096 * by the higher (256) bits * 2^(4096)
        // $w = w_hi*2^{128+1} + w_lo$ => + $ g^w = g^{w_lo}*g^{{2^128+1}^{w_hi}} $
        let (w_hi, w_lo) = self.w.split();

        let g_to_the_power_of_w = g.pow_bounded_exp(&w_hi, 256);
        let g_to_the_power_of_w =
            g.pow(&w_lo) * (g_to_the_power_of_w.pow(&U4096::MAX)) * g_to_the_power_of_w;

        let h_to_the_power_of_w = h.pow_bounded_exp(&w_hi, 256);
        let h_to_the_power_of_w =
            h.pow(&w_lo) * (h_to_the_power_of_w.pow(&U4096::MAX)) * h_to_the_power_of_w;

        let a_to_the_power_of_u = a.pow_bounded_exp(&u, 128);
        let b_to_the_power_of_u = b.pow_bounded_exp(&u, 128);

        // TODO: question - how does this work if the exponent is modulo Nphi(N)? why doesn't it go through modulation
        if (g_to_the_power_of_w * a_to_the_power_of_u).retrieve() == self.g_hat
            && (h_to_the_power_of_w * b_to_the_power_of_u).retrieve() == self.h_hat
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
            w: U8192::random(&mut OsRng),
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
        invalid_proof.w = U8192::random(&mut OsRng);
        assert!(invalid_proof.verify(&encryption_key, &g, &h).is_err());
    }
}
