use crate::proofs::{ProofError, TranscriptProtocol};
use crate::traits::{AsNaturalNumber, AsRingElement, Kappa, Kappa2, Pow, RingElement, N, N2, R};
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Concat, Encoding, Limb, NonZero, Random, RandomMod};
use merlin::Transcript;
use rand_core::CryptoRngCore;

#[derive(Debug, Clone)]
pub struct ProofOfEqualityOfDiscreteLogs {
    a: N2,
    b: N2,
    g_hat: N2,
    h_hat: N2,
    w: R,
}

impl ProofOfEqualityOfDiscreteLogs {
    pub fn prove(
        n: &N, // TODO: is there a more generalized version of this proof that isn't Paillier-specific? i.e. maybe the ring we are proving on shouldn't be $Z_{N^2|$ but a generic $Z_n$?
        d: &N2,
        g: &N2,
        h: &N2,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let n2 = n.square();
        let g = g.as_ring_element(&n2);
        let h = h.as_ring_element(&n2);

        // Sample $r \leftarrow [0,2^{2\kappa}N^2)$, where k is the security parameter.
        // Note that we use 4096-bit instead of N^2 and that's even better
        let r: R = R::random(rng);

        let g_hat = <RingElement as Pow<R>>::pow(&g, &r).as_natural_number();
        let h_hat = <RingElement as Pow<R>>::pow(&h, &r).as_natural_number();

        let a: N2 = g.pow(&d).as_natural_number();
        let b: N2 = h.pow(&d).as_natural_number();

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append_statement(b"a", &a);
        transcript.append_statement(b"b", &b);
        transcript.append_statement(b"g_hat", &g_hat);
        transcript.append_statement(b"h_hat", &h_hat);

        let u: Kappa = transcript.challenge(b"u");

        // $u$ is a 128-bit number, multiplied by a 4096-bit $d$ => (4096 + 128)-bit number.
        // $r$ is a (256+4096)-bit number, so to get $ w = r - u*d $, which will never overflow (r is sampled randomly, the probability for r to be < ud < 1/2^128 which is the computational security parameter.
        // This results in a  a (4096 + 256)-bit number $w$
        let w: R = r.wrapping_sub(&((u * d).into()));

        ProofOfEqualityOfDiscreteLogs {
            a: a.clone(),
            b: b.clone(),
            g_hat,
            h_hat,
            w,
        }
    }

    pub fn verify(&self, n: &N, g: &N2, h: &N2) -> Result<(), ProofError> {
        // TODO: need to check not zero for every member?
        let n2 = n.square();
        let g = g.as_ring_element(&n2);
        let h = h.as_ring_element(&n2);
        let a = self.a.as_ring_element(&n2);
        let b = self.b.as_ring_element(&n2);

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");
        transcript.append_statement(b"a", &self.a);
        transcript.append_statement(b"b", &self.b);
        transcript.append_statement(b"g_hat", &self.g_hat);
        transcript.append_statement(b"h_hat", &self.h_hat);

        let u: Kappa = transcript.challenge(b"u");

        let g_to_the_power_of_w = <RingElement as Pow<R>>::pow(&g, &self.w);
        let h_to_the_power_of_w = <RingElement as Pow<R>>::pow(&h, &self.w);

        let a_to_the_power_of_u = a.pow_bounded_exp(&u.into(), 128);
        let b_to_the_power_of_u = b.pow_bounded_exp(&u.into(), 128);

        if (g_to_the_power_of_w * a_to_the_power_of_u).as_natural_number() == self.g_hat
            && (h_to_the_power_of_w * b_to_the_power_of_u).as_natural_number() == self.h_hat
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

    pub(crate) const N: N = N::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
    pub(crate) const D: N2 = N2::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");

    #[test]
    fn valid_proof_verifies() {
        let n2 = N.square();
        let g = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        let h = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());

        let proof = ProofOfEqualityOfDiscreteLogs::prove(&N, &D, &g, &h, &mut OsRng);

        assert!(proof.verify(&N, &g, &h).is_ok());
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let n2 = N.square();
        let g = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        let h = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());

        /* First generate a truly random proof and make sure it fails */
        let invalid_proof = ProofOfEqualityOfDiscreteLogs {
            a: N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap()),
            b: N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap()),
            g_hat: N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap()),
            h_hat: N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap()),
            w: R::random(&mut OsRng),
        };

        assert!(invalid_proof.verify(&N, &g, &h).is_err());

        /* Now generate a valid proof, and make sure that if we change any field it fails */
        let a = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        let b = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        let g = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        let h = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());

        let valid_proof = ProofOfEqualityOfDiscreteLogs::prove(&N, &D, &g, &h, &mut OsRng);

        let mut invalid_proof = valid_proof.clone();

        invalid_proof.a = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        assert!(invalid_proof.verify(&N, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.b = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        assert!(invalid_proof.verify(&N, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.g_hat = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        assert!(invalid_proof.verify(&N, &g, &h).is_err());

        invalid_proof = valid_proof.clone();
        invalid_proof.h_hat = N2::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        assert!(invalid_proof.verify(&N, &g, &h).is_err());

        invalid_proof = valid_proof;
        invalid_proof.w = R::random(&mut OsRng);
        assert!(invalid_proof.verify(&N, &g, &h).is_err());
    }
}
