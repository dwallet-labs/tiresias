#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark_proof_of_equality_of_discrete_logs;
use crypto_bigint::{rand_core::CryptoRngCore, Pow, Random};
use merlin::Transcript;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    proofs::TranscriptProtocol, AsNaturalNumber, AsRingElement, ComputationalSecuritySizedNumber,
    PaillierModulusSizedNumber, PaillierRingElement,
    ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
};

/// A proof of equality of discrete logarithms, utilized to validate threshold
/// decryptions performed by the parties.
///
/// This proves the following language:
///         $L_{\EDL^2}[N,\tilde g,a;x] = \{(\tilde h,b) \mid \tilde h\in \ZZ_{N^2}^* \wedge
/// a=\tilde g^{2x} \wedge b=\tilde h^{2x} \}$
///
/// Where, for the usecase of threshold Paillier:
///     - $g'\gets\ZZ_{N^2}^*$ is a random element sampled and published in the setup, and we set
///       $\tilde{g}={g'}^{\Delta_n}$
///     - For prover $P_j$, $a$ is the public verification key $v_j=g^{n!d_j}$.
///     - For prover $P_j$, the witness $x$ is simply its secret key share $d_j$.
///     - $\tilde{h}=\ct^{2n!}\in\ZZ_{N^2}^*$ where $\ct$ is the ciphertext to be decrypted.
///     - For prover $P_j$, $b$ is set to the decryption share of $\ct$, namely,
///       $\ct_j=\ct^{2n!d_j}$.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfEqualityOfDiscreteLogs {
    // Base randomizer $u=g^r \in \mathbb{Z}_{N^2}^*$.
    base_randomizer: PaillierModulusSizedNumber,
    // Decryption share base randomizer $v=h^r \in \mathbb{Z}_{N^2}^*$.
    decryption_share_base_randomizer: PaillierModulusSizedNumber,
    // Response $z \in \mathbb{Z}$.
    response: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("Invalid Params")]
    InvalidParams(),

    #[error("Invalid proof - didn't satisfy the proof equation")]
    ProofVerificationError(),
}

pub type Result<T> = std::result::Result<T, Error>;

impl ProofOfEqualityOfDiscreteLogs {
    /// Create a `ProofOfEqualityOfDiscreteLogs` that proves the equality of the discrete logs of $a
    /// a = g^x$ and $b = h^x$ in zero-knowledge (i.e. without revealing the witness `x`).
    /// Implements PROTOCOL 4.1 from Section 4.2. of the paper.
    pub fn prove(
        // The Paillier modulus
        n2: PaillierModulusSizedNumber,
        // Witness $x$ (the secret key share $d_j$ in threshold decryption)
        witness: PaillierModulusSizedNumber,
        // Base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // Decryption share base $\tilde{h}=\ct^{2n!}\in\ZZ_{N^2}^*$ where $\ct$ is the
        // ciphertext to be decrypted
        decryption_share_base: PaillierModulusSizedNumber,
        // Public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // Decryption share $\ct_j=\ct^{2n!d_j}$
        decryption_share: PaillierModulusSizedNumber,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let (base, _, decryption_shares_and_bases, mut transcript) = Self::setup_protocol(
            n2,
            base,
            public_verification_key,
            vec![(decryption_share_base, decryption_share)],
        );

        let (decryption_share_base, _) = decryption_shares_and_bases.first().unwrap();

        Self::prove_inner(
            n2,
            witness,
            base,
            *decryption_share_base,
            &mut transcript,
            rng,
        )
    }

    fn prove_inner(
        n2: PaillierModulusSizedNumber,
        witness: PaillierModulusSizedNumber,
        base: PaillierModulusSizedNumber,
        decryption_share_base: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        // Sample $r \leftarrow [0,2^{2\kappa}N^2)$, where k is the security parameter.
        // Note that we use 4096-bit instead of N^2 and that's even better.
        let randomizer = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::random(rng);

        let base_randomizer = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(&base.as_ring_element(&n2), &randomizer)
        .as_natural_number();

        let decryption_share_base_randomizer =
            <PaillierRingElement as Pow<ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber>>::pow(
                &decryption_share_base.as_ring_element(&n2),
                &randomizer,
            )
            .as_natural_number();

        let challenge = Self::compute_challenge(
            base_randomizer,
            decryption_share_base_randomizer,
            transcript,
        );

        // $e*d$ is a 128-bit number $e$, multiplied by a 4096-bit number $d$ => (4096 + 128)-bit
        // number. $r$ is a (256+4096)-bit number, so to get $z = r - e*d$, which will
        // never overflow (r is sampled randomly, the probability for $r < e*d$
        // is smaller than $1/2^128$ which is the computational security parameter.
        //
        // This results in a (4096 + 256)-bit number $z$
        let response = randomizer.wrapping_sub(&((challenge * witness).into()));

        ProofOfEqualityOfDiscreteLogs {
            base_randomizer,
            decryption_share_base_randomizer,
            response,
        }
    }

    /// Verify that `self` proves the equality of the discrete logs of $a = g^d$ and $b = h^d$.
    /// Implements PROTOCOL 4.1 from Section 4.2. of the paper.
    pub fn verify(
        &self,
        // The Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // The decryption share base $\tilde{h}=\ct^{2n!}\in\ZZ_{N^2}^*$ where $\ct$ is the
        // ciphertext to be decrypted
        decryption_share_base: PaillierModulusSizedNumber,
        // The public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // The decryption share $\ct_j=\ct^{2n!d_j}$
        decryption_share: PaillierModulusSizedNumber,
    ) -> Result<()> {
        let (base, public_verification_key, decryption_shares_and_bases, mut transcript) =
            Self::setup_protocol(
                n2,
                base,
                public_verification_key,
                vec![(decryption_share_base, decryption_share)],
            );

        let (decryption_share_base, decryption_share) =
            decryption_shares_and_bases.first().unwrap();

        self.verify_inner(
            n2,
            base,
            *decryption_share_base,
            public_verification_key,
            *decryption_share,
            &mut transcript,
        )
    }

    fn verify_inner(
        &self,
        n2: PaillierModulusSizedNumber,
        base: PaillierModulusSizedNumber,
        decryption_share_base: PaillierModulusSizedNumber,
        public_verification_key: PaillierModulusSizedNumber,
        decryption_share: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
    ) -> Result<()> {
        // Every square number except for zero that is not co-primed to $N^2$ yields factorization
        // of $N$, Therefore checking that a square number is not zero sufficiently assures
        // they belong to the quadratic-residue group.
        //
        // Note that if we'd have perform this check prior to squaring, it wouldn't have suffice;
        // take e.g. g = N != 0 -> g^2 = N^2 mod N^2 = 0 (accepting this value would have allowed
        // bypassing of the proof).
        //
        // For self.ciphertext_biquadrated_randomizer and self.base_squared_randomizer checking it
        // is non-zero is sufficient and we don't have to check their in the
        // quadratic-residue group otherwise the proof verification formula will fail
        if base == PaillierModulusSizedNumber::ZERO
            || decryption_share_base == PaillierModulusSizedNumber::ZERO
            || public_verification_key == PaillierModulusSizedNumber::ZERO
            || decryption_share == PaillierModulusSizedNumber::ZERO
            || self.base_randomizer == PaillierModulusSizedNumber::ZERO
            || self.decryption_share_base_randomizer == PaillierModulusSizedNumber::ZERO
        {
            return Err(Error::InvalidParams());
        }

        let base_squared_raised_to_the_response = <PaillierRingElement as Pow<
            ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
        >>::pow(
            &base.as_ring_element(&n2), &self.response
        );

        let ciphertext_biquadrated_raised_to_the_response =
            <PaillierRingElement as Pow<ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber>>::pow(
                &decryption_share_base.as_ring_element(&n2),
                &self.response,
            );

        let challenge = Self::compute_challenge(
            self.base_randomizer,
            self.decryption_share_base_randomizer,
            transcript,
        );

        let public_verification_key_squared_raised_to_the_challenge =
            <PaillierRingElement as Pow<ComputationalSecuritySizedNumber>>::pow(
                &public_verification_key.as_ring_element(&n2),
                &challenge,
            );

        let decryption_share_squared_raised_to_the_challenge =
            <PaillierRingElement as Pow<ComputationalSecuritySizedNumber>>::pow(
                &decryption_share.as_ring_element(&n2),
                &challenge,
            );

        if (base_squared_raised_to_the_response
            * public_verification_key_squared_raised_to_the_challenge)
            .as_natural_number()
            == self.base_randomizer
            && (ciphertext_biquadrated_raised_to_the_response
                * decryption_share_squared_raised_to_the_challenge)
                .as_natural_number()
                == self.decryption_share_base_randomizer
        {
            return Ok(());
        }
        Err(Error::ProofVerificationError())
    }

    fn setup_protocol(
        n2: PaillierModulusSizedNumber,
        base: PaillierModulusSizedNumber,
        public_verification_key: PaillierModulusSizedNumber,
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
    ) -> (
        PaillierModulusSizedNumber,
        PaillierModulusSizedNumber,
        Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
        Transcript,
    ) {
        // The paper requires that $a, b, g, h\in QR_{N}$, which is enforced by obtaining their
        // square roots as parameters to begin with. Therefore we perform the squaring to
        // assure it is in the quadratic residue group.
        let base = base
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .as_natural_number();

        let public_verification_key = public_verification_key
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .as_natural_number();

        let decryption_shares_and_bases: Vec<(
            PaillierModulusSizedNumber,
            PaillierModulusSizedNumber,
        )> = decryption_shares_and_bases
            .iter()
            .map(|(decryption_share_base, decryption_share)| {
                (
                    decryption_share_base
                        .as_ring_element(&n2)
                        .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                        .as_natural_number(),
                    decryption_share
                        .as_ring_element(&n2)
                        .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                        .as_natural_number(),
                )
            })
            .collect();

        let mut transcript = Transcript::new(b"Proof of Equality of Discrete Logs");

        transcript.append_statement(b"The Paillier modulus $N^2$", &n2);
        transcript.append_statement(b"The base $g$", &base);
        transcript.append_statement(
            b"The public verification key $a=g^x$",
            &public_verification_key,
        );

        decryption_shares_and_bases
            .iter()
            .for_each(|(decryption_share_base, decryption_share)| {
                transcript
                    .append_statement(b"The decryption share base $h$", decryption_share_base);
                transcript.append_statement(b"The decryption share $b=h^x$", decryption_share);
            });

        (
            base,
            public_verification_key,
            decryption_shares_and_bases,
            transcript,
        )
    }

    fn compute_challenge(
        base_squared_randomizer: PaillierModulusSizedNumber,
        decryption_share_base_randomizer: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
    ) -> ComputationalSecuritySizedNumber {
        transcript.append_statement(b"The base randomizer $u=g^r$", &base_squared_randomizer);
        transcript.append_statement(
            b"The decryption share base randomizer $v=h^r$",
            &decryption_share_base_randomizer,
        );

        let challenge: ComputationalSecuritySizedNumber =
            transcript.challenge(b"The challenge $e$");

        challenge
    }

    /// Create a `ProofOfEqualityOfDiscreteLogs` that proves the equality of the discrete logs
    /// of $a = g^x$ and $b=\prod_{i}{b_i^{t_i}}$ where ${{b_i}}_i = {{h_i^x}}_i$
    /// with respects to the bases $g$ and $h_i$ respectively in zero-knowledge (i.e. without
    /// revealing the witness `x`) for every (`decryption_share_base`, `decryption_share`) in
    /// `decryption_shares_and_bases`.
    ///
    /// Implements PROTOCOL 4.2 from Section 4.4. of the paper.
    pub fn batch_prove(
        // The Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The witness $d$ (the secret key share in threshold decryption)
        witness: PaillierModulusSizedNumber,
        // The base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // The public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // The decryption share bases ${\tilde{h_i}}_i={\ct^i^{2n!}\in\ZZ_{N^2}^*}$ where ${\ct^i}$
        // are the ciphertexts to be decrypted and their matching decryption shares
        // ${\ct^i_j}_i = {{\tilde{h_i}^d}}_i$
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<ProofOfEqualityOfDiscreteLogs> {
        let (base, _, batched_decryption_share_base, _, mut transcript) =
            Self::setup_batch_protocol(
                n2,
                base,
                public_verification_key,
                decryption_shares_and_bases,
            )?;

        Ok(Self::prove_inner(
            n2,
            witness,
            base,
            batched_decryption_share_base,
            &mut transcript,
            rng,
        ))
    }

    /// Verify that `self` proves the equality of the discrete logs
    /// of $a = g^x$ and $b=\prod_{i}{b_i^{t_i}}$ where ${{b_i}}_i = {{h_i^x}}_i$
    /// with respects to the bases $g$ and $h_i$ for every (`decryption_share_base`,
    /// `decryption_share`) in `decryption_shares_and_bases`.
    ///
    /// Implements PROTOCOL 4.2 from Section 4.4. of the paper.
    pub fn batch_verify(
        &self,
        // The Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // The public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // The decryption share bases ${\tilde{h_i}}_i={\ct^i^{2n!}\in\ZZ_{N^2}^*}$ where ${\ct^i}$
        // are the ciphertexts to be decrypted and their matching decryption shares
        // ${\ct^i_j}_i = {{\tilde{h_i}^d}}_i$
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
    ) -> Result<()> {
        let (
            base,
            public_verification_key,
            batched_decryption_share_base,
            batched_decryption_share,
            mut transcript,
        ) = Self::setup_batch_protocol(
            n2,
            base,
            public_verification_key,
            decryption_shares_and_bases,
        )?;

        self.verify_inner(
            n2,
            base,
            batched_decryption_share_base,
            public_verification_key,
            batched_decryption_share,
            &mut transcript,
        )
    }

    fn setup_batch_protocol(
        n2: PaillierModulusSizedNumber,
        base: PaillierModulusSizedNumber,
        public_verification_key: PaillierModulusSizedNumber,
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
    ) -> Result<(
        PaillierModulusSizedNumber,
        PaillierModulusSizedNumber,
        PaillierModulusSizedNumber,
        PaillierModulusSizedNumber,
        Transcript,
    )> {
        if decryption_shares_and_bases.is_empty() {
            return Err(Error::InvalidParams());
        }

        let (base, public_verification_key, decryption_shares_and_bases, mut transcript) =
            Self::setup_protocol(
                n2,
                base,
                public_verification_key,
                decryption_shares_and_bases,
            );

        let randomizers: Vec<ComputationalSecuritySizedNumber> = (1..=decryption_shares_and_bases
            .len())
            .map(|_| {
                let challenge: ComputationalSecuritySizedNumber =
                    transcript.challenge(b"challenge");
                challenge
            })
            .collect();

        let randomizers_ciphertexts_and_decryption_shares: Vec<(
            (PaillierModulusSizedNumber, PaillierModulusSizedNumber),
            ComputationalSecuritySizedNumber,
        )> = decryption_shares_and_bases
            .iter()
            .zip(randomizers.iter())
            .map(|((a, b), c)| ((*a, *b), *c))
            .collect();

        #[cfg(not(feature = "parallel"))]
        let randomizers_decryption_shares_and_bases_iter =
            randomizers_ciphertexts_and_decryption_shares.iter();
        #[cfg(feature = "parallel")]
        let randomizers_decryption_shares_and_bases_iter =
            randomizers_ciphertexts_and_decryption_shares.par_iter();

        let batched_decryption_share_base = randomizers_decryption_shares_and_bases_iter
            .clone()
            .map(|((ciphertext, _), randomizer)| {
                <PaillierRingElement as Pow<ComputationalSecuritySizedNumber>>::pow(
                    &ciphertext.as_ring_element(&n2),
                    randomizer,
                )
            });

        #[cfg(not(feature = "parallel"))]
        let batched_decryption_share_base = batched_decryption_share_base
            .reduce(|x, y| x * y)
            .unwrap()
            .as_natural_number();
        #[cfg(feature = "parallel")]
        let batched_decryption_share_base = batched_decryption_share_base
            .reduce(
                || PaillierModulusSizedNumber::ONE.as_ring_element(&n2),
                |x, y| x * y,
            )
            .as_natural_number();

        let batched_decryption_share = randomizers_decryption_shares_and_bases_iter.map(
            |((_, decryption_share), randomizer)| {
                <PaillierRingElement as Pow<ComputationalSecuritySizedNumber>>::pow(
                    &decryption_share.as_ring_element(&n2),
                    randomizer,
                )
            },
        );

        #[cfg(not(feature = "parallel"))]
        let batched_decryption_share = batched_decryption_share
            .reduce(|x, y| x * y)
            .unwrap()
            .as_natural_number();
        #[cfg(feature = "parallel")]
        let batched_decryption_share = batched_decryption_share
            .reduce(
                || PaillierModulusSizedNumber::ONE.as_ring_element(&n2),
                |x, y| x * y,
            )
            .as_natural_number();

        Ok((
            base,
            public_verification_key,
            batched_decryption_share_base,
            batched_decryption_share,
            transcript,
        ))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::{
        tests::{BASE, CIPHERTEXT, N, SECRET_KEY},
        LargeBiPrimeSizedNumber,
    };

    #[test]
    fn valid_proof_verifies() {
        let n2 = N.square();

        let n_factorial: u8 = 2 * 3;
        let base = BASE
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();
        let decryption_share_base = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();
        let public_verification_key = base
            .as_ring_element(&n2)
            .pow(&SECRET_KEY)
            .as_natural_number();
        let decryption_share = decryption_share_base
            .as_ring_element(&n2)
            .pow(&SECRET_KEY)
            .as_natural_number();

        let witness = SECRET_KEY;

        let proof = ProofOfEqualityOfDiscreteLogs::prove(
            n2,
            witness,
            base,
            decryption_share_base,
            public_verification_key,
            decryption_share,
            &mut OsRng,
        );

        assert!(proof
            .verify(
                n2,
                base,
                decryption_share_base,
                public_verification_key,
                decryption_share,
            )
            .is_ok());
    }

    #[test]
    fn valid_batched_proof_verifies() {
        let n2 = N.square();

        let decryption_share_base = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .as_natural_number();
        let public_verification_key = BASE
            .as_ring_element(&n2)
            .pow(&SECRET_KEY)
            .as_natural_number();
        let decryption_share = decryption_share_base
            .as_ring_element(&n2)
            .pow(&SECRET_KEY)
            .as_natural_number();

        let squared_ciphertexts_and_decryption_shares =
            vec![(decryption_share_base, decryption_share)];

        let proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            SECRET_KEY,
            BASE,
            public_verification_key,
            squared_ciphertexts_and_decryption_shares.clone(),
            &mut OsRng,
        )
        .unwrap();

        assert!(proof
            .batch_verify(
                n2,
                BASE,
                public_verification_key,
                squared_ciphertexts_and_decryption_shares,
            )
            .is_ok());

        let ciphertext2: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("07B839504B9E1D94DE3A0B72BB60C6DD17038E493876994B9C7753593368B2FD3D193883852121C127DAF4E575988FA731F52A6AD7617F13F4826EEBD25E278C0E462787D9FFC96B424C2843930C13E61A3B1C2505BF8EDE86FC3E2DBCA31B193ABE12F3840FCFBF8505145A94A794825B8EBE48DF25066997C2C4261925FEE83308EED9FCE8F5CE6E9E9074E7EC145608EED32F5D7FA00E65E63A3879F1B4B63FFEAA71A9E7F531F0A399F25E684A11B3F826680623599B9E1AA7EA00AC9326E1FE6826B7DE7457DF6CDCD94451268D474B412F821217322B77F8ECAB2ADA6EDE7BA4DF9355B13A3D71158F82AFCF16C8A4180BF59BB0CA1C59DC1E884D66DA3F8AA85D65EE9D9C32721843CAC4DCB7DFA83304FFD96280C8CCE464870BF1F5065699A61006011631EBD937B19BAAECD05CE11DA410265878049CFB3E2D1428B10D9C81B6239E221020166A4B72C41EDAA88E340002525B1DF67A7CC4BE21F62D17EEA266DAC7319044AD89BEC39DD77863E936499DCD1D787882939023402B5F5AD440DA8195679672E7E82C9FD0AF40B5184C97C3FBC626B4A32E3C8311492A0D105B7DB49BA39C225C9EB274790D2C40B6B461372CCE8516635D4D65955612A4CBEAE915E2C651282093213624466DF2901E3DF626A0935F1998E532AB01DB56678FD1D49EBEE51B75A31858DA87827A87E7D2FE858B92897B1F748CB27D");
        let decryption_share_base2 = ciphertext2
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .as_natural_number();
        let decryption_share2 = decryption_share_base2
            .as_ring_element(&n2)
            .pow(&SECRET_KEY)
            .as_natural_number();

        let squared_ciphertexts_and_decryption_shares = vec![
            (decryption_share_base, decryption_share),
            (decryption_share_base2, decryption_share2),
        ];

        let proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            SECRET_KEY,
            BASE,
            public_verification_key,
            squared_ciphertexts_and_decryption_shares.clone(),
            &mut OsRng,
        )
        .unwrap();

        assert!(proof
            .batch_verify(
                n2,
                BASE,
                public_verification_key,
                squared_ciphertexts_and_decryption_shares,
            )
            .is_ok());
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let n2 = N.square();

        let decryption_share_base = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .as_natural_number();

        // generate a random proof and make sure it fails
        let wrong_base = PaillierModulusSizedNumber::from_be_hex("391875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let wrong_decryption_share_base = PaillierModulusSizedNumber::from_be_hex("458884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let wrong_public_verification_key = PaillierModulusSizedNumber::from_be_hex("891875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let wrong_decryption_share = PaillierModulusSizedNumber::from_be_hex("058884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let wrong_response = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::from_be_hex("D09B42E9E0E7923F33FB1A81A72545DBF6710C72D43F1CDA195A2461A414BE228F4DA35BF1056AC4E58D04167D66C0E69417ED428CE39CE810BFA0AA589917E22C2D9519EC475BDCBDE46B5898E730F3B15D58E5906848106909B5A423F3DCA73F7C130424442E171CDFD7F58A808D974766A576D90C72119084A91156989E8DBB100329B81F1EC8E592CF84802FACC1049ED522C83D13E52CC45630DD70A2045F657E209496B4218CD6B394BBDC799CABB393BF8A3AEC3379BF40F19FA40C5EC4A375C6946A56778F3CAFA43D319F1116E36D88D447A89EF2D7BD822E15FB09F1C4E3B00FEB167C715DF1318DC0D1C3ACE3B739C0E1C886E43AB49EFFD1E697CE0F8F68BA31468DED59B466F0249A9AE395A1FC4533164AD7F543D1195C11F99B9D18E08464A10CB6CC42FD39E838B0CD5512435F1CC1A29D4B60A013700D5D5E95459C354A140533B7FA938A9E7E6E7ECFB233BC80A40E495577F901DE5229B73823473EACCFC058320F98CA2D124E47E5412BA8C88517077DE964830A487E80C8A4A49343B7000AE2D702998F8CB3A812BB01971BC47BA514A5723382AFD3AF3EC5F9D9C17FC33157C49B8E84453B80F636C92600D31A4EEF6E92694B99C02489443351319CC576B763E4C293A0CDDF620A38DB381D252D8FDD2DF239B67404586DA8C34A4A993351AAC1188DF6D26CDAEF1B3A46599C3A310376C7FFB2CA75AE4A32E539D34615269A9D2BE93C4CF8B557677E04737AA0395E392AE6A804");
        let wrong_base_randomizer = PaillierModulusSizedNumber::from_be_hex("1B8DC8C817CAF6ABF6B3BE337E6D723BABFC968213DFC5BE5E9B524B380A58BE0ADB12576177AFC3604D6DC28303D5F5A0B54303B033AA73C10DA59008C6B5806CE3C781096BBB32CBC3E5FF70B62A1D6F0525152E70F8FA5751249EF7B3E21DBB6DD735C11CA6282863B4FDA8FE2C993F03C3D5E008F28218FA57647F0526BCF355CB2D589DA8D2CEED3E2013B55A803300544368AF573184CC7472C9B33CB39B541E2D388384BA86E913A62B6C61D65755FD75CD79B7ACBF41EF8755E8C50C1E9D5D01B0FFCAEA990194EA41FC4591032C79517B10F2DBB23868300B222BE6DFA7B974A7BCAC395CAE72D655F2EDBFF6D6407DF874600CE7688EBFE440336681EA1A44395F67D1CC9D1C092B889D3049465D0FC21C74FA3642018A73C9510FDF6C89CE0AAC3DCC089A3092BC029F518548B2D158FBBDCEA4634D0EEDBA32E2A095886F995F5C3D6C146371F633145823DA4AAA022A62CF7F9D76597F6A550F41FEA5EC7310ED59E1134F5F86B84AFAD4911270361370B3313CD46F01CEDDCAEA1A580F5A4D3C58888F5802BEC2FED81AC7733D3399A5E6D9D3EF8B136906694709E0C0348EF083A0106AC41979289A41B0356362A85BA40A6AEA0191A83E5C48CE580FAA9AE1DE8462E8CEBDCB3BC879C5F5AFB4F2B136E057BFB314AB19CC64018F933647FA18BD4CB6F75BE614708EF748EDBA2A1BEDB115E8BBEB2B96CC");
        let wrong_decryption_share_randomizer = PaillierModulusSizedNumber::from_be_hex("2EAA0D625BD67781CFFCC4563365C37CDCEC8782B451703D4130F7B05E4D080EFF1668E8E96125EE991C45076AB92EFA40232A2C150A96A8DB72F9FB1E7EC57924A13465113ECF9CA575C312C11841C83935B81137B3172C5AB86CCF7EE400D525F5FDA24194F6BCEB4ECDA99EDCE509DDA1B5106EECE1962FFA65FE6B359E5524685ECB5C785B8B0F91744BB2B50EBEE981099AC4B66F6CCF01B1D16F6611D0846EAA44E20C4895CC77CC4CECD1A2AA34CCC97AE0D91C9438FBD0A59A66AB669BD35D78869DD9801C0B13CBBF202F8E21C21B4B76C006DE01A93DC708DE5777B1F305598DEC6552F92DB4166D10B784C6E897579265CA6C48721947F5CF0FC2B65C1EF15A0A62AF54478DD2E3275942A6D2E628C7FD56F1522DD6B251ECD129B93CDC76167A16B52711AB02315EA7D53C0F5F15403AC7BDC1DB3D65D714DA38ED350590D4ACB2B8CC6F4597C4CBCE311F8EA71B3B5783A3C57BACAA7D065EA12190DD982ADC78ECBE0F864016EDB59E9097D6D0DBECAA5F9E8272F1204246059AE42348DC978AF8F0E82BC13940559A7900AE10F343253F97611493EFA673FF74C695476A90FAD5AE734885C86C895F1CFF3E4731A3569F2295B119A46D48632BEB2576D0C0435E49C61FDFA0960C31E79D6BEFF0A1676F8F15A45B3E74B1905035DC3414B812B4253896CB04EDD6C9C4B9822FC2A2A567DEDB3F8730BBD2BD");

        let invalid_proof = ProofOfEqualityOfDiscreteLogs {
            base_randomizer: wrong_base_randomizer,
            decryption_share_base_randomizer: wrong_decryption_share_randomizer,
            response: wrong_response,
        };

        assert_eq!(
            invalid_proof
                .verify(
                    n2,
                    BASE,
                    decryption_share_base,
                    wrong_public_verification_key,
                    wrong_decryption_share,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            invalid_proof
                .batch_verify(
                    n2,
                    BASE,
                    wrong_public_verification_key,
                    vec![(decryption_share_base, wrong_decryption_share)],
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        let public_verification_key = BASE
            .as_ring_element(&n2)
            .pow(&SECRET_KEY)
            .as_natural_number();
        let decryption_share = CIPHERTEXT
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow(&SECRET_KEY)
            .as_natural_number();

        // Try to fool verification with zeroed out fields
        let crafted_proof = ProofOfEqualityOfDiscreteLogs {
            base_randomizer: PaillierModulusSizedNumber::ZERO,
            decryption_share_base_randomizer: PaillierModulusSizedNumber::ZERO,
            response: wrong_response,
        };

        assert_eq!(
            crafted_proof
                .verify(
                    n2,
                    BASE,
                    decryption_share_base,
                    PaillierModulusSizedNumber::ZERO,
                    PaillierModulusSizedNumber::ZERO,
                )
                .err()
                .unwrap(),
            Error::InvalidParams()
        );

        assert_eq!(
            crafted_proof
                .batch_verify(
                    n2,
                    BASE,
                    PaillierModulusSizedNumber::ZERO,
                    vec![(decryption_share_base, PaillierModulusSizedNumber::ZERO)],
                )
                .err()
                .unwrap(),
            Error::InvalidParams()
        );

        // Try to fool verification with fields that their square is zero mod N^2 (e.g. N)
        let crafted_proof = ProofOfEqualityOfDiscreteLogs {
            base_randomizer: (N * LargeBiPrimeSizedNumber::from(2u8)),
            decryption_share_base_randomizer: (N * LargeBiPrimeSizedNumber::from(2u8)),
            response: wrong_response,
        };

        assert_eq!(
            crafted_proof
                .verify(
                    n2,
                    BASE,
                    decryption_share_base,
                    N * LargeBiPrimeSizedNumber::from(2u8),
                    N * LargeBiPrimeSizedNumber::from(2u8),
                )
                .err()
                .unwrap(),
            Error::InvalidParams()
        );

        assert_eq!(
            crafted_proof
                .batch_verify(
                    n2,
                    BASE,
                    N * LargeBiPrimeSizedNumber::from(2u8),
                    vec![(
                        decryption_share_base,
                        (N * LargeBiPrimeSizedNumber::from(2u8))
                    )],
                )
                .err()
                .unwrap(),
            Error::InvalidParams()
        );

        // Now generate a valid proof, and make sure that if we change any field it fails
        let valid_proof = ProofOfEqualityOfDiscreteLogs::prove(
            n2,
            SECRET_KEY,
            BASE,
            decryption_share_base,
            public_verification_key,
            decryption_share,
            &mut OsRng,
        );

        let valid_batched_proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            SECRET_KEY,
            BASE,
            public_verification_key,
            vec![(decryption_share_base, decryption_share)],
            &mut OsRng,
        )
        .unwrap();

        // Assure that verification fails for random values
        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    wrong_base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    wrong_base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    BASE,
                    wrong_decryption_share_base,
                    public_verification_key,
                    decryption_share,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    BASE,
                    public_verification_key,
                    vec![(wrong_decryption_share_base, decryption_share)],
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    BASE,
                    decryption_share_base,
                    wrong_public_verification_key,
                    decryption_share,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    BASE,
                    wrong_public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    BASE,
                    decryption_share_base,
                    public_verification_key,
                    wrong_decryption_share,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    BASE,
                    public_verification_key,
                    vec![(decryption_share_base, wrong_decryption_share)],
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.base_randomizer = wrong_base_randomizer;
        assert_eq!(
            invalid_proof
                .verify(
                    n2,
                    BASE,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        let mut invalid_batched_proof = valid_batched_proof.clone();
        invalid_batched_proof.base_randomizer = wrong_base_randomizer;
        assert_eq!(
            invalid_batched_proof
                .batch_verify(
                    n2,
                    BASE,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        invalid_proof = valid_proof.clone();
        invalid_proof.decryption_share_base_randomizer = wrong_decryption_share_randomizer;
        assert_eq!(
            invalid_proof
                .verify(
                    n2,
                    BASE,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        invalid_batched_proof = valid_batched_proof.clone();
        invalid_batched_proof.decryption_share_base_randomizer = wrong_decryption_share_randomizer;
        assert_eq!(
            invalid_batched_proof
                .batch_verify(
                    n2,
                    BASE,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        invalid_proof = valid_proof;
        invalid_proof.response = wrong_response;
        assert_eq!(
            invalid_proof
                .verify(
                    n2,
                    BASE,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        invalid_batched_proof = valid_batched_proof;
        invalid_batched_proof.response = wrong_response;
        assert_eq!(
            invalid_batched_proof
                .batch_verify(
                    n2,
                    BASE,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );
    }
}

#[cfg(feature = "benchmarking")]
mod benches {
    use std::iter;

    use criterion::Criterion;
    use crypto_bigint::{NonZero, RandomMod};
    use rand_core::OsRng;

    use super::*;
    use crate::LargeBiPrimeSizedNumber;

    pub(crate) fn benchmark_proof_of_equality_of_discrete_logs(c: &mut Criterion) {
        let mut g = c.benchmark_group("proof of equality of discrete logs benches");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let n2 = n.square();
        let secret_key_share = PaillierModulusSizedNumber::from_be_hex("19d698592b9ccb2890fb84be46cd2b18c360153b740aeccb606cf4168ee2de399f05273182bf468978508a5f4869cb867b340e144838dfaf4ca9bfd38cd55dc2837688aed2dbd76d95091640c47b2037d3d0ca854ffb4c84970b86f905cef24e876ddc8ab9e04f2a5f171b9c7146776c469f0d90908aa436b710cf4489afc73cd3ee38bb81e80a22d5d9228b843f435c48c5eb40088623a14a12b44e2721b56625da5d56d257bb27662c6975630d51e8f5b930d05fc5ba461a0e158cbda0f3266408c9bf60ff617e39ae49e707cbb40958adc512f3b4b69a5c3dc8b6d34cf45bc9597840057438598623fb65254869a165a6030ec6bec12fd59e192b3c1eefd33ef5d9336e0666aa8f36c6bd2749f86ea82290488ee31bf7498c2c77a8900bae00efcff418b62d41eb93502a245236b89c241ad6272724858122a2ebe1ae7ec4684b29048ba25b3a516c281a93043d58844cf3fa0c6f1f73db5db7ecba179652349dea8df5454e0205e910e0206736051ac4b7c707c3013e190423532e907af2e85e5bb6f6f0b9b58257ca1ec8b0318dd197f30352a96472a5307333f0e6b83f4f775fb302c1e10f21e1fcbfff17e3a4aa8bb6f553d9c6ebc2c884ae9b140dd66f21afc8610418e9f0ba2d14ecfa51ff08744a3470ebe4bb21bd6d65b58ac154630b8331ea620673ffbabb179a971a6577c407a076654a629c7733836c250000");

        let base = PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        let ciphertext =
            PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
        let ciphertext_squared = ciphertext
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .as_natural_number();
        let public_verification_key = base
            .as_ring_element(&n2)
            .pow(&secret_key_share)
            .as_natural_number();
        let decryption_share = ciphertext_squared
            .as_ring_element(&n2)
            .pow(&secret_key_share)
            .as_natural_number();

        g.bench_function("equality of discrete logs prove()", |bench| {
            bench.iter(|| {
                ProofOfEqualityOfDiscreteLogs::prove(
                    n2,
                    secret_key_share,
                    base,
                    ciphertext_squared,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng,
                )
            });
        });

        let proof = ProofOfEqualityOfDiscreteLogs::prove(
            n2,
            secret_key_share,
            base,
            ciphertext_squared,
            public_verification_key,
            decryption_share,
            &mut OsRng,
        );

        g.bench_function("equality of discrete logs verify()", |bench| {
            bench.iter(|| {
                assert!(proof
                    .verify(
                        n2,
                        base,
                        ciphertext_squared,
                        public_verification_key,
                        decryption_share,
                    )
                    .is_ok());
            });
        });

        for batch_size in [10, 100, 1000] {
            let squared_ciphertexts = iter::repeat_with(|| {
                PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap())
                    .as_ring_element(&n2)
                    .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                    .as_natural_number()
            })
            .take(batch_size);

            let squared_ciphertexts_and_decryption_shares: Vec<(
                PaillierModulusSizedNumber,
                PaillierModulusSizedNumber,
            )> = squared_ciphertexts
                .map(|ciphertext| {
                    (
                        ciphertext,
                        ciphertext
                            .as_ring_element(&n2)
                            .pow(&secret_key_share)
                            .as_natural_number(),
                    )
                })
                .collect();

            g.bench_function(
                format!("equality of discrete logs batch_prove() for {batch_size} decryptions"),
                |bench| {
                    bench.iter(|| {
                        ProofOfEqualityOfDiscreteLogs::batch_prove(
                            n2,
                            secret_key_share,
                            base,
                            public_verification_key,
                            squared_ciphertexts_and_decryption_shares.clone(),
                            &mut OsRng,
                        )
                    });
                },
            );

            let batched_proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
                n2,
                secret_key_share,
                base,
                public_verification_key,
                squared_ciphertexts_and_decryption_shares.clone(),
                &mut OsRng,
            )
            .unwrap();

            g.bench_function(
                format!("equality of discrete logs batch_verify() for {batch_size} decryptions"),
                |bench| {
                    bench.iter(|| {
                        assert!(batched_proof
                            .batch_verify(
                                n2,
                                base,
                                public_verification_key,
                                squared_ciphertexts_and_decryption_shares.clone()
                            )
                            .is_ok());
                    });
                },
            );
        }

        g.finish();
    }
}
