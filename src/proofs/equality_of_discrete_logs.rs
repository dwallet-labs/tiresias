// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark_proof_of_equality_of_discrete_logs;
use crypto_bigint::{
    modular::runtime_mod::DynResidueParams, rand_core::CryptoRngCore, MultiExponentiateBoundedExp,
    NonZero, RandomMod,
};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use crate::{
    batch_verification::batch_verification,
    proofs::{Error, Result, TranscriptProtocol},
    secret_key_share_size_upper_bound, AsNaturalNumber, AsRingElement,
    ComputationalSecuritySizedNumber, PaillierModulusSizedNumber, PaillierRingElement,
    ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber, SecretKeyShareSizedNumber,
};

/// A proof of equality of discrete logarithms, utilized to validate threshold
/// decryption performed by the parties.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfEqualityOfDiscreteLogs {
    // Base randomizer $u=g^r \in \mathbb{Z}_{N^2}^*$.
    base_randomizer: PaillierModulusSizedNumber,
    // Decryption share base randomizer $v=h^r \in \mathbb{Z}_{N^2}^*$.
    decryption_share_base_randomizer: PaillierModulusSizedNumber,
    // Response $z \in \mathbb{Z}$.
    response: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber,
}

impl ProofOfEqualityOfDiscreteLogs {
    /// Create a `ProofOfEqualityOfDiscreteLogs` that proves the equality of the discrete logs of $a
    /// a = g^x$ and $b = h^x$ in zero-knowledge (i.e. without revealing the witness `x`).
    /// Implements PROTOCOL 4.1 from Section 4.2. of the paper.
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        // The Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The number of parties $n$
        number_of_parties: u16,
        // The threshold $t$
        threshold: u16,
        // Witness $x$ (the secret key share $d_j$ in threshold decryption)
        witness: SecretKeyShareSizedNumber,
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
            number_of_parties,
            threshold,
            witness,
            base,
            *decryption_share_base,
            &mut transcript,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_inner(
        n2: PaillierModulusSizedNumber,
        number_of_parties: u16,
        threshold: u16,
        witness: SecretKeyShareSizedNumber,
        base: PaillierModulusSizedNumber,
        decryption_share_base: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> ProofOfEqualityOfDiscreteLogs {
        let witness_size_upper_bound = secret_key_share_size_upper_bound(
            usize::from(number_of_parties),
            usize::from(threshold),
        );

        let randomizer = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::random_mod(
            rng,
            &NonZero::new(
                ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::ONE.shl_vartime(
                    witness_size_upper_bound + 2 * ComputationalSecuritySizedNumber::BITS,
                ),
            )
            .unwrap(),
        );

        let base_randomizer = base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &randomizer,
                witness_size_upper_bound + 2 * ComputationalSecuritySizedNumber::BITS,
            )
            .as_natural_number();

        let decryption_share_base_randomizer = decryption_share_base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &randomizer,
                witness_size_upper_bound + 2 * ComputationalSecuritySizedNumber::BITS,
            )
            .as_natural_number();

        let challenge = Self::compute_challenge(
            base_randomizer,
            decryption_share_base_randomizer,
            transcript,
        );

        // No overflow can happen here by the choice of sizes in types. See lib.rs
        let challenge: SecretKeyShareSizedNumber = challenge.resize();
        let challenge_multiplied_by_witness: SecretKeyShareSizedNumber =
            witness.wrapping_mul(&challenge);
        let challenge_multiplied_by_witness: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber =
            challenge_multiplied_by_witness.resize();
        let response = randomizer.wrapping_sub(&challenge_multiplied_by_witness);

        ProofOfEqualityOfDiscreteLogs {
            base_randomizer,
            decryption_share_base_randomizer,
            response,
        }
    }

    /// Verify that `self` proves the equality of the discrete logs of $a = g^d$ and $b = h^d$.
    /// Implements PROTOCOL 4.1 from Section 4.2. of the paper.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        // The Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The number of parties $n$
        number_of_parties: u16,
        // The threshold $t$
        threshold: u16,
        // The base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // The decryption share base $\tilde{h}=\ct^{2n!}\in\ZZ_{N^2}^*$ where $\ct$ is the
        // ciphertext to be decrypted
        decryption_share_base: PaillierModulusSizedNumber,
        // The public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // The decryption share $\ct_j=\ct^{2n!d_j}$
        decryption_share: PaillierModulusSizedNumber,
        rng: &mut impl CryptoRngCore,
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
            number_of_parties,
            threshold,
            base,
            *decryption_share_base,
            public_verification_key,
            *decryption_share,
            &mut transcript,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_inner(
        &self,
        n2: PaillierModulusSizedNumber,
        number_of_parties: u16,
        threshold: u16,
        base: PaillierModulusSizedNumber,
        decryption_share_base: PaillierModulusSizedNumber,
        public_verification_key: PaillierModulusSizedNumber,
        decryption_share: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let witness_size_upper_bound = secret_key_share_size_upper_bound(
            usize::from(number_of_parties),
            usize::from(threshold),
        );

        // Every square number except for zero that is not co-primed to $N^2$ yields factorization
        // of $N$, Therefore checking that a square number is not zero sufficiently assures
        // they belong to the quadratic-residue group.
        //
        // Note that if we'd have perform this check prior to squaring, it wouldn't have suffice;
        // take e.g. g = N != 0 -> g^2 = N^2 mod N^2 = 0 (accepting this value would have allowed
        // bypassing of the proof).
        //
        // For self.decryption_share_base_randomizer and self.base_randomizer checking it
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

        let challenge: ComputationalSecuritySizedNumber = Self::compute_challenge(
            self.base_randomizer,
            self.decryption_share_base_randomizer,
            transcript,
        )
        .resize();

        // We resize the challenge to be of equal size of the other exponent, the response, so we
        // can use batched_verification().
        let challenge: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber = challenge.resize();

        let bases_lhs = vec![
            vec![base, public_verification_key],
            vec![decryption_share_base, decryption_share],
        ];

        let bases_rhs = vec![
            vec![self.base_randomizer],
            vec![self.decryption_share_base_randomizer],
        ];

        let exponents_lhs = vec![
            (
                self.response,
                witness_size_upper_bound + 2 * ComputationalSecuritySizedNumber::BITS,
            ),
            (challenge, ComputationalSecuritySizedNumber::BITS),
        ];

        if batch_verification::<
            { PaillierModulusSizedNumber::LIMBS },
            { ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::LIMBS },
            { ComputationalSecuritySizedNumber::LIMBS },
        >(
            bases_lhs,
            bases_rhs,
            exponents_lhs,
            vec![],
            DynResidueParams::new(&n2),
            rng,
        )
        .is_ok()
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
        base_randomizer: PaillierModulusSizedNumber,
        decryption_share_base_randomizer: PaillierModulusSizedNumber,
        transcript: &mut Transcript,
    ) -> ComputationalSecuritySizedNumber {
        transcript.append_statement(b"The base randomizer $u=g^r$", &base_randomizer);
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
    #[allow(clippy::too_many_arguments)]
    pub fn batch_prove(
        // Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The number of parties $n$
        number_of_parties: u16,
        // The threshold $t$
        threshold: u16,
        // Witness $d$ (the secret key share in threshold decryption)
        witness: SecretKeyShareSizedNumber,
        // Base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // Public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // Decryption share bases ${\tilde{h_i}}_i={\ct^i^{2n!}\in\ZZ_{N^2}^*}$ where ${\ct^i}$
        // are the ciphertexts to be decrypted and their matching decryption shares
        // ${\ct^i_j}_i = {{\tilde{h_i}^x}}_i$
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
            number_of_parties,
            threshold,
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
    #[allow(clippy::too_many_arguments)]
    pub fn batch_verify(
        &self,
        // Paillier modulus
        n2: PaillierModulusSizedNumber,
        // The number of parties $n$
        number_of_parties: u16,
        // The threshold $t$
        threshold: u16,
        // Base $\tilde{g}$
        base: PaillierModulusSizedNumber,
        // Public verification key $v_j=g^{n!d_j}$
        public_verification_key: PaillierModulusSizedNumber,
        // Decryption share bases ${\tilde{h_i}}_i={\ct^i^{2n!}\in\ZZ_{N^2}^*}$ where ${\ct^i}$
        // are the ciphertexts to be decrypted and their matching decryption shares
        // ${\ct^i_j}_i = {{\tilde{h_i}^d}}_i$
        decryption_shares_and_bases: Vec<(PaillierModulusSizedNumber, PaillierModulusSizedNumber)>,
        rng: &mut impl CryptoRngCore,
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
            number_of_parties,
            threshold,
            base,
            batched_decryption_share_base,
            public_verification_key,
            batched_decryption_share,
            &mut transcript,
            rng,
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
                // The `.challenge` method mutates `transcript` by adding the label to it.
                // Although the same label is used for all values,
                // each value will be a digest of different values
                // (i.e. it will hold different `multiple` of the label inside the digest),
                // and will therefore be unique.
                transcript.challenge(b"challenge")
            })
            .collect();

        let bases_and_exponents: Vec<_> = decryption_shares_and_bases
            .iter()
            .zip(randomizers.iter())
            .map(|((a, _), c)| (a.as_ring_element(&n2), *c))
            .collect();

        let batched_decryption_share_base: PaillierModulusSizedNumber =
            PaillierRingElement::multi_exponentiate_bounded_exp(
                bases_and_exponents.as_slice(),
                ComputationalSecuritySizedNumber::BITS,
            )
            .as_natural_number();

        let bases_and_exponents: Vec<_> = decryption_shares_and_bases
            .iter()
            .zip(randomizers.iter())
            .map(|((_, b), c)| (b.as_ring_element(&n2), *c))
            .collect();

        let batched_decryption_share: PaillierModulusSizedNumber =
            PaillierRingElement::multi_exponentiate_bounded_exp(
                bases_and_exponents.as_slice(),
                ComputationalSecuritySizedNumber::BITS,
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

// This implementation yields invalid proofs, its just so the proof would be usable within a
// `CtOption`.
impl Default for ProofOfEqualityOfDiscreteLogs {
    fn default() -> Self {
        ProofOfEqualityOfDiscreteLogs {
            base_randomizer: PaillierModulusSizedNumber::ZERO,
            decryption_share_base_randomizer: PaillierModulusSizedNumber::ZERO,
            response: ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::test_exports::{BASE, CIPHERTEXT, N, WITNESS};

    #[test]
    fn valid_proof_verifies() {
        let n2 = N.square();
        let number_of_parties = 3;
        let threshold = 2;
        let n_factorial: u8 = 2 * 3;

        let witness = WITNESS;

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
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    usize::from(number_of_parties),
                    usize::from(threshold),
                ),
            )
            .as_natural_number();
        let decryption_share = decryption_share_base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    usize::from(number_of_parties),
                    usize::from(threshold),
                ),
            )
            .as_natural_number();

        let proof = ProofOfEqualityOfDiscreteLogs::prove(
            n2,
            number_of_parties,
            threshold,
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
                number_of_parties,
                threshold,
                base,
                decryption_share_base,
                public_verification_key,
                decryption_share,
                &mut OsRng
            )
            .is_ok());
    }

    #[test]
    fn valid_batched_proof_verifies() {
        let n2 = N.square();
        let number_of_parties = 3;
        let threshold = 2;
        let n_factorial: u8 = 2 * 3;

        let witness = WITNESS;

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
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    usize::from(number_of_parties),
                    usize::from(threshold),
                ),
            )
            .as_natural_number();
        let decryption_share = decryption_share_base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    usize::from(number_of_parties),
                    usize::from(threshold),
                ),
            )
            .as_natural_number();

        let decryption_shares_and_bases = vec![(decryption_share_base, decryption_share)];

        let proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            public_verification_key,
            decryption_shares_and_bases.clone(),
            &mut OsRng,
        )
        .unwrap();

        assert!(proof
            .batch_verify(
                n2,
                number_of_parties,
                threshold,
                base,
                public_verification_key,
                decryption_shares_and_bases,
                &mut OsRng
            )
            .is_ok());

        let ciphertext2: PaillierModulusSizedNumber = PaillierModulusSizedNumber::from_be_hex("07B839504B9E1D94DE3A0B72BB60C6DD17038E493876994B9C7753593368B2FD3D193883852121C127DAF4E575988FA731F52A6AD7617F13F4826EEBD25E278C0E462787D9FFC96B424C2843930C13E61A3B1C2505BF8EDE86FC3E2DBCA31B193ABE12F3840FCFBF8505145A94A794825B8EBE48DF25066997C2C4261925FEE83308EED9FCE8F5CE6E9E9074E7EC145608EED32F5D7FA00E65E63A3879F1B4B63FFEAA71A9E7F531F0A399F25E684A11B3F826680623599B9E1AA7EA00AC9326E1FE6826B7DE7457DF6CDCD94451268D474B412F821217322B77F8ECAB2ADA6EDE7BA4DF9355B13A3D71158F82AFCF16C8A4180BF59BB0CA1C59DC1E884D66DA3F8AA85D65EE9D9C32721843CAC4DCB7DFA83304FFD96280C8CCE464870BF1F5065699A61006011631EBD937B19BAAECD05CE11DA410265878049CFB3E2D1428B10D9C81B6239E221020166A4B72C41EDAA88E340002525B1DF67A7CC4BE21F62D17EEA266DAC7319044AD89BEC39DD77863E936499DCD1D787882939023402B5F5AD440DA8195679672E7E82C9FD0AF40B5184C97C3FBC626B4A32E3C8311492A0D105B7DB49BA39C225C9EB274790D2C40B6B461372CCE8516635D4D65955612A4CBEAE915E2C651282093213624466DF2901E3DF626A0935F1998E532AB01DB56678FD1D49EBEE51B75A31858DA87827A87E7D2FE858B92897B1F748CB27D");
        let decryption_share_base2 = ciphertext2
            .as_ring_element(&n2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
            .pow_bounded_exp(&PaillierModulusSizedNumber::from(n_factorial), 3)
            .as_natural_number();
        let decryption_share2 = decryption_share_base2
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    usize::from(number_of_parties),
                    usize::from(threshold),
                ),
            )
            .as_natural_number();

        let decryption_shares_and_bases = vec![
            (decryption_share_base, decryption_share),
            (decryption_share_base2, decryption_share2),
        ];

        let proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            public_verification_key,
            decryption_shares_and_bases.clone(),
            &mut OsRng,
        )
        .unwrap();

        assert!(proof
            .batch_verify(
                n2,
                number_of_parties,
                threshold,
                base,
                public_verification_key,
                decryption_shares_and_bases,
                &mut OsRng
            )
            .is_ok());
    }

    #[test]
    fn invalid_proof_fails_verification() {
        let n2 = N.square();
        let number_of_parties = 3;
        let threshold = 2;
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

        // generate a random proof and make sure it fails
        let wrong_base = PaillierModulusSizedNumber::from_be_hex("391875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let wrong_decryption_share_base = PaillierModulusSizedNumber::from_be_hex("458884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let wrong_public_verification_key = PaillierModulusSizedNumber::from_be_hex("891875311F6A7F18F7347C96A61922B21E5CA4F042A3BF5E7F46EA43AF927CB1806417A800CE327D45EC6846F3FBCF898F5BF8DE76A8A84B762E44043ADC1E2BED2C8BF7C017ADE77342DA758933360063BE7272C22467D98B99578BACBAE7D0B332CE246940F577B8A328F0DC2007A6E132C8B138A669940E81A499B10D5396658F9E8E6B4D01AB5E7A2B7401C11615628F53086DE498D4501B07C4F35D096E04608E129F09BC90DA051DE836FA143C48DCB968135C85784D02340D6EE45A8345127C6CC8A2C5AF837D64005307A64844A8198DCD0FA493DFB717AEB9022FA89B32F4643EF2F2C963586372241768D050B2AFE3A9092394E1AD49DFDB3E013D318E4D9162747F41CD4F4DBBA67642AD57563FA6A1203F2839B30D27F2D39AF50A70BA8337FA260A1AF6763D633F9CCF60F27C3D01A884F623A31977ADC62DDC2586CCF9C395C8DF3E513F92E377E9D11673BA1DB247D514CE8CBBC0BF2426167459914437077A020B710B22FE44BBC794FE4166175C5754137F0CE9B9B6DB8C622C4437D162E4731D3939E35413416710BB23B2A59FAED88765523E38ABB4134649C87A05935F1CAD26C6F3C61562EABF11ED607D4B7EB5B9A5C36405BAF548F88561B47625099BFE46B73CD2E4D6EF62A1A2A843297B8CAB546E46461C1293FC292C9C765CA3403C1C034B71973693E93C2DC3B4D8AFC872F6456B746742FF");
        let wrong_decryption_share = PaillierModulusSizedNumber::from_be_hex("058884DF955E54100E0E5F22DB059C993EE98BA75738B0F1A4383F9B38E5E79585F3290B04687C318CA471AF303E193BB303F1A659AD60204E3BF811F222BA4D14C92F3FC4B957E9718944E631373B9BA0E20F53F2260219B03F00D2691DA1E928489DDC9FC45F198FD162C8DBAC30653F4DEB3B00CFB58F534E93941B045CD54D4879BED79CD0E553D6DE0688E4FB7EBA375CD63FDE2E205387A4D30D7B0ED552D03E44AA17BB152BD8A05B449A15AB6DCB06BC912CE4691D2D2F0604A8B2218668416183F99923F9FB1BA3EFF1CE6D1CA3390DC062157CE7002AE6D5C3A580BA076F36308182C40B1E8C81140DDDA0E99FDC54C2A8330620A7C8048705E000AF78B3FA3EBF892157BC4CEB934B8E5822EAC596FC00E2D28F4B5372E80E5CF722D17035ABA8FF642C6ADE11D39E3E9DD9B034B5256E671B8B0C291D042C70BF2896E1ACD6BED1F1055EE01C368FC70C896A20479534C2A7300603524B7A6BA0206404AB289D5752BDD57C56B72CD47060224D9B43B2F8AC3D91AC605814A1FBB44C17B5283D0BDC56658B1D9823A74048CFE0A5001A80EC1F8764A96305C65C5B66F52C9A2D8C9C4F9247907716C6E18BA5F6747A59F25FA3F6A10BDCC5369481A3DB861FA1A95E3F2A5A6C054807E0386AF7FF8C6D3DFC81509FDC55E749E8C9EAB44D46C6A1E75AD364F0C178ACC62875BF626D9354283968AFF958FAD855");
        let wrong_response = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::from_be_hex("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006BA5455A81AA6CF9307458F284A2111A6E77C404C43D11A5DEF115B3051A11D53279A377C41F9ADB2136AC6B77996531E797B13746A498B8D4B44397BCC6FE9F6F49099048A3054FC14730D289EA17C3A86372B28F9AFE28DA836B3564267748679C38683A76878A27FE0E2EF633EBDFF552C30B142F6E7DCCE5AA5C2B7992F1B8E8D688C6400912C82406C03D0F2DB38C9BAD3B8C96053C190C45310C6990294FD6A5D5037917F0B63EC5833CCA36696B1D710BA058919E5418615DA1B2A2ACBA089332C8E9C1A4667C9C57342737039AA00A11981A2F926FD523D09B9A9CE46B8C4B86397FDF79590A465124471B44CD499CC76E0C05C33DAFCB6CC3286ADFCC755ECEBA356BEC6D7220B652E4752E980B81FF7155430E1980F20CFB320D51606CB0FDEAA9ACA2472677FD0F156F695BD4FA6383F4C1A3C3D5550287F8341F88A8E91EF3F97858BAB2E67937204D99ECA8CD287F2112EA24AFB9717BE494CA8D4F7D1B1F1DB798E5EB49CBAA2FC502CDADEA8039E494DF47C9DFE07CC5D41F0ED73F4A5D57AC380DFF1A822223E4868F739BBB643E0CADB5930AFB1F9B63325038CF2F0EA67FEA16244CB5D01B3F587A5EC8152A372CC7F568F3BA36E479328874DA541233AFA4921033D00310A72541C0B4F6AEDC5A4CACB04D6C8D36B27EB0DE30D6E336BE3BC946CE86F23EFC4111EFB049D308D75FFE31F9B588BAC4F82BA2F2C0EF95DAE6B3344F5AC6201CF2027E95959DB8F239F6C3F503A94802F41AC3B1D8166C928A7336531CD65AEC7C0F0E1F0EF98AFD6193EBE6DDD222FC05E0964DFCB21DD341B52D15A0F78F0307BD069D9A36655834E44205C9B03856351BD14CF8F27655700F134868BEC7186096F846EECA36CC758BA2487ED9308BDBCD7D2AC10137DCB348AA62DA4DD10C035308B6E3BB34F692CBCDE28D8B1A5647F68D1828F8A24D4D503A0E38A056CDBBB2CE1CC5C11F10AC6A97F6611C3349F7FFFB09FB47DD1650D5EE5E79D981DE87B9E7ECC986687001E47915649591B1B79270EF0FF5247D637B94C694BAA4DCB693073567C17493663C4EC69A3F65B90E923E87FD2E148D57EE4A2F97494DA73755EEDD8BEF4E434C54CD9C9789BE39408A96AA5277E3A137EC3CADCF3740B52B78719074DC882C7571A3632CAA6AB7DD3A4EE5E5564B07FC13E6B5915760932D6D0CAF2C49999558AB709AC17D89A98E8CF9DD0B6A244DA6666C279DB59807E0789F3274B7DA48EFB14B99E894326FCDE63F03413D974B220FC9D2FEDC75CEFE222BE779091E51A7A53B1283E7036197319B1A00BA84143C8E7CC862D35EA0EE8874EFC3121A4854FF08E09C6041A839D33FAD8BFF642B0D922EB904E666CE0779B48BDC1A137404B86AD73B7FDDB854EDAC227E251C576A9614E26EE37637A02FE480211D52459405E4602686606A0A7B1941F9E06768021DF07650879B8348EE4DC396DBC3A445D5BE9998223F270C2B9D199CA828E263DDA73F932C143D53FCA9DCACF0E68B0BED4EFD1B29AB88B74B9AD06884FA4566C54A046649C75288C01FBE7C872AAB5AD7C37632BEC8A161D1F849C1D0A833C62148AE2F0E867D19F61A7BB71876A36CD81422F372225846114526D8B9FD2CB0A92571A89289DC5DBAECE89A3D271F10537ED67CD600CE2EDFBEDF8D98C99D4BB0FBDEDC5219107A0E732DBD5BE4FBBB3E98A909FC153C912C904C8734923811E40250D575986D6A93DA0B945280754FFA1CC1FC16DB91CB93FB4156E0042DB4D0CD4CB19EC218A75C7913E3DD7110461D37D70C2BC20C74A61B6EE6F95CC798B147C6F681F0223EAE9F949F22A0AB242EE52480C1EA8FE7744444948888797673D48A7539A3C9D130E991399CED24AB3657FF49B1EC2E8FFC840444AAF39E3A7D120050CF931342120E7C2448233D275D71BF3104422973DBCD0E295DAD6F09278CBC91B09619563AF49A32318A1751702AA65E2B231FD039FF90B618BCB75DCDCBB0AF4CCE9BE67654D13DC1A2EC68FC60D81A3D297963213437A1FBF1545183A7F42F68FFBB532F5360F2687847BE2E55A9FA26636D21A864DE368379108650F840B3647AA37894AA6594669B0C097ED1070E27A0F53BC2AB2754FBA0C8B00589AB2217388FBFD1DF502C9A62C2352BFBA843CFCDE632538192BB058E22E8EBC6F9953A70AB5374BC39CA85265C749207B382FDB2ADD1908F926EF82FC59ABE299A47AB96DD3357AC5858BF9F6AC9A8067B1A028B1E9FD82EAAE0839D83A4770466EA40C06ED500EB7F8181DCE995AB25FA142EE6ED0C20474B9665BF989B7C69E09CC3C1313FF751BCC1D4BC51F964560A910016F7E2DD05F2858B1C47693E481A82ED2B7FAB6EE5ABA29F74C6C97151E57911D7E3191AA7E95FA60DA3E9E7945A0289B52C771CA9ED7D18ECF5B35836E84358368C0F70ABAC1C398198865AD8810FDDDC2906A0A21B7B9D530A9A24DFD26DAD4DCFE5766F5C7A9E9196D2C1A2717159E618AEC84AF7F05EC4A0E51F3052433D7558F3476DB0510A0DB722E30087388A26C03B8F62BCA76931D18F348AF9ECB72BEFCC0154594E31EFF73B969C2EA7514E19D82935AB5BF3E89FDA5D9944DB862AA21D2E9C836D63584A31274D0DC9CF7F2BDD3281B68BDB3E967379CAEFD36A45D9DBD932D3FDC6FDFACAA7AD186B39ECAA571537443892B100BBF5733FAF6A97258F23A49806E5594862F701B91F9482E8E9426CE0CEE3009F102418959A72824EA14EDAF2D4977848E34C55238EB32C74759A8C071B5392D447D5788F2D6674B6F2F242868884BB2F72E32174804271B02438C55FA9F54A9B8DF6C831E85F2DACEDDE1C75E4A1BA489C2E92FD059F0230C0F3575DA75F4A458AA543A9334BAFB08BA658BCC3008E2C2048237FA441E70BB411FC1C9C565249A3AAAF2A63905A7874E45378CFF04534868547CD8050578B3F04DFAAC856C5CEAA5631FC1CE8FF868A5791774D54F60A4A2670002F225B5BF7B786E16E1D4AE126DC44C72CB8C6A47D8263B588E19DDB918631F2F7F41E4A6B3E4C1FAD7785E14F64FF44DC47DBDE33D76076961232DCF05CF3615F58C567D68C14C29A5B9EC3BC550510FCF0374CE037BA2DCC7CFFA8B8D44687506BBE57150300C63987559E86FE84F29B5BBD032292DAC2BED4657A7CBA7E6BA7BF2F068714A9225A8702D4734C55909289BFB5466E0777DF6807C4428AD6FCC75724147C5973FCCA3BE6202260A3E391749169F724A7C338D20F9C345A2FF025F4B9617D78E7698E09844BFA8B4FA1359D7BD4A247BA91D4C1011CD6DCF0A01B33AF5D55EE82148B3003B12B6FC0F4169A97518C581DF154B11116AECB1B0AE0496F6D39E29D7F49B96A4D78C4D7C98A6BA45050C83389FCC8C7EF396E16A01B80174E03301684D8E7680E59DD907DE9EB66E2DD595319278FA7E20DBF6DFBE5FFE655E2473537E4BC1B5A0AF7D4ED2E51E216C87671CE43E0C536F91D13D336921D83802E1A833817A3FB8A405AE3BF6E13503CAF0158F3013665268ACA4F4F8671EF3D3812943EECF3EAE07F945270078F2B51AD593B4C9B163FC4A5C6360A0844F35834C806703A830C60FF93C788AFCB75D5BB8034C16199615903E0AEE7F5C9EC5A34EC9A0D592144B8C521BA440ADDA019CCC1929693711DF6CBD4F121069C87F51E72F35402050756D4088D9C9134D496150F173E263F061F516167ECAAB65293B4DDBD2F9487A83FB0C93A80AD5E662784CDE0319FC183E36900D77C19180FF7815FE1FB4163091009FF43A13082E1B627436438690E355E8FC9259AABAAB3A0838BAB13BC8EBC719ECCE921830AABCF8EDC9BD3D3F67C1AD0F6EC08A356C1CE16EF068940023F94C8DE7905516B34550E44799170CB4FC836F6B7248A0B1EA1CE810B2946A0951F9D286F51EC8BEC1495E83F1A4CB115B820C6422BCF6AEC34219A8D46B42F76DC4156679ABA8BE4FC2D6ADBB0E73982244DD78E739549A40FFBF20639D9EF3FDDCEAFBFABAE5B11201E01F4049711EEDC2CAA501D95815616C05F91D8D8B80E5391A4F705DEB0F631804924F0C8D12D75C2778A0D6F2DB3AEA27128E933E0203D46F83C834C9B3B680ABC549EB1B724E8B61E0F2CD088E11338F8C16A96D24C7165544AFBF1A679DA309CE4269B7A9E22A027BF68A8B245D32F6DA035D1D738871D04254BD6C02DCF1F9664A8B9C67123EE725FE838B01ABAB890AF02271AD9B0CA67DBD33AD0EA3B8783D0EDDFFC27AA5EF06572D4423BE83282453AE2316C413322B6F1F624760FDD38152081AE4E4EC3757AB368589A73017B0CE70D5570408EB6AACBCC29F89BDB4F8A4FA8C77C6A2D24EF2EDC6989809BB27F2E02114F130FA0A3A5E7A1ACFEA233E9E527A4A40D05B651C900B8CAD8070923A1117070732B90D09F79F7CF20C6A2A963A54B0A127265672605A591C80BFE8B6D860E716554D48CA71D174A1665516E677F6822345DDC4A20EE072E7E4A293598866675466EB48CBD72E2F0FAEF9F2DB26A019E419B0BA53EAE7C12D4E0086F11447051AA2AE4873E61230B5A8C0BB382FE6B12AB5DB432B7BA1B2A7BDAFA0CBB41F51E9ECDC86D0F89A569849483D3CFD2A87F2CE37F9DBCEBE13560839CA8B34AFEE8C67EDF3814F0D4AA0F95E029620C07874D8E3C9C2907D4F7DD2ACF61C23A24719475B87A82316728A2373DCBF088B47F71EC975F7A0F654025697B497F1D1F1E75875A9B04AB86779B342C9FB0114441964C585536FD89C9F7601F2616CAFAD7160EE8BAE139DB27DC49A3F2B554713478BC9A1ACCFC0AF99805A65C7042F58CB4C130D13F526B1E9563B47B92639C9EF5958040A2EC90ED8B10D621CDE7CEA88B75099DB541530BB0CBC43F0B6A691A4835B83C2905A77413EB837F88911B15F8685064950771B2BD54D302BB04AF4C291D7D74D85E12C834842778874652672903B80A0DF152BB34BDE34C2DAC594EB7D7F0CE17F2AEB3FE52CF3F623E7A2967EAEC5C5E340E142947B09174AAE47F0C594739D988AEFE13B7C3FA64D38ACE3E04E6ACB8EBFA92D7CDDC194E713CF27EDA77B8F46C7717862BA03F481A13404110E68A6FCF8FD5CD8DFFF4FB05B3EE0A90565D62E2CF40B6");
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
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    wrong_public_verification_key,
                    wrong_decryption_share,
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            invalid_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    wrong_public_verification_key,
                    vec![(decryption_share_base, wrong_decryption_share)],
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        let witness = WITNESS;

        let public_verification_key = base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    usize::from(number_of_parties),
                    usize::from(threshold),
                ),
            )
            .as_natural_number();

        let decryption_share = decryption_share_base
            .as_ring_element(&n2)
            .pow_bounded_exp(
                &witness,
                secret_key_share_size_upper_bound(
                    usize::from(number_of_parties),
                    usize::from(threshold),
                ),
            )
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
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    PaillierModulusSizedNumber::ZERO,
                    PaillierModulusSizedNumber::ZERO,
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::InvalidParams()
        );

        assert_eq!(
            crafted_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    PaillierModulusSizedNumber::ZERO,
                    vec![(decryption_share_base, PaillierModulusSizedNumber::ZERO)],
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::InvalidParams()
        );

        let two_n: PaillierModulusSizedNumber = N
            .resize()
            .wrapping_mul(&PaillierModulusSizedNumber::from(2u8));

        // Try to fool verification with fields that their square is zero mod N^2 (e.g. N)
        let crafted_proof = ProofOfEqualityOfDiscreteLogs {
            base_randomizer: two_n,
            decryption_share_base_randomizer: two_n,
            response: wrong_response,
        };

        assert_eq!(
            crafted_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    two_n,
                    two_n,
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::InvalidParams()
        );

        assert_eq!(
            crafted_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    two_n,
                    vec![(decryption_share_base, two_n)],
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::InvalidParams()
        );

        // Now generate a valid proof, and make sure that if we change any field it fails
        let valid_proof = ProofOfEqualityOfDiscreteLogs::prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
            decryption_share_base,
            public_verification_key,
            decryption_share,
            &mut OsRng,
        );

        let valid_batched_proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
            n2,
            number_of_parties,
            threshold,
            witness,
            base,
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
                    number_of_parties,
                    threshold,
                    wrong_base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    wrong_base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    wrong_decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(wrong_decryption_share_base, decryption_share)],
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    wrong_public_verification_key,
                    decryption_share,
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    wrong_public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_proof
                .verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    public_verification_key,
                    wrong_decryption_share,
                    &mut OsRng
                )
                .err()
                .unwrap(),
            Error::ProofVerificationError()
        );

        assert_eq!(
            valid_batched_proof
                .batch_verify(
                    n2,
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(decryption_share_base, wrong_decryption_share)],
                    &mut OsRng
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
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng
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
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng
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
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng
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
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng
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
                    number_of_parties,
                    threshold,
                    base,
                    decryption_share_base,
                    public_verification_key,
                    decryption_share,
                    &mut OsRng
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
                    number_of_parties,
                    threshold,
                    base,
                    public_verification_key,
                    vec![(decryption_share_base, decryption_share)],
                    &mut OsRng
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
    use rand_core::OsRng;

    use super::*;
    use crate::LargeBiPrimeSizedNumber;

    pub(crate) fn benchmark_proof_of_equality_of_discrete_logs(c: &mut Criterion) {
        let mut g = c.benchmark_group("equality of discrete logs");
        g.sample_size(10);

        let n = LargeBiPrimeSizedNumber::from_be_hex("97431848911c007fa3a15b718ae97da192e68a4928c0259f2d19ab58ed01f1aa930e6aeb81f0d4429ac2f037def9508b91b45875c11668cea5dc3d4941abd8fbb2d6c8750e88a69727f982e633051f60252ad96ba2e9c9204f4c766c1c97bc096bb526e4b7621ec18766738010375829657c77a23faf50e3a31cb471f72c7abecdec61bdf45b2c73c666aa3729add2d01d7d96172353380c10011e1db3c47199b72da6ae769690c883e9799563d6605e0670a911a57ab5efc69a8c5611f158f1ae6e0b1b6434bafc21238921dc0b98a294195e4e88c173c8dab6334b207636774daad6f35138b9802c1784f334a82cbff480bb78976b22bb0fb41e78fdcb8095");
        let n2 = n.square();

        for (threshold, number_of_parties) in [(6, 10), (67, 100), (667, 1000)] {
            let witness_size_upper_bound = secret_key_share_size_upper_bound(
                usize::from(number_of_parties),
                usize::from(threshold),
            );
            let witness = ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::random_mod(
                &mut OsRng,
                &NonZero::new(
                    ProofOfEqualityOfDiscreteLogsRandomnessSizedNumber::ONE
                        .shl_vartime(witness_size_upper_bound),
                )
                .unwrap(),
            );

            let base =
                PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
            let ciphertext =
                PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap());
            let decryption_share_base = ciphertext
                .as_ring_element(&n2)
                .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                .as_natural_number();
            let public_verification_key = base
                .as_ring_element(&n2)
                .pow_bounded_exp(&witness, witness_size_upper_bound)
                .as_natural_number();

            let decryption_share = decryption_share_base
                .as_ring_element(&n2)
                .pow_bounded_exp(&witness, witness_size_upper_bound)
                .as_natural_number();

            g.bench_function(
                format!("prove() for {number_of_parties} parties"),
                |bench| {
                    bench.iter(|| {
                        ProofOfEqualityOfDiscreteLogs::prove(
                            n2,
                            number_of_parties,
                            threshold,
                            witness,
                            base,
                            decryption_share_base,
                            public_verification_key,
                            decryption_share,
                            &mut OsRng,
                        )
                    });
                },
            );

            let proof = ProofOfEqualityOfDiscreteLogs::prove(
                n2,
                number_of_parties,
                threshold,
                witness,
                base,
                decryption_share_base,
                public_verification_key,
                decryption_share,
                &mut OsRng,
            );

            g.bench_function(
                format!("verify() for {number_of_parties} parties"),
                |bench| {
                    bench.iter(|| {
                        assert!(proof
                            .verify(
                                n2,
                                number_of_parties,
                                threshold,
                                base,
                                decryption_share_base,
                                public_verification_key,
                                decryption_share,
                                &mut OsRng
                            )
                            .is_ok());
                    });
                },
            );

            for batch_size in [10, 100, 1000] {
                let decryption_share_bases = iter::repeat_with(|| {
                    PaillierModulusSizedNumber::random_mod(&mut OsRng, &NonZero::new(n2).unwrap())
                        .as_ring_element(&n2)
                        .pow_bounded_exp(&PaillierModulusSizedNumber::from(2u8), 2)
                        .as_natural_number()
                })
                .take(batch_size);

                let decryption_shares_and_bases: Vec<(
                    PaillierModulusSizedNumber,
                    PaillierModulusSizedNumber,
                )> = decryption_share_bases
                    .map(|decryption_share_base| {
                        (
                            decryption_share_base,
                            decryption_share_base
                                .as_ring_element(&n2)
                                .pow_bounded_exp(&witness, witness_size_upper_bound)
                                .as_natural_number(),
                        )
                    })
                    .collect();

                g.bench_function(
                    format!("batch_prove() for {batch_size} decryptions and {number_of_parties} parties"),
                    |bench| {
                        bench.iter(|| {
                            ProofOfEqualityOfDiscreteLogs::batch_prove(
                                n2,
                                number_of_parties,
                                threshold,
                                witness,
                                base,
                                public_verification_key,
                                decryption_shares_and_bases.clone(),
                                &mut OsRng,
                            )
                        });
                    },
                );

                let batched_proof = ProofOfEqualityOfDiscreteLogs::batch_prove(
                    n2,
                    number_of_parties,
                    threshold,
                    witness,
                    base,
                    public_verification_key,
                    decryption_shares_and_bases.clone(),
                    &mut OsRng,
                )
                .unwrap();

                g.bench_function(
                    format!(
                        "batch_verify() for {batch_size} decryptions and {number_of_parties} parties"
                    ),
                    |bench| {
                        bench.iter(|| {
                            assert!(batched_proof
                                .batch_verify(
                                    n2,
                                    number_of_parties,
                                    threshold,
                                    base,
                                    public_verification_key,
                                    decryption_shares_and_bases.clone(),
                                    &mut OsRng
                                )
                                .is_ok());
                        });
                    },
                );
            }
        }

        g.finish();
    }
}
