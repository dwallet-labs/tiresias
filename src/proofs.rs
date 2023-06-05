use crypto_bigint::{Encoding, Limb, Uint};
#[cfg(feature = "benchmarking")]
pub(crate) use equality_of_discrete_logs::benchmark_proof_of_equality_of_discrete_logs;
pub use equality_of_discrete_logs::ProofOfEqualityOfDiscreteLogs;
use merlin::Transcript;

mod equality_of_discrete_logs;

/// A transcript protocol for fiat-shamir transforms of interactive to non-interactive proofs.
trait TranscriptProtocol {
    fn append_statement<const LIMBS: usize>(
        &mut self,
        label: &'static [u8],
        statement: &Uint<LIMBS>,
    ) where
        Uint<LIMBS>: Encoding;

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS>;
}

impl TranscriptProtocol for Transcript {
    fn append_statement<const LIMBS: usize>(
        &mut self,
        label: &'static [u8],
        statement: &Uint<LIMBS>,
    ) where
        Uint<LIMBS>: Encoding,
    {
        self.append_message(label, Uint::<LIMBS>::to_le_bytes(statement).as_mut());
    }

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS> {
        let mut buf: Vec<u8> = vec![0u8; LIMBS * Limb::BYTES];
        self.challenge_bytes(label, buf.as_mut_slice());

        Uint::<LIMBS>::from_le_slice(&buf)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::ComputationalSecuritySizedNumber;

    #[test]
    fn challenge_modifies_transcript() {
        let num_challenges = 5;
        let mut transcript = Transcript::new(b"Test");

        let challenges: HashSet<ComputationalSecuritySizedNumber> = (1..=num_challenges)
            .map(|_| {
                let challenge: ComputationalSecuritySizedNumber =
                    transcript.challenge(b"challenge");
                challenge
            })
            .collect();

        assert_eq!(challenges.len(), num_challenges);
    }
}
