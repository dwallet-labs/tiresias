use core::fmt;
use std::error::Error;

use crypto_bigint::{Encoding, Limb, Uint};
use merlin::Transcript;

pub(crate) mod equality_of_discrete_logs;

#[derive(Debug, Clone, Copy)]
/// An error generated for an invalid proof during verification.
pub struct ProofError;

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ProofError")
    }
}

impl Error for ProofError {
    fn description(&self) -> &str {
        "Verification failure!"
    }
}

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
