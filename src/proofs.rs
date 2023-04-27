use core::fmt;
use crypto_bigint::{Encoding, Limb, Uint, U4096};
use merlin::Transcript;
use std::error::Error;

mod equality_of_discrete_logs;

#[derive(Debug, Clone, Copy)]
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

/// Defines a `TranscriptProtocol` trait for using a Merlin transcript.
pub trait TranscriptProtocol {
    /// Append a `statement` with the given `label`.
    fn append_statement<const LIMBS: usize>(
        &mut self,
        label: &'static [u8],
        statement: &Uint<LIMBS>,
    ) where
        Uint<LIMBS>: Encoding;

    /// Compute a `label`ed challenge variable.
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
        self.append_message(label, Uint::<LIMBS>::to_le_bytes(&statement).as_mut());
    }

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS> {
        let mut buf: Vec<u8> = vec![0u8; LIMBS * Limb::BYTES];
        self.challenge_bytes(label, buf.as_mut_slice());

        Uint::<LIMBS>::from_le_slice(&buf)
    }
}
