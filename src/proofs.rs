use core::fmt;
use crypto_bigint::{Encoding, U4096};
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
    // TODO: is field element the correct phrase here?
    /// Append a `field_element` with the given `label`.
    fn append(&mut self, label: &'static [u8], field_element: &U4096);

    /// Compute a `label`ed challenge variable.
    fn challenge(&mut self, label: &'static [u8]) -> U4096;
}

impl TranscriptProtocol for Transcript {
    fn append(&mut self, label: &'static [u8], field_element: &U4096) {
        self.append_message(label, &field_element.to_le_bytes());
    }

    // TODO: this actually needs to be a different size, kappa smth.
    fn challenge(&mut self, label: &'static [u8]) -> U4096 {
        let mut buf = [0u8; U4096::BYTES];
        self.challenge_bytes(label, &mut buf);

        U4096::from_le_slice(&buf)
    }
}
