// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: Apache-2.0

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("The following protocol error occurred: {0}")]
    ProtocolError(ProtocolError),
    #[error("The following sanity-check error occurred: {0}")]
    SanityCheckError(SanityCheckError),
}

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum ProtocolError {
    #[error("The following parties {malicious_parties:?} behaved maliciously by submitting invalid proofs")]
    ProofVerificationError { malicious_parties: Vec<u16> },
}

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum SanityCheckError {
    #[error("Invalid Params")]
    InvalidParams(),
}

pub type Result<T> = std::result::Result<T, Error>;
