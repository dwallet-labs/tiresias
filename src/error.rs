// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum Error {
    #[error("the following protocol error occurred: {0}")]
    ProtocolError(ProtocolError),
    #[error("the following sanity-check error occurred: {0}")]
    SanityCheckError(SanityCheckError),
    #[error("group error")]
    GroupInstantiation(#[from] group::Error),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
    #[error("homomorphic-encryption error")]
    HomomorphicEncryption(#[from] homomorphic_encryption::Error),
}

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum ProtocolError {
    #[error("the following parties {malicious_parties:?} behaved maliciously by submitting invalid proofs")]
    ProofVerificationError { malicious_parties: Vec<u16> },
}

#[derive(thiserror::Error, Clone, Debug, PartialEq)]
pub enum SanityCheckError {
    #[error("invalid Params")]
    InvalidParams(),
}

pub type Result<T> = std::result::Result<T, Error>;
