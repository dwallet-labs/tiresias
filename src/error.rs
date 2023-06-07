#[derive(thiserror::Error, Debug, PartialEq)]
pub enum Error {
    #[error("The following protocol error occurred: {0}")]
    ProtocolError(ProtocolError),
    #[error("The following sanity-check error occurred: {0}")]
    SanityCheckError(SanityCheckError),
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum ProtocolError {}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum SanityCheckError {
    #[error("Invalid Params")]
    InvalidParams(),
}

pub type Result<T> = std::result::Result<T, Error>;
