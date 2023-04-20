use core::fmt;
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
